import { Injectable, effect, inject, signal } from '@angular/core';
import { AuthService } from './auth.service';
import { LOCKED_MESSAGE, VaultService } from './vault.service';

// Gleiche Grenzen wie im Breach-Service (routes/Validation.kt), sonst gibt es nur 400
const USERNAME_MIN = 3;
const USERNAME_MAX = 254;
// 429 beim Anlegen heißt: Queue im Service voll. Nicht endlos wiederholen.
const BREACH_MAX_RETRIES = 5;
// Der Service antwortet sofort mit einem Job, das Ergebnis wird abgefragt.
// Öfter fragen bringt nichts, der Worker schafft eh nur ~1 LeakCheck-Anfrage pro Sekunde.
const BREACH_POLL_MS = 1500;
// Danach gibt der Browser für dieses Konto auf. Der Job läuft im Service weiter (bis zu 1 h),
// beim nächsten Klick kommt das Ergebnis dann meist schon aus dem Cache.
const BREACH_MAX_WAIT_MS = 3 * 60 * 1000;

// LeakCheck durchsucht nur diese Zeichen, alles andere (Leerzeichen, Umlaute, alle anderen Sonderzeichen)
// lehnt es ab. Gleiche Regel wie routes/Validation.kt.
const USERNAME_CHARS = /^[A-Za-z0-9._-]+$/;

interface BreachCheck {
  type: 'email_hash' | 'username';
  label: string;
}

interface BreachResult {
  found: number;
  fields: string[];
  sources: { name: string; date?: string }[];
}

interface BreachJob {
  jobId: string;
  status: 'queued' | 'running' | 'waiting_for_upstream' | 'done' | 'failed';
  attempts?: number;
  nextAttemptAt?: string;
  result?: BreachResult;
}

// Ergebnis für ein Konto: null = nicht geprüft (Job failed, Queue voll, zu lange gewartet),
// 'unsupported' = LeakCheck kann den Namen nicht durchsuchen (400), 'locked' = Tresor gesperrt
type CheckOutcome = BreachResult | null | 'unsupported' | 'locked';

export interface BreachLine {
  text: string;
  hit: boolean;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// LeakCheck-Hash: SHA-256 über die E-Mail in Kleinbuchstaben, hex, die ersten 24 Zeichen
async function emailHash(email: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(email.trim().toLowerCase()));
  return bytesToHex(new Uint8Array(digest)).slice(0, 24);
}

function hasCheckableLength(name: string): boolean {
  return name.length >= USERNAME_MIN && name.length <= USERNAME_MAX;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Beim Warten auf LeakCheck steht in nextAttemptAt, wann der nächste Versuch kommt. Vorher fragen ist sinnlos,
// aber höchstens 10 s still sein, damit die Anzeige nicht hängt.
function nextPoll(job: BreachJob): number {
  if (!job.nextAttemptAt) return BREACH_POLL_MS;
  const untilRetry = Date.parse(job.nextAttemptAt) - Date.now();
  return Math.min(Math.max(untilRetry, BREACH_POLL_MS), 10_000);
}

function unsupportedLine(names: string[]): BreachLine {
  return { text: `Nicht prüfbar, weil LeakCheck nur Buchstaben a–z, Ziffern und . _ - unterstützt: ${names.join(', ')}`, hit: false };
}

function describe(check: BreachCheck, result: Exclude<CheckOutcome, 'locked'>): BreachLine {
  const who = check.label;
  if (result === null) {
    return { text: `${who}: nicht geprüft (LeakCheck gerade nicht erreichbar)`, hit: false };
  }
  if (result === 'unsupported') {
    return { text: `${who}: nicht prüfbar (LeakCheck unterstützt nur Buchstaben a–z, Ziffern und . _ -)`, hit: false };
  }
  if (result.found === 0) {
    return { text: `${who}: in keinem bekannten Leak`, hit: false };
  }
  const sources = result.sources
    .map((source) => source.date ? `${source.name} (${source.date})` : source.name)
    .join(', ');
  const fields = result.fields.length ? ` Betroffen: ${result.fields.join(', ')}.` : '';
  return { text: `${who}: in ${result.found} Leak(s) gefunden.${fields} Quellen: ${sources || 'unbekannt'}`, hit: true };
}

// Konten auf Leaks prüfen (Breach-Service, POST /breach/account + GET /breach/account/jobs/{jobId}).
// Als Service, damit eine laufende Prüfung beim Seitenwechsel weiterläuft und das Ergebnis bleibt.
@Injectable({ providedIn: 'root' })
export class BreachService {
  private auth = inject(AuthService);
  private vault = inject(VaultService);

  readonly running = signal(false);
  readonly progress = signal('');
  readonly error = signal('');
  readonly lines = signal<BreachLine[]>([]);

  // "Prüfe 3 von 7 …", Wartehinweise werden hinten angehängt statt aufzusummieren
  private progressBase = '';

  constructor() {
    // Beim Sperren keine alten Ergebnisse (E-Mails, Benutzernamen) stehen lassen
    effect(() => {
      if (!this.vault.unlocked()) {
        this.clear();
      }
    });
  }

  private showProgress(extra: string | null): void {
    this.progress.set(extra ? `${this.progressBase} (${extra})` : this.progressBase);
  }

  // Konto-E-Mail + alle verschiedenen "user"-Felder aus den Köpfen, ohne Duplikate.
  // Enthält "@" → E-Mail (nur als Hash), sonst Benutzername (nur mit Zustimmung, geht im Klartext raus).
  // Benutzernamen mit Zeichen, die LeakCheck nicht kann, gehen gar nicht erst raus und landen in unsupported.
  private collectChecks(withUsernames: boolean): { checks: BreachCheck[]; unsupported: string[] } {
    const checks = new Map<string, BreachCheck>();
    const unsupported = new Set<string>();
    const values = [this.auth.email, ...this.vault.items().map((item) => item.user)];
    for (const raw of values) {
      const value = (raw ?? '').trim();
      if (!value) continue;
      if (value.includes('@')) {
        const key = 'e:' + value.toLowerCase();
        if (!checks.has(key)) checks.set(key, { type: 'email_hash', label: value.toLowerCase() });
      } else if (withUsernames && hasCheckableLength(value)) {
        if (!USERNAME_CHARS.test(value)) {
          unsupported.add(value);
          continue;
        }
        const key = 'u:' + value;
        if (!checks.has(key)) checks.set(key, { type: 'username', label: value });
      }
    }
    return { checks: [...checks.values()], unsupported: [...unsupported] };
  }

  private async checkOne(check: BreachCheck): Promise<CheckOutcome> {
    const value = check.type === 'email_hash' ? await emailHash(check.label) : check.label;
    const job = await this.submitJob(check.type, value);
    if (job === null || job === 'locked' || job === 'unsupported') return job;
    return await this.awaitJob(job);
  }

  // Legt den Job an. Antwort ist sofort 202 mit { jobId, status, ... }, bei Cache-Treffer schon mit status "done".
  private async submitJob(type: string, value: string): Promise<BreachJob | null | 'unsupported' | 'locked'> {
    for (let attempt = 0; attempt <= BREACH_MAX_RETRIES; attempt++) {
      const request = this.vault.breachRequest('POST', '/breach/account', { type: type, value: value });
      if (!request) return 'locked';
      const response = await request;

      if (response.ok) {
        return await response.json();
      }
      if (response.status === 429) {
        const seconds = Number(response.headers.get('Retry-After')) || 2;
        this.showProgress(`Service ausgelastet, warte ${seconds} s …`);
        await sleep(seconds * 1000);
        continue;
      }
      // readError leitet bei 401 unauthorized (Login abgelaufen) schon zum Login weiter
      const errorCode = await this.vault.readError(response);
      if (errorCode === 'vault_locked') return 'locked';
      // 400: Der Breach-Service lehnt Namen ab, die LeakCheck nicht durchsuchen kann. Ein neuer Versuch ändert daran nichts.
      if (response.status === 400) return 'unsupported';
      return null;
    }
    return null;
  }

  // Fragt den Job ab, bis er done oder failed ist. Der Service wiederholt LeakCheck selbst (429, Ausfall),
  // der Browser muss nur warten und darf nicht vorher abbrechen.
  private async awaitJob(job: BreachJob): Promise<CheckOutcome> {
    const deadline = Date.now() + BREACH_MAX_WAIT_MS;
    while (true) {
      if (job.status === 'done') return job.result ?? null;
      if (job.status === 'failed') return null;
      if (Date.now() > deadline) return null;

      this.showProgress(job.status === 'waiting_for_upstream'
        ? `LeakCheck antwortet gerade nicht, Versuch ${job.attempts} …`
        : null);
      await sleep(nextPoll(job));

      const request = this.vault.breachRequest('GET', '/breach/account/jobs/' + encodeURIComponent(job.jobId));
      if (!request) return 'locked';
      const response = await request;
      if (!response.ok) {
        const errorCode = await this.vault.readError(response);
        if (errorCode === 'vault_locked') return 'locked';
        // 404: Job weg, z. B. weil der Service neu gestartet wurde (die Queue liegt nur im Speicher)
        return null;
      }
      job = await response.json();
    }
  }

  async run(withUsernames: boolean): Promise<void> {
    this.error.set('');
    this.lines.set([]);
    this.progress.set('');

    // Nur bei entsperrtem Tresor: Die Benutzernamen stammen aus dem Tresor, und der Breach-Service will den Tresor-Token
    if (!this.vault.unlocked()) {
      this.error.set('Bitte entsperre zuerst deinen Tresor.');
      return;
    }

    const { checks, unsupported } = this.collectChecks(withUsernames);
    if (checks.length === 0) {
      this.error.set('Keine E-Mails oder Benutzernamen zum Prüfen gefunden.');
      if (unsupported.length) this.lines.set([unsupportedLine(unsupported)]);
      return;
    }

    this.running.set(true);
    let hits = 0;

    try {
      // Der Reihe nach, LeakCheck erlaubt nur 1 Anfrage pro Sekunde für den ganzen Server
      for (let i = 0; i < checks.length; i++) {
        this.progressBase = `Prüfe ${i + 1} von ${checks.length} …`;
        this.showProgress(null);
        const result = await this.checkOne(checks[i]);
        if (result === 'locked') {
          this.vault.forget(LOCKED_MESSAGE);
          return;
        }
        if (result && result !== 'unsupported' && result.found > 0) hits++;
        this.lines.update((lines) => [...lines, describe(checks[i], result)]);
      }
      if (unsupported.length) this.lines.update((lines) => [...lines, unsupportedLine(unsupported)]);
      this.progress.set(hits === 0
        ? `Fertig: ${checks.length} geprüft, nichts gefunden.`
        : `Fertig: ${hits} von ${checks.length} in Leaks gefunden. Ändere dort am besten die Passwörter.`);
    } catch (error) {
      console.error(error);
      this.error.set('Breach-Service nicht erreichbar.');
    } finally {
      this.running.set(false);
    }
  }

  clear(): void {
    this.progress.set('');
    this.error.set('');
    this.lines.set([]);
  }
}
