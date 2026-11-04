import { Injectable, effect, inject, signal } from '@angular/core';
import { AuthService } from './auth.service';
import { LOCKED_MESSAGE, VaultService } from './vault.service';

// Gleiche Grenzen wie im Breach-Service (validation/RequestValidation.kt), sonst gibt es nur 400
const USERNAME_MIN = 3;
const USERNAME_MAX = 254;
// Wer länger als 3 s warten müsste, bekommt sofort 429. Nicht endlos wiederholen.
const BREACH_MAX_RETRIES = 5;

interface BreachCheck {
  type: 'email_hash' | 'username';
  label: string;
}

interface BreachResult {
  found: number;
  fields: string[];
  sources: { name: string; date?: string }[];
}

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

function isCheckableUsername(name: string): boolean {
  return name.length >= USERNAME_MIN && name.length <= USERNAME_MAX && !/[\u0000-\u001f\u007f]/.test(name);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function describe(check: BreachCheck, result: BreachResult | null): BreachLine {
  const who = check.label;
  if (result === null) {
    return { text: `${who}: nicht geprüft (LeakCheck gerade nicht erreichbar)`, hit: false };
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

// Konten auf Leaks prüfen (Breach-Service, POST /breach/account).
// Als Service, damit eine laufende Prüfung beim Seitenwechsel weiterläuft und das Ergebnis bleibt.
@Injectable({ providedIn: 'root' })
export class BreachService {
  private auth = inject(AuthService);
  private vault = inject(VaultService);

  readonly running = signal(false);
  readonly progress = signal('');
  readonly error = signal('');
  readonly lines = signal<BreachLine[]>([]);

  constructor() {
    // Beim Sperren keine alten Ergebnisse (E-Mails, Benutzernamen) stehen lassen
    effect(() => {
      if (!this.vault.unlocked()) {
        this.clear();
      }
    });
  }

  // Konto-E-Mail + alle verschiedenen "user"-Felder aus den Köpfen, ohne Duplikate.
  // Enthält "@" → E-Mail (nur als Hash), sonst Benutzername (nur mit Zustimmung, geht im Klartext raus).
  private collectChecks(withUsernames: boolean): BreachCheck[] {
    const checks = new Map<string, BreachCheck>();
    const values = [this.auth.email, ...this.vault.items().map((item) => item.user)];
    for (const raw of values) {
      const value = (raw ?? '').trim();
      if (!value) continue;
      if (value.includes('@')) {
        const key = 'e:' + value.toLowerCase();
        if (!checks.has(key)) checks.set(key, { type: 'email_hash', label: value.toLowerCase() });
      } else if (withUsernames && isCheckableUsername(value)) {
        const key = 'u:' + value;
        if (!checks.has(key)) checks.set(key, { type: 'username', label: value });
      }
    }
    return [...checks.values()];
  }

  // Ergebnis bei Erfolg, null = nicht geprüft (502, zu oft 429), 'locked' = Tresor gesperrt
  private async checkOne(check: BreachCheck): Promise<BreachResult | null | 'locked'> {
    const value = check.type === 'email_hash' ? await emailHash(check.label) : check.label;

    for (let attempt = 0; attempt <= BREACH_MAX_RETRIES; attempt++) {
      const request = this.vault.breachRequest({ type: check.type, value: value });
      if (!request) return 'locked';
      const response = await request;

      if (response.ok) {
        return await response.json();
      }
      if (response.status === 429) {
        const seconds = Number(response.headers.get('Retry-After')) || 2;
        this.progress.update((text) => text + ` (warte ${seconds} s …)`);
        await sleep(seconds * 1000);
        continue;
      }
      // readError leitet bei 401 unauthorized (Login abgelaufen) schon zum Login weiter
      const errorCode = await this.vault.readError(response);
      if (errorCode === 'vault_locked') return 'locked';
      return null;
    }
    return null;
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

    const checks = this.collectChecks(withUsernames);
    if (checks.length === 0) {
      this.error.set('Keine E-Mails oder Benutzernamen zum Prüfen gefunden.');
      return;
    }

    this.running.set(true);
    let hits = 0;

    try {
      // Der Reihe nach, LeakCheck erlaubt nur 1 Anfrage pro Sekunde für den ganzen Server
      for (let i = 0; i < checks.length; i++) {
        this.progress.set(`Prüfe ${i + 1} von ${checks.length} …`);
        const result = await this.checkOne(checks[i]);
        if (result === 'locked') {
          this.vault.forget(LOCKED_MESSAGE);
          this.lines.set([]);
          this.progress.set('');
          this.error.set('Prüfung abgebrochen, der Tresor wurde gesperrt.');
          return;
        }
        if (result && result.found > 0) hits++;
        this.lines.update((lines) => [...lines, describe(checks[i], result)]);
      }
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
