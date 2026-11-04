import { Injectable, inject, signal } from '@angular/core';
import { AuthService } from './auth.service';
import { BREACH_BASE, VAULT_BASE } from './config';
import {
  KDF, Kdf, base64ToBytes, bytesToBase64, decryptPart, deriveVaultKeys, encryptPart, isDefaultKdf, unwrapDek, wrapDek,
} from './crypto';

export interface VaultItem {
  id: string;
  rev: number;
  title: string;
  url: string;
  user: string;
  alg: string;
}

interface Head {
  title: string;
  url: string;
  user: string;
}

// Eingaben aus dem Formular "Passwort hinzufügen / Eintrag bearbeiten"
export interface ItemInput extends Head {
  password: string;
  alg: string;
}

export const LOCKED_MESSAGE = 'Der Tresor wurde gesperrt. Bitte gib dein Masterpasswort erneut ein.';
const AUTO_LOCK_MS = 15 * 60 * 1000;

export function vaultErrorMessage(errorCode: string | undefined, fallback: string): string {
  // Einer der beiden Crypto-Services (AES / ChaCha) ist weg, der Vault sagt in reason welcher
  if (errorCode === 'crypto_unavailable') {
    return 'Verschlüsselungsservice ist gerade nicht erreichbar. Versuche es mit einem anderen oder später wieder.';
  }
  if (errorCode === 'upstream_error') {
    return 'Gerade nicht möglich. Bitte versuche es später erneut.';
  }
  if (errorCode === 'integrity_error') {
    return 'Achtung: Daten auf dem Server wurden verändert. Bitte melde das dem Support.';
  }
  return fallback;
}

// Hält Tresor-Token und Tresorschlüssel (DEK). Der Service lebt, solange die SPA offen ist,
// deshalb bleibt der Tresor beim Wechsel zwischen Dashboard und Tresor entsperrt.
@Injectable({ providedIn: 'root' })
export class VaultService {
  private auth = inject(AuthService);

  // Nur im Arbeitsspeicher, nie im Storage
  private vaultToken: string | null = null;
  private dek: CryptoKey | null = null;
  private autoLockTimer: ReturnType<typeof setTimeout> | undefined;

  readonly unlocked = signal(false);
  readonly items = signal<VaultItem[]>([]);
  // Meldung auf dem Sperrbildschirm, z. B. "Tresor gesperrt."
  readonly lockMessage = signal('');
  // Fehler beim Laden der Einträge oder eines Passworts
  readonly error = signal('');

  private request(method: string, path: string, body?: object, itemId?: string): Promise<Response> {
    const headers: Record<string, string> = {
      'Authorization': 'Bearer ' + this.auth.loginToken,
      // Platzhalter, solange es kein Gateway gibt
      'X-User-Id': this.auth.userId,
      'X-Session-Id': this.auth.vaultSessionId(),
    };
    if (body) {
      headers['Content-Type'] = 'application/json';
    }
    if (this.vaultToken) {
      headers['X-Vault-Token'] = this.vaultToken;
    }
    if (itemId) {
      headers['X-Item-Id'] = itemId;
    }

    return fetch(VAULT_BASE + path, {
      method: method,
      headers: headers,
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  async readError(response: Response): Promise<string | undefined> {
    const data = await response.json().catch(() => ({}));
    console.warn('Vault-Fehler', response.status, data.error, data.reason || '',
      'X-Request-ID:', response.headers.get('X-Request-ID'));
    if (response.status === 401 && data.error === 'unauthorized') {
      this.auth.goToLogin(true);
    }
    return data.error;
  }

  // Für den Breach-Service: der will Login-Token und Tresor-Token. null = Tresor gesperrt
  breachRequest(body: object): Promise<Response> | null {
    if (!this.vaultToken) {
      return null;
    }
    return fetch(BREACH_BASE + '/breach/account', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + this.auth.loginToken,
        'X-Vault-Token': this.vaultToken,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
  }

  // 'create' = es gibt noch keinen Tresor, 'unlock' = Tresor vorhanden, null = Fehler (steht in lockMessage)
  async checkVault(): Promise<'create' | 'unlock' | null> {
    try {
      const response = await this.request('GET', '/vault/params');
      if (response.status === 404) {
        return 'create';
      }
      if (response.ok) {
        return 'unlock';
      }
      this.lockMessage.set(vaultErrorMessage(await this.readError(response),
        'Tresor gerade nicht erreichbar. Bitte lade die Seite neu.'));
    } catch (error) {
      console.error(error);
      this.lockMessage.set('Tresor-Server nicht erreichbar.');
    }
    return null;
  }

  // Rückgabe: null = geklappt, 'exists' = gibt schon einen Tresor, sonst Fehlermeldung
  async create(password: string): Promise<string | null> {
    try {
      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const keys = await deriveVaultKeys(password, saltBytes, KDF);

      const dekBytes = crypto.getRandomValues(new Uint8Array(32));
      const wdek = await wrapDek(dekBytes, keys.kek, this.auth.userId);

      const response = await this.request('POST', '/vault', {
        salt: bytesToBase64(saltBytes),
        kdf: KDF,
        unlockKey: bytesToBase64(keys.unlockKey),
        wdek: bytesToBase64(wdek),
      });
      keys.unlockKey.fill(0);
      keys.kek.fill(0);

      if (response.status === 409) {
        return 'exists';
      }
      if (!response.ok) {
        return vaultErrorMessage(await this.readError(response), 'Tresor konnte nicht erstellt werden.');
      }

      const data = await response.json();
      await this.opened(data.vaultToken, dekBytes);
      return null;
    } catch (error) {
      console.error(error);
      return 'Tresor-Server nicht erreichbar.';
    }
  }

  // Rückgabe: null = geklappt, sonst Fehlermeldung
  async unlock(password: string): Promise<string | null> {
    try {
      const paramsResponse = await this.request('GET', '/vault/params');
      if (!paramsResponse.ok) {
        return vaultErrorMessage(await this.readError(paramsResponse), 'Tresor gerade nicht erreichbar.');
      }
      const params: { salt: string; kdf: Kdf } = await paramsResponse.json();
      if (!isDefaultKdf(params.kdf)) {
        return 'Der Tresor konnte nicht geöffnet werden.';
      }

      const keys = await deriveVaultKeys(password, base64ToBytes(params.salt), params.kdf);

      const response = await this.request('POST', '/vault/unlock', {
        unlockKey: bytesToBase64(keys.unlockKey),
      });
      keys.unlockKey.fill(0);

      if (response.status === 401) {
        return 'Masterpasswort ist falsch.';
      }
      if (response.status === 429) {
        const seconds = response.headers.get('Retry-After');
        return `Zu viele Fehlversuche. Bitte ${seconds} Sekunden warten.`;
      }
      if (!response.ok) {
        const errorCode = await this.readError(response);
        return errorCode === 'integrity_error'
          ? 'Der Tresor konnte nicht geöffnet werden.'
          : vaultErrorMessage(errorCode, 'Tresor konnte nicht entsperrt werden.');
      }

      const data = await response.json();
      const wdek = base64ToBytes(data.wdek);
      if (wdek.length !== 62 || wdek[0] !== 1 || wdek[1] !== 1) {
        return 'Der Tresor konnte nicht geöffnet werden.';
      }
      const dekBytes = await unwrapDek(wdek, keys.kek, this.auth.userId);
      keys.kek.fill(0);

      await this.opened(data.vaultToken, dekBytes);
      return null;
    } catch (error) {
      console.error(error);
      return error instanceof Error && error.name === 'OperationError'
        ? 'Tresor konnte nicht geöffnet werden.'
        : 'Tresor-Server nicht erreichbar.';
    }
  }

  private async opened(vaultToken: string, dekBytes: Uint8Array<ArrayBuffer>): Promise<void> {
    this.vaultToken = vaultToken;
    this.dek = await crypto.subtle.importKey('raw', dekBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
    dekBytes.fill(0);
    this.lockMessage.set('');
    this.unlocked.set(true);
    this.resetAutoLock();
    await this.loadItems();
  }

  // Schlüssel vergessen und Sperrbildschirm zeigen
  forget(message: string): void {
    clearTimeout(this.autoLockTimer);
    this.vaultToken = null;
    this.dek = null;
    this.items.set([]);
    this.error.set('');
    this.lockMessage.set(message);
    this.unlocked.set(false);
  }

  async lock(message = 'Tresor gesperrt.'): Promise<void> {
    try {
      await this.request('POST', '/vault/lock');
    } catch (error) {
      console.error(error);
    }
    this.forget(message);
  }

  resetAutoLock(): void {
    clearTimeout(this.autoLockTimer);
    if (this.dek) {
      this.autoLockTimer = setTimeout(() => this.lock('Tresor nach 15 Minuten ohne Aktivität gesperrt.'), AUTO_LOCK_MS);
    }
  }

  async loadItems(): Promise<void> {
    this.error.set('');
    try {
      const response = await this.request('GET', '/items');
      if (!response.ok) {
        const errorCode = await this.readError(response);
        if (errorCode === 'vault_locked') {
          this.forget(LOCKED_MESSAGE);
          return;
        }
        this.error.set(vaultErrorMessage(errorCode, 'Einträge konnten nicht geladen werden.'));
        return;
      }
      const data: { items: { id: string; rev: number; head: string; alg?: string }[] } = await response.json();

      const items: VaultItem[] = [];
      for (const item of data.items) {
        const head = await decryptPart<Head>(this.dek!, base64ToBytes(item.head), this.auth.userId, item.id, 'h', item.rev);
        // alg: welcher Crypto-Service den Eintrag auf dem Server verschlüsselt (älterer Vault ohne Feld → chacha)
        items.push({ id: item.id, rev: item.rev, title: head.title, url: head.url, user: head.user, alg: item.alg || 'chacha' });
      }
      this.items.set(items);
    } catch (error) {
      console.error(error);
      this.error.set(error instanceof Error && error.name === 'OperationError'
        ? 'Ein Eintrag konnte nicht entschlüsselt werden.'
        : 'Tresor-Server nicht erreichbar.');
    }
  }

  // Passwort eines Eintrags erst bei Bedarf vom Vault holen. null = Fehler (steht in error)
  async fetchSecret(item: VaultItem): Promise<string | null> {
    this.error.set('');
    try {
      const response = await this.request('GET', '/items/secret', undefined, item.id);
      if (!response.ok) {
        const errorCode = await this.readError(response);
        if (errorCode === 'vault_locked') {
          this.forget(LOCKED_MESSAGE);
          return null;
        }
        this.error.set(errorCode === 'not_found'
          ? 'Diesen Eintrag gibt es nicht mehr.'
          : vaultErrorMessage(errorCode, 'Passwort konnte nicht geladen werden.'));
        return null;
      }
      const data: { data: string; rev: number } = await response.json();
      const secret = await decryptPart<{ pw: string }>(this.dek!, base64ToBytes(data.data), this.auth.userId, item.id, 's', data.rev);
      return secret.pw;
    } catch (error) {
      console.error(error);
      this.error.set(error instanceof Error && error.name === 'OperationError'
        ? 'Passwort konnte nicht entschlüsselt werden.'
        : 'Tresor-Server nicht erreichbar.');
      return null;
    }
  }

  // editing = null → neuer Eintrag, sonst wird dieser Eintrag überschrieben.
  // Rückgabe: null = geklappt, 'close' = Formular schließen (woanders geändert oder Tresor gesperrt), sonst Fehlermeldung
  async saveItem(editing: VaultItem | null, input: ItemInput): Promise<string | null> {
    try {
      const itemId = editing ? editing.id : crypto.randomUUID();
      const rev = editing ? editing.rev + 1 : 1;
      const userId = this.auth.userId;

      const head = await encryptPart(this.dek!, { title: input.title, url: input.url, user: input.user }, userId, itemId, 'h', rev);
      const secret = await encryptPart(this.dek!, { pw: input.password }, userId, itemId, 's', rev);

      const response = await this.request('PUT', '/items', {
        rev: rev,
        head: bytesToBase64(head),
        secret: bytesToBase64(secret),
        // Welcher Crypto-Service Schicht 2 macht. Wechsel beim Bearbeiten: der Vault verschlüsselt einfach neu.
        alg: input.alg,
      }, itemId);

      if (response.status === 409) {
        await this.loadItems();
        this.error.set('Der Eintrag wurde inzwischen woanders geändert. Bitte prüfe ihn und bearbeite ihn erneut.');
        return 'close';
      }
      if (!response.ok) {
        const errorCode = await this.readError(response);
        if (errorCode === 'vault_locked') {
          this.forget(LOCKED_MESSAGE);
          return 'close';
        }
        return vaultErrorMessage(errorCode, 'Eintrag konnte nicht gespeichert werden.');
      }

      const saved: VaultItem = { id: itemId, rev: rev, title: input.title, url: input.url, user: input.user, alg: input.alg };
      this.items.update((items) => editing
        ? items.map((other) => (other.id === itemId ? saved : other))
        : [...items, saved]);
      return null;
    } catch (error) {
      console.error(error);
      return 'Tresor-Server nicht erreichbar.';
    }
  }

  // Rückgabe: null = geklappt, sonst Fehlermeldung
  async deleteItem(item: VaultItem): Promise<string | null> {
    try {
      const response = await this.request('DELETE', '/items', undefined, item.id);

      // 404: schon weg, ist auch in Ordnung
      if (!response.ok && response.status !== 404) {
        const errorCode = await this.readError(response);
        if (errorCode === 'vault_locked') {
          this.forget(LOCKED_MESSAGE);
          return null;
        }
        return vaultErrorMessage(errorCode, 'Eintrag konnte nicht gelöscht werden.');
      }

      this.items.update((items) => items.filter((other) => other.id !== item.id));
      return null;
    } catch (error) {
      console.error(error);
      return 'Tresor-Server nicht erreichbar.';
    }
  }
}
