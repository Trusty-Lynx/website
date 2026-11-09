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

export interface ItemInput extends Head {
  password: string;
  alg: string;
}

interface QueryResult<T> {
  data: T | null;
  error: string | null;
}

export const LOCKED_MESSAGE = 'Der Tresor wurde gesperrt. Bitte gib dein Masterpasswort erneut ein.';
const AUTO_LOCK_MS = 15 * 60 * 1000;

export function vaultErrorMessage(errorCode: string | null | undefined, fallback: string): string {
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

@Injectable({ providedIn: 'root' })
export class VaultService {
  private auth = inject(AuthService);

  private vaultToken: string | null = null;
  private dek: CryptoKey | null = null;
  private autoLockTimer: ReturnType<typeof setTimeout> | undefined;

  readonly unlocked = signal(false);
  readonly items = signal<VaultItem[]>([]);
  readonly lockMessage = signal('');
  readonly error = signal('');

  private async query<T>(query: string, variables: object = {}): Promise<QueryResult<T>> {
    const headers: Record<string, string> = {
      'Authorization': 'Bearer ' + this.auth.loginToken,
      'Content-Type': 'application/json',
    };
    if (this.vaultToken) {
      headers['X-Vault-Token'] = this.vaultToken;
    }

    const response = await fetch(VAULT_BASE + '/graphql', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ query: query, variables: variables }),
    });

    if (!response.ok) {
      return { data: null, error: (await this.readError(response)) || 'upstream_error' };
    }

    const result = await response.json();
    const error = result.errors && result.errors[0];
    if (error) {
      const extensions = error.extensions || {};
      console.warn('Vault-Fehler', extensions.code || error.message, extensions.reason || '',
        'X-Request-ID:', response.headers.get('X-Request-ID'));
      return { data: result.data, error: extensions.code || 'internal_error' };
    }
    return { data: result.data, error: null };
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

  breachRequest(method: string, path: string, body?: object): Promise<Response> | null {
    if (!this.vaultToken) {
      return null;
    }
    const headers: Record<string, string> = {
      'Authorization': 'Bearer ' + this.auth.loginToken,
      'X-Vault-Token': this.vaultToken,
    };
    if (body) {
      headers['Content-Type'] = 'application/json';
    }
    return fetch(BREACH_BASE + path, {
      method: method,
      headers: headers,
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  async checkVault(): Promise<'create' | 'unlock' | null> {
    try {
      const result = await this.query('query { vaultParams { salt } }');
      if (result.error === 'not_found') {
        return 'create';
      }
      if (!result.error) {
        return 'unlock';
      }
      this.lockMessage.set(vaultErrorMessage(result.error, 'Tresor gerade nicht erreichbar. Bitte lade die Seite neu.'));
    } catch (error) {
      console.error(error);
      this.lockMessage.set('Tresor-Server nicht erreichbar.');
    }
    return null;
  }

  async create(password: string): Promise<string | null> {
    try {
      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const keys = await deriveVaultKeys(password, saltBytes, KDF);

      const dekBytes = crypto.getRandomValues(new Uint8Array(32));
      const wdek = await wrapDek(dekBytes, keys.kek, this.auth.userId);

      const result = await this.query<{ createVault: { vaultToken: string } }>(
        'mutation($input: CreateVaultInput!) { createVault(input: $input) { vaultToken } }',
        {
          input: {
            salt: bytesToBase64(saltBytes),
            kdf: KDF,
            unlockKey: bytesToBase64(keys.unlockKey),
            wdek: bytesToBase64(wdek),
          },
        }
      );
      keys.unlockKey.fill(0);
      keys.kek.fill(0);

      if (result.error === 'already_exists') {
        return 'exists';
      }
      if (result.error) {
        return vaultErrorMessage(result.error, 'Tresor konnte nicht erstellt werden.');
      }

      await this.opened(result.data!.createVault.vaultToken, dekBytes);
      return null;
    } catch (error) {
      console.error(error);
      return 'Tresor-Server nicht erreichbar.';
    }
  }

  async unlock(password: string): Promise<string | null> {
    try {
      const paramsResult = await this.query<{ vaultParams: { salt: string; kdf: Kdf } }>(
        'query { vaultParams { salt kdf { alg m t p len } } }'
      );
      if (paramsResult.error) {
        return vaultErrorMessage(paramsResult.error, 'Tresor gerade nicht erreichbar.');
      }
      const params = paramsResult.data!.vaultParams;
      if (!isDefaultKdf(params.kdf)) {
        return 'Der Tresor konnte nicht geöffnet werden.';
      }

      const keys = await deriveVaultKeys(password, base64ToBytes(params.salt), params.kdf);

      const result = await this.query<{ unlockVault: { vaultToken: string; wdek: string } }>(
        'mutation($unlockKey: String!) { unlockVault(unlockKey: $unlockKey) { vaultToken wdek } }',
        { unlockKey: bytesToBase64(keys.unlockKey) }
      );
      keys.unlockKey.fill(0);

      if (result.error === 'unauthorized') {
        return 'Masterpasswort ist falsch.';
      }
      if (result.error) {
        return result.error === 'integrity_error'
          ? 'Der Tresor konnte nicht geöffnet werden.'
          : vaultErrorMessage(result.error, 'Tresor konnte nicht entsperrt werden.');
      }

      const data = result.data!.unlockVault;
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
      await this.query('mutation { lockVault }');
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
      const result = await this.query<{ items: { id: string; rev: number; head: string; alg?: string }[] }>(
        'query { items { id rev head alg } }'
      );
      if (result.error) {
        if (result.error === 'vault_locked') {
          this.forget(LOCKED_MESSAGE);
          return;
        }
        this.error.set(vaultErrorMessage(result.error, 'Einträge konnten nicht geladen werden.'));
        return;
      }

      const items: VaultItem[] = [];
      for (const item of result.data!.items) {
        const head = await decryptPart<Head>(this.dek!, base64ToBytes(item.head), this.auth.userId, item.id, 'h', item.rev);
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

  async fetchSecret(item: VaultItem): Promise<string | null> {
    this.error.set('');
    try {
      const result = await this.query<{ itemSecret: { data: string; rev: number } }>(
        'query($itemId: ID!) { itemSecret(itemId: $itemId) { data rev } }',
        { itemId: item.id }
      );
      if (result.error) {
        if (result.error === 'vault_locked') {
          this.forget(LOCKED_MESSAGE);
          return null;
        }
        this.error.set(result.error === 'not_found'
          ? 'Diesen Eintrag gibt es nicht mehr.'
          : vaultErrorMessage(result.error, 'Passwort konnte nicht geladen werden.'));
        return null;
      }
      const data = result.data!.itemSecret;
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

  async saveItem(editing: VaultItem | null, input: ItemInput): Promise<string | null> {
    try {
      const itemId = editing ? editing.id : crypto.randomUUID();
      const rev = editing ? editing.rev + 1 : 1;
      const userId = this.auth.userId;

      const head = await encryptPart(this.dek!, { title: input.title, url: input.url, user: input.user }, userId, itemId, 'h', rev);
      const secret = await encryptPart(this.dek!, { pw: input.password }, userId, itemId, 's', rev);

      const result = await this.query(
        'mutation($itemId: ID!, $input: PutItemInput!) { putItem(itemId: $itemId, input: $input) { rev } }',
        {
          itemId: itemId,
          input: {
            rev: rev,
            head: bytesToBase64(head),
            secret: bytesToBase64(secret),
            alg: input.alg,
          },
        }
      );

      if (result.error === 'rev_conflict') {
        await this.loadItems();
        this.error.set('Der Eintrag wurde inzwischen woanders geändert. Bitte prüfe ihn und bearbeite ihn erneut.');
        return 'close';
      }
      if (result.error) {
        if (result.error === 'vault_locked') {
          this.forget(LOCKED_MESSAGE);
          return 'close';
        }
        return vaultErrorMessage(result.error, 'Eintrag konnte nicht gespeichert werden.');
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

  async deleteItem(item: VaultItem): Promise<string | null> {
    try {
      const result = await this.query(
        'mutation($itemId: ID!) { deleteItem(itemId: $itemId) }',
        { itemId: item.id }
      );

      if (result.error && result.error !== 'not_found') {
        if (result.error === 'vault_locked') {
          this.forget(LOCKED_MESSAGE);
          return null;
        }
        return vaultErrorMessage(result.error, 'Eintrag konnte nicht gelöscht werden.');
      }

      this.items.update((items) => items.filter((other) => other.id !== item.id));
      return null;
    } catch (error) {
      console.error(error);
      return 'Tresor-Server nicht erreichbar.';
    }
  }
}
