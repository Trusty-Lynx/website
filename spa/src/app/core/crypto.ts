import { argon2id } from 'hash-wasm';

// Gleiche Krypto wie dashboard/dashboard.js und common.js der MPA

type Bytes = Uint8Array<ArrayBuffer>;

export interface Kdf {
  alg: string;
  m: number;
  t: number;
  p: number;
  len: number;
}

export const KDF: Kdf = { alg: 'argon2id', m: 65536, t: 3, p: 1, len: 32 };

export function base64ToBytes(base64: string): Bytes {
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

export function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

// kdf vom Server muss genau den Standardwerten entsprechen, sonst könnte ein Server schwächere Parameter unterschieben
export function isDefaultKdf(kdf: Kdf | null): boolean {
  return kdf !== null && typeof kdf === 'object'
    && kdf.alg === KDF.alg
    && kdf.m === KDF.m
    && kdf.t === KDF.t
    && kdf.p === KDF.p
    && kdf.len === KDF.len;
}

// HKDF-SHA256: Salt = 32 × 00, Länge 32 Byte, info = Etikett als UTF-8
async function hkdf(keyBytes: Bytes, label: string): Promise<Bytes> {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode(label),
    },
    key,
    256
  );
  return new Uint8Array(bits);
}

export async function deriveVaultKeys(password: string, saltBytes: Bytes, kdf: Kdf) {
  const mk = new Uint8Array(await argon2id({
    password: password,
    salt: saltBytes,
    parallelism: kdf.p,
    iterations: kdf.t,
    memorySize: kdf.m,
    hashLength: kdf.len,
    outputType: 'binary',
  }));
  const keys = {
    unlockKey: await hkdf(mk, 'TL-auth-v1'),
    kek: await hkdf(mk, 'TL-enc-v1'),
  };
  mk.fill(0);
  return keys;
}

function dekAad(userId: string): Bytes {
  return new TextEncoder().encode('TL-DEK|' + userId);
}

export async function wrapDek(dekBytes: Bytes, kekBytes: Bytes, userId: string): Promise<Bytes> {
  const kek = await crypto.subtle.importKey('raw', kekBytes, 'AES-GCM', false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: dekAad(userId) },
    kek,
    dekBytes
  );

  const wdek = new Uint8Array(62);
  wdek.set([1, 1], 0);
  wdek.set(nonce, 2);
  wdek.set(new Uint8Array(encrypted), 14);
  return wdek;
}

export async function unwrapDek(wdek: Bytes, kekBytes: Bytes, userId: string): Promise<Bytes> {
  const kek = await crypto.subtle.importKey('raw', kekBytes, 'AES-GCM', false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: wdek.slice(2, 14), additionalData: dekAad(userId) },
    kek,
    wdek.slice(14)
  );
  return new Uint8Array(decrypted);
}

function pad(bytes: Uint8Array): Bytes {
  let size = 32;
  while (size < bytes.length + 1) {
    size *= 2;
  }
  const block = new Uint8Array(size);
  block.set(bytes, 0);
  block[bytes.length] = 0x80;
  return block;
}

function unpad(block: Uint8Array): Uint8Array {
  let end = block.length - 1;
  while (end >= 0 && block[end] === 0x00) {
    end--;
  }
  if (block[end] !== 0x80) {
    throw new Error('Ungültiges Padding');
  }
  return block.slice(0, end);
}

function itemAad(userId: string, itemId: string, part: string, rev: number): Bytes {
  return new TextEncoder().encode(`TL-L1|${userId}|${itemId}|${part}|${rev}`);
}

export async function encryptPart(dek: CryptoKey, value: unknown, userId: string, itemId: string, part: string, rev: number): Promise<Bytes> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const block = pad(new TextEncoder().encode(JSON.stringify(value)));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: itemAad(userId, itemId, part, rev) },
    dek,
    block
  );
  block.fill(0);

  const c1 = new Uint8Array(14 + encrypted.byteLength);
  c1.set([1, 1], 0);
  c1.set(nonce, 2);
  c1.set(new Uint8Array(encrypted), 14);
  return c1;
}

export async function decryptPart<T>(dek: CryptoKey, c1: Bytes, userId: string, itemId: string, part: string, rev: number): Promise<T> {
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: c1.slice(2, 14), additionalData: itemAad(userId, itemId, part, rev) },
    dek,
    c1.slice(14)
  );
  const json = new TextDecoder().decode(unpad(new Uint8Array(decrypted)));
  return JSON.parse(json);
}
