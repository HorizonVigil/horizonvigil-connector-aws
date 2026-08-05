/**
 * AES-256-GCM envelope encryption for stored AWS credentials, via the
 * Workers-native Web Crypto API — same primitive the prior cloud-api build
 * proved out. `ENCRYPTION_KEY` is a base64-encoded 32-byte key (Worker secret).
 */

async function importKey(base64Key: string): Promise<CryptoKey> {
  const raw = Uint8Array.from(atob(base64Key), (ch) => ch.charCodeAt(0));
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value), (ch) => ch.charCodeAt(0));
}

export interface EncryptedEnvelope {
  iv: string;
  ciphertext: string;
}

export async function encryptCredentials(encryptionKey: string, plain: Record<string, string>): Promise<EncryptedEnvelope> {
  const key = await importKey(encryptionKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(plain));
  const ciphertextBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  return { iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(ciphertextBuf)) };
}

export async function decryptCredentials(encryptionKey: string, envelope: EncryptedEnvelope): Promise<Record<string, string>> {
  const key = await importKey(encryptionKey);
  const iv = fromBase64(envelope.iv);
  const ciphertext = fromBase64(envelope.ciphertext);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

export function maskAccessKey(accessKeyId: string): string {
  if (accessKeyId.length <= 8) return '••••••••';
  return `${accessKeyId.slice(0, 4)}${'•'.repeat(8)}${accessKeyId.slice(-4)}`;
}

const ACCESS_KEY_PATTERN = /^(AKIA|ASIA)[A-Z0-9]{16}$/;

export function looksLikeValidAccessKeyId(accessKeyId: string): boolean {
  return ACCESS_KEY_PATTERN.test(accessKeyId);
}
