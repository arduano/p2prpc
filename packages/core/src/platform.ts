import { sha256 } from '@noble/hashes/sha256';

const encoder = new TextEncoder();
export const utf8Bytes = (value: string): Uint8Array => encoder.encode(value);
/** Count without allocating an untrusted string's encoded byte buffer. */
export function byteLength(value: string): number {
  let size = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x7f) size += 1;
    else if (code <= 0x7ff) size += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length &&
      value.charCodeAt(index + 1) >= 0xdc00 && value.charCodeAt(index + 1) <= 0xdfff) {
      size += 4;
      index += 1;
    } else size += 3;
  }
  return size;
}
export const utf8ByteLength = byteLength;
export const hex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');

/** Preserve Node byte-array compatibility without importing or polyfilling Node. */
export function isByteArray(value: unknown): value is Uint8Array {
  if (!(value instanceof Uint8Array)) return false;
  const prototype = Object.getPrototypeOf(value);
  const nodeBytes = Reflect.get(globalThis, 'Buffer') as { readonly prototype?: object } | undefined;
  return prototype === Uint8Array.prototype || (nodeBytes !== undefined && prototype === nodeBytes.prototype);
}

function base64url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

export interface Sha256Hasher {
  update(value: string | Uint8Array): Sha256Hasher;
  digest(encoding: 'hex' | 'base64url'): string;
}

export function createSha256(): Sha256Hasher {
  const hash = sha256.create();
  const result: Sha256Hasher = {
    update(value) { hash.update(value); return result; },
    digest(encoding) {
      const bytes = hash.digest();
      return encoding === 'hex' ? hex(bytes) : base64url(bytes);
    }
  };
  return result;
}

export const sha256Hex = (value: string | Uint8Array): string => createSha256().update(value).digest('hex');
export const randomUuid = (): string => globalThis.crypto.randomUUID();
export function randomToken(size = 32): string {
  if (!Number.isSafeInteger(size) || size < 1 || size > 65_536) throw new RangeError('Invalid random token size');
  return base64url(globalThis.crypto.getRandomValues(new Uint8Array(size)));
}

/** Node may unref timers; browser numeric timer handles need no action. */
export function unrefTimer(timer: ReturnType<typeof setTimeout>): void {
  if (typeof timer === 'object') (timer as { unref?: () => void }).unref?.();
}

export function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new DOMException('The operation was aborted', 'AbortError'));
      return;
    }
    const abort = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      reject(signal?.reason ?? new DOMException('The operation was aborted', 'AbortError'));
    };
    const timer = setTimeout(() => { signal?.removeEventListener('abort', abort); resolve(); }, ms);
    signal?.addEventListener('abort', abort, { once: true });
  });
}
