import { P2PError } from '../errors.js';
import { containsUnsafeDisplayCharacters } from '../text.js';

export type RpcHeaders = Readonly<Record<string, string>>;
export type RpcHeaderInput = Readonly<Record<string, string | undefined>> | Iterable<readonly [string, string]>;

export interface RpcHeaderLimits {
  readonly maxCount: number;
  readonly maxBytes: number;
}

export const DEFAULT_RPC_HEADER_LIMITS: RpcHeaderLimits = { maxCount: 64, maxBytes: 16 * 1024 };

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const RESERVED = /^(?:authorization|cookie|set-cookie|connection|forwarded|host|origin|proxy-|x-forwarded-|x-real-ip|p2prpc-|x-p2prpc-)/i;

/** Normalize and validate untrusted, headers-like RPC metadata. */
export function normalizeRpcHeaders(
  input: RpcHeaderInput | undefined,
  limits: RpcHeaderLimits = DEFAULT_RPC_HEADER_LIMITS
): RpcHeaders {
  validateLimits(limits);
  const output: Record<string, string> = Object.create(null) as Record<string, string>;
  let count = 0;
  let bytes = 0;
  for (const [rawName, rawValue] of entries(input)) {
    if (typeof rawName !== 'string' || typeof rawValue !== 'string') {
      throw new P2PError('INVALID_FRAME', 'RPC header names and values must be strings');
    }
    if (Buffer.byteLength(rawName) > 64) throw new P2PError('RESOURCE_LIMIT', 'RPC header name exceeds 64 bytes');
    const name = rawName.toLowerCase();
    if (!TOKEN.test(name)) throw new P2PError('INVALID_FRAME', 'Invalid RPC header name');
    if (RESERVED.test(name)) throw new P2PError('UNAUTHORIZED', 'RPC header name is reserved');
    if (Buffer.byteLength(rawValue) > 8 * 1024) throw new P2PError('RESOURCE_LIMIT', 'RPC header value exceeds 8 KiB');
    if (containsUnsafeDisplayCharacters(rawValue)) {
      throw new P2PError('INVALID_FRAME', 'RPC header value contains unsafe control or formatting characters');
    }
    if (Object.hasOwn(output, name)) throw new P2PError('INVALID_FRAME', 'Duplicate RPC header name');
    count += 1;
    bytes += Buffer.byteLength(name) + Buffer.byteLength(rawValue);
    if (count > limits.maxCount || bytes > limits.maxBytes) {
      throw new P2PError('RESOURCE_LIMIT', 'RPC headers exceed configured limits');
    }
    output[name] = rawValue;
  }
  return Object.freeze(output);
}

export function mergeRpcHeaders(
  defaults: RpcHeaderInput | undefined,
  perCall: RpcHeaderInput | undefined,
  limits: RpcHeaderLimits = DEFAULT_RPC_HEADER_LIMITS
): RpcHeaders {
  const merged: Record<string, string> = Object.create(null) as Record<string, string>;
  Object.assign(merged, normalizeRpcHeaders(defaults, limits));
  Object.assign(merged, normalizeRpcHeaders(perCall, limits));
  return normalizeRpcHeaders(merged, limits);
}

function *entries(input: RpcHeaderInput | undefined): Iterable<readonly [unknown, unknown]> {
  if (input === undefined) return [];
  if ((typeof input !== 'object' && typeof input !== 'function') || input === null) {
    throw new P2PError('INVALID_FRAME', 'RPC headers must be a record or iterable of pairs');
  }
  if (Symbol.iterator in input) {
    for (const pair of input as Iterable<unknown>) {
      if (!Array.isArray(pair) || pair.length !== 2) {
        throw new P2PError('INVALID_FRAME', 'RPC header iterable entries must be name/value pairs');
      }
      yield [pair[0], pair[1]];
    }
    return;
  }
  for (const pair of Object.entries(input)) {
    if (pair[1] !== undefined) yield pair;
  }
}

function validateLimits(limits: RpcHeaderLimits): void {
  if (!Number.isSafeInteger(limits.maxCount) || limits.maxCount < 0 || limits.maxCount > 256) {
    throw new P2PError('RESOURCE_LIMIT', 'maxRpcHeaders must be between 0 and 256');
  }
  if (!Number.isSafeInteger(limits.maxBytes) || limits.maxBytes < 0 || limits.maxBytes > 64 * 1024) {
    throw new P2PError('RESOURCE_LIMIT', 'maxRpcHeaderBytes must be between 0 and 64 KiB');
  }
}
