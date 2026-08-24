import { types as nodeTypes } from 'node:util';
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
const MAX_DESCRIPTOR_PROTOTYPE_DEPTH = 16;
type Callable = (this: unknown, ...arguments_: unknown[]) => unknown;

/** Normalize and validate untrusted, headers-like RPC metadata. */
export function normalizeRpcHeaders(
  input: RpcHeaderInput | undefined,
  limits: RpcHeaderLimits = DEFAULT_RPC_HEADER_LIMITS
): RpcHeaders {
  validateLimits(limits);
  const output: Record<string, string> = Object.create(null) as Record<string, string>;
  let count = 0;
  let bytes = 0;
  for (const [rawName, rawValue] of entries(input, limits.maxCount)) {
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

function *entries(
  input: RpcHeaderInput | undefined,
  maximumEntries: number
): Iterable<readonly [unknown, unknown]> {
  if (input === undefined) return [];
  if ((typeof input !== 'object' && typeof input !== 'function') || input === null) {
    throw new P2PError('INVALID_FRAME', 'RPC headers must be a record or iterable of pairs');
  }
  assertNotProxy(input, 'RPC headers');
  const iterable = lookupDataProperty(input, Symbol.iterator, 'RPC header iterator');
  if (iterable.found) {
    if (!isCallable(iterable.value)) {
      throw new P2PError('INVALID_FRAME', 'RPC header iterator must be a data-property function');
    }
    yield *iterableEntries(input, iterable.value, maximumEntries);
    return;
  }
  const prototype = Object.getPrototypeOf(input) as object | null;
  if (prototype !== null && prototype !== Object.prototype) {
    throw new P2PError('INVALID_FRAME', 'RPC headers must be a plain record or iterable of pairs');
  }
  let inspected = 0;
  // Unlike Object.entries(), for-in does not create a user-visible array of
  // every property before the header bound can reject a wide record. Proxies
  // are rejected above so enumeration cannot invoke an ownKeys trap.
  for (const name in input) {
    if (!Object.hasOwn(input, name)) continue;
    inspected += 1;
    assertEntryBudget(inspected, maximumEntries);
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor?.enumerable) continue;
    if (!('value' in descriptor)) {
      throw new P2PError('INVALID_FRAME', 'RPC header records may contain only own data properties');
    }
    if (descriptor.value !== undefined) yield [name, descriptor.value];
  }
}

function *iterableEntries(
  input: object,
  iteratorMethod: Callable,
  maximumEntries: number
): Iterable<readonly [unknown, unknown]> {
  const iterator = Reflect.apply(iteratorMethod, input, []) as unknown;
  if ((typeof iterator !== 'object' && typeof iterator !== 'function') || iterator === null) {
    throw new P2PError('INVALID_FRAME', 'RPC header iterator must return an object');
  }
  assertNotProxy(iterator, 'RPC header iterator');
  const next = lookupDataProperty(iterator, 'next', 'RPC header iterator next');
  if (!next.found || !isCallable(next.value)) {
    throw new P2PError('INVALID_FRAME', 'RPC header iterator next must be a data-property function');
  }

  let inspected = 0;
  let finished = false;
  try {
    while (true) {
      const result = Reflect.apply(next.value, iterator, []) as unknown;
      if ((typeof result !== 'object' && typeof result !== 'function') || result === null) {
        throw new P2PError('INVALID_FRAME', 'RPC header iterator result must be an object');
      }
      assertNotProxy(result, 'RPC header iterator result');
      const done = lookupDataProperty(result, 'done', 'RPC header iterator result done');
      if (!done.found || typeof done.value !== 'boolean') {
        throw new P2PError('INVALID_FRAME', 'RPC header iterator result done must be a data-property boolean');
      }
      if (done.value) {
        finished = true;
        return;
      }

      inspected += 1;
      // The one look-ahead next() needed to distinguish an exactly-full
      // iterable from an over-limit one is rejected before its value is read.
      assertEntryBudget(inspected, maximumEntries);
      const value = lookupDataProperty(result, 'value', 'RPC header iterator result value');
      if (!value.found) {
        throw new P2PError('INVALID_FRAME', 'RPC header iterator result must contain a value');
      }
      yield iterablePair(value.value);
    }
  } finally {
    if (!finished) closeIterator(iterator);
  }
}

function iterablePair(pair: unknown): readonly [unknown, unknown] {
  if (!Array.isArray(pair) || nodeTypes.isProxy(pair)) {
    throw new P2PError('INVALID_FRAME', 'RPC header iterable entries must be plain name/value pairs');
  }
  const length = Object.getOwnPropertyDescriptor(pair, 'length');
  const name = Object.getOwnPropertyDescriptor(pair, '0');
  const value = Object.getOwnPropertyDescriptor(pair, '1');
  if (
    !length || !('value' in length) || length.value !== 2 ||
    !name || !('value' in name) ||
    !value || !('value' in value)
  ) {
    throw new P2PError('INVALID_FRAME', 'RPC header iterable entries must be dense data-property pairs');
  }
  return [name.value, value.value];
}

function lookupDataProperty(
  input: object,
  key: PropertyKey,
  description: string
): { readonly found: boolean; readonly value?: unknown } {
  let cursor: object | null = input;
  let depth = 0;
  while (cursor !== null) {
    depth += 1;
    if (depth > MAX_DESCRIPTOR_PROTOTYPE_DEPTH) {
      throw new P2PError('RESOURCE_LIMIT', `${description} prototype chain is too deep`);
    }
    assertNotProxy(cursor, description);
    const descriptor = Object.getOwnPropertyDescriptor(cursor, key);
    if (descriptor) {
      if (!('value' in descriptor)) {
        throw new P2PError('INVALID_FRAME', `${description} must be a data property`);
      }
      return { found: true, value: descriptor.value };
    }
    cursor = Object.getPrototypeOf(cursor) as object | null;
  }
  return { found: false };
}

function assertNotProxy(input: object, description: string): void {
  if (nodeTypes.isProxy(input)) {
    throw new P2PError('INVALID_FRAME', `${description} cannot be a Proxy`);
  }
}

function assertEntryBudget(inspected: number, maximumEntries: number): void {
  if (inspected > maximumEntries) {
    throw new P2PError('RESOURCE_LIMIT', 'RPC headers exceed configured limits');
  }
}

function closeIterator(iterator: object): void {
  try {
    const close = lookupDataProperty(iterator, 'return', 'RPC header iterator return');
    if (close.found && isCallable(close.value)) Reflect.apply(close.value, iterator, []);
  } catch {
    // Cleanup cannot replace the parser's primary rejection.
  }
}

function isCallable(input: unknown): input is Callable {
  return typeof input === 'function';
}

function validateLimits(limits: RpcHeaderLimits): void {
  if (!Number.isSafeInteger(limits.maxCount) || limits.maxCount < 0 || limits.maxCount > 256) {
    throw new P2PError('RESOURCE_LIMIT', 'maxRpcHeaders must be between 0 and 256');
  }
  if (!Number.isSafeInteger(limits.maxBytes) || limits.maxBytes < 0 || limits.maxBytes > 64 * 1024) {
    throw new P2PError('RESOURCE_LIMIT', 'maxRpcHeaderBytes must be between 0 and 64 KiB');
  }
}
