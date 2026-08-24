import { P2PError } from './errors.js';

export function exactRecord(
  value: unknown,
  keys: readonly string[],
  label: string
): asserts value is Record<string, unknown> {
  const actual = exactDataKeys(value, label).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new P2PError('INVALID_FRAME', `${label} contains missing or unknown fields`);
  }
}

export function exactRecordWithOptional(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  label: string
): asserts value is Record<string, unknown> {
  const actual = exactDataKeys(value, label);
  const allowed = new Set([...required, ...optional]);
  const present = new Set(actual);
  if (required.some((key) => !present.has(key)) || actual.some((key) => !allowed.has(key))) {
    throw new P2PError('INVALID_FRAME', `${label} contains missing or unknown fields`);
  }
}

function exactDataKeys(value: unknown, label: string): string[] {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new P2PError('INVALID_FRAME', `${label} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new P2PError('INVALID_FRAME', `${label} must be a plain object`);
  }
  const keys: string[] = [];
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      throw new P2PError('INVALID_FRAME', `${label} contains a non-string field`);
    }
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new P2PError('INVALID_FRAME', `${label} contains a prototype-confusing field`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new P2PError('INVALID_FRAME', `${label} fields must be enumerable data properties`);
    }
    keys.push(key);
  }
  return keys;
}
