import { Packr } from 'msgpackr';
import { P2PError } from './errors.js';
import type { QuicRecvStream, QuicSendStream } from './transport/types.js';

export const PROTOCOL_VERSION = 4;

export enum StreamKind {
  Rpc = 1,
  TransferControl = 2,
  TransferData = 3,
  /** The only stream permitted before application authentication completes. */
  SessionAuth = 4
}

export enum RpcFrameKind {
  Request = 1,
  Data = 2,
  Error = 3,
  Complete = 4,
  Cancel = 5
}

export enum TransferFrameKind {
  Offer = 20,
  Accept = 21,
  Reject = 22,
  ChunkHeader = 23,
  Complete = 25,
  /** Echoes the receiver's fresh completion challenge before either half closes. */
  Receipt = 26,
  Pull = 27
}

export enum SessionFrameKind {
  ClientHello = 40,
  ServerChallenge = 41,
  ClientCredential = 42,
  ServerCredential = 43,
  ClientFinished = 44,
  ServerFinished = 45
}

export interface Frame<T = unknown> {
  readonly kind: number;
  readonly value: T;
}

export interface FrameLimits {
  readonly maxControlFrameBytes: number;
  /** Maximum decoded values, including map keys. Defaults to 131,072. */
  readonly maxControlFrameItems?: number;
  /** Maximum MessagePack container nesting. Defaults to 64. */
  readonly maxControlFrameDepth?: number;
}

export const DEFAULT_FRAME_LIMITS: FrameLimits = {
  maxControlFrameBytes: 1024 * 1024,
  maxControlFrameItems: 128 * 1024,
  maxControlFrameDepth: 64
};

const utf8 = new TextDecoder('utf-8', { fatal: true });
// Keep the project-canonical map16 encoding explicit instead of inheriting a
// mutable/default codec configuration from the hosting application.
const frameCodec = new Packr({
  useRecords: false,
  variableMapSize: false,
  mapsAsObjects: true,
  moreTypes: false
});

export async function writeStreamKind(send: QuicSendStream, kind: StreamKind): Promise<void> {
  await send.writeAll(Uint8Array.of(kind));
}

export async function readStreamKind(recv: QuicRecvStream): Promise<StreamKind> {
  const value = (await recv.readExact(1))[0];
  if (
    value !== StreamKind.Rpc &&
    value !== StreamKind.TransferControl &&
    value !== StreamKind.TransferData &&
    value !== StreamKind.SessionAuth
  ) {
    throw new P2PError('INVALID_FRAME', `Unknown stream kind: ${String(value)}`);
  }
  return value;
}

export async function writeFrame(
  send: QuicSendStream,
  kind: number,
  value: unknown,
  limits: FrameLimits = DEFAULT_FRAME_LIMITS
): Promise<void> {
  if (!Number.isSafeInteger(kind) || kind < 0 || kind > 255) throw new P2PError('INVALID_FRAME', 'Invalid frame kind');
  const shapeLimits = validateFrameLimits(limits);
  validateOutboundValue(value, limits.maxControlFrameBytes, shapeLimits);
  let body: Uint8Array;
  try {
    body = frameCodec.pack(value);
  } catch (cause) {
    throw new P2PError('INVALID_FRAME', 'Outbound frame is not serializable plain data', { cause });
  }
  if (body.byteLength > limits.maxControlFrameBytes) {
    throw new P2PError('RESOURCE_LIMIT', `Outbound frame length ${body.byteLength} exceeds ${limits.maxControlFrameBytes}`);
  }
  validateMessagePack(body, shapeLimits);
  const length = encodeVarint(body.byteLength);
  const header = new Uint8Array(1 + length.byteLength);
  header[0] = kind;
  header.set(length, 1);
  await send.writeAll(header);
  await send.writeAll(body);
}

export async function readFrame<T = unknown>(
  recv: QuicRecvStream,
  limits: FrameLimits = DEFAULT_FRAME_LIMITS
): Promise<Frame<T>> {
  const shapeLimits = validateFrameLimits(limits);
  const kind = (await recv.readExact(1))[0];
  if (kind === undefined) throw new P2PError('INVALID_FRAME', 'Missing frame kind');
  const length = await readVarint(recv);
  if (length > limits.maxControlFrameBytes) {
    throw new P2PError('RESOURCE_LIMIT', `Frame length ${length} exceeds ${limits.maxControlFrameBytes}`);
  }
  let value: T;
  try {
    const body = await recv.readExact(length);
    validateMessagePack(body, shapeLimits);
    value = frameCodec.unpack(body) as T;
  } catch (cause) {
    if (cause instanceof P2PError) throw cause;
    throw new P2PError('INVALID_FRAME', 'Invalid MessagePack frame', { cause });
  }
  return { kind, value };
}

interface MessagePackShapeLimits {
  readonly maxItems: number;
  readonly maxDepth: number;
}

interface MessagePackState extends MessagePackShapeLimits {
  readonly bytes: Uint8Array;
  readonly view: DataView;
  offset: number;
  items: number;
}

interface OutboundShapeState extends MessagePackShapeLimits {
  readonly maxBytes: number;
  readonly ancestors: WeakSet<object>;
  items: number;
  estimatedBytes: number;
}

function validateFrameLimits(limits: FrameLimits): MessagePackShapeLimits {
  if (
    !Number.isSafeInteger(limits.maxControlFrameBytes) ||
    limits.maxControlFrameBytes < 0 ||
    limits.maxControlFrameBytes > 16 * 1024 * 1024
  ) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid control-frame size limit');
  }
  const maxItems = limits.maxControlFrameItems ?? DEFAULT_FRAME_LIMITS.maxControlFrameItems!;
  const maxDepth = limits.maxControlFrameDepth ?? DEFAULT_FRAME_LIMITS.maxControlFrameDepth!;
  if (!Number.isSafeInteger(maxItems) || maxItems < 1 || maxItems > 1_000_000) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid control-frame item limit');
  }
  if (!Number.isSafeInteger(maxDepth) || maxDepth < 1 || maxDepth > 256) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid control-frame depth limit');
  }
  return { maxItems, maxDepth };
}

/**
 * Reject oversized or exotic outbound values before msgpackr allocates a body.
 * The byte estimate is a conservative upper bound for the plain MessagePack
 * subset accepted by validateMessagePack(), so packing cannot create an
 * allocation larger than the configured frame limit.
 */
function validateOutboundValue(
  value: unknown,
  maxBytes: number,
  limits: MessagePackShapeLimits
): void {
  const state: OutboundShapeState = {
    ...limits,
    maxBytes,
    ancestors: new WeakSet(),
    items: 0,
    estimatedBytes: 0
  };
  visitOutboundValue(value, 0, state);
}

function visitOutboundValue(value: unknown, depth: number, state: OutboundShapeState): void {
  if (depth > state.maxDepth) {
    throw new P2PError('RESOURCE_LIMIT', 'MessagePack nesting exceeds the configured limit');
  }
  reserveOutbound(state, 1, 0);
  if (value === null || typeof value === 'boolean') {
    reserveOutbound(state, 0, 1);
    return;
  }
  if (typeof value === 'number') {
    if (Object.is(value, -0)) throw invalidOutboundValue();
    reserveOutbound(state, 0, 9);
    return;
  }
  if (typeof value === 'bigint') {
    reserveOutbound(state, 0, 9);
    return;
  }
  if (typeof value === 'string') {
    reserveOutbound(state, 0, encodedStringUpperBound(value));
    return;
  }
  if (isWireByteArray(value)) {
    reserveOutbound(state, 0, checkedEncodedLength(value.byteLength));
    return;
  }
  if (typeof value !== 'object' || value === null) throw invalidOutboundValue();
  if (state.ancestors.has(value)) throw invalidOutboundValue();
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      assertPlainArray(value, state);
      reserveOutbound(state, 0, 5);
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw invalidOutboundValue();
        visitOutboundValue(descriptor.value, depth + 1, state);
      }
      return;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw invalidOutboundValue();
    reserveOutbound(state, 0, 5);
    // Enumerate incrementally: Object.keys() would allocate an attacker-sized
    // key array before the item/byte budgets get a chance to reject it.
    let entries = 0;
    for (const key in value) {
      if (!Object.hasOwn(value, key)) continue;
      entries += 1;
      if (entries > 0xffff) {
        throw new P2PError('RESOURCE_LIMIT', 'Outbound object exceeds the project map limit');
      }
      if (isPrototypeKey(key)) throw invalidOutboundValue();
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw invalidOutboundValue();
      reserveOutbound(state, 1, encodedStringUpperBound(key));
      visitOutboundValue(descriptor.value, depth + 1, state);
    }
    // msgpackr consults hasOwnProperty while walking plain objects. Reject
    // hidden/symbol/accessor fields as well, so a non-enumerable shadow cannot
    // execute between preflight and packing.
    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        typeof key !== 'string' ||
        isPrototypeKey(key) ||
        !descriptor ||
        !descriptor.enumerable ||
        !Object.hasOwn(descriptor, 'value')
      ) throw invalidOutboundValue();
    }
  } finally {
    state.ancestors.delete(value);
  }
}

function assertPlainArray(value: readonly unknown[], state: OutboundShapeState): void {
  if (Object.getPrototypeOf(value) !== Array.prototype) throw invalidOutboundValue();
  // A dense array contributes at least one item and one byte per element.
  // Reject impossible shapes before walking indexes or enumerating keys.
  if (
    value.length > state.maxItems - state.items ||
    value.length > state.maxBytes - state.estimatedBytes
  ) {
    throw new P2PError('RESOURCE_LIMIT', 'Outbound array exceeds configured frame limits');
  }
  let elements = 0;
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw invalidOutboundValue();
    if (key === 'length') continue;
    if (
      typeof key !== 'string' ||
      !descriptor.enumerable ||
      !/^(?:0|[1-9]\d*)$/.test(key) ||
      Number(key) >= value.length
    ) throw invalidOutboundValue();
    elements += 1;
  }
  if (elements !== value.length) throw invalidOutboundValue();
}

function encodedStringUpperBound(value: string): number {
  return checkedEncodedLength(Buffer.byteLength(value));
}

function checkedEncodedLength(length: number): number {
  if (!Number.isSafeInteger(length) || length < 0) throw invalidOutboundValue();
  return length + 5;
}

function reserveOutbound(state: OutboundShapeState, items: number, bytes: number): void {
  if (
    !Number.isSafeInteger(items) ||
    !Number.isSafeInteger(bytes) ||
    state.items + items > state.maxItems
  ) {
    throw new P2PError('RESOURCE_LIMIT', 'MessagePack values exceed the configured limit');
  }
  state.items += items;
  if (bytes > state.maxBytes - state.estimatedBytes) {
    throw new P2PError('RESOURCE_LIMIT', `Outbound frame exceeds ${state.maxBytes} bytes`);
  }
  state.estimatedBytes += bytes;
}

function invalidOutboundValue(): P2PError {
  return new P2PError('INVALID_FRAME', 'Outbound frame must contain bounded, accessor-free plain data');
}

/**
 * Preflight MessagePack before decoding. A small array32/map32 declaration can
 * otherwise make a bounded byte frame allocate or iterate over an unbounded
 * number of JavaScript values. The wire format intentionally accepts only
 * standard, plain-data MessagePack; extension values are not part of p2prpc.
 */
function validateMessagePack(bytes: Uint8Array, limits: MessagePackShapeLimits): void {
  const state: MessagePackState = {
    bytes,
    view: new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength),
    offset: 0,
    items: 0,
    ...limits
  };
  parseMessagePackValue(state, 0, false);
  if (state.offset !== bytes.byteLength) throw invalidMessagePackShape();
}

function parseMessagePackValue(state: MessagePackState, depth: number, mapKey: boolean): string | undefined {
  if (depth > state.maxDepth) throw new P2PError('RESOURCE_LIMIT', 'MessagePack nesting exceeds the configured limit');
  state.items += 1;
  if (state.items > state.maxItems) throw new P2PError('RESOURCE_LIMIT', 'MessagePack values exceed the configured limit');
  const token = readUnsigned(state, 1);

  if (mapKey && !isStringToken(token)) throw invalidMessagePackShape();
  if (token <= 0x7f || token >= 0xe0) return undefined;
  if (token >= 0xa0 && token <= 0xbf) return readMessagePackString(state, token & 0x1f);
  if (token >= 0x90 && token <= 0x9f) {
    parseMessagePackArray(state, token & 0x0f, depth);
    return undefined;
  }
  if (token >= 0x80 && token <= 0x8f) {
    // Plain objects are encoded by this protocol's pinned msgpackr settings
    // as map16, including empty/small objects.
    throw invalidMessagePackShape();
  }

  switch (token) {
    case 0xc0:
    case 0xc2:
    case 0xc3:
      return undefined;
    case 0xc4:
      skipBytes(state, readUnsigned(state, 1));
      return undefined;
    case 0xc5: {
      const length = readUnsigned(state, 2);
      if (length <= 0xff) throw invalidMessagePackShape();
      skipBytes(state, length);
      return undefined;
    }
    case 0xc6: {
      const length = readUnsigned(state, 4);
      if (length <= 0xffff) throw invalidMessagePackShape();
      skipBytes(state, length);
      return undefined;
    }
    case 0xca:
      // The encoder deliberately uses float64 only. Accepting float32 would
      // give the same JavaScript number multiple wire representations.
      throw invalidMessagePackShape();
    case 0xcb: {
      const offset = state.offset;
      const number = readFloat64(state);
      if (
        (Number.isNaN(number) && (
          state.view.getUint32(offset) !== 0x7ff8_0000 ||
          state.view.getUint32(offset + 4) !== 0
        )) ||
        Object.is(number, -0) ||
        (Number.isInteger(number) && number >= -0x8000_0000 && number <= 0xffff_ffff)
      ) {
        throw invalidMessagePackShape();
      }
      return undefined;
    }
    case 0xcc:
      if (readUnsigned(state, 1) < 0x80) throw invalidMessagePackShape();
      return undefined;
    case 0xcd:
      if (readUnsigned(state, 2) <= 0xff) throw invalidMessagePackShape();
      return undefined;
    case 0xce:
      if (readUnsigned(state, 4) <= 0xffff) throw invalidMessagePackShape();
      return undefined;
    case 0xcf: {
      const highByte = readUnsigned(state, 1);
      if ((highByte & 0x80) === 0) throw invalidMessagePackShape();
      skipBytes(state, 7);
      return undefined;
    }
    case 0xd0:
      if (readSigned(state, 1) >= -32) throw invalidMessagePackShape();
      return undefined;
    case 0xd1:
      if (readSigned(state, 2) >= -0x80) throw invalidMessagePackShape();
      return undefined;
    case 0xd2:
      if (readSigned(state, 4) >= -0x8000) throw invalidMessagePackShape();
      return undefined;
    case 0xd3:
      // Signed int64 is also the canonical representation of every signed
      // bigint, including values that would fit in a smaller number token.
      skipBytes(state, 8);
      return undefined;
    case 0xd9: {
      const length = readUnsigned(state, 1);
      if (length < 32) throw invalidMessagePackShape();
      return readMessagePackString(state, length);
    }
    case 0xda: {
      const length = readUnsigned(state, 2);
      if (length <= 0xff) throw invalidMessagePackShape();
      return readMessagePackString(state, length);
    }
    case 0xdb: {
      const length = readUnsigned(state, 4);
      if (length <= 0xffff) throw invalidMessagePackShape();
      return readMessagePackString(state, length);
    }
    case 0xdc: {
      const length = readUnsigned(state, 2);
      if (length < 16) throw invalidMessagePackShape();
      parseMessagePackArray(state, length, depth);
      return undefined;
    }
    case 0xdd: {
      const length = readUnsigned(state, 4);
      if (length <= 0xffff) throw invalidMessagePackShape();
      parseMessagePackArray(state, length, depth);
      return undefined;
    }
    case 0xde:
      // msgpackr intentionally emits map16 for small plain objects so it can
      // reserve the count and serialize them in one pass. This is the sole
      // project-canonical exception to preferred MessagePack sizing.
      parseMessagePackMap(state, readUnsigned(state, 2), depth);
      return undefined;
    case 0xdf:
      throw invalidMessagePackShape();
    default:
      // 0xc1 and all extension encodings (0xc7-0xc9, 0xd4-0xd8) are not
      // emitted by the plain p2prpc wire schema and are deliberately rejected.
      throw invalidMessagePackShape();
  }
}

function parseMessagePackArray(state: MessagePackState, length: number, depth: number): void {
  reserveItems(state, length);
  for (let index = 0; index < length; index += 1) parseMessagePackValue(state, depth + 1, false);
}

function parseMessagePackMap(state: MessagePackState, length: number, depth: number): void {
  reserveItems(state, length * 2);
  const keys = new Set<string>();
  for (let index = 0; index < length; index += 1) {
    const key = parseMessagePackValue(state, depth + 1, true);
    if (key === undefined || isPrototypeKey(key) || keys.has(key)) throw invalidMessagePackShape();
    keys.add(key);
    parseMessagePackValue(state, depth + 1, false);
  }
}

function reserveItems(state: MessagePackState, count: number): void {
  if (!Number.isSafeInteger(count) || count < 0 || state.items + count > state.maxItems) {
    throw new P2PError('RESOURCE_LIMIT', 'MessagePack values exceed the configured limit');
  }
}

function readMessagePackString(state: MessagePackState, length: number): string {
  const start = state.offset;
  skipBytes(state, length);
  try {
    return utf8.decode(state.bytes.subarray(start, start + length));
  } catch (cause) {
    throw new P2PError('INVALID_FRAME', 'MessagePack contains invalid UTF-8', { cause });
  }
}

function isStringToken(token: number): boolean {
  return (token >= 0xa0 && token <= 0xbf) || token === 0xd9 || token === 0xda || token === 0xdb;
}

function readUnsigned(state: MessagePackState, size: 1 | 2 | 4): number {
  const offset = state.offset;
  skipBytes(state, size);
  if (size === 1) return state.bytes[offset]!;
  if (size === 2) return state.view.getUint16(offset);
  return state.view.getUint32(offset);
}

function readSigned(state: MessagePackState, size: 1 | 2 | 4): number {
  const offset = state.offset;
  skipBytes(state, size);
  if (size === 1) return state.view.getInt8(offset);
  if (size === 2) return state.view.getInt16(offset);
  return state.view.getInt32(offset);
}

function readFloat64(state: MessagePackState): number {
  const offset = state.offset;
  skipBytes(state, 8);
  return state.view.getFloat64(offset);
}

function skipBytes(state: MessagePackState, count: number): void {
  if (!Number.isSafeInteger(count) || count < 0 || count > state.bytes.byteLength - state.offset) {
    throw invalidMessagePackShape();
  }
  state.offset += count;
}

function invalidMessagePackShape(): P2PError {
  return new P2PError('INVALID_FRAME', 'Invalid or non-canonical MessagePack frame');
}

function isWireByteArray(value: unknown): value is Uint8Array {
  if (typeof value !== 'object' || value === null) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Uint8Array.prototype && prototype !== Buffer.prototype) return false;
  if (
    Object.getOwnPropertyDescriptor(value, 'byteLength') ||
    Object.getOwnPropertyDescriptor(value, 'constructor') ||
    Object.getOwnPropertyDescriptor(value, Symbol.iterator)
  ) throw invalidOutboundValue();
  return true;
}

function isPrototypeKey(value: string): boolean {
  return value === '__proto__' || value === 'prototype' || value === 'constructor';
}

export function encodeVarint(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new P2PError('INVALID_FRAME', `Invalid varint value: ${value}`);
  }
  const bytes: number[] = [];
  let remaining = value;
  do {
    const low = remaining % 128;
    remaining = Math.floor(remaining / 128);
    bytes.push(low | (remaining > 0 ? 0x80 : 0));
  } while (remaining > 0);
  return Uint8Array.from(bytes);
}

export async function readVarint(recv: QuicRecvStream): Promise<number> {
  let value = 0;
  let multiplier = 1;
  for (let index = 0; index < 8; index += 1) {
    const byte = (await recv.readExact(1))[0];
    if (byte === undefined) throw new P2PError('INVALID_FRAME', 'Truncated varint');
    value += (byte & 0x7f) * multiplier;
    if (!Number.isSafeInteger(value)) throw new P2PError('INVALID_FRAME', 'Varint exceeds safe integer range');
    if ((byte & 0x80) === 0) {
      if (index > 0 && (byte & 0x7f) === 0) throw new P2PError('INVALID_FRAME', 'Varint is not canonical');
      return value;
    }
    multiplier *= 128;
  }
  throw new P2PError('INVALID_FRAME', 'Varint is too long');
}

export function assertRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new P2PError('INVALID_FRAME', `${label} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new P2PError('INVALID_FRAME', `${label} must be a plain object`);
  }
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== 'string' ||
      isPrototypeKey(key) ||
      !descriptor ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, 'value')
    ) throw new P2PError('INVALID_FRAME', `${label} contains an unsafe field`);
  }
}
