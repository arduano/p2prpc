import { pack, unpack } from 'msgpackr';
import { P2PError } from './errors.js';
import type { QuicRecvStream, QuicSendStream } from './transport/types.js';

export const PROTOCOL_VERSION = 2;

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
  Progress = 24,
  Complete = 25,
  Cancel = 26,
  Pull = 27
}

export enum SessionFrameKind {
  ClientHello = 40,
  ServerHello = 41,
  ClientAck = 42,
  ServerReady = 43
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
  const body = pack(value);
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
    value = unpack(body) as T;
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
    parseMessagePackMap(state, token & 0x0f, depth);
    return undefined;
  }

  switch (token) {
    case 0xc0:
    case 0xc2:
    case 0xc3:
      return undefined;
    case 0xc4:
      skipBytes(state, readUnsigned(state, 1));
      return undefined;
    case 0xc5:
      skipBytes(state, readUnsigned(state, 2));
      return undefined;
    case 0xc6:
      skipBytes(state, readUnsigned(state, 4));
      return undefined;
    case 0xca:
    case 0xce:
    case 0xd2:
      skipBytes(state, 4);
      return undefined;
    case 0xcb:
    case 0xcf:
    case 0xd3:
      skipBytes(state, 8);
      return undefined;
    case 0xcc:
    case 0xd0:
      skipBytes(state, 1);
      return undefined;
    case 0xcd:
    case 0xd1:
      skipBytes(state, 2);
      return undefined;
    case 0xd9:
      return readMessagePackString(state, readUnsigned(state, 1));
    case 0xda:
      return readMessagePackString(state, readUnsigned(state, 2));
    case 0xdb:
      return readMessagePackString(state, readUnsigned(state, 4));
    case 0xdc:
      parseMessagePackArray(state, readUnsigned(state, 2), depth);
      return undefined;
    case 0xdd:
      parseMessagePackArray(state, readUnsigned(state, 4), depth);
      return undefined;
    case 0xde:
      parseMessagePackMap(state, readUnsigned(state, 2), depth);
      return undefined;
    case 0xdf:
      parseMessagePackMap(state, readUnsigned(state, 4), depth);
      return undefined;
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
    if (key === undefined || key === '__proto__' || keys.has(key)) throw invalidMessagePackShape();
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

function skipBytes(state: MessagePackState, count: number): void {
  if (!Number.isSafeInteger(count) || count < 0 || count > state.bytes.byteLength - state.offset) {
    throw invalidMessagePackShape();
  }
  state.offset += count;
}

function invalidMessagePackShape(): P2PError {
  return new P2PError('INVALID_FRAME', 'Invalid or non-canonical MessagePack frame');
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
    if ((byte & 0x80) === 0) return value;
    multiplier *= 128;
  }
  throw new P2PError('INVALID_FRAME', 'Varint is too long');
}

export function assertRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new P2PError('INVALID_FRAME', `${label} must be an object`);
  }
}
