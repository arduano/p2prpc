import SuperJSON, { type SuperJSONResult, type SuperJSONValue } from 'superjson';
import { P2PError } from '../errors.js';
import { DEFAULT_FRAME_LIMITS, type FrameLimits } from '../protocol.js';
import type { RpcHeaders } from './headers.js';

export interface RpcRequest {
  readonly id: number;
  readonly path: string;
  readonly type: 'query' | 'mutation' | 'subscription';
  readonly headers: RpcHeaders;
  readonly input: unknown;
}

export interface RpcData {
  readonly id: number;
  readonly data: unknown;
}

export interface RpcFailure {
  readonly id: number;
  readonly shape: unknown;
}

// Never use SuperJSON's mutable process-wide default instance for wire data.
// An application may register classes or custom deserializers globally; a
// peer-controlled annotation must not be able to invoke that application code.
const wireCodec = new SuperJSON();

const SIMPLE_ANNOTATIONS = new Set([
  'undefined',
  'bigint',
  'Date',
  'Error',
  'regexp',
  'set',
  'map',
  'number',
  'URL'
]);

const TYPED_ARRAYS = new Set([
  'Int8Array',
  'Uint8Array',
  'Int16Array',
  'Uint16Array',
  'Int32Array',
  'Uint32Array',
  'Float32Array',
  'Float64Array',
  'Uint8ClampedArray'
]);

const TYPED_ARRAY_PROTOTYPES = new Map<object, string>([
  [Int8Array.prototype, 'Int8Array'],
  [Uint8Array.prototype, 'Uint8Array'],
  [Int16Array.prototype, 'Int16Array'],
  [Uint16Array.prototype, 'Uint16Array'],
  [Int32Array.prototype, 'Int32Array'],
  [Uint32Array.prototype, 'Uint32Array'],
  [Float32Array.prototype, 'Float32Array'],
  [Float64Array.prototype, 'Float64Array'],
  [Uint8ClampedArray.prototype, 'Uint8ClampedArray']
]);

const TYPED_ARRAY_ELEMENT_BYTES = new Map<string, number>([
  ['Int8Array', 1],
  ['Uint8Array', 1],
  ['Int16Array', 2],
  ['Uint16Array', 2],
  ['Int32Array', 4],
  ['Uint32Array', 4],
  ['Float32Array', 4],
  ['Float64Array', 8],
  ['Uint8ClampedArray', 1]
]);

const ERROR_PROTOTYPES = new Set<object>([
  Error.prototype,
  EvalError.prototype,
  RangeError.prototype,
  ReferenceError.prototype,
  SyntaxError.prototype,
  TypeError.prototype,
  URIError.prototype
]);

interface ValidationState {
  readonly maxBytes: number;
  readonly maxItems: number;
  readonly maxDepth: number;
  readonly seen: WeakSet<object>;
  readonly metadataSeen: WeakSet<object>;
  readonly annotationTargets: Set<string>;
  bytes: number;
  items: number;
}

interface WirePathBudget {
  readonly segments: number;
  readonly bytes: number;
}

const ROOT_WIRE_PATH: WirePathBudget = { segments: 0, bytes: 0 };

export function serializeValue(
  value: unknown,
  limits: FrameLimits = DEFAULT_FRAME_LIMITS
): unknown {
  const state = validationState(limits);
  try {
    // Bound traversal before SuperJSON walks caller-owned input. writeFrame()
    // subsequently enforces the exact encoded envelope size and shape.
    reserve(state, 0, 5);
    reserveFixedBytes(state, 32);
    validateSerializableValue(value, 0, state, ROOT_WIRE_PATH);
    const envelope = wireCodec.serialize(value as SuperJSONValue);
    validateEnvelope(envelope, validationState(limits));
    return envelope;
  } catch (cause) {
    if (cause instanceof P2PError) throw cause;
    throw new P2PError('INVALID_FRAME', 'RPC value is not supported wire data', { cause });
  }
}

export function deserializeValue(
  value: unknown,
  limits: FrameLimits = DEFAULT_FRAME_LIMITS
): unknown {
  try {
    const envelope = validateEnvelope(value, validationState(limits));
    return wireCodec.deserialize(envelope);
  } catch (cause) {
    if (cause instanceof P2PError) throw cause;
    throw new P2PError('INVALID_FRAME', 'Invalid RPC value envelope', { cause });
  }
}

export function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return typeof value === 'object' && value !== null && Symbol.asyncIterator in value;
}

function validationState(limits: FrameLimits): ValidationState {
  const maxBytes = limits.maxControlFrameBytes;
  const maxItems = limits.maxControlFrameItems ?? DEFAULT_FRAME_LIMITS.maxControlFrameItems!;
  const maxDepth = limits.maxControlFrameDepth ?? DEFAULT_FRAME_LIMITS.maxControlFrameDepth!;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 16 * 1024 * 1024) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid RPC wire byte limit');
  }
  if (!Number.isSafeInteger(maxItems) || maxItems < 1 || maxItems > 1_000_000) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid RPC wire item limit');
  }
  if (!Number.isSafeInteger(maxDepth) || maxDepth < 1 || maxDepth > 256) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid RPC wire depth limit');
  }
  return {
    maxBytes,
    maxItems,
    maxDepth,
    seen: new WeakSet(),
    metadataSeen: new WeakSet(),
    annotationTargets: new Set(),
    bytes: 0,
    items: 0
  };
}

function validateSerializableValue(
  value: unknown,
  depth: number,
  state: ValidationState,
  path: WirePathBudget
): void {
  reserve(state, depth, 1);
  if (value === undefined) {
    reserveAnnotation(state, depth, path, 'undefined');
    return;
  }
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    reserveFixedBytes(state, 8);
    if (!Number.isFinite(value) || Object.is(value, -0)) reserveAnnotation(state, depth, path, 'number');
    return;
  }
  if (typeof value === 'string') {
    reserveOutboundString(state, value);
    return;
  }
  if (typeof value === 'bigint') {
    reserveOutboundString(state, value.toString());
    reserveAnnotation(state, depth, path, 'bigint');
    return;
  }
  if (typeof value !== 'object') throw unsupportedValue();
  // The wire model is a bounded tree, not a JavaScript object graph. Rejecting
  // cycles and aliases avoids reference-annotation amplification and makes
  // decoded ownership independent and unsurprising by construction.
  if (state.seen.has(value)) {
    throw new P2PError('INVALID_FRAME', 'RPC values must not contain cycles or shared object references');
  }
  state.seen.add(value);

  if (Array.isArray(value)) {
    if (value.length > state.maxItems - state.items || value.length > state.maxBytes - state.bytes) {
      throw resourceLimit('RPC array exceeds the configured limits');
    }
    assertDenseDataArray(value);
    reserveFixedBytes(state, 5);
    for (let index = 0; index < value.length; index += 1) {
      validateSerializableValue(
        dataProperty(value, String(index)),
        depth + 1,
        state,
        appendWirePath(path, String(index))
      );
    }
    return;
  }
  if (Object.getPrototypeOf(value) === Date.prototype) {
    assertOnlyOwnKeys(value, []);
    const date = value as Date;
    if (!Number.isFinite(Date.prototype.valueOf.call(date))) throw unsupportedValue();
    reserveOutboundString(state, Date.prototype.toISOString.call(date));
    reserveAnnotation(state, depth, path, 'Date');
    return;
  }
  if (Object.getPrototypeOf(value) === RegExp.prototype) {
    assertOnlyOwnKeys(value, ['lastIndex']);
    reserveOutboundString(state, RegExp.prototype.toString.call(value));
    reserveAnnotation(state, depth, path, 'regexp');
    return;
  }
  if (Object.getPrototypeOf(value) === URL.prototype) {
    assertOnlyOwnKeys(value, []);
    reserveOutboundString(state, URL.prototype.toString.call(value));
    reserveAnnotation(state, depth, path, 'URL');
    return;
  }
  if (ERROR_PROTOTYPES.has(Object.getPrototypeOf(value))) {
    assertSafeErrorOwnKeys(value);
    const error = value as Error;
    const name = errorProperty(error, 'name');
    const message = errorProperty(error, 'message');
    if (typeof name !== 'string' || typeof message !== 'string') throw unsupportedValue();
    reserve(state, depth + 1, 4);
    reserveFixedBytes(state, 5);
    reserveOutboundString(state, 'name');
    reserveOutboundString(state, name);
    reserveOutboundString(state, 'message');
    reserveOutboundString(state, message);
    reserveAnnotation(state, depth, path, 'Error');
    const cause = Object.getOwnPropertyDescriptor(value, 'cause');
    if (cause && Object.hasOwn(cause, 'value')) {
      reserve(state, depth + 1, 1);
      reserveOutboundString(state, 'cause');
      validateSerializableValue(cause.value, depth + 1, state, appendWirePath(ROOT_WIRE_PATH, 'cause'));
    }
    return;
  }
  if (Object.getPrototypeOf(value) === Map.prototype) {
    assertOnlyOwnKeys(value, []);
    const size = mapSize(value as Map<unknown, unknown>);
    if (size > Math.floor((state.maxItems - state.items) / 2)) {
      throw resourceLimit('RPC map exceeds the configured item limit');
    }
    reserveFixedBytes(state, 5);
    reserveAnnotation(state, depth, path, 'map');
    let row = 0;
    for (const [key, entry] of Map.prototype.entries.call(value) as MapIterator<[unknown, unknown]>) {
      reserve(state, depth + 1, 1);
      reserveFixedBytes(state, 5);
      const rowPath = appendWirePath(ROOT_WIRE_PATH, String(row));
      validateSerializableValue(key, depth + 1, state, appendWirePath(rowPath, '0'));
      validateSerializableValue(entry, depth + 1, state, appendWirePath(rowPath, '1'));
      row += 1;
    }
    return;
  }
  if (Object.getPrototypeOf(value) === Set.prototype) {
    assertOnlyOwnKeys(value, []);
    if (setSize(value as Set<unknown>) > state.maxItems - state.items) {
      throw resourceLimit('RPC set exceeds the configured item limit');
    }
    reserveFixedBytes(state, 5);
    reserveAnnotation(state, depth, path, 'set');
    let index = 0;
    for (const entry of Set.prototype.values.call(value) as SetIterator<unknown>) {
      validateSerializableValue(entry, depth + 1, state, appendWirePath(ROOT_WIRE_PATH, String(index)));
      index += 1;
    }
    return;
  }
  if (isSupportedTypedArray(value)) {
    const length = value.length;
    reserveMany(state, depth + 1, length);
    reserveFixedBytes(state, 5);
    reserveFixedBytes(state, checkedProduct(length, 8));
    reserveAnnotation(state, depth, path, 'typed-array');
    for (let index = 0; index < length; index += 1) {
      const entry = value[index];
      // SuperJSON leaves exceptional numbers inside composite typed-array
      // payloads unannotated. msgpackr would also collapse -0 to +0, so reject
      // these values before either codec allocates or silently changes them.
      if (typeof entry !== 'number' || !Number.isFinite(entry) || Object.is(entry, -0)) {
        throw unsupportedValue();
      }
    }
    return;
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw unsupportedValue();
  assertSerializableRecord(value);
  reserveFixedBytes(state, 5);
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    assertSafeKey(key);
    reserve(state, depth + 1, 1);
    reserveOutboundString(state, key);
    validateSerializableValue(dataProperty(value, key), depth + 1, state, appendWirePath(path, key));
  }
}

function assertSerializableRecord(value: object): void {
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw unsupportedValue();
    assertSafeKey(key);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw unsupportedValue();
    }
  }
}

function validateEnvelope(value: unknown, state: ValidationState): SuperJSONResult {
  assertPlainRecord(value, 'RPC value envelope');
  const keys = Object.keys(value);
  if (!keys.includes('json') || keys.some((key) => key !== 'json' && key !== 'meta')) {
    throw invalidEnvelope();
  }
  validateJsonValue(value.json, 0, state);
  if (Object.hasOwn(value, 'meta')) validateMetadata(value.meta, value.json, 0, state);
  return value as unknown as SuperJSONResult;
}

function validateJsonValue(value: unknown, depth: number, state: ValidationState): void {
  reserve(state, depth, 1);
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw invalidEnvelope();
    return;
  }
  if (typeof value === 'string') {
    reserveBytes(state, value);
    return;
  }
  if (typeof value !== 'object' || value === null) throw invalidEnvelope();
  if (state.seen.has(value)) throw invalidEnvelope();
  state.seen.add(value);
  if (Array.isArray(value)) {
    if (value.length > state.maxItems - state.items || value.length > state.maxBytes - state.bytes) {
      throw resourceLimit('RPC JSON array exceeds the configured limits');
    }
    assertDenseDataArray(value);
    for (let index = 0; index < value.length; index += 1) {
      validateJsonValue(dataProperty(value, String(index)), depth + 1, state);
    }
    return;
  }
  assertPlainRecord(value, 'RPC JSON value');
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    assertSafeKey(key);
    reserve(state, depth + 1, 1);
    reserveBytes(state, key);
    validateJsonValue(dataProperty(value, key), depth + 1, state);
  }
}

function validateMetadata(value: unknown, json: unknown, depth: number, state: ValidationState): void {
  assertPlainRecord(value, 'RPC value metadata');
  claimMetadataNode(value, state);
  const keys = Object.keys(value);
  if (keys.length !== 2 || !keys.includes('v') || !keys.includes('values')) {
    throw invalidEnvelope();
  }
  reserve(state, depth, keys.length + 1);
  if (value.v !== 1) throw invalidEnvelope();
  validateAnnotationRoot(value.values, json, depth + 1, state);
}

function validateAnnotationRoot(
  value: unknown,
  json: unknown,
  depth: number,
  state: ValidationState
): void {
  if (Array.isArray(value)) {
    validateAnnotationNode(value, json, [], depth, state);
    return;
  }
  validateAnnotationChildren(value, json, [], depth, state);
}

function validateAnnotationNode(
  value: unknown,
  json: unknown,
  origin: readonly string[],
  depth: number,
  state: ValidationState
): void {
  reserve(state, depth, 1);
  if (!Array.isArray(value)) throw invalidEnvelope();
  claimMetadataNode(value, state);
  if (value.length < 1 || value.length > 2) throw invalidEnvelope();
  assertDenseDataArray(value);
  const targetKey = JSON.stringify(origin);
  if (state.annotationTargets.has(targetKey)) throw invalidEnvelope();
  state.annotationTargets.add(targetKey);
  const annotation = validateAnnotation(dataProperty(value, '0'), valueAtPath(json, origin), state);
  if (value.length === 2) {
    if (annotation !== 'Error' && annotation !== 'map' && annotation !== 'set') throw invalidEnvelope();
    validateAnnotationChildren(dataProperty(value, '1'), json, origin, depth + 1, state, annotation);
  }
}

function validateAnnotationChildren(
  value: unknown,
  json: unknown,
  origin: readonly string[],
  depth: number,
  state: ValidationState,
  parentAnnotation?: string
): void {
  assertPlainRecord(value, 'RPC value annotations');
  claimMetadataNode(value, state);
  const keys = Object.keys(value);
  if (keys.length === 0) throw invalidEnvelope();
  const entries = keys.map((key) => ({ key, path: validatePath(key, origin.length, state) }));
  entries.sort((left, right) => comparePaths(left.path, right.path));
  for (let index = 1; index < entries.length; index += 1) {
    if (isPathPrefix(entries[index - 1]!.path, entries[index]!.path)) throw invalidEnvelope();
  }
  for (const { key, path } of entries) {
    if (parentAnnotation !== undefined) validateChildComposition(parentAnnotation, path);
    validateAnnotationNode(dataProperty(value, key), json, [...origin, ...path], depth + 1, state);
  }
}

function validateAnnotation(value: unknown, target: unknown, state: ValidationState): string {
  if (typeof value === 'string') {
    if (!SIMPLE_ANNOTATIONS.has(value)) throw invalidEnvelope();
    validateSimpleAnnotationTarget(value, target);
    return value;
  }
  if (Array.isArray(value)) {
    claimMetadataNode(value, state);
    if (value.length !== 2) throw invalidEnvelope();
    assertDenseDataArray(value);
  }
  if (
    Array.isArray(value) &&
    value.length === 2 &&
    dataProperty(value, '0') === 'typed-array' &&
    typeof dataProperty(value, '1') === 'string' &&
    TYPED_ARRAYS.has(dataProperty(value, '1') as string)
  ) {
    if (!Array.isArray(target)) {
      throw invalidEnvelope();
    }
    for (let index = 0; index < target.length; index += 1) {
      const entry = dataProperty(target, String(index));
      if (typeof entry !== 'number' || !Number.isFinite(entry) || Object.is(entry, -0)) throw invalidEnvelope();
    }
    const type = dataProperty(value, '1') as string;
    const bytesPerElement = TYPED_ARRAY_ELEMENT_BYTES.get(type);
    if (bytesPerElement === undefined || target.length > Math.floor(state.maxBytes / bytesPerElement)) {
      throw resourceLimit('RPC typed-array allocation exceeds the configured byte limit');
    }
    return 'typed-array';
  }
  // In particular, class/symbol/custom annotations are never accepted.
  throw invalidEnvelope();
}

function validateSimpleAnnotationTarget(annotation: string, target: unknown): void {
  switch (annotation) {
    case 'undefined':
      if (target !== null) throw invalidEnvelope();
      return;
    case 'bigint':
      if (
        typeof target !== 'string' ||
        Buffer.byteLength(target) > 16 * 1024 ||
        !/^-?(?:0|[1-9]\d*)$/.test(target)
      ) throw invalidEnvelope();
      return;
    case 'Date': {
      if (typeof target !== 'string') throw invalidEnvelope();
      const parsed = new Date(target);
      if (!Number.isFinite(parsed.valueOf()) || parsed.toISOString() !== target) throw invalidEnvelope();
      return;
    }
    case 'Error':
      assertPlainRecord(target, 'RPC Error value');
      if (
        Object.keys(target).length < 2 ||
        Object.keys(target).length > 3 ||
        Object.keys(target).some((key) => !['name', 'message', 'cause'].includes(key)) ||
        typeof target.name !== 'string' ||
        Buffer.byteLength(target.name) > 256 ||
        typeof target.message !== 'string' ||
        Buffer.byteLength(target.message) > 8 * 1024
      ) throw invalidEnvelope();
      return;
    case 'regexp': {
      if (typeof target !== 'string' || Buffer.byteLength(target) > 64 * 1024 || !target.startsWith('/')) {
        throw invalidEnvelope();
      }
      const separator = target.lastIndexOf('/');
      if (separator < 1) throw invalidEnvelope();
      try {
        const regexp = RegExp(target.slice(1, separator), target.slice(separator + 1));
        if (RegExp.prototype.toString.call(regexp) !== target) throw invalidEnvelope();
      } catch {
        throw invalidEnvelope();
      }
      return;
    }
    case 'set':
      if (!Array.isArray(target)) throw invalidEnvelope();
      return;
    case 'map':
      if (!Array.isArray(target)) throw invalidEnvelope();
      for (let index = 0; index < target.length; index += 1) {
        const row = dataProperty(target, String(index));
        if (!Array.isArray(row) || row.length !== 2) throw invalidEnvelope();
        assertDenseDataArray(row);
      }
      return;
    case 'number':
      if (!['NaN', 'Infinity', '-Infinity', '-0'].includes(target as string)) throw invalidEnvelope();
      return;
    case 'URL':
      if (typeof target !== 'string' || Buffer.byteLength(target) > 8 * 1024) throw invalidEnvelope();
      try {
        const url = new URL(target);
        if (URL.prototype.toString.call(url) !== target) throw invalidEnvelope();
      } catch {
        throw invalidEnvelope();
      }
      return;
    default:
      throw invalidEnvelope();
  }
}

function valueAtPath(root: unknown, path: readonly string[]): unknown {
  let value = root;
  for (const segment of path) {
    if (Array.isArray(value)) {
      if (!/^(?:0|[1-9]\d*)$/.test(segment)) throw invalidEnvelope();
      const index = Number(segment);
      if (!Number.isSafeInteger(index) || index >= value.length || !Object.hasOwn(value, index)) {
        throw invalidEnvelope();
      }
      value = dataProperty(value, segment);
      continue;
    }
    if (typeof value === 'object' && value !== null && Object.hasOwn(value, segment)) {
      value = dataProperty(value, segment);
      continue;
    }
    throw invalidEnvelope();
  }
  return value;
}

function validatePath(path: string, originDepth: number, state: ValidationState): string[] {
  reserveBytes(state, path);
  let segment = '';
  const segments: string[] = [];
  const pushSegment = (): void => {
    if (originDepth + segments.length >= state.maxDepth) {
      throw resourceLimit('RPC value path depth exceeds the configured limit');
    }
    assertSafeKey(segment);
    segments.push(segment);
    segment = '';
  };
  for (let index = 0; index < path.length; index += 1) {
    const character = path[index]!;
    if (character === '\\') {
      const escaped = path[index + 1];
      if (escaped !== '\\' && escaped !== '.') throw invalidEnvelope();
      segment += escaped;
      index += 1;
    } else if (character === '.') {
      pushSegment();
    } else {
      segment += character;
    }
  }
  pushSegment();
  if (stringifyPath(segments) !== path) throw invalidEnvelope();
  return segments;
}

function stringifyPath(path: readonly string[]): string {
  return path
    .map((segment) => segment.replace(/\\/g, '\\\\').replace(/\./g, '\\.'))
    .join('.');
}

function comparePaths(left: readonly string[], right: readonly string[]): number {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index += 1) {
    if (left[index]! < right[index]!) return -1;
    if (left[index]! > right[index]!) return 1;
  }
  return left.length - right.length;
}

function isPathPrefix(prefix: readonly string[], value: readonly string[]): boolean {
  return prefix.length <= value.length && prefix.every((segment, index) => segment === value[index]);
}

function validateChildComposition(annotation: string, path: readonly string[]): void {
  switch (annotation) {
    case 'Error':
      if (path[0] !== 'cause') throw invalidEnvelope();
      return;
    case 'map':
      if (
        path.length < 2 ||
        !isCanonicalArrayIndex(path[0]!) ||
        (path[1] !== '0' && path[1] !== '1')
      ) throw invalidEnvelope();
      return;
    case 'set':
      if (path.length < 1 || !isCanonicalArrayIndex(path[0]!)) throw invalidEnvelope();
      return;
    default:
      throw invalidEnvelope();
  }
}

function claimMetadataNode(value: object, state: ValidationState): void {
  if (state.seen.has(value) || state.metadataSeen.has(value)) throw invalidEnvelope();
  state.metadataSeen.add(value);
}

function isCanonicalArrayIndex(value: string): boolean {
  return /^(?:0|[1-9]\d*)$/.test(value);
}

function mapSize(value: Map<unknown, unknown>): number {
  const getter = Object.getOwnPropertyDescriptor(Map.prototype, 'size')?.get;
  if (!getter) throw unsupportedValue();
  return getter.call(value) as number;
}

function setSize(value: Set<unknown>): number {
  const getter = Object.getOwnPropertyDescriptor(Set.prototype, 'size')?.get;
  if (!getter) throw unsupportedValue();
  return getter.call(value) as number;
}

function assertDenseDataArray(value: readonly unknown[]): void {
  if (Object.getPrototypeOf(value) !== Array.prototype) throw invalidEnvelope();
  let elements = 0;
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw invalidEnvelope();
    if (key === 'length') {
      if (descriptor.enumerable || descriptor.value !== value.length) throw invalidEnvelope();
      continue;
    }
    if (
      typeof key !== 'string' ||
      !descriptor.enumerable ||
      !isCanonicalArrayIndex(key) ||
      Number(key) >= value.length
    ) throw invalidEnvelope();
    elements += 1;
  }
  if (elements !== value.length) throw invalidEnvelope();
}

function assertPlainRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new P2PError('INVALID_FRAME', `${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalidEnvelope();
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== 'string' ||
      !descriptor ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, 'value')
    ) throw invalidEnvelope();
  }
}

function assertSafeErrorOwnKeys(value: object): void {
  const allowed = new Set<PropertyKey>(['stack', 'name', 'message', 'cause']);
  for (const key of Reflect.ownKeys(value)) {
    if (!allowed.has(key)) throw unsupportedValue();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor) throw unsupportedValue();
    // V8 lazily materializes stack through a non-enumerable accessor. The wire
    // codec never reads or emits it; every field it does read must be data.
    if (key === 'stack') {
      if (descriptor.enumerable) throw unsupportedValue();
      continue;
    }
    if (!Object.hasOwn(descriptor, 'value')) throw unsupportedValue();
  }
}

function errorProperty(value: Error, key: 'name' | 'message'): unknown {
  let cursor: object | null = value;
  while (cursor !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(cursor, key);
    if (descriptor) {
      if (!Object.hasOwn(descriptor, 'value')) throw unsupportedValue();
      return descriptor.value;
    }
    cursor = Object.getPrototypeOf(cursor);
  }
  throw unsupportedValue();
}

function assertOnlyOwnKeys(value: object, allowed: readonly PropertyKey[]): void {
  const allowedKeys = new Set(allowed);
  for (const key of Reflect.ownKeys(value)) {
    if (!allowedKeys.has(key)) throw unsupportedValue();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw unsupportedValue();
  }
}

function dataProperty(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw invalidEnvelope();
  return descriptor.value;
}

function assertSafeKey(value: string): void {
  if (value === '__proto__' || value === 'prototype' || value === 'constructor') throw invalidEnvelope();
}

function isSupportedTypedArray(
  value: object
): value is Exclude<ArrayBufferView, DataView> & { readonly length: number; readonly [index: number]: number } {
  if (!ArrayBuffer.isView(value) || value instanceof DataView) return false;
  const type = TYPED_ARRAY_PROTOTYPES.get(Object.getPrototypeOf(value));
  if (type === undefined) return false;
  if (
    Object.getOwnPropertyDescriptor(value, 'length') ||
    Object.getOwnPropertyDescriptor(value, 'byteLength') ||
    Object.getOwnPropertyDescriptor(value, 'constructor') ||
    Object.getOwnPropertyDescriptor(value, Symbol.iterator)
  ) throw unsupportedValue();
  return true;
}

function reserve(state: ValidationState, depth: number, items: number): void {
  if (depth > state.maxDepth) throw resourceLimit('RPC value depth exceeds the configured limit');
  if (!Number.isSafeInteger(items) || items < 0 || state.items + items > state.maxItems) {
    throw resourceLimit('RPC value items exceed the configured limit');
  }
  state.items += items;
  if (items > state.maxBytes - state.bytes) throw resourceLimit('RPC value exceeds the configured byte limit');
  state.bytes += items;
}

function reserveMany(state: ValidationState, depth: number, items: number): void {
  reserve(state, depth, items);
}

function reserveFixedBytes(state: ValidationState, bytes: number): void {
  if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > state.maxBytes - state.bytes) {
    throw resourceLimit('RPC value exceeds the configured byte limit');
  }
  state.bytes += bytes;
}

function reserveOutboundString(state: ValidationState, value: string): void {
  const bytes = Buffer.byteLength(value);
  reserveFixedBytes(state, bytes + 5);
}

function reserveAnnotation(
  state: ValidationState,
  depth: number,
  path: WirePathBudget,
  annotation: string
): void {
  // One annotation contributes a path key (except at the root), an annotation
  // tuple/string, and surrounding array/map entries. The fixed allowance is a
  // conservative upper bound for those small MessagePack structures.
  reserve(state, depth, 4);
  reserveFixedBytes(
    state,
    (path.segments === 0 ? 0 : path.bytes + 5) + Buffer.byteLength(annotation) + 32
  );
}

function appendWirePath(path: WirePathBudget, segment: string): WirePathBudget {
  let escapedBytes = Buffer.byteLength(segment);
  for (const character of segment) {
    if (character === '.' || character === '\\') escapedBytes += 1;
  }
  return {
    segments: path.segments + 1,
    bytes: path.bytes + (path.segments === 0 ? 0 : 1) + escapedBytes
  };
}

function checkedProduct(left: number, right: number): number {
  const value = left * right;
  if (!Number.isSafeInteger(value) || value < 0) throw resourceLimit('RPC value size is invalid');
  return value;
}

function reserveBytes(state: ValidationState, value: string): void {
  const bytes = Buffer.byteLength(value);
  if (bytes > state.maxBytes - state.bytes) throw resourceLimit('RPC value exceeds the configured byte limit');
  state.bytes += bytes;
}

function unsupportedValue(): P2PError {
  return new P2PError('INVALID_FRAME', 'RPC values must use supported, accessor-free SuperJSON data types');
}

function invalidEnvelope(): P2PError {
  return new P2PError('INVALID_FRAME', 'Invalid RPC value envelope');
}

function resourceLimit(message: string): P2PError {
  return new P2PError('RESOURCE_LIMIT', message);
}
