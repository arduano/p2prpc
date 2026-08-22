import SuperJSON from 'superjson';
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

export function serializeValue(value: unknown): unknown {
  return SuperJSON.serialize(value);
}

export function deserializeValue(value: unknown): unknown {
  return SuperJSON.deserialize(value as ReturnType<typeof SuperJSON.serialize>);
}

export function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return typeof value === 'object' && value !== null && Symbol.asyncIterator in value;
}
