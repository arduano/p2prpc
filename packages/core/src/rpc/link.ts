import type { TRPCLink } from '@trpc/client';
import type { AnyTRPCRouter } from '@trpc/server';
import { nativeRpcHeaders, type RpcHeaderInput } from './headers.js';
import {
  irohLink as portableIrohLink,
  p2pRpcContext as portableRpcContext,
  type IrohLinkOptions,
  type P2PRpcOperationContext
} from './portable-link.js';

export type { IrohLinkOptions, P2PRpcOperationContext } from './portable-link.js';

export function p2pRpcContext(headers: RpcHeaderInput): P2PRpcOperationContext {
  return portableRpcContext(headers, nativeRpcHeaders);
}

export function irohLink<TRouter extends AnyTRPCRouter>(options: IrohLinkOptions): TRPCLink<TRouter> {
  return portableIrohLink<TRouter>(options, nativeRpcHeaders);
}
