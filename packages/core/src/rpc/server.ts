import type { AnyTRPCRouter } from '@trpc/server';
import { nativeRpcHeaders } from './headers.js';
import { RpcServer as PortableRpcServer, type RpcServerOptions } from './portable-server.js';

export { safeErrorShape } from './portable-server.js';
export type { RpcServerOptions, RpcServerRequest, RpcWorkTracker } from './portable-server.js';

export class RpcServer<TRouter extends AnyTRPCRouter> extends PortableRpcServer<TRouter> {
  constructor(options: RpcServerOptions<TRouter>) {
    super(options, nativeRpcHeaders);
  }
}
