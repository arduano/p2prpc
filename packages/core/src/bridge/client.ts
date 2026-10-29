import type { AnyTRPCRouter } from '@trpc/server';
import type { z } from 'zod';
import { P2PError } from '../errors.js';
import { freezePrincipal } from '../security/types.js';
import type { QuicConnection } from '../transport/types.js';
import type { BridgePeer, BridgePeerOptions } from './contracts.js';
import { admission, controlChannel, readySchema, type publicPrincipalSchema } from './control.js';
import { createBridgePeer } from './peer.js';
import { fromByteDuplex, webSocketDuplex, type BinaryWebSocket, type ByteDuplex } from './transport/index.js';

export interface ConnectBridgeOptions<L extends AnyTRPCRouter = AnyTRPCRouter, M = unknown>
  extends Omit<BridgePeerOptions<L, M>, 'localId' | 'remoteId' | 'connection' | 'authorize'> {
  readonly url: string;
  readonly expectedHostId: string;
  readonly socket?: (url: string) => BinaryWebSocket;
  readonly authorize?: BridgePeerOptions<L, M>['authorize'];
}

/** One browser-owned engine and resumption secret, never a persisted identity.
 * Reconnection admits a carrier only; an interrupted RPC is never replayed. */
export interface BrowserBridgePeer<R extends AnyTRPCRouter, M = unknown> extends Pick<BridgePeer<R, M>, 'rpc' | 'files' | 'diagnostics' | 'close'> { reconnect(): Promise<void>; }
function publicIdentity(value: z.output<typeof publicPrincipalSchema>) {
  return freezePrincipal({ id: value.id, subject: value.subject, expiresAt: value.expiresAt,
    ...(value.issuer === undefined ? {} : { issuer: value.issuer }),
    ...(value.clientId === undefined ? {} : { clientId: value.clientId }),
    ...(value.tenantId === undefined ? {} : { tenantId: value.tenantId }), scopes: new Set(), claims: {} });
}
export async function connectBridge<R extends AnyTRPCRouter, L extends AnyTRPCRouter = AnyTRPCRouter, M = unknown>(options: ConnectBridgeOptions<L, M>): Promise<BrowserBridgePeer<R, M>> {
  let engine: BridgePeer<R, M> | undefined;
  let current: QuicConnection | undefined;
  let opening: ByteDuplex | undefined;
  let pending: Promise<QuicConnection> | undefined;
  let closing: Promise<void> | undefined;
  let resume: string | undefined;
  let peerId: string | undefined;
  let closed = false;
  const connection = (): Promise<QuicConnection> => {
    if (closed) return Promise.reject(new P2PError('DISCONNECTED', 'Browser Bridge closed'));
    if (pending) return pending;
    if (current && engine?.diagnostics().connected) return Promise.resolve(current);
    const attempt = (async () => {
      if (current) { current.close(0n, new Uint8Array()); await current.closed(); }
      if (closed) throw new P2PError('DISCONNECTED', 'Browser Bridge closed');
      const socket = (options.socket ?? (url => new WebSocket(url)))(options.url);
      const channel = webSocketDuplex(socket);
      opening = channel;
      try {
        return await admission(async admissionSignal => {
          const control = controlChannel(channel);
          await control.write(62, { version: 1, ...(resume ? { resume } : {}) });
          const frame = await control.read();
          if (frame.kind !== 63) throw new P2PError('INCOMPATIBLE_PROTOCOL', 'Expected BrowserReady');
          admissionSignal.throwIfAborted();
          const ready = readySchema.parse(frame.value);
          if (ready.hostId !== options.expectedHostId || ready.principal.id !== ready.hostId || ready.principal.subject !== ready.hostId ||
            (peerId !== undefined && (peerId !== ready.peerId || resume !== ready.resume))) {
            throw new P2PError('UNAUTHORIZED', 'Unexpected Bridge Host or resumption identity');
          }
          if (closed) throw new P2PError('DISCONNECTED', 'Browser Bridge closed');
          const raw = fromByteDuplex(control.remaining, { side: 'client', remoteId: ready.hostId });
          engine ??= createBridgePeer<R, L, M>({ ...options,
            localId: ready.peerId, remoteId: ready.hostId, connection,
            authorize: options.authorize ?? (context => context.action.kind === 'file.pull' ||
              (context.action.kind === 'file.push' && options.incoming !== undefined)) });
          engine.attach(raw, { id: ready.sessionId, expiresAt: ready.expiresAt,
            principal: publicIdentity(ready.principal),
            via: { peerId: ready.gateway.peerId, principal: publicIdentity(ready.gateway.principal) } });
          resume = ready.resume; peerId = ready.peerId; current = raw;
          void raw.closed().then(() => { if (current === raw) current = undefined; }, () => {});
          return raw;
        }, channel, undefined, options.limits?.setupTimeoutMs);
      } finally { if (opening === channel) opening = undefined; }
    })();
    pending = attempt;
    void attempt.finally(() => { if (pending === attempt) pending = undefined; }).catch(() => {});
    return attempt;
  };
  try { await connection(); }
  catch (error) { closed = true; await engine?.close('Browser Bridge admission failed'); throw error; }
  const admitted = engine!;
  return {
    rpc: admitted.rpc,
    files: admitted.files,
    diagnostics: () => admitted.diagnostics(),
    reconnect: async (): Promise<void> => { await connection(); },
    close(): Promise<void> {
      if (closing) return closing;
      closed = true;
      closing = (async () => {
        const results = await Promise.allSettled([
          admitted.close('Browser Bridge closed'),
          ...(opening ? [((channel: ByteDuplex) => Promise.resolve(channel.close()).then(() => channel.closed))(opening)] : []),
          ...(pending ? [pending.then(() => undefined, () => undefined)] : [])
        ]);
        const failures = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
        if (failures.length) throw new AggregateError(failures.map(result => result.reason), 'Browser Bridge cleanup failed');
      })();
      return closing;
    }
  };
}
