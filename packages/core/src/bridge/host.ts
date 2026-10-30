import type { AnyTRPCRouter } from '@trpc/server';
import { P2PError } from '../errors.js';
import { randomToken, randomUuid, sha256Hex, unrefTimer } from '../platform.js';
import { freezePrincipal, type SessionPrincipal } from '../security/types.js';
import { TaskGroup } from '../runtime/task-group.js';
import type { QuicConnection } from '../transport/types.js';
import type { BridgePeer, BridgePeerOptions } from './contracts.js';
import { admission, controlChannel, helloSchema } from './control.js';
import type { NativeBridgeOffer } from './native.js';
import { createBridgePeer } from './peer.js';
import { fromByteDuplex } from './transport/index.js';

export interface BridgeHostOptions<R extends AnyTRPCRouter, M = unknown> {
  readonly router: R;
  readonly createContext: NonNullable<BridgePeerOptions<R, M>['local']>['createContext'];
  readonly authorizeDelegation: (offer: NativeBridgeOffer) => SessionPrincipal | Promise<SessionPrincipal>;
  readonly authorizeOperation: BridgePeerOptions<R, M>['authorize'];
  readonly onIncomingFile?: BridgePeerOptions<R, M>['incoming'];
  readonly fileMetadataSchema?: BridgePeerOptions<R, M>['fileMetadataSchema'];
  /** Same logical RPC envelope limit as the browser peer. Carrier chunks and
   * authentication frames keep their independent small bounds. */
  readonly frameLimits?: BridgePeerOptions<R, M>['frameLimits'];
  readonly onError?: BridgePeerOptions<R, M>['onError'];
  readonly limits?: BridgePeerOptions<R, M>['limits'] & { readonly maxPeers?: number };
}
interface Entry<M> {
  readonly peerId: string;
  readonly identity: string;
  readonly engine: BridgePeer<AnyTRPCRouter, M>;
  expiresAt: number;
  connection?: QuicConnection;
  attaching: boolean;
  timer?: ReturnType<typeof setTimeout>;
  retiring?: Promise<void>;
  waiting?: { readonly promise: Promise<QuicConnection>; resolve(connection: QuicConnection): void; reject(error: Error): void };
}
const identity = (value: SessionPrincipal): string => JSON.stringify([
  value.id, value.subject, value.issuer ?? null, value.clientId ?? null, value.tenantId ?? null
]);
const publicPrincipal = (value: SessionPrincipal) => ({ id: value.id, subject: value.subject,
  ...(value.issuer === undefined ? {} : { issuer: value.issuer }),
  ...(value.clientId === undefined ? {} : { clientId: value.clientId }),
  ...(value.tenantId === undefined ? {} : { tenantId: value.tenantId }), expiresAt: value.expiresAt });

/** One Host-owned logical Peer/file ledger per delegated browser lifetime. */
export interface BridgeHost {
  accept(offer: NativeBridgeOffer): Promise<void>;
  revoke(peerId: string): Promise<void>;
  close(): Promise<void>;
  diagnostics(): { readonly closed: boolean; readonly admitting: number; readonly tasks: number; readonly channels: number; readonly peers: number; readonly entries: readonly { readonly peerId: string; readonly expiresAt: number; readonly retiring: boolean }[] };
}
export function createBridgeHost<R extends AnyTRPCRouter, M = unknown>(options: BridgeHostOptions<R, M>): BridgeHost {
  const { maxPeers = 32, ...limits } = options.limits ?? {};
  if (!Number.isSafeInteger(maxPeers) || maxPeers < 1 || maxPeers > 4096) throw new P2PError('RESOURCE_LIMIT', 'Invalid Bridge Host capacity');
  const entries = new Map<string, Entry<M>>();
  const tasks = new TaskGroup('Bridge Host');
  const channels = new Set<NativeBridgeOffer['channel']>();
  let closed = false;
  let admitting = 0;
  const retire = (key: string, entry: Entry<M>): Promise<void> => {
    if (entry.retiring) return entry.retiring;
    if (entry.timer) clearTimeout(entry.timer);
    entry.waiting?.reject(new P2PError('DISCONNECTED', 'Bridge lifetime ended'));
    delete entry.waiting;
    entry.retiring = entry.engine.close('Bridge lifetime ended').then(() => { if (entries.get(key) === entry) entries.delete(key); });
    void entry.retiring.catch(() => {}); // Failed custody stays in the bounded map.
    return entry.retiring;
  };
  const expire = (key: string, entry: Entry<M>): void => {
    if (entry.timer) clearTimeout(entry.timer);
    const remaining = entry.expiresAt - Date.now();
    if (remaining <= 0) { void retire(key, entry); return; }
    entry.timer = setTimeout(() => expire(key, entry), Math.min(remaining, 2_147_483_647));
    unrefTimer(entry.timer);
  };
  return {
    accept(offer: NativeBridgeOffer): Promise<void> { return tasks.track((async () => {
      const signal = AbortSignal.any([offer.signal, tasks.signal]);
      offer = { ...offer, signal };
      if (closed || admitting >= maxPeers || channels.size >= maxPeers * 2) { await offer.channel.close(new P2PError('RESOURCE_LIMIT', 'Bridge admission unavailable')); await offer.channel.closed; throw new P2PError('RESOURCE_LIMIT', 'Bridge admission unavailable'); }
      channels.add(offer.channel);
      admitting += 1;
      let selected: Entry<M> | undefined;
      const abort = () => { void Promise.resolve(offer.channel.close(new P2PError('DISCONNECTED', 'Gateway carrier ended'))).catch(() => {}); };
      offer.signal.addEventListener('abort', abort, { once: true });
      try {
        const connection = await admission(async admissionSignal => {
          const principal = freezePrincipal(await options.authorizeDelegation({ ...offer, signal: admissionSignal }));
          admissionSignal.throwIfAborted();
          const expiresAt = Math.min(principal.expiresAt, offer.auth.expiresAt);
          if (closed || expiresAt <= Date.now()) throw new P2PError('UNAUTHORIZED', 'Bridge delegation expired');
          const user = freezePrincipal({ ...principal, expiresAt });
          const control = controlChannel(offer.channel);
          const frame = await control.read();
          if (frame.kind !== 62) throw new P2PError('INCOMPATIBLE_PROTOCOL', 'Expected BrowserHello');
          admissionSignal.throwIfAborted();
          const hello = helloSchema.parse(frame.value);
          const resume = hello.resume ?? randomToken();
          const key = sha256Hex(resume);
          let entry = entries.get(key);
          if (!hello.resume && entry) throw new P2PError('REJECTED', 'Bridge resumption collision');
          if (hello.resume && (!entry || entry.identity !== identity(user))) throw new P2PError('UNAUTHORIZED', 'Unknown Bridge resumption');
          if (!entry) {
            if (entries.size >= maxPeers) throw new P2PError('RESOURCE_LIMIT', 'Bridge Host capacity');
            const peerId = randomUuid();
            const engine = createBridgePeer<AnyTRPCRouter, R, M>({ localId: offer.localPeerId, remoteId: peerId,
              connection: async () => {
                if (closed || entry!.retiring || entry!.expiresAt <= Date.now()) throw new P2PError('DISCONNECTED', 'Bridge lifetime ended');
                if (entry!.connection) return entry!.connection;
                if (!entry!.waiting) {
                  let resolve!: (value: QuicConnection) => void, reject!: (error: Error) => void;
                  const promise = new Promise<QuicConnection>((yes, no) => { resolve = yes; reject = no; });
                  void promise.catch(() => {});
                  const waiting = { promise,
                    resolve(value: QuicConnection) { clearTimeout(timer); resolve(value); },
                    reject(error: Error) { clearTimeout(timer); reject(error); } };
                  const timer = setTimeout(() => {
                    if (entry!.waiting === waiting) delete entry!.waiting;
                    reject(new P2PError('TIMEOUT', 'Bridge reattachment timed out'));
                  }, limits.ioTimeoutMs ?? 30_000);
                  unrefTimer(timer);
                  entry!.waiting = waiting;
                }
                return entry!.waiting.promise;
              },
              authorize: options.authorizeOperation, local: { router: options.router, createContext: options.createContext },
              ...(options.onIncomingFile ? { incoming: options.onIncomingFile } : {}),
              ...(options.fileMetadataSchema ? { fileMetadataSchema: options.fileMetadataSchema } : {}),
              ...(options.frameLimits ? { frameLimits: options.frameLimits } : {}),
              ...(options.onError ? { onError: options.onError } : {}), limits });
            entry = { peerId, identity: identity(user), engine, expiresAt, attaching: false };
            entries.set(key, entry);
            expire(key, entry);
          }
          if (entry.retiring || entry.attaching || entry.expiresAt <= Date.now()) throw new P2PError('REJECTED', 'Bridge lifetime unavailable');
          selected = entry;
          entry.attaching = true;
          if (entry.connection) { entry.connection.close(0n, new Uint8Array()); await entry.connection.closed(); }
          admissionSignal.throwIfAborted();
          if (closed || entry.retiring) throw new P2PError('DISCONNECTED', 'Bridge Host closed');
          const sessionId = randomUuid();
          await control.write(63, { version: 1, hostId: offer.localPeerId, peerId: entry.peerId, sessionId, resume, expiresAt,
            principal: { id: offer.localPeerId, subject: offer.localPeerId, expiresAt },
            gateway: { peerId: offer.peer.id, principal: publicPrincipal(offer.auth.principal) } });
          admissionSignal.throwIfAborted();
          const raw = fromByteDuplex(control.remaining, { side: 'server', remoteId: entry.peerId,
            ...(options.frameLimits ? { limits: {
              maxReadBytes: Math.max(1024 * 1024, options.frameLimits.maxControlFrameBytes),
              maxBufferedBytes: limits.maxBufferedBytes ?? 32 * 1024 * 1024
            } } : {}) });
          entry.engine.attach(raw, { id: sessionId, principal: user, expiresAt, via: { peerId: offer.peer.id, principal: offer.auth.principal } });
          entry.connection = raw;
          entry.expiresAt = expiresAt;
          entry.waiting?.resolve(raw);
          delete entry.waiting;
          expire(key, entry);
          void raw.closed().then(() => { if (entry!.connection === raw) delete entry!.connection; }, () => {});
          return raw;
        }, offer.channel, offer.signal, limits.setupTimeoutMs).finally(() => { admitting -= 1; if (selected) selected.attaching = false; });
        await connection.closed();
      } finally {
        offer.signal.removeEventListener('abort', abort);
        void offer.channel.closed.then(() => { channels.delete(offer.channel); }, () => {});
      }
    })()); },
    revoke(peerId: string): Promise<void> { const found = [...entries].find(([, entry]) => entry.peerId === peerId); return found ? retire(...found) : Promise.resolve(); },
    async close(): Promise<void> {
      closed = true;
      const reason = new P2PError('DISCONNECTED', 'Bridge Host closed');
      const cleanup = [...entries].map(([key, entry]) => retire(key, entry)).concat([...channels].map(channel => Promise.resolve().then(() => channel.close(reason)).then(() => channel.closed)));
      for (const work of cleanup) tasks.track(work);
      await tasks.close(reason, { timeoutMs: limits.shutdownTimeoutMs ?? 5_000 });
      const results = await Promise.allSettled(cleanup);
      const failures = results.filter((value): value is PromiseRejectedResult => value.status === 'rejected');
      if (failures.length) throw new AggregateError(failures.map(value => value.reason), 'Bridge Host cleanup failed');
    },
    diagnostics: () => ({ closed, admitting, tasks: tasks.size, channels: channels.size, peers: entries.size, entries: [...entries.values()].map(entry => ({ peerId: entry.peerId, expiresAt: entry.expiresAt, retiring: !!entry.retiring, ...entry.engine.diagnostics() })) })
  };
}
