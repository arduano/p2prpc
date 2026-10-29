import type { AnyTRPCRouter } from '@trpc/server';
import { P2PError } from '../errors.js';
import type { Peer } from '../node.js';
import type { OpenBridgeOptions } from './native.js';
import { webSocketDuplex, type BinaryWebSocket, type ByteDuplex } from './transport/index.js';

/** Relay one authorized WebSocket to one native Bridge stream. Headers come
 * from the Gateway's verified HTTP/session context, never BrowserHello JSON. */
export async function relayBridge(
  socket: BinaryWebSocket,
  peer: Pick<Peer<AnyTRPCRouter>, 'openBridge'>,
  options: OpenBridgeOptions = {}
): Promise<void> {
  const browser = webSocketDuplex(socket);
  const controller = new AbortController();
  let host: ByteDuplex | undefined;
  let failure: { error: unknown } | undefined;
  const abort = (): void => {
    const reason = new P2PError('CANCELLED', 'Gateway relay cancelled');
    controller.abort(reason);
    void Promise.resolve(browser.close(reason)).catch(() => {});
    if (host) void Promise.resolve(host.close(reason)).catch(() => {});
  };
  options.signal?.addEventListener('abort', abort, { once: true });
  void browser.closed.then(abort, abort);
  try {
    options.signal?.throwIfAborted();
    host = await peer.openBridge({ ...options, signal: controller.signal });
    controller.signal.throwIfAborted();
    const copy = async (source: ByteDuplex, destination: ByteDuplex): Promise<void> => {
      try { for await (const bytes of source.readable) await destination.write(bytes); }
      finally { await Promise.all([source, destination].map(channel => Promise.resolve().then(() => channel.close()))); }
    };
    const results = await Promise.allSettled([copy(browser, host), copy(host, browser)]);
    const failure = results.find((result): result is PromiseRejectedResult => result.status === 'rejected');
    if (failure) throw failure.reason;
  } catch (error) { failure = { error }; }
  finally { options.signal?.removeEventListener('abort', abort); }
  const channels = [browser, ...(host ? [host] : [])];
  const results = await Promise.allSettled(channels.map(channel => Promise.resolve().then(() => channel.close())));
  const proofs = await Promise.allSettled(channels.map(channel => channel.closed));
  const failures = [...results, ...proofs].filter((result): result is PromiseRejectedResult => result.status === 'rejected');
  if (failures.length) throw new AggregateError(failures.map(result => result.reason), 'Gateway relay cleanup failed', { cause: failure?.error });
  if (failure) throw failure.error;
}
