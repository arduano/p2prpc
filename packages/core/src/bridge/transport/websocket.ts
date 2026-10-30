import { P2PError } from '../../errors.js';
import type { BinaryWebSocket, ByteDuplex, WebSocketCarrierLimits } from './contracts.js';

/** Adapts one owned binary WebSocket. No RPC, authentication, or reconnect policy
 * lives here. The WebSocket close event is the terminal resource proof. */
export function webSocketDuplex(socket: BinaryWebSocket, options: WebSocketCarrierLimits = {}): ByteDuplex {
  const maxBufferedBytes = options.maxBufferedBytes ?? 1024 * 1024;
  const maxMessageBytes = options.maxMessageBytes ?? 256 * 1024;
  const maxPendingWrites = options.maxPendingWrites ?? 16;
  const writeTimeoutMs = options.writeTimeoutMs ?? 15_000;
  for (const value of [maxBufferedBytes, maxMessageBytes, maxPendingWrites, writeTimeoutMs]) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new P2PError('RESOURCE_LIMIT', 'Invalid WebSocket limit');
  }
  if (maxMessageBytes > maxBufferedBytes) throw new P2PError('RESOURCE_LIMIT', 'WebSocket message exceeds buffer limit');
  socket.binaryType = 'arraybuffer';
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  let terminal = socket.readyState === 3;
  let closing = terminal;
  let error: Error | undefined;
  let reader = false;
  let pending = 0;
  let writes = Promise.resolve();
  let wake: (() => void) | undefined;
  let finish!: () => void;
  const closed = new Promise<void>(resolve => { finish = resolve; });
  const notify = (): void => { wake?.(); wake = undefined; };
  const close = (reason?: Error): void => {
    error ??= reason;
    if (closing) return;
    closing = true;
    chunks.length = 0; bytes = 0; notify();
    socket.close(reason ? 4000 : 1000, 'Logical channel closed');
  };
  const message = (event: { data: unknown }): void => {
    if (closing) return;
    let value: Uint8Array;
    if (event.data instanceof ArrayBuffer) value = new Uint8Array(event.data);
    else if (ArrayBuffer.isView(event.data)) value = new Uint8Array(event.data.buffer, event.data.byteOffset, event.data.byteLength);
    else { close(new P2PError('INVALID_FRAME', 'WebSocket requires binary messages')); return; }
    if (value.length > maxMessageBytes || bytes + value.length > maxBufferedBytes) {
      close(new P2PError('RESOURCE_LIMIT', 'WebSocket receive limit')); return;
    }
    // Preserve WebSocket message storage lifetime independently of the emitter.
    if (value.length !== 0) { chunks.push(value.slice()); bytes += value.length; }
    notify();
  };
  const onClose = (): void => {
    terminal = true; closing = true; notify();
    socket.removeEventListener('message', message);
    socket.removeEventListener('close', onClose);
    socket.removeEventListener('error', onError);
    finish();
  };
  const onError = (): void => { close(new P2PError('DISCONNECTED', 'WebSocket failed')); };
  socket.addEventListener('message', message);
  socket.addEventListener('close', onClose);
  socket.addEventListener('error', onError);
  if (terminal) onClose();
  const readable: AsyncIterable<Uint8Array> = {
    async *[Symbol.asyncIterator]() {
      if (reader) throw new P2PError('REJECTED', 'WebSocket reader already owned');
      reader = true;
      try {
        while (true) {
          const value = chunks.shift();
          if (value) { bytes -= value.length; yield value; continue; }
          if (error) throw error;
          if (closing) return;
          await new Promise<void>(resolve => { wake = resolve; });
        }
      } finally { close(); }
    }
  };
  return {
    readable, closed, close,
    write(value) {
      if (closing) return Promise.reject(error ?? new P2PError('DISCONNECTED', 'WebSocket closed'));
      if (value.length > maxMessageBytes || pending >= maxPendingWrites) return Promise.reject(new P2PError('RESOURCE_LIMIT', 'WebSocket write limit'));
      // Queued writes own their bounded bytes; caller mutation cannot alter them.
      if ((pending + 1) * maxMessageBytes > maxBufferedBytes) return Promise.reject(new P2PError('RESOURCE_LIMIT', 'WebSocket queued byte limit'));
      pending++;
      const copy = value.slice();
      const deadline = Date.now() + writeTimeoutMs;
      const task = writes.then(async () => {
        const wait = async (condition: () => boolean): Promise<void> => {
          while (!condition()) {
            if (closing) throw error ?? new P2PError('DISCONNECTED', 'WebSocket closed');
            if (Date.now() >= deadline) throw new P2PError('TIMEOUT', 'WebSocket write timed out');
            await new Promise<void>(resolve => setTimeout(resolve, 8));
          }
        };
        await wait(() => socket.readyState === 1 && socket.bufferedAmount + copy.length <= maxBufferedBytes);
        if (closing) throw error ?? new P2PError('DISCONNECTED', 'WebSocket closed');
        socket.send(copy);
        // WebSocket.send copies/enqueues the bytes. Backpressure belongs to
        // admission against the bounded native buffer, not a full flush after
        // every fragment (which serializes tiny Yamux window updates on TLS).
      }).catch((reason: unknown) => {
        const failure = reason instanceof Error ? reason : new P2PError('DISCONNECTED', 'WebSocket write failed');
        close(failure); throw failure;
      }).finally(() => { pending--; });
      writes = task.catch(() => {});
      return task;
    }
  };
}
