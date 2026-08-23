import { TRPCClientError, type TRPCLink } from '@trpc/client';
import type { AnyTRPCRouter } from '@trpc/server';
import { observable } from '@trpc/server/observable';
import { P2PError, asP2PError } from '../errors.js';
import { sanitizeBoundedDisplayText } from '../text.js';
import {
  DEFAULT_FRAME_LIMITS,
  RpcFrameKind,
  StreamKind,
  readFrame,
  writeFrame,
  writeStreamKind,
  type FrameLimits
} from '../protocol.js';
import type { QuicConnection } from '../transport/types.js';
import {
  DEFAULT_RPC_HEADER_LIMITS,
  mergeRpcHeaders,
  normalizeRpcHeaders,
  type RpcHeaderInput,
  type RpcHeaderLimits
} from './headers.js';
import { deserializeValue, serializeValue, type RpcData, type RpcFailure, type RpcRequest } from './wire.js';

export interface IrohLinkOptions {
  readonly connection: () => Promise<QuicConnection>;
  readonly frameLimits?: FrameLimits;
  readonly headerLimits?: RpcHeaderLimits;
  /** Maximum time for each header, connection, stream, read, or write operation. */
  readonly ioTimeoutMs?: number;
  readonly getRequestHeaders?: (request: {
    readonly path: string;
    readonly type: 'query' | 'mutation' | 'subscription';
    readonly signal: AbortSignal;
  }) => Promise<RpcHeaderInput | undefined> | RpcHeaderInput | undefined;
}

export interface P2PRpcOperationContext extends Record<string, unknown> {
  readonly p2prpc: { readonly headers: RpcHeaderInput };
}

/** Context object for the second argument of a tRPC query/mutation call. */
export function p2pRpcContext(headers: RpcHeaderInput): P2PRpcOperationContext {
  const snapshot = normalizeRpcHeaders(headers);
  return Object.freeze({ p2prpc: Object.freeze({ headers: snapshot }) });
}

export function irohLink<TRouter extends AnyTRPCRouter>(options: IrohLinkOptions): TRPCLink<TRouter> {
  const ioTimeoutMs = resolveIoTimeout(options.ioTimeoutMs);
  const cleanupTimeoutMs = Math.min(ioTimeoutMs, 1_000);
  return () => ({ op }) =>
    observable((observer) => {
      let active = true;
      let requestSent = false;
      let stream: Awaited<ReturnType<QuicConnection['openBi']>> | undefined;
      let cleanedStream: typeof stream;
      let cleanupTask: Promise<void> | undefined;
      let unaryResult: unknown;
      let hasUnaryResult = false;
      const controller = new AbortController();

      const removeAbortListener = (): void => op.signal?.removeEventListener('abort', onSignalAbort);

      const cleanup = (
        current: NonNullable<typeof stream>,
        mode: 'cancel' | 'failure' | 'terminal'
      ): Promise<void> => {
        if (cleanedStream === current && cleanupTask) return cleanupTask;
        cleanedStream = current;
        cleanupTask = cleanupRpcStream(
          current,
          mode,
          requestSent ? op.id : undefined,
          options.frameLimits ?? DEFAULT_FRAME_LIMITS,
          cleanupTimeoutMs
        );
        return cleanupTask;
      };

      const ensureActive = (): void => {
        if (!active || controller.signal.aborted) {
          throw controller.signal.reason ?? new P2PError('CANCELLED', 'RPC cancelled');
        }
      };

      const io = <T>(operation: () => Promise<T> | T, message: string): Promise<T> => {
        ensureActive();
        return withDeadline(Promise.resolve().then(() => {
          ensureActive();
          return operation();
        }), ioTimeoutMs, message, controller);
      };

      const run = async (): Promise<void> => {
        try {
          ensureActive();
          const headerLimits = options.headerLimits ?? DEFAULT_RPC_HEADER_LIMITS;
          // Snapshot per-call metadata before the first await so caller-owned
          // objects cannot be changed while an asynchronous default provider runs.
          const perCall = normalizeRpcHeaders(readPerCallHeaders(op.context), headerLimits);
          const defaults = await io(
            () => options.getRequestHeaders?.(Object.freeze({
              path: op.path,
              type: op.type,
              signal: controller.signal
            })),
            'RPC request headers timed out'
          );
          ensureActive();
          const headers = mergeRpcHeaders(defaults, perCall, headerLimits);
          const input = serializeValue(op.input);
          ensureActive();
          const connection = await io(options.connection, 'RPC connection acquisition timed out');
          ensureActive();
          const opening = Promise.resolve().then(() => {
            ensureActive();
            return connection.openBi();
          });
          try {
            stream = await withDeadline(opening, ioTimeoutMs, 'RPC stream opening timed out', controller);
          } catch (cause) {
            void opening.then(
              (lateStream) => cleanupRpcStream(
                lateStream,
                'failure',
                undefined,
                options.frameLimits ?? DEFAULT_FRAME_LIMITS,
                cleanupTimeoutMs
              ),
              () => undefined
            );
            throw cause;
          }
          ensureActive();
          const guardedSend = {
            writeAll: async (data: Uint8Array): Promise<void> => {
              ensureActive();
              await stream!.send.writeAll(data);
              ensureActive();
            },
            finish: () => stream!.send.finish(),
            reset: (code: bigint) => stream!.send.reset(code),
            setPriority: (priority: number) => stream!.send.setPriority(priority)
          };
          await io(() => stream!.send.setPriority(100), 'RPC stream priority timed out');
          ensureActive();
          await io(() => writeStreamKind(guardedSend, StreamKind.Rpc), 'RPC stream kind write timed out');
          ensureActive();
          const request: RpcRequest = {
            id: op.id,
            path: op.path,
            type: op.type,
            headers,
            input
          };
          await io(
            () => writeFrame(guardedSend, RpcFrameKind.Request, request, options.frameLimits ?? DEFAULT_FRAME_LIMITS),
            'RPC request write timed out'
          );
          requestSent = true;
          ensureActive();

          while (active) {
            const frame = await io(
              () => readFrame<RpcData | RpcFailure>(
                stream!.recv,
                options.frameLimits ?? DEFAULT_FRAME_LIMITS
              ),
              'RPC response frame timed out'
            );
            ensureActive();
            if (frame.kind === RpcFrameKind.Data) {
              const data = frame.value as RpcData;
              if (data.id !== op.id) throw new P2PError('INVALID_FRAME', 'RPC response ID does not match request');
              const value = deserializeValue(data.data);
              if (op.type === 'subscription') observer.next({ result: { data: value } });
              else {
                if (hasUnaryResult) throw new P2PError('INVALID_FRAME', 'Unary RPC returned multiple data frames');
                hasUnaryResult = true;
                unaryResult = value;
              }
            } else if (frame.kind === RpcFrameKind.Complete) {
              assertResponseId(frame.value, op.id);
              if (op.type !== 'subscription' && !hasUnaryResult) {
                throw new P2PError('INVALID_FRAME', 'Unary RPC completed without a result');
              }
              await io(() => stream!.recv.expectEnd(), 'RPC response finish timed out');
              active = false;
              removeAbortListener();
              await cleanup(stream, 'terminal');
              if (op.type !== 'subscription' && hasUnaryResult) {
                observer.next({ result: { data: unaryResult } });
              }
              observer.complete();
              return;
            } else if (frame.kind === RpcFrameKind.Error) {
              const failure = frame.value as RpcFailure;
              if (failure.id !== op.id) throw new P2PError('INVALID_FRAME', 'RPC error ID does not match request');
              await io(() => stream!.recv.expectEnd(), 'RPC response finish timed out');
              const message = readErrorMessage(failure.shape);
              active = false;
              removeAbortListener();
              await cleanup(stream, 'terminal');
              observer.error(new TRPCClientError(message, { result: { error: failure.shape as never } }));
              return;
            } else {
              throw new P2PError('INVALID_FRAME', `Unexpected RPC frame kind ${frame.kind}`);
            }
          }
        } catch (cause) {
          const notify = active;
          active = false;
          removeAbortListener();
          if (stream) await cleanup(stream, 'failure');
          if (notify) observer.error(TRPCClientError.from(asP2PError(cause, 'DISCONNECTED')));
        }
      };

      function onSignalAbort(): void {
        cancel(true);
      }

      function cancel(notify: boolean): void {
        if (!active) return;
        active = false;
        removeAbortListener();
        const error = new P2PError('CANCELLED', 'RPC cancelled');
        controller.abort(error);
        const closing = stream
          ? cleanup(stream, requestSent ? 'cancel' : 'failure')
          : Promise.resolve();
        if (notify) void closing.then(() => observer.error(TRPCClientError.from(error)));
      }

      if (op.signal?.aborted) onSignalAbort();
      else op.signal?.addEventListener('abort', onSignalAbort, { once: true });
      void run();
      return () => {
        removeAbortListener();
        cancel(false);
      };
    });
}

function readPerCallHeaders(context: Record<string, unknown>): RpcHeaderInput | undefined {
  const namespace = context.p2prpc;
  if (namespace === undefined) return undefined;
  if (typeof namespace !== 'object' || namespace === null || !('headers' in namespace)) {
    throw new P2PError('INVALID_FRAME', 'tRPC p2prpc context must contain a headers field');
  }
  return (namespace as { headers: RpcHeaderInput }).headers;
}

function assertResponseId(value: unknown, expected: number): void {
  if (typeof value !== 'object' || value === null || !('id' in value) || value.id !== expected) {
    throw new P2PError('INVALID_FRAME', 'RPC completion ID does not match request');
  }
}

function readErrorMessage(shape: unknown): string {
  const message = typeof shape === 'object' && shape !== null && 'message' in shape && typeof shape.message === 'string'
    ? shape.message
    : 'Remote procedure failed';
  return sanitizeBoundedDisplayText(message, 8 * 1024, 'Remote procedure failed');
}

function resolveIoTimeout(value: number | undefined): number {
  const timeout = value ?? 30_000;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 10 * 60_000) {
    throw new P2PError('RESOURCE_LIMIT', 'RPC I/O timeout must be between 1 and 600000 milliseconds');
  }
  return timeout;
}

async function withDeadline<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
  controller: AbortController
): Promise<T> {
  controller.signal.throwIfAborted();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let removeAbortListener: (() => void) | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          const error = new P2PError('TIMEOUT', message);
          controller.abort(error);
          reject(error);
        }, timeoutMs);
        timer.unref?.();
      }),
      new Promise<never>((_, reject) => {
        const onAbort = (): void => reject(
          controller.signal.reason ?? new P2PError('CANCELLED', 'RPC cancelled')
        );
        controller.signal.addEventListener('abort', onAbort, { once: true });
        removeAbortListener = () => controller.signal.removeEventListener('abort', onAbort);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
    removeAbortListener?.();
  }
}

async function cleanupRpcStream(
  stream: Awaited<ReturnType<QuicConnection['openBi']>>,
  mode: 'cancel' | 'failure' | 'terminal',
  requestId: number | undefined,
  frameLimits: FrameLimits,
  timeoutMs: number
): Promise<void> {
  const stopTask = cleanupOperation(() => stream.recv.stop(mode === 'terminal' ? 0n : 2n), timeoutMs);
  if (mode === 'terminal') {
    const finished = await cleanupOperation(() => stream.send.finish(), timeoutMs);
    if (!finished) await cleanupOperation(() => stream.send.reset(2n), timeoutMs);
  } else {
    if (mode === 'cancel' && requestId !== undefined) {
      let cancelWritable = true;
      const guardedSend = {
        writeAll: async (data: Uint8Array): Promise<void> => {
          if (!cancelWritable) throw new P2PError('CANCELLED', 'RPC cancellation write stopped');
          await stream.send.writeAll(data);
          if (!cancelWritable) throw new P2PError('CANCELLED', 'RPC cancellation write stopped');
        },
        finish: () => stream.send.finish(),
        reset: (code: bigint) => stream.send.reset(code),
        setPriority: (priority: number) => stream.send.setPriority(priority)
      };
      await cleanupOperation(
        () => writeFrame(guardedSend, RpcFrameKind.Cancel, { id: requestId }, frameLimits),
        timeoutMs
      );
      cancelWritable = false;
    }
    await cleanupOperation(() => stream.send.reset(2n), timeoutMs);
  }
  await stopTask;
}

async function cleanupOperation(operation: () => Promise<unknown>, timeoutMs: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const task = Promise.resolve().then(operation).then(() => true, () => false);
    return await Promise.race([
      task,
      new Promise<false>((resolve) => {
        timer = setTimeout(() => resolve(false), timeoutMs);
        timer.unref?.();
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
