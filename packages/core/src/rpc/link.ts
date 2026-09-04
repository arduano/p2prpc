import { TRPCClientError, type TRPCLink } from '@trpc/client';
import type { AnyTRPCRouter } from '@trpc/server';
import { observable } from '@trpc/server/observable';
import { TRPC_ERROR_CODES_BY_KEY } from '@trpc/server/rpc';
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
import { exactRecord } from '../wire-schema.js';
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
      let requestWriteStarted = false;
      let requestSent = false;
      let stream: Awaited<ReturnType<QuicConnection['openBi']>> | undefined;
      let physicalConnection: QuicConnection | undefined;
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
        ).then((cleaned) => {
          if (!cleaned) {
            requestConnectionClose(physicalConnection, 'RPC stream cleanup failed');
          }
        });
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
          const connection = await io(options.connection, 'RPC connection acquisition timed out');
          physicalConnection = connection;
          ensureActive();
          let openingSettled = false;
          const opening = Promise.resolve().then(() => {
            ensureActive();
            return connection.openBi({ signal: controller.signal });
          }).then(
            (opened) => {
              openingSettled = true;
              return opened;
            },
            (cause: unknown) => {
              openingSettled = true;
              throw cause;
            }
          );
          try {
            stream = await withDeadline(opening, ioTimeoutMs, 'RPC stream opening timed out', controller);
          } catch (cause) {
            // A native open which has not settled cannot be cancelled safely at
            // the JavaScript seam. Quarantine even custom/raw transports; a
            // ManagedConnection additionally retains its admission lease until
            // native rejection, terminal late-stream cleanup, or physical close.
            if (!openingSettled) requestConnectionClose(connection, 'RPC stream opening was cancelled');
            void opening.then(
              async (lateStream) => {
                const cleaned = await cleanupRpcStream(
                  lateStream,
                  'failure',
                  undefined,
                  options.frameLimits ?? DEFAULT_FRAME_LIMITS,
                  cleanupTimeoutMs
                );
                if (!cleaned) {
                  requestConnectionClose(connection, 'Late RPC stream cleanup failed');
                }
              },
              () => undefined
            );
            throw cause;
          }
          ensureActive();
          // The admitted stream owns the potentially frame-sized serialized
          // input, so concurrent local calls cannot allocate those buffers
          // outside maxBufferedBytes accounting.
          const input = serializeValue(op.input, options.frameLimits ?? DEFAULT_FRAME_LIMITS);
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
          requestWriteStarted = true;
          await io(
            () => writeFrame(guardedSend, RpcFrameKind.Request, request, options.frameLimits ?? DEFAULT_FRAME_LIMITS),
            'RPC request write timed out'
          );
          requestSent = true;
          ensureActive();
          // Match tRPC's subscription lifecycle contract.  In particular,
          // consumers need a positive boundary at which an unsubscribe can no
          // longer race a still-pending native stream open.  Emitting started
          // only after the complete request is on the wire makes that boundary
          // useful without claiming that the remote procedure has produced an
          // item yet.
          if (op.type === 'subscription') {
            observer.next({ result: { type: 'started' } });
          }

          // Application response liveness belongs to the caller's AbortSignal.
          // A fixed transport timer would make a healthy long-running query or
          // subscription fail for reasons unrelated to its API contract.
          while (active) {
            const frame = await withAbortOnly(
              readFrame<RpcData | RpcFailure>(
                stream!.recv,
                options.frameLimits ?? DEFAULT_FRAME_LIMITS
              ),
              controller.signal
            );
            ensureActive();
            if (frame.kind === RpcFrameKind.Data) {
              exactRecord(frame.value, ['id', 'data'], 'RPC data response');
              const data = frame.value as RpcData;
              if (data.id !== op.id) throw new P2PError('INVALID_FRAME', 'RPC response ID does not match request');
              const value = deserializeValue(data.data, options.frameLimits ?? DEFAULT_FRAME_LIMITS);
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
              exactRecord(frame.value, ['id', 'shape'], 'RPC error response');
              const failure = frame.value as RpcFailure;
              if (failure.id !== op.id) throw new P2PError('INVALID_FRAME', 'RPC error ID does not match request');
              const shape = normalizeErrorShape(failure.shape, op.path);
              await io(() => stream!.recv.expectEnd(), 'RPC response finish timed out');
              active = false;
              removeAbortListener();
              await cleanup(stream, 'terminal');
              observer.error(new TRPCClientError(shape.message, { result: { error: shape as never } }));
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
          const error = requestWriteStarted
            ? new P2PError('OUTCOME_UNKNOWN', 'RPC ended after dispatch without a terminal response', { cause })
            : asP2PError(cause, 'DISCONNECTED');
          if (notify) observer.error(TRPCClientError.from(error));
        }
      };

      function onSignalAbort(): void {
        cancel(true);
      }

      function cancel(notify: boolean): void {
        if (!active) return;
        active = false;
        removeAbortListener();
        const error = requestWriteStarted
          ? new P2PError('OUTCOME_UNKNOWN', 'RPC was cancelled after dispatch; the remote outcome is unknown')
          : new P2PError('CANCELLED', 'RPC cancelled before dispatch');
        controller.abort(error);
        const closing = stream
          ? cleanup(stream, requestSent ? 'cancel' : 'failure')
          : Promise.resolve();
        if (notify) {
          void closing.then(
            () => observer.error(TRPCClientError.from(error)),
            () => observer.error(TRPCClientError.from(error))
          );
        }
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
  exactRecord(value, ['id'], 'RPC completion');
  if (value.id !== expected) {
    throw new P2PError('INVALID_FRAME', 'RPC completion ID does not match request');
  }
}

function normalizeErrorShape(shape: unknown, expectedPath: string): Readonly<{
  code: number;
  message: string;
  data: Readonly<{ code: string; httpStatus: number; path: string }>;
}> {
  exactRecord(shape, ['code', 'message', 'data'], 'RPC error shape');
  exactRecord(shape.data, ['code', 'httpStatus', 'path'], 'RPC error data');
  if (typeof shape.code !== 'number' || !Number.isSafeInteger(shape.code)) {
    throw new P2PError('INVALID_FRAME', 'RPC error code must be a safe integer');
  }
  if (typeof shape.message !== 'string') {
    throw new P2PError('INVALID_FRAME', 'RPC error message must be a string');
  }
  if (typeof shape.data.code !== 'string' || !Object.hasOwn(TRPC_ERROR_CODES_BY_KEY, shape.data.code)) {
    throw new P2PError('INVALID_FRAME', 'RPC error data code is invalid');
  }
  const errorCode = shape.data.code as keyof typeof TRPC_ERROR_CODES_BY_KEY;
  if (shape.code !== TRPC_ERROR_CODES_BY_KEY[errorCode]) {
    throw new P2PError('INVALID_FRAME', 'RPC error codes are inconsistent');
  }
  if (
    typeof shape.data.httpStatus !== 'number' ||
    !Number.isSafeInteger(shape.data.httpStatus) ||
    shape.data.httpStatus < 100 ||
    shape.data.httpStatus > 599
  ) {
    throw new P2PError('INVALID_FRAME', 'RPC error HTTP status is invalid');
  }
  if (
    typeof shape.data.path !== 'string' ||
    shape.data.path !== expectedPath
  ) {
    throw new P2PError('INVALID_FRAME', 'RPC error path does not match request');
  }
  const data = Object.freeze({
    code: shape.data.code,
    httpStatus: shape.data.httpStatus,
    path: shape.data.path
  });
  return Object.freeze({
    code: shape.code,
    message: sanitizeBoundedDisplayText(shape.message, 8 * 1024, 'Remote procedure failed'),
    data
  });
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

async function withAbortOnly<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  let removeAbortListener: (() => void) | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        const onAbort = (): void => reject(signal.reason ?? new P2PError('CANCELLED', 'RPC cancelled'));
        signal.addEventListener('abort', onAbort, { once: true });
        removeAbortListener = () => signal.removeEventListener('abort', onAbort);
      })
    ]);
  } finally {
    removeAbortListener?.();
  }
}

async function cleanupRpcStream(
  stream: Awaited<ReturnType<QuicConnection['openBi']>>,
  mode: 'cancel' | 'failure' | 'terminal',
  requestId: number | undefined,
  frameLimits: FrameLimits,
  timeoutMs: number
): Promise<boolean> {
  const stopTask = cleanupOperation(() => stream.recv.stop(mode === 'terminal' ? 0n : 2n), timeoutMs);
  let sendSettled: boolean;
  if (mode === 'terminal') {
    const finished = await cleanupOperation(() => stream.send.finish(), timeoutMs);
    sendSettled = finished || await cleanupOperation(() => stream.send.reset(2n), timeoutMs);
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
    sendSettled = await cleanupOperation(() => stream.send.reset(2n), timeoutMs);
  }
  const receiveSettled = await stopTask;
  return sendSettled && receiveSettled;
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

/** A quarantine request must never replace the RPC outcome which required it. */
function requestConnectionClose(connection: QuicConnection | undefined, reason: string): void {
  if (!connection) return;
  try {
    connection.close(4n, new TextEncoder().encode(reason));
  } catch {
    // The owning runtime retains the physical closed() barrier.
  }
}
