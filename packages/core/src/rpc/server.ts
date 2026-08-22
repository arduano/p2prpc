import type { AnyTRPCRouter, inferRouterContext } from '@trpc/server';
import { TRPCError, callTRPCProcedure, getTRPCErrorFromUnknown } from '@trpc/server';
import { getHTTPStatusCodeFromError } from '@trpc/server/http';
import { TRPC_ERROR_CODES_BY_KEY } from '@trpc/server/rpc';
import { P2PError, asP2PError } from '../errors.js';
import { containsUnsafeDisplayCharacters, sanitizeBoundedDisplayText } from '../text.js';
import {
  DEFAULT_FRAME_LIMITS,
  RpcFrameKind,
  readFrame,
  writeFrame,
  type FrameLimits
} from '../protocol.js';
import type { QuicBiStream } from '../transport/types.js';
import { normalizeRpcHeaders, type RpcHeaderLimits, type RpcHeaders } from './headers.js';
import {
  deserializeValue,
  isAsyncIterable,
  serializeValue,
  type RpcFailure,
  type RpcRequest
} from './wire.js';

export interface RpcServerOptions<TRouter extends AnyTRPCRouter> {
  readonly router: TRouter;
  readonly createContext: (request: RpcServerRequest) => Promise<inferRouterContext<TRouter>> | inferRouterContext<TRouter>;
  readonly authorize: (request: RpcRequest, signal: AbortSignal) => Promise<void> | void;
  readonly frameLimits?: FrameLimits;
  readonly headerLimits: RpcHeaderLimits;
  readonly maxPathBytes: number;
  readonly setupTimeoutMs: number;
  /** Aborts every request on the authenticated physical session when it is replaced or closed. */
  readonly sessionSignal?: AbortSignal;
  /** Per QUIC read/write/finish deadline. Defaults to setupTimeoutMs. */
  readonly ioTimeoutMs?: number;
  readonly onError?: (error: Error, request?: RpcRequest) => void;
}

export interface RpcServerRequest {
  readonly id: number;
  readonly path: string;
  readonly type: RpcRequest['type'];
  readonly headers: RpcHeaders;
  readonly signal: AbortSignal;
}

export class RpcServer<TRouter extends AnyTRPCRouter> {
  private readonly ioTimeoutMs: number;

  constructor(private readonly options: RpcServerOptions<TRouter>) {
    validateTimeout(options.setupTimeoutMs, 'RPC setup timeout');
    this.ioTimeoutMs = options.ioTimeoutMs ?? options.setupTimeoutMs;
    validateTimeout(this.ioTimeoutMs, 'RPC I/O timeout');
  }

  async handle(stream: QuicBiStream): Promise<void> {
    let request: RpcRequest | undefined;
    let context: inferRouterContext<TRouter> | undefined;
    const controller = new AbortController();
    let cancelTask: Promise<void> | undefined;
    let terminal = false;
    let sendFinished = false;
    const requestSignal = this.options.sessionSignal
      ? AbortSignal.any([controller.signal, this.options.sessionSignal])
      : controller.signal;

    try {
      requestSignal.throwIfAborted();
      await this.ioOperation(stream.send.setPriority(100), 'RPC stream priority timed out', controller, requestSignal);
      const first = await this.ioOperation(
        readFrame<RpcRequest>(stream.recv, this.options.frameLimits ?? DEFAULT_FRAME_LIMITS),
        'RPC request frame timed out',
        controller,
        requestSignal,
        this.options.setupTimeoutMs
      );
      if (first.kind !== RpcFrameKind.Request) throw new Error('RPC stream must begin with a request frame');
      request = validateRequest(first.value, this.options.headerLimits, this.options.maxPathBytes);
      const currentRequest = request;
      cancelTask = (async () => {
        try {
          const frame = await readFrame(stream.recv, this.options.frameLimits ?? DEFAULT_FRAME_LIMITS);
          if (terminal) return;
          if (frame.kind !== RpcFrameKind.Cancel || !hasRequestId(frame.value, currentRequest.id)) {
            throw new P2PError('INVALID_FRAME', 'Invalid RPC cancellation frame');
          }
          controller.abort(new P2PError('CANCELLED', 'Remote cancelled RPC'));
        } catch (cause) {
          if (!terminal && !requestSignal.aborted) controller.abort(asP2PError(cause, 'DISCONNECTED'));
        }
      })();

      await withDeadline(
        Promise.resolve(this.options.authorize(currentRequest, requestSignal)),
        this.options.setupTimeoutMs,
        'RPC authorization timed out',
        controller,
        requestSignal
      );
      context = await withDeadline(Promise.resolve(this.options.createContext(Object.freeze({
        id: currentRequest.id,
        path: currentRequest.path,
        type: currentRequest.type,
        headers: currentRequest.headers,
        signal: requestSignal
      }))), this.options.setupTimeoutMs, 'RPC context creation timed out', controller, requestSignal);

      const result = await withAbort(callTRPCProcedure({
        router: this.options.router,
        path: currentRequest.path,
        type: currentRequest.type,
        ctx: context,
        batchIndex: 0,
        signal: requestSignal,
        getRawInput: async () => deserializeValue(currentRequest.input)
      }), requestSignal);

      if (isAsyncIterable(result)) {
        const iterator = result[Symbol.asyncIterator]();
        try {
          while (true) {
            const item = await withAbort(Promise.resolve(iterator.next()), requestSignal);
            if (item.done) break;
            await this.ioOperation(writeFrame(stream.send, RpcFrameKind.Data, {
              id: currentRequest.id,
              data: serializeValue(item.value)
            }, this.options.frameLimits ?? DEFAULT_FRAME_LIMITS), 'RPC response write timed out', controller, requestSignal);
          }
        } finally {
          if (requestSignal.aborted && iterator.return) {
            void settleWithin(Promise.resolve().then(() => iterator.return!()), cleanupTimeout(this.ioTimeoutMs));
          }
        }
      } else {
        requestSignal.throwIfAborted();
        await this.ioOperation(writeFrame(stream.send, RpcFrameKind.Data, {
          id: currentRequest.id,
          data: serializeValue(result)
        }, this.options.frameLimits ?? DEFAULT_FRAME_LIMITS), 'RPC response write timed out', controller, requestSignal);
      }

      requestSignal.throwIfAborted();
      terminal = true;
      await this.ioOperation(writeFrame(
        stream.send,
        RpcFrameKind.Complete,
        { id: currentRequest.id },
        this.options.frameLimits ?? DEFAULT_FRAME_LIMITS
      ), 'RPC completion write timed out', controller, requestSignal);
      await this.ioOperation(stream.send.finish(), 'RPC response finish timed out', controller, requestSignal);
      sendFinished = true;
    } catch (cause) {
      terminal = true;
      const error = cause instanceof P2PError && cause.code === 'UNAUTHORIZED'
        ? new TRPCError({ code: 'FORBIDDEN', message: 'Operation is not authorized' })
        : getTRPCErrorFromUnknown(cause);
      // Derive the wire response before notifying diagnostics. Observability
      // callbacks must not be able to mutate an error or request into a leak.
      const shape = request ? safeErrorShape(error, request.path) : undefined;
      try {
        const delivered = this.options.onError?.(error, request);
        void Promise.resolve(delivered).catch(() => undefined);
      } catch {
        // Observability failures cannot affect protocol state.
      }
      if (request && !requestSignal.aborted) {
        const failure: RpcFailure = { id: request.id, shape };
        try {
          await this.ioOperation(writeFrame(
            stream.send,
            RpcFrameKind.Error,
            failure,
            this.options.frameLimits ?? DEFAULT_FRAME_LIMITS
          ), 'RPC error write timed out', controller, requestSignal);
          await this.ioOperation(stream.send.finish(), 'RPC error finish timed out', controller, requestSignal);
          sendFinished = true;
        } catch (writeCause) {
          throw asP2PError(writeCause, 'DISCONNECTED');
        }
      }
    } finally {
      terminal = true;
      if (!controller.signal.aborted) controller.abort(new P2PError('CANCELLED', 'RPC stream completed'));
      const timeoutMs = cleanupTimeout(this.ioTimeoutMs);
      const cleanup: Promise<unknown>[] = [
        settleWithin(Promise.resolve().then(() => stream.recv.stop(sendFinished ? 0n : 1n)), timeoutMs)
      ];
      if (!sendFinished) {
        cleanup.push(settleWithin(Promise.resolve().then(() => stream.send.reset(1n)), timeoutMs));
      }
      // stop() owns cancellation of the pending read. The watcher already has
      // a terminal catch path, so it cannot surface an unhandled rejection.
      void cancelTask;
      await Promise.all(cleanup);
    }
  }

  private async ioOperation<T>(
    promise: Promise<T>,
    message: string,
    controller: AbortController,
    signal: AbortSignal = controller.signal,
    timeoutMs = this.ioTimeoutMs
  ): Promise<T> {
    return withDeadline(promise, timeoutMs, message, controller, signal);
  }
}

function validateRequest(value: RpcRequest, headerLimits: RpcHeaderLimits, maxPathBytes: number): RpcRequest {
  if (
    !value ||
    typeof value !== 'object' ||
    !Number.isSafeInteger(value.id) ||
    value.id < 0 ||
    typeof value.path !== 'string' ||
    value.path.length < 1 ||
    Buffer.byteLength(value.path) > maxPathBytes ||
    hasPathControlOrSpace(value.path) ||
    !['query', 'mutation', 'subscription'].includes(value.type) ||
    !Object.hasOwn(value, 'headers')
  ) {
    throw new Error('Invalid RPC request');
  }
  return Object.freeze({
    id: value.id,
    path: value.path,
    type: value.type,
    headers: normalizeRpcHeaders(value.headers, headerLimits),
    input: value.input
  });
}

function hasPathControlOrSpace(value: string): boolean {
  return containsUnsafeDisplayCharacters(value) || value.includes(' ');
}

function hasRequestId(value: unknown, expected: number): boolean {
  return typeof value === 'object' && value !== null && 'id' in value && value.id === expected;
}

async function withDeadline<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
  controller?: AbortController,
  signal: AbortSignal | undefined = controller?.signal
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let removeAbortListener: (() => void) | undefined;
  try {
    const tasks: Array<Promise<T>> = [
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          const error = new P2PError('TIMEOUT', message);
          controller?.abort(error);
          reject(error);
        }, timeoutMs);
        timer.unref?.();
      })
    ];
    if (signal) {
      tasks.push(new Promise<never>((_, reject) => {
        const onAbort = (): void => reject(signal.reason ?? new P2PError('CANCELLED', 'RPC setup cancelled'));
        if (signal.aborted) onAbort();
        else {
          signal.addEventListener('abort', onAbort, { once: true });
          removeAbortListener = () => signal.removeEventListener('abort', onAbort);
        }
      }));
    }
    return await Promise.race(tasks);
  } finally {
    if (timer) clearTimeout(timer);
    removeAbortListener?.();
  }
}

async function withAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  let removeAbortListener: (() => void) | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        const onAbort = (): void => reject(signal.reason ?? new P2PError('CANCELLED', 'RPC cancelled'));
        if (signal.aborted) onAbort();
        else {
          signal.addEventListener('abort', onAbort, { once: true });
          removeAbortListener = () => signal.removeEventListener('abort', onAbort);
        }
      })
    ]);
  } finally {
    removeAbortListener?.();
  }
}

async function settleWithin(promise: Promise<unknown>, timeoutMs: number): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      promise.catch(() => undefined),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, timeoutMs);
        timer.unref?.();
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function cleanupTimeout(ioTimeoutMs: number): number {
  return Math.min(ioTimeoutMs, 1_000);
}

function validateTimeout(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 10 * 60_000) {
    throw new P2PError('RESOURCE_LIMIT', `${label} must be between 1 ms and 10 minutes`);
  }
}

export function safeErrorShape(error: TRPCError, path: string): unknown {
  const code = trustedErrorCode(error.code);
  return {
    code: TRPC_ERROR_CODES_BY_KEY[code],
    message: code === 'INTERNAL_SERVER_ERROR'
      ? 'Internal server error'
      : sanitizePublicErrorMessage(error.message),
    data: {
      code,
      httpStatus: getHTTPStatusCodeFromError(new TRPCError({ code })),
      path
    }
  };
}

function trustedErrorCode(value: unknown): keyof typeof TRPC_ERROR_CODES_BY_KEY {
  return typeof value === 'string' && Object.hasOwn(TRPC_ERROR_CODES_BY_KEY, value)
    ? value as keyof typeof TRPC_ERROR_CODES_BY_KEY
    : 'INTERNAL_SERVER_ERROR';
}

function sanitizePublicErrorMessage(value: string): string {
  return sanitizeBoundedDisplayText(value, 8 * 1024, 'Remote procedure failed');
}
