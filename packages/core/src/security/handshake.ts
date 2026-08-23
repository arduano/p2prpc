import { createHash, randomBytes } from 'node:crypto';
import { P2PError, asP2PError } from '../errors.js';
import {
  SessionFrameKind,
  StreamKind,
  readFrame,
  readStreamKind,
  writeFrame,
  writeStreamKind,
  type FrameLimits
} from '../protocol.js';
import type { QuicConnection, QuicRecvStream } from '../transport/types.js';
import {
  freezePrincipal,
  type AuthenticatedSession,
  type SessionAuthenticationContext,
  type SessionCredential,
  type SessionSecurity
} from './types.js';

interface ClientHello {
  readonly version: 2;
  readonly protocol: string;
  readonly nonce: string;
  readonly presentedAt: number;
  readonly credential: SessionCredential;
}

interface ServerHello extends ClientHello {
  readonly echo: string;
  readonly grantExpiresAt: number;
}

interface ClientAck {
  readonly echo: string;
  readonly sessionId: string;
  readonly grantExpiresAt: number;
}

interface ServerReady {
  readonly sessionId: string;
  readonly expiresAt: number;
}

export interface SessionHandshakeOptions<TFileMetadata = unknown> {
  readonly localPeerId: string;
  readonly protocol: string;
  readonly security: SessionSecurity<TFileMetadata>;
  readonly timeoutMs: number;
  readonly maxSessionTtlMs: number;
  readonly clockSkewMs: number;
  readonly frameLimits: FrameLimits;
}

interface HandshakeCleanupState {
  current?: Promise<void>;
}

export async function authenticateConnection<TFileMetadata>(
  connection: QuicConnection,
  direction: 'inbound' | 'outbound',
  options: SessionHandshakeOptions<TFileMetadata>
): Promise<AuthenticatedSession> {
  const controller = new AbortController();
  const cleanup: HandshakeCleanupState = {};
  const task = connection.side === 'client'
    ? authenticateInitiator(connection, direction, options, controller.signal, cleanup)
    : authenticateResponder(connection, direction, options, controller.signal, cleanup);
  return withTimeout(task, options.timeoutMs, 'Session authentication timed out', controller);
}

async function authenticateInitiator<TFileMetadata>(
  connection: QuicConnection,
  direction: 'inbound' | 'outbound',
  options: SessionHandshakeOptions<TFileMetadata>,
  signal: AbortSignal,
  cleanup: HandshakeCleanupState
): Promise<AuthenticatedSession> {
  const startedAt = Date.now();
  const initiatorNonce = nonce();
  const credential = canonicalCredential(await options.security.getCredential(Object.freeze({
    localPeerId: options.localPeerId,
    remotePeerId: connection.remoteId,
    direction,
    protocol: options.protocol,
    nonce: initiatorNonce,
    signal
  })));
  signal.throwIfAborted();
  const stream = await connection.openBi();
  const abortStream = async (): Promise<void> => {
    cleanup.current ??= abortHandshakeStream(stream);
    await cleanup.current;
  };
  const onAbort = (): void => { void abortStream(); };
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    signal.throwIfAborted();
    await stream.send.setPriority(1_000);
    signal.throwIfAborted();
    await writeStreamKind(stream.send, StreamKind.SessionAuth);
    signal.throwIfAborted();
    await writeFrame(stream.send, SessionFrameKind.ClientHello, {
      version: 2,
      protocol: options.protocol,
      nonce: initiatorNonce,
      presentedAt: Date.now(),
      credential
    } satisfies ClientHello, options.frameLimits);
    signal.throwIfAborted();

    const frame = await readFrame<ServerHello>(stream.recv, options.frameLimits);
    signal.throwIfAborted();
    if (frame.kind !== SessionFrameKind.ServerHello) throw new P2PError('UNAUTHORIZED', 'Expected session server hello');
    const hello = validateServerHello(frame.value, initiatorNonce, options);
    const authenticationContext = transcriptContext(
      options,
      connection,
      direction,
      options.localPeerId,
      connection.remoteId,
      initiatorNonce,
      hello.nonce,
      hello.presentedAt,
      signal
    );
    const principal = freezePrincipal(await options.security.authenticate(hello.credential, authenticationContext));
    signal.throwIfAborted();
    validatePrincipalExpiry(principal.expiresAt);
    const id = sessionId(authenticationContext);
    const credentialExpiresAt = Math.min(principal.expiresAt, hello.grantExpiresAt);
    await writeFrame(stream.send, SessionFrameKind.ClientAck, {
      echo: hello.nonce,
      sessionId: id,
      grantExpiresAt: principal.expiresAt
    } satisfies ClientAck, options.frameLimits);
    signal.throwIfAborted();
    // ClientAck is the initiator's final message. Its FIN allows the responder
    // to reject trailing handshake bytes before granting the session.
    await stream.send.finish();
    signal.throwIfAborted();
    const readyFrame = await readFrame<ServerReady>(stream.recv, options.frameLimits);
    signal.throwIfAborted();
    if (readyFrame.kind !== SessionFrameKind.ServerReady) throw new P2PError('UNAUTHORIZED', 'Expected session ready frame');
    const ready = readyFrame.value;
    if (
      !isRecord(ready) ||
      ready.sessionId !== id ||
      typeof ready.expiresAt !== 'number' ||
      !Number.isSafeInteger(ready.expiresAt) ||
      ready.expiresAt <= Date.now() ||
      ready.expiresAt > credentialExpiresAt ||
      ready.expiresAt > Date.now() + options.maxSessionTtlMs + options.clockSkewMs
    ) {
      throw new P2PError('UNAUTHORIZED', 'Session confirmation did not match the authenticated transcript');
    }
    await expectRecvEnd(stream.recv);
    signal.throwIfAborted();
    return Object.freeze({ id, establishedAt: startedAt, expiresAt: ready.expiresAt, principal });
  } catch (cause) {
    // The node closes the physical connection after rejection. Do not let a
    // wedged native reset/stop extend the externally visible deadline.
    void abortStream();
    throw cause;
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

async function authenticateResponder<TFileMetadata>(
  connection: QuicConnection,
  direction: 'inbound' | 'outbound',
  options: SessionHandshakeOptions<TFileMetadata>,
  signal: AbortSignal,
  cleanup: HandshakeCleanupState
): Promise<AuthenticatedSession> {
  const startedAt = Date.now();
  const stream = await connection.acceptBi();
  const abortStream = async (): Promise<void> => {
    cleanup.current ??= abortHandshakeStream(stream);
    await cleanup.current;
  };
  const onAbort = (): void => { void abortStream(); };
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    signal.throwIfAborted();
    if ((await readStreamKind(stream.recv)) !== StreamKind.SessionAuth) {
      throw new P2PError('UNAUTHORIZED', 'Application authentication is required before opening streams');
    }
    signal.throwIfAborted();
    const frame = await readFrame<ClientHello>(stream.recv, options.frameLimits);
    signal.throwIfAborted();
    if (frame.kind !== SessionFrameKind.ClientHello) throw new P2PError('UNAUTHORIZED', 'Expected session client hello');
    const hello = validateClientHello(frame.value, options);
    const responderNonce = nonce();
    const authenticationContext = transcriptContext(
      options,
      connection,
      direction,
      connection.remoteId,
      options.localPeerId,
      hello.nonce,
      responderNonce,
      hello.presentedAt,
      signal
    );
    const principal = freezePrincipal(await options.security.authenticate(hello.credential, authenticationContext));
    signal.throwIfAborted();
    validatePrincipalExpiry(principal.expiresAt);
    const credential = canonicalCredential(await options.security.getCredential(Object.freeze({
      localPeerId: options.localPeerId,
      remotePeerId: connection.remoteId,
      direction,
      protocol: options.protocol,
      nonce: responderNonce,
      signal
    })));
    signal.throwIfAborted();
    await stream.send.setPriority(1_000);
    signal.throwIfAborted();
    await writeFrame(stream.send, SessionFrameKind.ServerHello, {
      version: 2,
      protocol: options.protocol,
      nonce: responderNonce,
      echo: hello.nonce,
      presentedAt: Date.now(),
      credential,
      grantExpiresAt: principal.expiresAt
    } satisfies ServerHello, options.frameLimits);
    signal.throwIfAborted();
    const ackFrame = await readFrame<ClientAck>(stream.recv, options.frameLimits);
    signal.throwIfAborted();
    if (ackFrame.kind !== SessionFrameKind.ClientAck) throw new P2PError('UNAUTHORIZED', 'Expected session acknowledgement');
    const ack = ackFrame.value;
    const id = sessionId(authenticationContext);
    if (
      !isRecord(ack) ||
      ack.echo !== responderNonce ||
      ack.sessionId !== id ||
      !Number.isSafeInteger(ack.grantExpiresAt)
    ) {
      throw new P2PError('UNAUTHORIZED', 'Invalid session acknowledgement');
    }
    await expectRecvEnd(stream.recv);
    signal.throwIfAborted();
    const expiresAt = capExpiry(Math.min(principal.expiresAt, ack.grantExpiresAt), options.maxSessionTtlMs);
    await writeFrame(
      stream.send,
      SessionFrameKind.ServerReady,
      { sessionId: id, expiresAt } satisfies ServerReady,
      options.frameLimits
    );
    signal.throwIfAborted();
    await stream.send.finish();
    return Object.freeze({ id, establishedAt: startedAt, expiresAt, principal });
  } catch (cause) {
    // The node closes the physical connection after rejection. Do not let a
    // wedged native reset/stop extend the externally visible deadline.
    void abortStream();
    throw cause;
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

async function abortHandshakeStream(stream: Awaited<ReturnType<QuicConnection['openBi']>>): Promise<void> {
  await Promise.allSettled([
    Promise.resolve().then(() => stream.send.reset(2n)),
    Promise.resolve().then(() => stream.recv.stop(2n))
  ]);
}

function validateClientHello<TFileMetadata>(value: unknown, options: SessionHandshakeOptions<TFileMetadata>): ClientHello {
  if (!isRecord(value) || value.version !== 2 || value.protocol !== options.protocol) {
    throw new P2PError('INCOMPATIBLE_PROTOCOL', 'Peer uses a different p2prpc application contract');
  }
  if (!validNonce(value.nonce) || typeof value.presentedAt !== 'number' || !Number.isSafeInteger(value.presentedAt)) {
    throw new P2PError('UNAUTHORIZED', 'Invalid session hello');
  }
  if (Math.abs(Date.now() - value.presentedAt) > options.clockSkewMs) {
    throw new P2PError('UNAUTHORIZED', 'Session hello is stale');
  }
  const credential = canonicalCredential(value.credential);
  return Object.freeze({
    version: 2,
    protocol: options.protocol,
    nonce: value.nonce,
    presentedAt: value.presentedAt,
    credential
  });
}

function validateServerHello<TFileMetadata>(
  value: unknown,
  initiatorNonce: string,
  options: SessionHandshakeOptions<TFileMetadata>
): ServerHello {
  const hello = validateClientHello(value, options);
  if (!isRecord(value)) {
    throw new P2PError('UNAUTHORIZED', 'Server hello did not match the client challenge');
  }
  const grantExpiresAt = value.grantExpiresAt;
  if (
    value.echo !== initiatorNonce ||
    typeof grantExpiresAt !== 'number' ||
    !Number.isSafeInteger(grantExpiresAt)
  ) {
    throw new P2PError('UNAUTHORIZED', 'Server hello did not match the client challenge');
  }
  validatePrincipalExpiry(grantExpiresAt);
  return Object.freeze({
    ...hello,
    echo: value.echo,
    grantExpiresAt
  });
}

function transcriptContext<TFileMetadata>(
  options: SessionHandshakeOptions<TFileMetadata>,
  connection: QuicConnection,
  direction: 'inbound' | 'outbound',
  initiatorPeerId: string,
  responderPeerId: string,
  initiatorNonce: string,
  responderNonce: string,
  presentedAt: number,
  signal: AbortSignal
): SessionAuthenticationContext {
  return Object.freeze({
    localPeerId: options.localPeerId,
    remotePeerId: connection.remoteId,
    direction,
    protocol: options.protocol,
    initiatorPeerId,
    responderPeerId,
    initiatorNonce,
    responderNonce,
    presentedAt,
    signal
  });
}

function sessionId(context: SessionAuthenticationContext): string {
  return createHash('sha256')
    .update('p2prpc-session-v2\n')
    .update(context.protocol)
    .update('\n')
    .update(context.initiatorPeerId)
    .update('\n')
    .update(context.responderPeerId)
    .update('\n')
    .update(context.initiatorNonce)
    .update('\n')
    .update(context.responderNonce)
    .digest('base64url');
}

function validateCredential(value: unknown): asserts value is SessionCredential {
  if (
    !isRecord(value) ||
    typeof value.scheme !== 'string' ||
    !/^[A-Za-z][A-Za-z0-9+.-]{0,63}$/.test(value.scheme) ||
    typeof value.value !== 'string' ||
    value.value.length < 1 ||
    Buffer.byteLength(value.value) > 48 * 1024
  ) {
    throw new P2PError('UNAUTHORIZED', 'Invalid session credential');
  }
}

function canonicalCredential(value: unknown): SessionCredential {
  validateCredential(value);
  return Object.freeze({ scheme: value.scheme, value: value.value });
}

function validatePrincipalExpiry(expiresAt: number): void {
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now()) {
    throw new P2PError('UNAUTHORIZED', 'Session credential is expired');
  }
}

function capExpiry(expiresAt: number, maxTtlMs: number): number {
  const capped = Math.min(expiresAt, Date.now() + maxTtlMs);
  validatePrincipalExpiry(capped);
  return capped;
}

function nonce(): string {
  return randomBytes(32).toString('base64url');
}

function validNonce(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function expectRecvEnd(recv: QuicRecvStream): Promise<void> {
  return recv.expectEnd();
}

async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
  controller: AbortController
): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timeout = setTimeout(() => {
          const error = new P2PError('TIMEOUT', message);
          controller.abort(error);
          reject(error);
        }, timeoutMs);
        timeout.unref?.();
      })
    ]);
  } catch (cause) {
    const error = asP2PError(cause, 'UNAUTHORIZED');
    if (!controller.signal.aborted) controller.abort(error);
    if (error.code === 'DISCONNECTED') {
      throw new P2PError('UNAUTHORIZED', 'Peer closed before application authentication completed', { cause: error });
    }
    throw error;
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}
