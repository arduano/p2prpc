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
import type { QuicBiStream, QuicConnection, QuicRecvStream } from '../transport/types.js';
import { exactRecord } from '../wire-schema.js';
import {
  freezePrincipal,
  type AuthenticatedSession,
  type CredentialRequestContext,
  type SessionCredential,
  type SessionRole,
  type SessionSecurity
} from './types.js';

const HANDSHAKE_VERSION = 4 as const;
const MAX_CREDENTIAL_BYTES = 48 * 1024;
const sessionDeadlines = new WeakMap<AuthenticatedSession, number>();

/** Local monotonic time is never sent on the wire. A backwards clock change
 * cannot stretch a grant between preparation, publication and admission. */
export function sessionRemainingLifetime(session: AuthenticatedSession): number {
  return Math.min(session.expiresAt - Date.now(),
    (sessionDeadlines.get(session) ?? performance.now() + session.expiresAt - session.establishedAt) - performance.now());
}

function boundedSession(session: AuthenticatedSession, startedMonotonic: number): AuthenticatedSession {
  sessionDeadlines.set(session, startedMonotonic + session.expiresAt - session.establishedAt);
  return session;
}

interface ClientHello {
  readonly version: typeof HANDSHAKE_VERSION;
  readonly protocol: string;
  readonly nonce: string;
  readonly presentedAt: number;
  readonly maxSessionTtlMs: number;
  readonly generation: number;
  readonly previousSessionId: string | null;
}

interface ServerChallenge extends ClientHello {
  readonly echo: string;
}

interface ClientCredential {
  readonly credential: SessionCredential;
}

interface ServerCredential extends ClientCredential {
  readonly grantExpiresAt: number;
}

interface ClientFinished {
  readonly sessionId: string;
  readonly grantExpiresAt: number;
}

interface ServerFinished {
  readonly sessionId: string;
  readonly expiresAt: number;
}

interface ChallengeTranscript {
  readonly initiatorPeerId: string;
  readonly responderPeerId: string;
  readonly initiatorNonce: string;
  readonly responderNonce: string;
  readonly initiatorPresentedAt: number;
  readonly responderPresentedAt: number;
  readonly generation: number;
  readonly previousSessionId: string | null;
  readonly hash: string;
}

export interface SessionHandshakeOptions<TFileMetadata = unknown> {
  readonly localPeerId: string;
  readonly protocol: string;
  readonly security: SessionSecurity<TFileMetadata>;
  readonly timeoutMs: number;
  readonly maxSessionTtlMs: number;
  readonly clockSkewMs: number;
  readonly frameLimits: FrameLimits;
  /** Renewal stays on the authenticated physical connection; only its client initiates. */
  readonly previousSession?: AuthenticatedSession;
  /** An already discriminated inbound renewal stream. */
  readonly stream?: QuicBiStream;
  readonly signal?: AbortSignal;
  /** Reauthorize active work before either side publishes the candidate. */
  readonly prepareSession?: (session: AuthenticatedSession, signal: AbortSignal) => Promise<void>;
  /** Retains admission ownership if a timeout wins before handshake work settles. */
  readonly trackWork?: (work: Promise<unknown>) => void;
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
  const abort = (): void => controller.abort(options.signal?.reason);
  if (options.signal?.aborted) abort();
  else options.signal?.addEventListener('abort', abort, { once: true });
  const task = connection.side === 'client'
    ? authenticateInitiator(connection, direction, options, controller.signal, cleanup)
    : authenticateResponder(connection, direction, options, controller.signal, cleanup);
  options.trackWork?.(task);
  try {
    return await withTimeout(task, options.timeoutMs, 'Session authentication timed out', controller);
  } finally {
    options.signal?.removeEventListener('abort', abort);
  }
}

async function authenticateInitiator<TFileMetadata>(
  connection: QuicConnection,
  direction: 'inbound' | 'outbound',
  options: SessionHandshakeOptions<TFileMetadata>,
  signal: AbortSignal,
  cleanup: HandshakeCleanupState
): Promise<AuthenticatedSession> {
  const startedAt = Date.now();
  const startedMonotonic = performance.now();
  const hello: ClientHello = Object.freeze({
    version: HANDSHAKE_VERSION,
    protocol: options.protocol,
    nonce: nonce(),
    presentedAt: Date.now(),
    maxSessionTtlMs: options.maxSessionTtlMs,
    generation: (options.previousSession?.generation ?? -1) + 1,
    previousSessionId: options.previousSession?.id ?? null
  });
  const stream = await connection.openBi({ signal });
  const abortStream = (): Promise<void> => {
    if (!cleanup.current) {
      cleanup.current = abortHandshakeStream(connection, stream);
      options.trackWork?.(cleanup.current);
    }
    return cleanup.current;
  };
  const onAbort = (): void => { void abortStream().catch(() => undefined); };
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    signal.throwIfAborted();
    await writeStreamKind(stream.send, StreamKind.SessionAuth);
    signal.throwIfAborted();
    await writeFrame(stream.send, SessionFrameKind.ClientHello, hello, options.frameLimits);
    signal.throwIfAborted();

    const challengeFrame = await readFrame<unknown>(stream.recv, options.frameLimits);
    signal.throwIfAborted();
    if (challengeFrame.kind !== SessionFrameKind.ServerChallenge) {
      throw new P2PError('UNAUTHORIZED', 'Expected session server challenge');
    }
    const challenge = validateServerChallenge(challengeFrame.value, hello.nonce, options);
    const transcript = challengeTranscript(
      options.protocol,
      options.localPeerId,
      connection.remoteId,
      hello,
      challenge
    );

    const initiatorContext = securityContext(
      options,
      connection,
      direction,
      'initiator',
      transcript,
      transcript.hash,
      signal
    );
    const credential = canonicalOutboundCredential(await options.security.getCredential(initiatorContext));
    signal.throwIfAborted();
    await writeFrame(
      stream.send,
      SessionFrameKind.ClientCredential,
      { credential } satisfies ClientCredential,
      options.frameLimits
    );
    signal.throwIfAborted();

    const serverCredentialFrame = await readFrame<unknown>(stream.recv, options.frameLimits);
    signal.throwIfAborted();
    if (serverCredentialFrame.kind !== SessionFrameKind.ServerCredential) {
      throw new P2PError('UNAUTHORIZED', 'Expected session server credential');
    }
    const serverCredential = validateServerCredential(serverCredentialFrame.value);
    validateRemoteGrant(serverCredential.grantExpiresAt, challenge.presentedAt);
    const responderTranscriptHash = transcriptAfterInitiatorCredential(
      transcript.hash,
      credential,
      serverCredential.grantExpiresAt
    );
    const responderContext = securityContext(
      options,
      connection,
      direction,
      'responder',
      transcript,
      responderTranscriptHash,
      signal
    );
    const principal = freezePrincipal(
      await options.security.authenticate(serverCredential.credential, responderContext)
    );
    signal.throwIfAborted();
    validatePrincipalExpiry(principal.expiresAt);

    const id = sessionId(responderTranscriptHash, serverCredential.credential, principal.expiresAt);
    // Translate the peer's verifier clock through its signed challenge. Using
    // our earlier handshake start is conservative by the network transit time;
    // allowed wall-clock skew never adds time to a credential grant.
    const credentialExpiresAt = Math.min(principal.expiresAt,
      startedAt + serverCredential.grantExpiresAt - challenge.presentedAt);
    const candidate = boundedSession(Object.freeze({ id, generation: hello.generation, establishedAt: startedAt,
      expiresAt: Math.min(credentialExpiresAt, startedAt + Math.min(hello.maxSessionTtlMs, challenge.maxSessionTtlMs)), principal }), startedMonotonic);
    if (options.prepareSession) {
      const preparation = options.prepareSession(candidate, signal);
      options.trackWork?.(preparation);
      await preparation;
    }
    signal.throwIfAborted();
    await writeFrame(stream.send, SessionFrameKind.ClientFinished, {
      sessionId: id,
      grantExpiresAt: principal.expiresAt
    } satisfies ClientFinished, options.frameLimits);
    signal.throwIfAborted();
    // The initiator has no more handshake messages. FIN lets the responder
    // reject trailing bytes before it grants the session.
    await stream.send.finish();
    signal.throwIfAborted();

    const finishedFrame = await readFrame<unknown>(stream.recv, options.frameLimits);
    signal.throwIfAborted();
    if (finishedFrame.kind !== SessionFrameKind.ServerFinished) {
      throw new P2PError('UNAUTHORIZED', 'Expected session server finish');
    }
    const finished = validateServerFinished(finishedFrame.value);
    const peerExpiresAt = startedAt + finished.expiresAt - challenge.presentedAt;
    if (
      finished.sessionId !== id ||
      peerExpiresAt <= Date.now() ||
      finished.expiresAt > serverCredential.grantExpiresAt ||
      finished.expiresAt > challenge.presentedAt + Math.min(hello.maxSessionTtlMs, challenge.maxSessionTtlMs)
    ) {
      throw new P2PError('UNAUTHORIZED', 'Session finish did not match the authenticated transcript');
    }
    await expectRecvEnd(stream.recv);
    signal.throwIfAborted();
    const completed = boundedSession(Object.freeze({ ...candidate, expiresAt: Math.min(candidate.expiresAt, peerExpiresAt) }), startedMonotonic);
    if (sessionRemainingLifetime(completed) <= 0) throw new P2PError("UNAUTHORIZED", "Session expired during authentication");
    return completed;
  } catch (cause) {
    // The node closes the physical connection after rejection. Do not let a
    // wedged native reset/stop extend the externally visible deadline.
    void abortStream().catch(() => undefined);
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
  const startedMonotonic = performance.now();
  const stream = options.stream ?? await connection.acceptBi();
  const abortStream = (): Promise<void> => {
    if (!cleanup.current) {
      cleanup.current = abortHandshakeStream(connection, stream);
      options.trackWork?.(cleanup.current);
    }
    return cleanup.current;
  };
  const onAbort = (): void => { void abortStream().catch(() => undefined); };
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    signal.throwIfAborted();
    if (!options.stream && (await readStreamKind(stream.recv)) !== StreamKind.SessionAuth) {
      throw new P2PError('UNAUTHORIZED', 'Application authentication is required before opening streams');
    }
    signal.throwIfAborted();
    const helloFrame = await readFrame<unknown>(stream.recv, options.frameLimits);
    signal.throwIfAborted();
    if (helloFrame.kind !== SessionFrameKind.ClientHello) {
      throw new P2PError('UNAUTHORIZED', 'Expected session client hello');
    }
    const hello = validateClientHello(helloFrame.value, options);
    const challenge: ServerChallenge = Object.freeze({
      version: HANDSHAKE_VERSION,
      protocol: options.protocol,
      nonce: nonce(),
      echo: hello.nonce,
      presentedAt: Date.now(),
      maxSessionTtlMs: options.maxSessionTtlMs,
      generation: hello.generation,
      previousSessionId: hello.previousSessionId
    });
    const transcript = challengeTranscript(
      options.protocol,
      connection.remoteId,
      options.localPeerId,
      hello,
      challenge
    );

    // The challenge intentionally contains no credential. The responder does
    // not ask its credential provider for secret material until the initiator
    // has authenticated successfully.
    await writeFrame(stream.send, SessionFrameKind.ServerChallenge, challenge, options.frameLimits);
    signal.throwIfAborted();
    const clientCredentialFrame = await readFrame<unknown>(stream.recv, options.frameLimits);
    signal.throwIfAborted();
    if (clientCredentialFrame.kind !== SessionFrameKind.ClientCredential) {
      throw new P2PError('UNAUTHORIZED', 'Expected session client credential');
    }
    const clientCredential = validateClientCredential(clientCredentialFrame.value);
    const initiatorContext = securityContext(
      options,
      connection,
      direction,
      'initiator',
      transcript,
      transcript.hash,
      signal
    );
    const principal = freezePrincipal(
      await options.security.authenticate(clientCredential.credential, initiatorContext)
    );
    signal.throwIfAborted();
    validatePrincipalExpiry(principal.expiresAt);

    const responderTranscriptHash = transcriptAfterInitiatorCredential(
      transcript.hash,
      clientCredential.credential,
      principal.expiresAt
    );
    const responderContext = securityContext(
      options,
      connection,
      direction,
      'responder',
      transcript,
      responderTranscriptHash,
      signal
    );
    const credential = canonicalOutboundCredential(await options.security.getCredential(responderContext));
    signal.throwIfAborted();
    await writeFrame(stream.send, SessionFrameKind.ServerCredential, {
      credential,
      grantExpiresAt: principal.expiresAt
    } satisfies ServerCredential, options.frameLimits);
    signal.throwIfAborted();

    const finishedFrame = await readFrame<unknown>(stream.recv, options.frameLimits);
    signal.throwIfAborted();
    if (finishedFrame.kind !== SessionFrameKind.ClientFinished) {
      throw new P2PError('UNAUTHORIZED', 'Expected session client finish');
    }
    const finished = validateClientFinished(finishedFrame.value);
    validateRemoteGrant(finished.grantExpiresAt, hello.presentedAt);
    const id = sessionId(responderTranscriptHash, credential, finished.grantExpiresAt);
    if (finished.sessionId !== id) {
      throw new P2PError('UNAUTHORIZED', 'Session finish did not match the authenticated transcript');
    }
    await expectRecvEnd(stream.recv);
    signal.throwIfAborted();

    const expiresAt = capExpiry(
      Math.min(principal.expiresAt, startedAt + finished.grantExpiresAt - hello.presentedAt),
      Math.max(1, startedAt + Math.min(hello.maxSessionTtlMs, challenge.maxSessionTtlMs) - Date.now())
    );
    const candidate = boundedSession(Object.freeze({ id, generation: hello.generation, establishedAt: startedAt, expiresAt, principal }), startedMonotonic);
    if (options.prepareSession) {
      const preparation = options.prepareSession(candidate, signal);
      options.trackWork?.(preparation);
      await preparation;
    }
    signal.throwIfAborted();
    validatePrincipalExpiry(expiresAt);
    if (sessionRemainingLifetime(candidate) <= 0) throw new P2PError("UNAUTHORIZED", "Session expired during authentication");
    await writeFrame(stream.send, SessionFrameKind.ServerFinished, {
      sessionId: id,
      expiresAt
    } satisfies ServerFinished, options.frameLimits);
    signal.throwIfAborted();
    await stream.send.finish();
    return candidate;
  } catch (cause) {
    // The node closes the physical connection after rejection. Do not let a
    // wedged native reset/stop extend the externally visible deadline.
    void abortStream().catch(() => undefined);
    throw cause;
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

async function abortHandshakeStream(
  connection: QuicConnection,
  stream: Awaited<ReturnType<QuicConnection['openBi']>>
): Promise<void> {
  // Start both terminals and observe both to settlement. allSettled alone
  // would incorrectly turn rejected cleanup into success; Promise.all alone
  // could settle ownership while the other terminal is still pending.
  const terminalCleanup = Promise.allSettled([
    startOperation(() => stream.send.reset(2n)),
    startOperation(() => stream.recv.stop(2n))
  ]).then((outcomes) => {
    const failures = outcomes
      .filter((outcome): outcome is PromiseRejectedResult => outcome.status === 'rejected')
      .map((outcome) => outcome.reason);
    if (failures.length > 0) {
      throw new P2PError('INTERNAL', 'Authentication stream cleanup failed', {
        cause: new AggregateError(failures, 'Authentication stream cleanup was incomplete')
      });
    }
  });
  // A transport close subsumes either stalled stream terminal. A rejected
  // closed() observation is not proof and deliberately never wins this race;
  // the node's separately tracked physical barrier remains fail-closed too.
  const physicalClosure = startOperation(() => connection.closed()).then(
    () => undefined,
    () => new Promise<void>(() => undefined)
  );
  await Promise.race([terminalCleanup, physicalClosure]);
}

function startOperation<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return Promise.resolve(operation());
  } catch (cause) {
    return Promise.reject(cause);
  }
}

function validateClientHello<TFileMetadata>(
  value: unknown,
  options: SessionHandshakeOptions<TFileMetadata>
): ClientHello {
  if (!isPlainRecord(value) || value.version !== HANDSHAKE_VERSION || value.protocol !== options.protocol) {
    throw new P2PError('INCOMPATIBLE_PROTOCOL', 'Peer uses a different p2prpc application contract');
  }
  exactRecord(value, ['version', 'protocol', 'nonce', 'presentedAt', 'maxSessionTtlMs', 'generation', 'previousSessionId'], 'Session client hello');
  validateNonceAndTime(value.nonce, value.presentedAt, options, 'client hello');
  validateGeneration(value, options);
  return Object.freeze({
    version: HANDSHAKE_VERSION,
    protocol: options.protocol,
    nonce: value.nonce as string,
    presentedAt: value.presentedAt as number,
    maxSessionTtlMs: value.maxSessionTtlMs as number,
    generation: value.generation as number,
    previousSessionId: value.previousSessionId as string | null
  });
}

function validateServerChallenge<TFileMetadata>(
  value: unknown,
  initiatorNonce: string,
  options: SessionHandshakeOptions<TFileMetadata>
): ServerChallenge {
  if (!isPlainRecord(value) || value.version !== HANDSHAKE_VERSION || value.protocol !== options.protocol) {
    throw new P2PError('INCOMPATIBLE_PROTOCOL', 'Peer uses a different p2prpc application contract');
  }
  exactRecord(value, ['version', 'protocol', 'nonce', 'echo', 'presentedAt', 'maxSessionTtlMs', 'generation', 'previousSessionId'], 'Session server challenge');
  validateNonceAndTime(value.nonce, value.presentedAt, options, 'server challenge');
  validateGeneration(value, options);
  if (value.echo !== initiatorNonce) {
    throw new P2PError('UNAUTHORIZED', 'Server challenge did not match the client nonce');
  }
  return Object.freeze({
    version: HANDSHAKE_VERSION,
    protocol: options.protocol,
    nonce: value.nonce as string,
    echo: initiatorNonce,
    presentedAt: value.presentedAt as number,
    maxSessionTtlMs: value.maxSessionTtlMs as number,
    generation: value.generation as number,
    previousSessionId: value.previousSessionId as string | null
  });
}

function validateGeneration<TFileMetadata>(value: Record<string, unknown>, options: SessionHandshakeOptions<TFileMetadata>): void {
  if (!Number.isSafeInteger(value.maxSessionTtlMs) || (value.maxSessionTtlMs as number) < 1 || (value.maxSessionTtlMs as number) > 24 * 60 * 60_000) {
    throw new P2PError('UNAUTHORIZED', 'Invalid session lifetime ceiling');
  }
  const expected = (options.previousSession?.generation ?? -1) + 1;
  if (!Number.isSafeInteger(value.generation) || value.generation !== expected ||
      value.previousSessionId !== (options.previousSession?.id ?? null)) {
    throw new P2PError('UNAUTHORIZED', 'Session generation did not match the current authenticated session');
  }
}

function validateNonceAndTime<TFileMetadata>(
  nonceValue: unknown,
  presentedAt: unknown,
  options: SessionHandshakeOptions<TFileMetadata>,
  label: string
): void {
  if (!validNonce(nonceValue) || !Number.isSafeInteger(presentedAt)) {
    throw new P2PError('UNAUTHORIZED', `Invalid session ${label}`);
  }
  if (Math.abs(Date.now() - (presentedAt as number)) > options.clockSkewMs) {
    throw new P2PError('UNAUTHORIZED', `Session ${label} is stale`);
  }
}

function validateClientCredential(value: unknown): ClientCredential {
  if (!isPlainRecord(value)) throw new P2PError('UNAUTHORIZED', 'Invalid client credential frame');
  exactRecord(value, ['credential'], 'Session client credential');
  return Object.freeze({ credential: canonicalInboundCredential(value.credential) });
}

function validateServerCredential(value: unknown): ServerCredential {
  if (!isPlainRecord(value)) throw new P2PError('UNAUTHORIZED', 'Invalid server credential frame');
  exactRecord(value, ['credential', 'grantExpiresAt'], 'Session server credential');
  if (!Number.isSafeInteger(value.grantExpiresAt)) {
    throw new P2PError('UNAUTHORIZED', 'Invalid server credential grant');
  }
  return Object.freeze({
    credential: canonicalInboundCredential(value.credential),
    grantExpiresAt: value.grantExpiresAt as number
  });
}

function validateClientFinished(value: unknown): ClientFinished {
  if (!isPlainRecord(value)) throw new P2PError('UNAUTHORIZED', 'Invalid client finish frame');
  exactRecord(value, ['sessionId', 'grantExpiresAt'], 'Session client finish');
  if (!validDigest(value.sessionId) || !Number.isSafeInteger(value.grantExpiresAt)) {
    throw new P2PError('UNAUTHORIZED', 'Invalid client finish frame');
  }
  return Object.freeze({ sessionId: value.sessionId, grantExpiresAt: value.grantExpiresAt as number });
}

function validateServerFinished(value: unknown): ServerFinished {
  if (!isPlainRecord(value)) throw new P2PError('UNAUTHORIZED', 'Invalid server finish frame');
  exactRecord(value, ['sessionId', 'expiresAt'], 'Session server finish');
  if (!validDigest(value.sessionId) || !Number.isSafeInteger(value.expiresAt)) {
    throw new P2PError('UNAUTHORIZED', 'Invalid server finish frame');
  }
  return Object.freeze({ sessionId: value.sessionId, expiresAt: value.expiresAt as number });
}

function challengeTranscript(
  protocol: string,
  initiatorPeerId: string,
  responderPeerId: string,
  hello: ClientHello,
  challenge: ServerChallenge
): ChallengeTranscript {
  const transcript = {
    initiatorPeerId,
    responderPeerId,
    initiatorNonce: hello.nonce,
    responderNonce: challenge.nonce,
    initiatorPresentedAt: hello.presentedAt,
    responderPresentedAt: challenge.presentedAt,
    generation: hello.generation,
    previousSessionId: hello.previousSessionId
  };
  return Object.freeze({
    ...transcript,
    hash: digest('p2prpc-handshake-challenge-v4', [
      HANDSHAKE_VERSION,
      protocol,
      transcript.initiatorPeerId,
      transcript.responderPeerId,
      transcript.initiatorNonce,
      transcript.responderNonce,
      transcript.initiatorPresentedAt,
      transcript.responderPresentedAt,
      hello.maxSessionTtlMs,
      challenge.maxSessionTtlMs,
      transcript.generation,
      transcript.previousSessionId ?? ""
    ])
  });
}

function securityContext<TFileMetadata>(
  options: SessionHandshakeOptions<TFileMetadata>,
  connection: QuicConnection,
  direction: 'inbound' | 'outbound',
  role: SessionRole,
  transcript: ChallengeTranscript,
  transcriptHash: string,
  signal: AbortSignal
): CredentialRequestContext {
  return Object.freeze({
    localPeerId: options.localPeerId,
    remotePeerId: connection.remoteId,
    direction,
    protocol: options.protocol,
    role,
    initiatorPeerId: transcript.initiatorPeerId,
    responderPeerId: transcript.responderPeerId,
    initiatorNonce: transcript.initiatorNonce,
    responderNonce: transcript.responderNonce,
    initiatorPresentedAt: transcript.initiatorPresentedAt,
    responderPresentedAt: transcript.responderPresentedAt,
    transcriptHash,
    generation: transcript.generation,
    previousSessionId: transcript.previousSessionId,
    signal
  });
}

function transcriptAfterInitiatorCredential(
  challengeHash: string,
  credential: SessionCredential,
  initiatorGrantExpiresAt: number
): string {
  return digest('p2prpc-handshake-initiator-credential-v4', [
    challengeHash,
    credential.scheme,
    credential.value,
    initiatorGrantExpiresAt
  ]);
}

function sessionId(
  responderTranscriptHash: string,
  responderCredential: SessionCredential,
  responderGrantExpiresAt: number
): string {
  return digest('p2prpc-session-v4', [
    responderTranscriptHash,
    responderCredential.scheme,
    responderCredential.value,
    responderGrantExpiresAt
  ]);
}

function digest(domain: string, fields: readonly (string | number)[]): string {
  return createHash('sha256')
    .update(`${domain}\n`)
    .update(JSON.stringify(fields))
    .digest('base64url');
}

function canonicalOutboundCredential(value: unknown): SessionCredential {
  // Copy only the two protocol fields. This prevents accidental properties on
  // a custom provider result from crossing the wire.
  return canonicalCredential(value, false);
}

function canonicalInboundCredential(value: unknown): SessionCredential {
  return canonicalCredential(value, true);
}

function canonicalCredential(value: unknown, exact: boolean): SessionCredential {
  if (!isPlainRecord(value)) {
    throw new P2PError('UNAUTHORIZED', 'Invalid session credential');
  }
  if (exact) exactRecord(value, ['scheme', 'value'], 'Session credential');
  const schemeDescriptor = Object.getOwnPropertyDescriptor(value, 'scheme');
  const valueDescriptor = Object.getOwnPropertyDescriptor(value, 'value');
  const scheme = schemeDescriptor && Object.hasOwn(schemeDescriptor, 'value')
    ? schemeDescriptor.value
    : undefined;
  const credentialValue = valueDescriptor && Object.hasOwn(valueDescriptor, 'value')
    ? valueDescriptor.value
    : undefined;
  if (
    typeof scheme !== 'string' ||
    !/^[A-Za-z][A-Za-z0-9+.-]{0,63}$/.test(scheme) ||
    typeof credentialValue !== 'string' ||
    credentialValue.length < 1 ||
    Buffer.byteLength(credentialValue) > MAX_CREDENTIAL_BYTES
  ) {
    throw new P2PError('UNAUTHORIZED', 'Invalid session credential');
  }
  return Object.freeze({ scheme, value: credentialValue });
}

function validateRemoteGrant(expiresAt: number, presentedAt: number): void {
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= presentedAt) {
    throw new P2PError('UNAUTHORIZED', 'Remote session credential is expired');
  }
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
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.byteLength === 32 && decoded.toString('base64url') === value;
}

function validDigest(value: unknown): value is string {
  return validNonce(value);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
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
  let removeAbort: (() => void) | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        const abort = (): void => reject(controller.signal.reason ?? new P2PError('CANCELLED', 'Authentication cancelled'));
        if (controller.signal.aborted) abort();
        else {
          controller.signal.addEventListener('abort', abort, { once: true });
          removeAbort = () => controller.signal.removeEventListener('abort', abort);
        }
      }),
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
    removeAbort?.();
  }
}
