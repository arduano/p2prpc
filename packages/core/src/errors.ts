export type P2PErrorCode =
  | 'UNAUTHORIZED'
  | 'INCOMPATIBLE_PROTOCOL'
  | 'REJECTED'
  | 'CANCELLED'
  | 'TIMEOUT'
  | 'DISCONNECTED'
  | 'INVALID_FRAME'
  | 'RESOURCE_LIMIT'
  | 'INTEGRITY_FAILED'
  | 'NOT_FOUND'
  | 'INTERNAL';

export class P2PError extends Error {
  readonly code: P2PErrorCode;
  override readonly cause?: unknown;

  constructor(code: P2PErrorCode, message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = 'P2PError';
    this.code = code;
    if (options && 'cause' in options) this.cause = options.cause;
  }
}

export function asP2PError(error: unknown, fallback: P2PErrorCode = 'INTERNAL'): P2PError {
  if (error instanceof P2PError) return error;
  return new P2PError(fallback, error instanceof Error ? error.message : String(error), { cause: error });
}
