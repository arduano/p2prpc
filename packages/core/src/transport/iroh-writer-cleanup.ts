import { IrohNode, PublicKey as SharedPublicKey, type IrohAdapter } from '@momics/iroh-http-shared';

const ADAPTER_HARDENED = Symbol.for('@p2prpc/iroh-adapter-writer-cleanup');
const FACTORY_HARDENED = Symbol.for('@p2prpc/iroh-node-factory-writer-cleanup');

type HardenedAdapter = IrohAdapter & { [ADAPTER_HARDENED]?: true };
type HardenedFactory = typeof IrohNode & { [FACTORY_HARDENED]?: true };

class ProvenWriterFailure {
  constructor(readonly cause: unknown) {}
}

/**
 * Consume exactly one proof that the adapter finalized the opaque native
 * writer associated with this failed sendChunk call.
 *
 * The private wrapper correlates proof with one exact failed sendChunk call.
 * This remains correct even if a defective adapter reuses an Error object for
 * concurrent handles whose cleanup outcomes differ. p2prpc unwraps the cause
 * before it crosses the public transport boundary.
 */
export function consumeIrohWriterCleanupProof(cause: unknown): {
  readonly cause: unknown;
  readonly terminal: boolean;
} {
  if (cause instanceof ProvenWriterFailure) {
    return { cause: cause.cause, terminal: true };
  }
  return { cause, terminal: false };
}

/**
 * Exact-pinned iroh-http-shared 0.6.1 leaves a native writer handle allocated when the
 * WritableStream sink's sendChunk call rejects. WHATWG streams transition to
 * errored before a later abort, so the sink abort callback can no longer call
 * finishBody. Finalize at the adapter boundary while the opaque handle is
 * still available.
 *
 * Keep this seam isolated so it can be deleted when upstream performs the same
 * try/catch/finally cleanup. The dependency is exact-pinned and the native
 * lifecycle stress gate proves that endpoint handle gauges return to baseline.
 */
export function hardenIrohWriterCleanup(adapter: IrohAdapter): void {
  const hardened = adapter as HardenedAdapter;
  if (hardened[ADAPTER_HARDENED]) return;

  const sendChunk = adapter.sendChunk.bind(adapter);
  const finishBody = adapter.finishBody.bind(adapter);
  const finishTerminal = async (handle: bigint): Promise<void> => {
    try {
      await finishBody(handle);
    } catch (cause) {
      // The exact-pinned native adapter reports a writer which the peer has
      // already retired as structured INVALID_INPUT JSON in Error.message.
      // Absence from the opaque handle table is positive terminal proof, so a
      // defensive/reset close is idempotent. Every other shape fails closed.
      if (!isExactUnknownHandle(cause, handle)) throw cause;
    }
  };
  Object.defineProperty(hardened, ADAPTER_HARDENED, { value: true });
  Object.defineProperty(hardened, 'finishBody', {
    configurable: true,
    value: finishTerminal
  });
  Object.defineProperty(hardened, 'sendChunk', {
    configurable: true,
    value: async (handle: bigint, chunk: Uint8Array): Promise<void> => {
      try {
        await sendChunk(handle, chunk);
      } catch (cause) {
        // Preserve the transport error. Only a fulfilled finishBody is proof
        // that the opaque writer became terminal; cleanup rejection leaves the
        // stream fail-closed until physical session closure.
        try {
          await finishTerminal(handle);
        } catch {
          throw cause;
        }
        throw new ProvenWriterFailure(cause);
      }
    }
  });
}

function isExactUnknownHandle(cause: unknown, handle: bigint): boolean {
  if (!(cause instanceof Error)) return false;
  let value: unknown;
  try {
    value = JSON.parse(cause.message);
  } catch {
    return false;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return keys.length === 2
    && keys[0] === 'code'
    && keys[1] === 'message'
    && record['code'] === 'INVALID_INPUT'
    && record['message'] === `unknown handle: ${handle}`;
}


/** Install the compatibility seam before @momics/iroh-http-node creates an adapter. */
export function installIrohWriterCleanup(nodePublicKey: typeof SharedPublicKey): void {
  // The node wrapper and p2prpc must resolve the same exact shared-package
  // instance. Otherwise patching this factory would silently leave the real
  // NodeAdapter unprotected. Fail closed instead of claiming native cleanup.
  if (nodePublicKey !== SharedPublicKey) {
    throw new Error('Incompatible @momics/iroh-http-shared dependency graph');
  }
  const factory = IrohNode as HardenedFactory;
  if (factory[FACTORY_HARDENED]) return;

  const create = factory._create.bind(factory);
  Object.defineProperty(factory, FACTORY_HARDENED, { value: true });
  Object.defineProperty(factory, '_create', {
    configurable: true,
    value: (...args: Parameters<typeof IrohNode._create>): IrohNode => {
      hardenIrohWriterCleanup(args[0]);
      return create(...args);
    }
  });
}
