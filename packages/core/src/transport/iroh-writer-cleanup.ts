import { IrohNode, PublicKey as SharedPublicKey, type IrohAdapter } from '@momics/iroh-http-shared';

const ADAPTER_HARDENED = Symbol.for('@p2prpc/iroh-adapter-writer-cleanup');
const FACTORY_HARDENED = Symbol.for('@p2prpc/iroh-node-factory-writer-cleanup');

type HardenedAdapter = IrohAdapter & { [ADAPTER_HARDENED]?: true };
type HardenedFactory = typeof IrohNode & { [FACTORY_HARDENED]?: true };

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
  Object.defineProperty(hardened, ADAPTER_HARDENED, { value: true });
  Object.defineProperty(hardened, 'sendChunk', {
    configurable: true,
    value: async (handle: bigint, chunk: Uint8Array): Promise<void> => {
      try {
        await sendChunk(handle, chunk);
      } catch (cause) {
        // Preserve the transport error. Cleanup failure does not make the
        // already-terminal write recoverable and must not hide its cause.
        await finishBody(handle).catch(() => undefined);
        throw cause;
      }
    }
  });
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
