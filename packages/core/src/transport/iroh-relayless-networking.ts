import { createRequire } from 'node:module';
import { basename, dirname, resolve } from 'node:path';
import type {
  createNode as createIrohNode,
  IrohNode,
  NodeOptions,
  PublicKey
} from '@momics/iroh-http-node';

const EXPECTED_NODE_PACKAGE = '@momics/iroh-http-node';
const EXPECTED_NODE_VERSION = '0.6.0';
const EXPECTED_SHARED_PACKAGE = '@momics/iroh-http-shared';
const EXPECTED_SHARED_VERSION = '0.6.1';

type IrohNodeFactory = typeof createIrohNode;
type IrohPublicKey = typeof PublicKey;
type RelayOptions = NonNullable<NodeOptions['relay']>;

interface NormalisedRelay {
  readonly relayMode: string | undefined;
  readonly relays: string[] | null;
  readonly disableNetworking: boolean;
}

type RelayNormaliser = (relay?: RelayOptions) => NormalisedRelay;

interface SharedModule {
  readonly PublicKey: IrohPublicKey;
  readonly normaliseRelayMode: RelayNormaliser;
}

interface NodeModule {
  readonly PublicKey: IrohPublicKey;
  readonly createNode: IrohNodeFactory;
}

interface PackageIdentity {
  readonly name: string;
  readonly version: string;
}

/**
 * iroh-http-node 0.6.0 maps `{ mode: 'disabled' }` to both "no relay" and
 * `disableNetworking: true`. The latter is an unrelated test-only switch that
 * binds the native endpoint to loopback and makes genuine relay-less LAN use
 * impossible.
 *
 * Keep this compatibility seam narrow and temporary:
 *
 * - accept only the exact reviewed node/shared package versions and module graph;
 * - replace the CommonJS export only for the exact relay object owned by this
 *   endpoint construction;
 * - restore its original descriptor before the JavaScript stack can yield; and
 * - fail closed if the pinned wrapper no longer performs synchronous
 *   normalization through that export.
 *
 * Remove this file when the upstream wrapper separates relay selection from
 * its `disableNetworking` test option.
 */
export function createRelaylessIrohNode(
  factory: IrohNodeFactory,
  nodePublicKey: IrohPublicKey,
  options: NodeOptions
): Promise<IrohNode> {
  const relay = options.relay;
  if (!isExactDisabledRelay(relay)) {
    throw new Error('Relay-less Iroh compatibility requires the exact disabled-relay option');
  }
  const shared = resolveCompatibleModuleGraph(factory, nodePublicKey);
  return withRelaylessNormalisation(shared, relay, () => factory(options));
}

/** @internal Exported only for compatibility-seam regression tests. */
export function withRelaylessNormalisation<T>(
  shared: SharedModule,
  targetRelay: RelayOptions,
  operation: () => T
): T {
  if (!isExactDisabledRelay(targetRelay)) {
    throw new Error('Relay-less Iroh compatibility received an invalid relay option');
  }

  const descriptor = Object.getOwnPropertyDescriptor(shared, 'normaliseRelayMode');
  if (
    descriptor === undefined ||
    typeof descriptor.get !== 'function' ||
    descriptor.set !== undefined ||
    descriptor.configurable !== true ||
    descriptor.enumerable !== true
  ) {
    throw new Error('Incompatible @momics/iroh-http-shared export descriptor');
  }
  const original = shared.normaliseRelayMode;
  if (typeof original !== 'function') {
    throw new Error('Incompatible @momics/iroh-http-shared relay normaliser');
  }

  let matched = false;
  const replacement: RelayNormaliser = (relay) => {
    if (relay === targetRelay) {
      matched = true;
      return { relayMode: 'disabled', relays: [], disableNetworking: false };
    }
    return original(relay);
  };

  let result!: T;
  try {
    Object.defineProperty(shared, 'normaliseRelayMode', {
      configurable: true,
      enumerable: true,
      writable: false,
      value: replacement
    });
    result = operation();
  } finally {
    Object.defineProperty(shared, 'normaliseRelayMode', descriptor);
  }

  if (!matched) {
    throw new Error('Incompatible @momics/iroh-http-node relay normalization path');
  }
  return result;
}

function resolveCompatibleModuleGraph(
  factory: IrohNodeFactory,
  nodePublicKey: IrohPublicKey
): SharedModule {
  const localRequire = createRequire(import.meta.url);
  const nodeEntry = localRequire.resolve(EXPECTED_NODE_PACKAGE);
  const sharedEntry = localRequire.resolve(EXPECTED_SHARED_PACKAGE);
  if (basename(nodeEntry) !== 'lib.js' || basename(sharedEntry) !== 'index.js' || basename(dirname(sharedEntry)) !== 'dist') {
    throw new Error('Incompatible @momics/iroh-http package layout');
  }

  const nodeIdentity = requirePackageIdentity(localRequire, resolve(dirname(nodeEntry), 'package.json'));
  const sharedIdentity = requirePackageIdentity(localRequire, resolve(dirname(sharedEntry), '..', 'package.json'));
  assertPackageIdentity(nodeIdentity, EXPECTED_NODE_PACKAGE, EXPECTED_NODE_VERSION);
  assertPackageIdentity(sharedIdentity, EXPECTED_SHARED_PACKAGE, EXPECTED_SHARED_VERSION);

  const node = localRequire(nodeEntry) as unknown as NodeModule;
  const shared = localRequire(sharedEntry) as unknown as SharedModule;
  if (
    node.createNode !== factory ||
    node.PublicKey !== nodePublicKey ||
    shared.PublicKey !== nodePublicKey
  ) {
    throw new Error('Incompatible @momics/iroh-http dependency graph');
  }
  return shared;
}

function requirePackageIdentity(localRequire: NodeRequire, path: string): PackageIdentity {
  const value = localRequire(path) as unknown;
  if (
    typeof value !== 'object' ||
    value === null ||
    typeof (value as { name?: unknown }).name !== 'string' ||
    typeof (value as { version?: unknown }).version !== 'string'
  ) {
    throw new Error('Invalid @momics/iroh-http package identity');
  }
  return value as PackageIdentity;
}

function assertPackageIdentity(identity: PackageIdentity, name: string, version: string): void {
  if (identity.name !== name || identity.version !== version) {
    throw new Error(`Unsupported ${name} version ${identity.version}`);
  }
}

function isExactDisabledRelay(value: NodeOptions['relay']): value is RelayOptions {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length === 1 && keys[0] === 'mode' && value.mode === 'disabled';
}
