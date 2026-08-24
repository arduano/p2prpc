import { PublicKey, type NodeOptions } from '@momics/iroh-http-node';
import { describe, expect, it, vi } from 'vitest';
import {
  createRelaylessIrohNode,
  withRelaylessNormalisation
} from '../src/transport/iroh-relayless-networking.js';

type RelayOptions = NonNullable<NodeOptions['relay']>;
type RelayNormaliser = (relay?: RelayOptions) => {
  relayMode: string | undefined;
  relays: string[] | null;
  disableNetworking: boolean;
};

describe('Iroh relay-less networking compatibility seam', () => {
  it('changes only the exact endpoint relay object and restores the export synchronously', () => {
    const original = vi.fn<RelayNormaliser>((relay) => ({
      relayMode: relay?.mode,
      relays: null,
      disableNetworking: relay?.mode === 'disabled'
    }));
    const shared = sharedModule(original);
    const before = Object.getOwnPropertyDescriptor(shared, 'normaliseRelayMode');
    const target = { mode: 'disabled' } as const;
    const unrelated = { mode: 'disabled' } as const;
    let targetResult: ReturnType<RelayNormaliser> | undefined;
    let unrelatedResult: ReturnType<RelayNormaliser> | undefined;

    const result = withRelaylessNormalisation(shared, target, () => {
      targetResult = shared.normaliseRelayMode(target);
      unrelatedResult = shared.normaliseRelayMode(unrelated);
      return 42;
    });

    expect(result).toBe(42);
    expect(targetResult).toEqual({
      relayMode: 'disabled',
      relays: [],
      disableNetworking: false
    });
    expect(unrelatedResult).toEqual({
      relayMode: 'disabled',
      relays: null,
      disableNetworking: true
    });
    expect(original).toHaveBeenCalledOnce();
    expect(original).toHaveBeenCalledWith(unrelated);
    expect(Object.getOwnPropertyDescriptor(shared, 'normaliseRelayMode')).toEqual(before);
  });

  it('restores the exact export descriptor when node creation throws', () => {
    const shared = sharedModule(() => ({ relayMode: undefined, relays: null, disableNetworking: false }));
    const before = Object.getOwnPropertyDescriptor(shared, 'normaliseRelayMode');
    const failure = new Error('native create failed');

    expect(() => withRelaylessNormalisation(shared, { mode: 'disabled' }, () => {
      shared.normaliseRelayMode({ mode: 'disabled' });
      throw failure;
    })).toThrow(failure);

    expect(Object.getOwnPropertyDescriptor(shared, 'normaliseRelayMode')).toEqual(before);
  });

  it('fails closed for an incompatible export descriptor or normalization path', () => {
    const normalise = () => ({ relayMode: 'disabled', relays: [], disableNetworking: true });
    const dataProperty = { PublicKey, normaliseRelayMode: normalise };
    expect(() => withRelaylessNormalisation(
      dataProperty,
      { mode: 'disabled' },
      () => undefined
    )).toThrow(/export descriptor/);

    const shared = sharedModule(normalise);
    expect(() => withRelaylessNormalisation(
      shared,
      { mode: 'disabled' },
      () => shared.normaliseRelayMode({ mode: 'disabled' })
    )).toThrow(/normalization path/);
  });

  it('fails closed on reentrant endpoint construction without contaminating the outer call', () => {
    const original = vi.fn<RelayNormaliser>((relay) => ({
      relayMode: relay?.mode,
      relays: 'urls' in (relay ?? {}) ? relay?.urls ?? null : null,
      disableNetworking: relay?.mode === 'disabled'
    }));
    const shared = sharedModule(original);
    const before = Object.getOwnPropertyDescriptor(shared, 'normaliseRelayMode');
    const outer = { mode: 'disabled' } as const;
    const inner = { mode: 'disabled' } as const;

    const result = withRelaylessNormalisation(shared, outer, () => {
      expect(shared.normaliseRelayMode(outer).disableNetworking).toBe(false);
      expect(() => withRelaylessNormalisation(shared, inner, () => {
        throw new Error('must not run');
      })).toThrow(/export descriptor/);
      expect(shared.normaliseRelayMode({ mode: 'default' }).disableNetworking).toBe(false);
      expect(shared.normaliseRelayMode({ urls: ['https://relay.example'] }).relays)
        .toEqual(['https://relay.example']);
      return 'outer-complete';
    });

    expect(result).toBe('outer-complete');
    expect(Object.getOwnPropertyDescriptor(shared, 'normaliseRelayMode')).toEqual(before);
  });

  it('restores isolation before concurrently-started promises can yield', async () => {
    const original = vi.fn<RelayNormaliser>((relay) => ({
      relayMode: relay?.mode,
      relays: null,
      disableNetworking: relay?.mode === 'disabled'
    }));
    const shared = sharedModule(original);
    const targets = Array.from({ length: 8 }, () => ({ mode: 'disabled' } as const));

    const results = await Promise.all(targets.map((target, index) =>
      withRelaylessNormalisation(shared, target, async () => {
        const normalized = shared.normaliseRelayMode(target);
        await Promise.resolve();
        return { index, normalized };
      })
    ));

    expect(results.map(({ index }) => index)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    expect(results.every(({ normalized }) => normalized.disableNetworking === false)).toBe(true);
    expect(original).not.toHaveBeenCalled();
  });

  it('fails before invocation when the factory is not from the pinned module graph', () => {
    const factory = vi.fn(async () => { throw new Error('must not run'); });
    expect(() => createRelaylessIrohNode(
      factory as never,
      PublicKey,
      { relay: { mode: 'disabled' } }
    )).toThrow(/dependency graph/);
    expect(factory).not.toHaveBeenCalled();
  });
});

function sharedModule(normalise: RelayNormaliser): {
  PublicKey: typeof PublicKey;
  readonly normaliseRelayMode: RelayNormaliser;
} {
  const shared = { PublicKey } as {
    PublicKey: typeof PublicKey;
    readonly normaliseRelayMode: RelayNormaliser;
  };
  Object.defineProperty(shared, 'normaliseRelayMode', {
    configurable: true,
    enumerable: true,
    get: () => normalise
  });
  return shared;
}
