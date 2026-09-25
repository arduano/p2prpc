import { randomBytes } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import { expect, it, vi } from 'vitest';
import { IrohEndpoint } from '../src/transport/iroh.js';

/** Explicitly opted-in, ephemeral proof through the configured real relay. */
it.skipIf(!process.env.IROH_CUSTOM_RELAY_PROBE_URL)(
  'exchanges bytes over the configured custom relay with no advertised direct or public-default route',
  { timeout: 90_000 },
  async () => {
    const origin = new URL(process.env.IROH_CUSTOM_RELAY_PROBE_URL!);
    expect(origin.protocol).toBe('https:');
    const tokenFile = process.env.IROH_CUSTOM_RELAY_PROBE_TOKEN_FILE;
    let token = randomBytes(32).toString('hex');
    if (tokenFile) {
      const info = await lstat(tokenFile);
      expect(info.isFile() && !info.isSymbolicLink() && info.uid === process.getuid?.() && (info.mode & 0o077) === 0).toBe(true);
      token = (await readFile(tokenFile, 'utf8')).trim();
      expect(/^[0-9a-f]{96}$/.test(token)).toBe(true);
    }
    const address = Object.entries(networkInterfaces())
      .filter(([name]) => /^(en|eth|wl)/.test(name))
      .flatMap(([, values]) => values ?? [])
      .find(value => value.family === 'IPv4' && !value.internal && /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(value.address));
    expect(address?.address, 'one assigned non-loopback private physical IPv4 is required').toBeDefined();
    const alpn = new TextEncoder().encode('p2prpc-private-relay-probe-v1');
    const config = {
      relay: { mode: 'custom' as const, urls: [origin.origin], authToken: token },
      discovery: { dns: false, mdns: false },
      bindAddress: `${address!.address}:0`,
      allowAdvertisedAddress: () => false,
      allowDirectAddress: () => false,
    };
    const receiver = await IrohEndpoint.create(alpn, config);
    let sender: IrohEndpoint | undefined;
    try {
      sender = await IrohEndpoint.create(alpn, config);
      let ticket = '';
      await vi.waitFor(async () => {
        ticket = await receiver.createTicket();
        const encoded = ticket.split('.')[1];
        expect(encoded).toBeDefined();
        const locator = JSON.parse(Buffer.from(encoded!, 'base64url').toString('utf8')) as {
          directAddresses: string[]; relayUrl: string | null;
        };
        expect(locator.directAddresses).toEqual([]);
        expect(locator.relayUrl && new URL(locator.relayUrl).origin).toBe(origin.origin);
      }, { timeout: 30_000, interval: 500 });
      const incoming = receiver.accept();
      const outbound = await sender.connect(ticket, alpn, receiver.id);
      const inbound = await incoming;
      expect(inbound).not.toBeNull();
      const receive = inbound!.acceptUni();
      const send = await outbound.openUni();
      await send.writeAll(Uint8Array.of(0x2a));
      await send.finish();
      const stream = await receive;
      expect(await stream.readExact(1)).toEqual(Uint8Array.of(0x2a));
      await stream.expectEnd();
      const stats = await outbound.stats();
      expect(stats.relay === true || stats.paths?.some(path => path.active && path.relay)).toBe(true);
      expect(stats.relayUrl && new URL(stats.relayUrl).origin).toBe(origin.origin);
    } finally { await Promise.allSettled([sender?.close(), receiver.close()]); }
  },
);
