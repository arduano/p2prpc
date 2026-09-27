import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import { initTRPC } from '@trpc/server';
import { z } from 'zod';
import { expect, it, vi } from 'vitest';
import { createAdvancedP2PNode } from '../src/node.js';
import { createSharedSecretSecurity } from '../src/security/shared-secret.js';
import { IrohEndpoint } from '../src/transport/iroh.js';
import type { PeerContext } from '../src/index.js';

const t = initTRPC.context<PeerContext>().create();
const router = t.router({ sum: t.procedure.input(z.object({ a: z.number(), b: z.number() })).query(({ input }) => input.a + input.b) });

it.skipIf(!process.env.IROH_CUSTOM_RELAY_PROBE_URL)(
  'completes a mutually authenticated application RPC only through the configured VPS relay',
  { timeout: 90_000 }, async () => {
    const origin = new URL(process.env.IROH_CUSTOM_RELAY_PROBE_URL!);
    expect(origin.protocol).toBe('https:');
    const interfaceAddress = Object.entries(networkInterfaces()).filter(([name]) => /^(en|eth|wl)/.test(name))
      .flatMap(([, values]) => values ?? [])
      .find(value => value.family === 'IPv4' && !value.internal && /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(value.address));
    expect(interfaceAddress?.address, 'one non-loopback physical private IPv4 is required').toBeDefined();
    const tokenFile = process.env.IROH_CUSTOM_RELAY_PROBE_TOKEN_FILE;
    let relayToken = randomBytes(32).toString('hex'); // synthetic until the VPS enforces shared_token
    if (tokenFile) {
      expect(typeof constants.O_NOFOLLOW).toBe('number');
      const handle = await open(tokenFile, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const file = await handle.stat();
        expect(file.isFile() && file.uid === process.getuid?.() && (file.mode & 0o077) === 0).toBe(true);
        relayToken = (await handle.readFile('utf8')).trim();
      } finally {
        await handle.close();
      }
      expect(/^[A-Za-z0-9._~+/=-]{32,4096}$/.test(relayToken)).toBe(true);
    }
    const secret = randomBytes(48).toString('base64');
    let acceptStarted = 0, acceptReturned = 0, peerEvents = 0;
    const errorCodes: string[] = [];
    const originalAccept = IrohEndpoint.prototype.accept;
    const acceptSpy = vi.spyOn(IrohEndpoint.prototype, 'accept').mockImplementation(function (this: IrohEndpoint) {
      acceptStarted++;
      return originalAccept.call(this).then(value => { if (value) acceptReturned++; return value; });
    });
    const create = async () => createAdvancedP2PNode({
      onError: error => { errorCodes.push(error.code); },
      onPeer: () => { peerEvents++; },
      router, protocol: { applicationId: 'custom-relay-vps-proof', contractVersion: '1' },
      createContext: context => context,
      security: createSharedSecretSecurity(secret, { authorize: () => true }),
      iroh: {
        bindAddress: `${interfaceAddress!.address}:0`,
        relay: { mode: 'custom', urls: [origin.origin], authToken: relayToken },
        discovery: { dns: false, mdns: false },
        allowAdvertisedAddress: () => false,
        allowDirectAddress: () => false,
      },
    });
    const receiver = await create();
    let sender: Awaited<ReturnType<typeof create>> | undefined;
    try {
      sender = await create();
      let ticket = '';
      await vi.waitFor(async () => {
        ticket = await receiver.createTicket();
        const payload = JSON.parse(Buffer.from(ticket.split('.')[1]!, 'base64url').toString('utf8')) as {
          directAddresses: string[]; relayUrl: string | null;
        };
        expect(payload.directAddresses).toEqual([]);
        expect(payload.relayUrl && new URL(payload.relayUrl).origin).toBe(origin.origin);
        expect(ticket).not.toContain(relayToken);
      }, { timeout: 30_000, interval: 500 });
      // Iroh advertises the configured relay URL before its authenticated
      // home connection has completed. Give both fresh endpoints one bounded
      // registration interval; production nodes remain long-lived.
      await new Promise(resolve => setTimeout(resolve, 1_500));
      let peer;
      try { peer = await sender.connect<typeof router>({
        locator: { kind: 'ticket', ticket }, expectedPeerId: receiver.id,
        expectedPrincipal: { id: receiver.id, subject: receiver.id, issuer: null, clientId: null, tenantId: null },
      }); } catch (error) {
        console.log(JSON.stringify({ phase: 'gated-dial', acceptStarted, acceptReturned, peerEvents, errorCodes }));
        throw error;
      }
      expect(await peer.rpc.sum.query({ a: 20, b: 22 })).toBe(42);
      const stats = await peer.stats();
      expect(stats.relay === true || stats.paths?.some(path => path.active && path.relay)).toBe(true);
      expect(stats.relayUrl && new URL(stats.relayUrl).origin).toBe(origin.origin);
    } finally { acceptSpy.mockRestore(); await Promise.allSettled([sender?.close(), receiver.close()]); }
  },
);
