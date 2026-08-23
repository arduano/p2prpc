import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { initTRPC } from '@trpc/server';
import {
  createP2PNode,
  dangerouslyAllowInsecureSessions,
  fileDestination,
  fileSource,
  type PeerContext
} from '../packages/core/src/index.js';

const t = initTRPC.context<PeerContext>().create();
const router = t.router({ ping: t.procedure.query(() => 1) });
const directory = await mkdtemp(join(tmpdir(), 'p2prpc-bench-'));
const sourcePath = join(directory, 'source.bin');
await writeFile(sourcePath, Buffer.alloc(256 * 1024 * 1024, 7));

const receiver = await createP2PNode({
  router,
  protocol: { applicationId: 'benchmark', contractVersion: '1' },
  security: dangerouslyAllowInsecureSessions(),
  createContext: (context) => context,
  onIncomingFile: (offer) => offer.accept(fileDestination(join(directory, 'received.bin'), { overwrite: true })),
  iroh: { relay: { mode: 'disabled' } }
});
const sender = await createP2PNode({
  router,
  protocol: { applicationId: 'benchmark', contractVersion: '1' },
  security: dangerouslyAllowInsecureSessions(),
  createContext: (context) => context,
  iroh: { relay: { mode: 'disabled' } }
});

try {
  const peer = await sender.connect<typeof router>({
    locator: { kind: 'ticket', ticket: await receiver.createTicket() },
    expectedPeerId: receiver.id,
    expectedPrincipal: {
      id: receiver.id,
      subject: receiver.id,
      issuer: null,
      clientId: null,
      tenantId: null
    }
  });
  const transfer = await peer.files.sendFile(await fileSource(sourcePath));
  const latencies: number[] = [];
  let nextCall = 0;
  const calls = Array.from({ length: 16 }, async () => {
    while (nextCall < 1_000) {
      nextCall += 1;
      const start = performance.now();
      await peer.rpc.ping.query();
      latencies.push(performance.now() - start);
    }
  });
  const transferStart = performance.now();
  await Promise.all([transfer.result, ...calls]);
  const elapsed = performance.now() - transferStart;
  latencies.sort((a, b) => a - b);
  console.log(JSON.stringify({
    rpcCalls: latencies.length,
    rpcP50Ms: percentile(latencies, 0.5),
    rpcP95Ms: percentile(latencies, 0.95),
    rpcP99Ms: percentile(latencies, 0.99),
    transferMiB: 256,
    transferMiBPerSecond: 256 / (elapsed / 1000)
  }, null, 2));
} finally {
  await Promise.all([sender.close(), receiver.close()]);
  await rm(directory, { recursive: true, force: true });
}

function percentile(values: number[], fraction: number): number {
  return values[Math.min(values.length - 1, Math.floor(values.length * fraction))] ?? 0;
}
