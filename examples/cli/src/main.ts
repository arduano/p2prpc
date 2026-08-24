import { mkdir } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { initTRPC } from '@trpc/server';
import { z } from 'zod';
import {
  createP2PNode,
  createSharedSecretSecurity,
  fileDestination,
  fileSource,
  type PeerContext
} from '../../../packages/core/src/index.js';

const t = initTRPC.context<PeerContext>().create();
const router = t.router({
  hello: t.procedure.input(z.object({ name: z.string() })).query(({ input, ctx }) => ({
    message: `Hello ${input.name}`,
    from: ctx.p2p.peer.id
  })),
  ticks: t.procedure.input(z.number().int().min(1).max(20)).subscription(async function* ({ input, signal }) {
    for (let index = 1; index <= input && !signal?.aborted; index += 1) {
      yield index;
      await new Promise((resolveTick) => setTimeout(resolveTick, 100));
    }
  })
});
type AppRouter = typeof router;

const [mode, first, second, third] = process.argv.slice(2);
const sharedSecret = process.env.P2PRPC_SHARED_SECRET;
if (!sharedSecret || Buffer.byteLength(sharedSecret) < 32) {
  throw new Error('Set P2PRPC_SHARED_SECRET to the same secret of at least 32 bytes on both peers');
}
const downloadDirectory = resolve(mode === 'serve' ? (first ?? 'downloads') : 'downloads');
// In production this directory must be service-owned; leaf no-follow checks
// cannot defend against an attacker who can replace a parent path component.
await mkdir(downloadDirectory, { recursive: true });

const node = await createP2PNode({
  router,
  protocol: { applicationId: 'p2prpc-example', contractVersion: '1' },
  security: createSharedSecretSecurity(sharedSecret, {
    // Example-only coarse policy. Production applications should inspect the
    // verified principal and requested RPC/file action.
    authorize: () => true
  }),
  // Demo-only: this CLI deliberately accepts the route hints in the supplied
  // ticket. Production services must check trusted address/relay allowlists.
  iroh: {
    allowDirectAddress: () => true,
    allowRelayUrl: () => true
  },
  createContext: (context) => context,
  onIncomingFile: (offer) => {
    // The remote name is display metadata, never a destination selector.
    const output = resolve(downloadDirectory, `${randomUUID()}.incoming`);
    console.log(`Accepting ${offer.manifest.name} (${offer.manifest.size} bytes) into ${output}`);
    return { accept: fileDestination(output) };
  },
  onTransferProgress: (progress) => {
    const percent = progress.totalBytes === 0 ? 100 : (progress.transferredBytes / progress.totalBytes) * 100;
    process.stdout.write(`\r${progress.direction} ${percent.toFixed(1)}%`);
    if (progress.completedChunks === progress.totalChunks) process.stdout.write('\n');
  }
});

if (mode === 'serve') {
  console.log(`Peer ID: ${node.id}`);
  console.log(`Ticket: ${node.ticket()}`);
  console.log('Waiting for peers. Press Ctrl+C to stop.');
  await waitForShutdown();
} else if (mode === 'connect' && first && second) {
  const peer = await node.connect<AppRouter>({
    expectedPeerId: first,
    locator: { kind: 'ticket', ticket: second },
    expectedPrincipal: {
      id: first,
      subject: first,
      issuer: null,
      clientId: null,
      tenantId: null
    }
  });
  console.log(await peer.rpc.hello.query({ name: 'peer' }));
  const subscription = peer.rpc.ticks.subscribe(5, {
    onData: (tick) => console.log('tick', tick),
    onError: (error) => console.error('subscription:', error.message)
  });
  if (third) {
    const transfer = await peer.files.sendFile(await fileSource(resolve(third)));
    console.log('transfer:', await transfer.result);
  }
  await new Promise((resolveWait) => setTimeout(resolveWait, 750));
  subscription.unsubscribe();
  await node.close();
} else {
  console.error('Usage:\n  npm start -w @p2prpc/cli-example -- serve [download-dir]\n  npm start -w @p2prpc/cli-example -- connect <expected-peer-id> <ticket> [file]');
  await node.close();
  process.exitCode = 1;
}

async function waitForShutdown(): Promise<void> {
  await new Promise<void>((resolveShutdown) => {
    const stop = (): void => resolveShutdown();
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
  await node.close();
}
