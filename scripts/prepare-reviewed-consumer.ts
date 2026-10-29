import process from 'node:process';
import { command, flag, positional, restPositionals, run, string } from 'cmd-ts';
import { invariant } from './package-validation-utils.mjs';
import { prepareReviewedConsumer } from './consumer-preparation.js';

await run(command({
  name: 'prepare-reviewed-consumer',
  description: 'Prepare only the immutable reviewed renewal.1 package and pinned Iroh forks.',
  args: {
    artifact: positional({ type: string, displayName: 'package.tgz' }),
    destination: positional({ type: string, displayName: 'new-directory' }),
    local: flag({ long: 'local', description: 'Use the two following, exact reviewed fork tarballs.' }),
    forks: restPositionals({ type: string, displayName: 'node-fork.tgz shared-fork.tgz' })
  },
  async handler({ artifact, destination, local, forks }) {
    invariant(local ? forks.length === 2 : forks.length === 0, 'Use --local <node-fork.tgz> <shared-fork.tgz>, or no fork arguments');
    await prepareReviewedConsumer(artifact, destination, local ? [forks[0]!, forks[1]!] : undefined);
  }
}), process.argv.slice(2));
