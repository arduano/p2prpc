import process from 'node:process';
import { command, positional, run, string } from 'cmd-ts';
import { prepareCandidateConsumer } from './consumer-preparation.js';

await run(command({
  name: 'prepare-candidate-consumer',
  description: 'Verify this source candidate against pack.json and SHA256SUMS, then prepare its pinned Iroh closure. This does not approve publication.',
  args: {
    artifactDirectory: positional({ type: string, displayName: 'artifact-directory' }),
    destination: positional({ type: string, displayName: 'new-directory' })
  },
  handler: ({ artifactDirectory, destination }) => prepareCandidateConsumer(artifactDirectory, destination)
}), process.argv.slice(2));
