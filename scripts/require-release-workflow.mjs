import process from 'node:process';

process.stderr.write(
  'Direct releases are disabled. Dispatch the pinned "Publish to npm" GitHub Actions workflow with a successful production-validation run for this exact commit.\n'
);
process.exitCode = 1;
