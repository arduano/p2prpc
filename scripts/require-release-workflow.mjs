import process from 'node:process';

process.stderr.write(
  'Direct releases are disabled. Push an exact semver tag after public CI passes for this main-branch commit; the pinned GitHub Packages workflow performs publication.\n'
);
process.exitCode = 1;
