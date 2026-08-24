import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import process from 'node:process';

const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '*.md'], {
  encoding: 'utf8'
}).trim().split('\n').filter((file) => file.length > 0 && existsSync(file));
const failures = [];

for (const file of files) {
  const markdown = readFileSync(file, 'utf8');
  for (const match of markdown.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    const target = match[1];
    if (/^(?:https?:|mailto:|#|\/)/.test(target)) continue;
    const localPath = decodeURIComponent(target.split('#', 1)[0]);
    if (!existsSync(resolve(dirname(file), localPath))) failures.push(`${file} -> ${target}`);
  }
  if ((markdown.match(/^```/gm) ?? []).length % 2 !== 0) failures.push(`${file} -> unbalanced code fences`);
}

if (failures.length > 0) {
  process.stderr.write(`${failures.join('\n')}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`Checked ${files.length} Markdown files; local links resolve and code fences balance.\n`);
}
