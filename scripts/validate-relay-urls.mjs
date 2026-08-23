import process from 'node:process';
import { URL } from 'node:url';

const requiredOrigins = Number(process.argv[2]);
if (!Number.isSafeInteger(requiredOrigins) || requiredOrigins < 1 || requiredOrigins > 32) {
  throw new Error('Required relay-origin count must be an integer between 1 and 32');
}

let values;
try {
  process.stdin.setEncoding('utf8');
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  values = JSON.parse(input);
} catch (cause) {
  throw new Error('Relay URLs must be a JSON array', { cause });
}

if (!Array.isArray(values) || values.length < requiredOrigins || values.length > 32) {
  throw new Error(`Configure between ${requiredOrigins} and 32 relay URLs`);
}

const origins = [];
const seen = new Set();
for (const value of values) {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 2_048 ||
    value !== value.trim() ||
    [...value].some((character) => {
      const code = character.codePointAt(0);
      return code !== undefined && (code <= 0x1f || code === 0x7f);
    })
  ) {
    throw new Error('Relay URLs must be bounded strings without surrounding whitespace or controls');
  }

  const originSyntax = /^https:\/\/([^/?#\\]+)\/?$/iu.exec(value);
  if (!originSyntax || originSyntax[1].includes('@') || originSyntax[1].endsWith(':')) {
    throw new Error('Relay URL must use an unambiguous credential-free HTTPS origin syntax');
  }

  let url;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new Error('Relay URL is invalid', { cause });
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password
  ) {
    throw new Error('Relay URL must be a credential-free HTTPS origin without path, query, or fragment');
  }

  // A DNS root dot changes URL serialization but not the server selected by DNS.
  // Strip one so two spellings of the same relay cannot satisfy a redundancy gate.
  if (!url.hostname.startsWith('[') && url.hostname.endsWith('.')) {
    if (url.hostname.endsWith('..')) {
      throw new Error('Relay DNS names may contain at most one trailing root dot');
    }
    url.hostname = url.hostname.slice(0, -1);
  }
  const origin = url.origin;
  if (seen.has(origin)) {
    throw new Error(`Relay URLs contain the same canonical HTTPS origin: ${origin}`);
  }
  seen.add(origin);
  origins.push(origin);
}

if (seen.size < requiredOrigins) {
  throw new Error(`At least ${requiredOrigins} distinct canonical relay origins are required`);
}

process.stdout.write(`${JSON.stringify(origins)}\n`);
