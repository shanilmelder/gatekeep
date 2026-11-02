// CI only, run by deploy/ci/stack-check.sh inside a container. Searches a directory tree,
// or a stream on stdin (an exported container filesystem), for the Master Key in any form
// it could be stored in: its raw bytes, hex in either case, and base64. Exits 1 naming
// where it was found, 0 if it's nowhere, 2 on a usage error. It never prints the key.
//
//   node find-key.mjs <key-file> <directory | ->
//
// The key is read from a file, so it is never in an argument or an environment variable.
import { createReadStream, lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const [keyFile, target] = process.argv.slice(2);
const key = keyFile ? readFileSync(keyFile) : Buffer.alloc(0);
const keyHex = key.toString('hex');
if (key.length !== 32 || !target) {
  console.error('usage: node find-key.mjs <32-byte key file> <directory | ->');
  process.exit(2);
}

const patterns = [
  ['raw', key],
  ['hex', Buffer.from(keyHex)],
  ['HEX', Buffer.from(keyHex.toUpperCase())],
  ['base64', Buffer.from(key.toString('base64').replace(/=+$/, ''))],
  ['base64url', Buffer.from(key.toString('base64url'))],
];
const overlap = Math.max(...patterns.map(([, p]) => p.length)) - 1;

async function search(stream) {
  let tail = Buffer.alloc(0);
  for await (const chunk of stream) {
    const window = Buffer.concat([tail, chunk]);
    for (const [form, pattern] of patterns) {
      if (window.indexOf(pattern) >= 0) {
        stream.destroy?.();
        return form;
      }
    }
    tail = window.subarray(Math.max(0, window.length - overlap));
  }
  return null;
}

const found = [];
if (target === '-') {
  const form = await search(process.stdin);
  if (form) found.push(`stdin (${form})`);
} else {
  const walk = async (path) => {
    const stat = lstatSync(path);
    if (stat.isDirectory()) {
      for (const entry of readdirSync(path)) await walk(join(path, entry));
    } else if (stat.isFile()) {
      const form = await search(createReadStream(path));
      if (form) found.push(`${path} (${form})`);
    }
  };
  await walk(target);
}

if (found.length > 0) {
  console.error(`find-key: the Master Key is in ${found.join(', ')}`);
  process.exit(1);
}
