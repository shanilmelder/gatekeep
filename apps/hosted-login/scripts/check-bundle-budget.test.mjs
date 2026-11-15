// The Budget row of the Story 4.1 matrix: the check passes within the budget, and over it exits
// non-zero naming the total, counting every JS and CSS file built. A URL to another origin fails too.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { check } from './check-bundle-budget.mjs';

const script = fileURLToPath(new URL('./check-bundle-budget.mjs', import.meta.url));
const temporary = await mkdtemp(path.join(os.tmpdir(), 'gk-budget-'));
after(() => rm(temporary, { recursive: true, force: true }));

async function dist(name, { js = 'console.log(1);', css = 'body{margin:0}', head = '' } = {}) {
  const root = path.join(temporary, name);
  await mkdir(path.join(root, 'assets'), { recursive: true });
  await writeFile(path.join(root, 'assets/index.js'), js);
  await writeFile(path.join(root, 'assets/index.css'), css);
  await writeFile(
    path.join(root, 'index.html'),
    `<!doctype html><html><head><script type="module" crossorigin src="/login/assets/index.js"></script>` +
      `<link rel="stylesheet" crossorigin href="/login/assets/index.css">${head}</head><body></body></html>`,
  );
  return root;
}

describe('Budget', () => {
  it('passes within the budget and prints the total', async () => {
    const { problems, lines } = await check(await dist('small'));
    assert.deepEqual(problems, []);
    assert.match(lines.at(-1), /^Total JS and CSS: \d+\.\d kB gzip, of a 150\.0 kB budget\.$/);
  });

  it('fails over the budget, naming the total', async () => {
    // Random bytes don't compress, so 200 kB of them gzip to about 200 kB.
    const root = await dist('large', { js: randomBytes(200_000).toString('base64') });
    const result = spawnSync(process.execPath, [script, root], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Hosted Login's JS and CSS are \d+\.\d kB gzip, over the 150\.0 kB budget\./);
  });

  it('counts a lazily loaded chunk and its CSS that index.html never names', async () => {
    const root = await dist('lazy');
    // Random bytes don't compress: 80 kB each, so only together are they over the budget.
    await writeFile(path.join(root, 'assets/lazy-chunk.js'), randomBytes(80_000).toString('base64'));
    await writeFile(path.join(root, 'assets/lazy-chunk.css'), `/*${randomBytes(80_000).toString('base64')}*/`);
    const { problems, lines } = await check(root);
    assert.ok(lines.some((line) => line.startsWith('/login/assets/lazy-chunk.js:')), lines.join('\n'));
    assert.ok(lines.some((line) => line.startsWith('/login/assets/lazy-chunk.css:')), lines.join('\n'));
    assert.match(problems.join('\n'), /over the 150\.0 kB budget/);
  });

  it('fails on a script, stylesheet or font from another origin', async () => {
    const root = await dist('elsewhere', {
      css: "@font-face{src:url('https://fonts.example/geist.woff2')}",
      head: '<script src="https://cdn.example/x.js"></script>',
    });
    const { problems } = await check(root);
    assert.equal(problems.length, 2);
    assert.match(problems.join('\n'), /cdn\.example/);
    assert.match(problems.join('\n'), /fonts\.example/);
  });
});
