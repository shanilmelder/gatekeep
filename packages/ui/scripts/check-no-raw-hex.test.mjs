// The Raw hex and QR exception rows of the Story 1.13 matrix.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { QR_EXCEPTION, findRawColours, lint } from './check-no-raw-hex.mjs';

const script = fileURLToPath(new URL('./check-no-raw-hex.mjs', import.meta.url));
const repository = path.resolve(path.dirname(script), '../../..');
const temporary = await mkdtemp(path.join(os.tmpdir(), 'gk-ui-lint-'));
after(() => rm(temporary, { recursive: true, force: true }));

async function fixture(name, files) {
  const root = path.join(temporary, name);
  await mkdir(path.join(root, 'packages/ui/src'), { recursive: true });
  for (const [file, text] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(root, file)), { recursive: true });
    await writeFile(path.join(root, file), text);
  }
  return root;
}

const message = (file, line, value) => `${file}:${line}: raw colour ${value}. Use a design token.`;

describe('Raw hex', () => {
  it('fails naming the file and line', async () => {
    const root = await fixture('raw', {
      'packages/ui/src/index.ts': 'export {};\n',
      'packages/ui/src/button.css': '.button {\n  color: var(--gk-color-tx);\n  background: #1a2b3c;\n}\n',
    });
    assert.deepEqual(await lint(root), [message('packages/ui/src/button.css', 3, '#1a2b3c')]);
  });

  it('lints apps/*/src too', async () => {
    const root = await fixture('apps', {
      'apps/hosted-login/src/main.tsx': "const accent = '#0b7d62';\n",
      'apps/hosted-login/index.html': '<meta name="theme-color" content="#0b7d62">\n',
    });
    assert.deepEqual(await lint(root), [message('apps/hosted-login/src/main.tsx', 1, '#0b7d62')]);
  });

  it('lints every text file whatever its extension, and skips binaries', async () => {
    const root = await fixture('extensions', {
      'packages/ui/src/notes': 'accent #abcdef\n',
      'packages/ui/src/theme.scss': '$accent: #abc;\n',
      'packages/ui/src/font.woff2': Buffer.from([0x77, 0x4f, 0x46, 0x32, 0x00, ...Buffer.from('#123456')]),
    });
    assert.deepEqual((await lint(root)).sort(), [
      message('packages/ui/src/notes', 1, '#abcdef'),
      message('packages/ui/src/theme.scss', 1, '#abc'),
    ]);
  });

  it('follows symlinked directories', async (t) => {
    const root = await fixture('symlink', { 'shared/colours.css': 'a { color: #fff; }\n' });
    try {
      await symlink(path.join(root, 'shared'), path.join(root, 'packages/ui/src/shared'), 'junction');
    } catch (error) {
      t.skip(`symlinks unavailable here: ${error.code}`);
      return;
    }
    assert.deepEqual(await lint(root), [message('packages/ui/src/shared/colours.css', 1, '#fff')]);
  });

  it('finds every hex form, and nothing that only looks like one', () => {
    const values = (text) => findRawColours(text).map((f) => f.value);
    assert.deepEqual(values('a { color: #fff; fill: #FFFFFF80; stroke: #abcd }'), ['#fff', '#FFFFFF80', '#abcd']);
    assert.deepEqual(values("const style = { color: '#1A2B3C' };"), ['#1A2B3C']);
    assert.deepEqual(values('#root, .x#main, &#123; #faded-panel, #12345'), []);
  });

  it('skips url(#id) fragment references', () => {
    const values = (text) => findRawColours(text).map((f) => f.value);
    assert.deepEqual(values('fill: url(#abc); mask: url("#bad"); clip-path: url( \'#face\' );'), []);
    assert.deepEqual(values('fill: url(#abc) #def;'), ['#def']);
  });

  it('flags rgb(), rgba(), hsl() and hsla() with literal numbers only', () => {
    const values = (text) => findRawColours(text).map((f) => f.value);
    assert.deepEqual(
      values('a { color: rgb(1, 2, 3); b: rgba(0,0,0,.5); c: hsl(120 50% 50%); d: HSLA(.5turn, 1%, 1%, 1) }'),
      ['rgb(1, 2, 3)', 'rgba(0,0,0,.5)', 'hsl(120 50% 50%)', 'HSLA(.5turn, 1%, 1%, 1)']);
    assert.deepEqual(values('a { color: rgb(var(--gk-rgb)); b: hsl(from var(--gk-color-ac) h s l) }'), []);
  });

  it('passes the real repository', async () => {
    assert.deepEqual(await lint(repository), []);
  });
});

describe('QR exception', () => {
  it('allows raw colours in the named QR file only', async () => {
    const root = await fixture('qr', {
      [QR_EXCEPTION]: "export const light = '#ffffff';\nexport const dark = 'rgb(0, 0, 0)';\n",
      'packages/ui/src/qr/other.tsx': "export const dark = '#000000';\n",
    });
    assert.deepEqual(await lint(root), [message('packages/ui/src/qr/other.tsx', 1, '#000000')]);
  });
});

describe('Main guard', () => {
  it('runs the lint when started through a link to the script', async (t) => {
    const linked = path.join(temporary, 'linked');
    await mkdir(linked, { recursive: true });
    const link = path.join(linked, 'check-no-raw-hex.mjs');
    try {
      await symlink(script, link, 'file');
    } catch (error) {
      t.skip(`symlinks unavailable here: ${error.code}`);
      return;
    }
    const result = spawnSync(process.execPath, [link], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /No raw colours/);
  });

  it('runs the lint when started by its own path', () => {
    const result = spawnSync(process.execPath, [script], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /No raw colours/);
  });
});
