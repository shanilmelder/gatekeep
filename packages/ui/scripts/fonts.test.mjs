// The fonts check: the bundled copies must be byte for byte the pinned geist release.

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { FONT_FILES, checkFonts } from './fonts.mjs';

const temporary = await mkdtemp(path.join(os.tmpdir(), 'gk-ui-fonts-'));
after(() => rm(temporary, { recursive: true, force: true }));

/** A fake geist package and a fonts directory holding copies of its files. */
async function fixture(name) {
  const source = path.join(temporary, name, 'geist');
  const target = path.join(temporary, name, 'fonts');
  await mkdir(target, { recursive: true });
  for (const [from, file] of FONT_FILES) {
    await mkdir(path.dirname(path.join(source, from)), { recursive: true });
    await writeFile(path.join(source, from), `bytes of ${file}`);
    await writeFile(path.join(target, file), `bytes of ${file}`);
  }
  return { source, target };
}

describe('Fonts check', () => {
  it('passes on exact copies', async () => {
    const { source, target } = await fixture('exact');
    assert.deepEqual(await checkFonts(source, target), []);
  });

  it('fails naming a missing file, and creates nothing', async () => {
    const { source, target } = await fixture('missing');
    await rm(path.join(target, 'GeistMono-Variable.woff2'));
    assert.deepEqual(await checkFonts(source, target), [
      'packages/ui/src/fonts/GeistMono-Variable.woff2: missing. Run `pnpm --filter @gatekeep/ui fonts`.',
    ]);

    const absent = path.join(temporary, 'missing', 'no-fonts');
    assert.equal((await checkFonts(source, absent)).length, FONT_FILES.length);
    assert.equal(existsSync(absent), false);
  });

  it('fails naming a byte mismatch', async () => {
    const { source, target } = await fixture('mismatch');
    await writeFile(path.join(target, 'LICENSE.txt'), 'bytes of LICENSE.txt\r\n');
    assert.deepEqual(await checkFonts(source, target), [
      'packages/ui/src/fonts/LICENSE.txt: differs from geist/LICENSE.txt.',
    ]);
  });

  it('names the geist package when it is not installed', async () => {
    const { target } = await fixture('no-package');
    await assert.rejects(checkFonts(path.join(temporary, 'nowhere', 'geist'), target), /The geist package is not installed/);
  });

  it('reports a read error other than a missing file as itself', async () => {
    const { source, target } = await fixture('unreadable');
    // A directory in place of the file: reading it fails with EISDIR, not ENOENT.
    await rm(path.join(target, 'Geist-Variable.woff2'));
    await mkdir(path.join(target, 'Geist-Variable.woff2'));
    assert.deepEqual(await checkFonts(source, target), [
      'packages/ui/src/fonts/Geist-Variable.woff2: cannot be read (EISDIR).',
    ]);
  });
});
