// The No third party row of the Story 1.14 matrix: what @gatekeep/ui's entry points reach may
// use React and React DOM at runtime and nothing else from outside the repository.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ENTRY_POINTS, check, checkEntry, checkManifest, importsIn, packageOf, stripComments } from './check-dependencies.mjs';

const script = fileURLToPath(new URL('./check-dependencies.mjs', import.meta.url));
const repository = path.resolve(path.dirname(script), '../../..');
const temporary = await mkdtemp(path.join(os.tmpdir(), 'gk-ui-deps-'));
after(() => rm(temporary, { recursive: true, force: true }));

const tokens = { name: '@gatekeep/design-tokens', devDependencies: { yaml: '2.9.1' } };
const workspace = async (name) => (name === tokens.name ? tokens : null);
const manifest = { name: '@gatekeep/ui', dependencies: { '@gatekeep/design-tokens': 'workspace:*' }, peerDependencies: { react: '19.3.1' } };
const entries = {
  'hosted.ts': "export * from './index';\n",
  'admin.ts': "export * from './index';\n",
  'index.ts': "export { Button } from './Button';\n",
  'Button.tsx': "import { useId } from 'react';\nimport styles from './Button.module.css';\n",
  'Button.module.css': '.button { color: var(--gk-color-tx); }\n',
  'styles.css': "@import '@gatekeep/design-tokens/tokens.css';\n@import './surface.css';\n",
  'surface.css': ':root { --x: 1px; }\n',
};

async function fixture(name, files = {}, ui = manifest, extra = {}) {
  const root = path.join(temporary, name);
  await mkdir(path.join(root, 'packages/ui/src'), { recursive: true });
  await mkdir(path.join(root, 'packages/design-tokens'), { recursive: true });
  await writeFile(path.join(root, 'packages/design-tokens/package.json'), JSON.stringify(tokens));
  await writeFile(path.join(root, 'packages/ui/package.json'), JSON.stringify(ui));
  for (const [file, text] of Object.entries({ ...entries, ...files })) {
    if (text === null) continue;
    await mkdir(path.dirname(path.join(root, 'packages/ui/src', file)), { recursive: true });
    await writeFile(path.join(root, 'packages/ui/src', file), text);
  }
  for (const [file, text] of Object.entries(extra)) {
    await mkdir(path.dirname(path.join(root, file)), { recursive: true });
    await writeFile(path.join(root, file), text);
  }
  return root;
}

const banned = (entry, file, specifier) =>
  `${entry}: src/${file} imports ${specifier}. Only React, React DOM and declared @gatekeep packages are allowed.`;

describe('No third party', () => {
  it('passes on the repository as it is', async () => {
    assert.deepEqual(await check(repository), []);
  });

  it('passes the command on the repository', () => {
    const run = spawnSync(process.execPath, [script], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
  });

  it('passes a clean fixture', async () => {
    assert.deepEqual(await check(await fixture('clean')), []);
  });

  it('allows React and React DOM, as dependencies or peers', async () => {
    assert.deepEqual(await checkManifest({ dependencies: { react: '19.3.1' }, peerDependencies: { 'react-dom': '19.3.1' } }, workspace), []);
  });

  it('fails on a headless primitive in any runtime field', async () => {
    for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
      const problems = await checkManifest({ [field]: { '@radix-ui/react-switch': '1.0.0' } }, workspace);
      assert.equal(problems.length, 1, field);
      assert.match(problems[0], /@radix-ui\/react-switch is a runtime dependency/);
    }
    assert.equal((await checkManifest({ bundleDependencies: ['react-aria'] }, workspace)).length, 1);
  });

  it('ignores dev dependencies', async () => {
    assert.deepEqual(await checkManifest({ devDependencies: { vite: '8.3.5', '@radix-ui/react-switch': '1.0.0' } }, workspace), []);
  });

  it('allows a first-party workspace package only while it has no runtime dependencies', async () => {
    assert.deepEqual(await checkManifest({ dependencies: { '@gatekeep/design-tokens': 'workspace:*' } }, workspace), []);
    const heavy = async () => ({ name: '@gatekeep/design-tokens', dependencies: { 'react-aria': '3.0.0' } });
    assert.match(
      (await checkManifest({ dependencies: { '@gatekeep/design-tokens': 'workspace:*' } }, heavy))[0],
      /brings runtime dependencies of its own: react-aria/,
    );
    // A published package under the @gatekeep scope is still third party.
    assert.match((await checkManifest({ dependencies: { '@gatekeep/other': '1.0.0' } }, workspace))[0], /is a runtime dependency/);
  });

  it('fails on what an entry point reaches, and ignores what it does not', async () => {
    const root = await fixture('reach', {
      'Button.tsx': "import { useId } from 'react';\nimport * as Switch from '@radix-ui/react-switch';\n",
      'unused.tsx': "import { motion } from 'framer-motion';\n",
    });
    assert.deepEqual((await check(root)).sort(), [
      banned('admin', 'Button.tsx', '@radix-ui/react-switch'),
      banned('hosted', 'Button.tsx', '@radix-ui/react-switch'),
    ]);
  });

  it('follows CSS @import and CSS Modules composes', async () => {
    const root = await fixture('css', {
      'surface.css': "@import 'normalize.css';\n",
      'Button.module.css': ".button { composes: base from 'some-css-kit/base.module.css'; composes: local from './local.module.css'; }\n",
      'local.module.css': ".local { composes: x from 'other-kit'; }\n",
    });
    assert.deepEqual((await check(root)).sort(), [
      banned('admin', 'Button.module.css', 'some-css-kit/base.module.css'),
      banned('admin', 'local.module.css', 'other-kit'),
      banned('admin', 'surface.css', 'normalize.css'),
      banned('hosted', 'Button.module.css', 'some-css-kit/base.module.css'),
      banned('hosted', 'local.module.css', 'other-kit'),
      banned('hosted', 'surface.css', 'normalize.css'),
    ]);
  });

  it('lets the admin entry reach what its allowlist names, and never Hosted', async () => {
    const root = await fixture('allow', { 'admin.ts': "export * from './index';\nimport 'react-aria';\n" });
    const packageDir = path.join(root, 'packages/ui');
    const admin = { ...ENTRY_POINTS.admin, allow: ['react-aria'] };
    assert.deepEqual(await checkEntry(packageDir, 'admin', admin, manifest), []);
    assert.deepEqual(await checkEntry(packageDir, 'admin', ENTRY_POINTS.admin, manifest), [banned('admin', 'admin.ts', 'react-aria')]);
    // The same allowance never reaches Hosted's graph.
    const hosted = await fixture('allow-hosted', { 'Button.tsx': "import 'react-aria';\n" });
    assert.deepEqual(
      await check(hosted, path.join(hosted, 'packages/ui'), { ...ENTRY_POINTS, admin }),
      [banned('hosted', 'Button.tsx', 'react-aria')],
    );
  });

  it('ignores import-like text in comments', async () => {
    const root = await fixture('comments', {
      'Button.tsx': "// import x from 'evil-line';\n/* import y from 'evil-block'; */\nconst url = 'https://example.com/x'; import { useId } from 'react';\n",
      'surface.css': "/* @import 'evil.css'; */\n:root { --x: 1px; }\n",
    });
    assert.deepEqual(await check(root), []);
    assert.deepEqual(importsIn("const u = 'http://x'; import a from 'kept';"), ['kept']);
    assert.equal(stripComments("a /* b */ 'c // d' // e"), "a   'c // d'  ");
  });

  it('reports a relative import that resolves to nothing, and a missing entry', async () => {
    const root = await fixture('missing', { 'index.ts': "export * from './Gone';\n", 'admin.ts': null });
    assert.deepEqual((await check(root)).sort(), [
      'admin: entry src/admin.ts does not exist.',
      'hosted: src/index.ts imports ./Gone, which resolves to no file.',
    ]);
  });

  it('reports a malformed workspace manifest instead of crashing', async () => {
    const root = await fixture('malformed', {}, manifest, { 'packages/broken/package.json': '{ "name": ' });
    const problems = await check(root);
    assert.equal(problems.length, 1);
    assert.match(problems[0], /^packages\/broken\/package\.json is not valid JSON/);
  });

  it('runs nothing when imported with an argv[1] that is not a file', () => {
    const code = `await import(${JSON.stringify(pathToFileURL(script).href)}); console.log('imported');`;
    const run = spawnSync(process.execPath, ['--input-type=module', '-e', code, path.join(temporary, 'no-such-file')], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(run.stdout.trim(), 'imported');
  });

  it('reads every import form', () => {
    const text = [
      "import a from 'one';",
      "import type { B } from 'two';",
      "export { c } from 'three';",
      "import 'four';",
      "const d = await import('five');",
      'import {\n  e,\n} from "seven/sub";',
    ].join('\n');
    assert.deepEqual(importsIn(text).map(packageOf).sort(), ['five', 'four', 'one', 'seven', 'three', 'two']);
    assert.deepEqual(importsIn("@import url('six/x.css');\n.a { composes: b c from \"eight\"; }", 'css').sort(), ['eight', 'six/x.css']);
    assert.equal(packageOf('@scope/name/deep'), '@scope/name');
    assert.equal(packageOf('react/jsx-runtime'), 'react');
  });
});
