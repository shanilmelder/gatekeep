// The Literal row of the Story 4.1 matrix: a hard-coded user-facing string in a scanned file fails
// the lint, naming the file and line; text from the catalogue, the catalogue itself and what a user
// never reads pass.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { findInHtml, findInSource, lint } from './check-no-hardcoded-strings.mjs';

const script = fileURLToPath(new URL('./check-no-hardcoded-strings.mjs', import.meta.url));
const repository = path.resolve(path.dirname(script), '../../..');
const temporary = await mkdtemp(path.join(os.tmpdir(), 'gk-ui-strings-'));
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

const texts = (found) => found.map((f) => `${f.line} ${f.text}`);

describe('Literal', () => {
  it('fails on JSX text and a literal aria-label, naming the file and line', async () => {
    const root = await fixture('literal', {
      'packages/ui/src/Thing.tsx': [
        'export function Thing() {',
        '  return (',
        '    <div>',
        '      <p>Hello</p>',
        '      <button type="button" aria-label="Close" />',
        '    </div>',
        '  );',
        '}',
        '',
      ].join('\n'),
    });
    const problems = await lint(root);
    assert.equal(problems.length, 2);
    assert.match(problems[0], /^packages\/ui\/src\/Thing\.tsx:4: hard-coded text "Hello"\./);
    assert.match(problems[1], /^packages\/ui\/src\/Thing\.tsx:5: hard-coded text "aria-label="Close""\./);
  });

  it('exits non-zero when started on a repository with a literal', async () => {
    const root = await fixture('main', { 'apps/hosted-login/src/main.tsx': 'export const page = <p>Hosted Login</p>;\n' });
    const result = spawnSync(process.execPath, [script, root], { encoding: 'utf8' });
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stderr, /apps\/hosted-login\/src\/main\.tsx:1: hard-coded text "Hosted Login"/);
  });

  it('flags every text attribute, as a string, an expression or a branch of one', () => {
    const source = [
      'const a = <img alt="Logo" />;',
      "const b = <input placeholder={'Email'} />;",
      'const c = <span title={open ? `Open` : name} />;',
      "const d = <option label={name ?? 'None'} />;",
      'const e = <div aria-description="More" />;',
    ].join('\n');
    assert.deepEqual(texts(findInSource(source)), [
      '1 alt="Logo"',
      '2 placeholder="Email"',
      '3 title="Open"',
      '4 label="None"',
      '5 aria-description="More"',
    ]);
  });

  it('flags a literal as a child expression, whatever reaches it', () => {
    const source = [
      "const a = <p>{'Hello'}</p>;",
      "const b = <p>{open ? 'Yes' : 'No'}</p>;",
      "const c = <p>{x && 'Hi'}</p>;",
      'const d = <p>{`Welcome ${name}`}</p>;',
      "const e = <>{'Hi ' + name}</>;",
    ].join('\n');
    assert.deepEqual(texts(findInSource(source)), ['1 Hello', '2 Yes', '2 No', '3 Hi', '4 Welcome', '5 Hi']);
  });

  it('flags + concatenation in a text attribute', () => {
    assert.deepEqual(texts(findInSource("const a = <button aria-label={'Close ' + name} />;")), ['1 aria-label="Close "']);
  });

  it('passes child expressions with no letter-bearing literal', () => {
    const source = "const a = <p>{messages.hi}{' '}{count + 1}{open ? messages.on : ''}{a === 'b' && messages.x}</p>;";
    assert.deepEqual(findInSource(source), []);
  });

  it('passes catalogue text, values without letters, entities and attributes a user never reads', () => {
    const source = [
      'const a = <p>{messages.hello}</p>;',
      'const b = <span aria-label={formatMessage(messages.named, { name: "Ada" })} />;',
      'const c = <p>{count} / {total} &nbsp;&middot; 42 –</p>;',
      'const d = <div className="card" data-testid="hosted-page" role="img" type="button" />;',
      "const e = <input placeholder={messages.example} title={open ? messages.on : ''} />;",
    ].join('\n');
    assert.deepEqual(findInSource(source), []);
  });

  it('exempts the catalogue', async () => {
    const root = await fixture('catalogue', {
      'packages/ui/src/messages.tsx': "export const MessagesProvider = () => <p>Hello</p>;\nexport const x = { title: 'Something went wrong' };\n",
    });
    assert.deepEqual(await lint(root), []);
  });

  it('reads apps/*/index.html: text and attributes, but not a catalogue placeholder, script, style or comment', async () => {
    const html = [
      '<!doctype html>',
      '<html lang="en">',
      '<head><title>%gk:hostedFallbackTitle%</title><!--gk-head--><style>p{}</style></head>',
      '<body><noscript><p>%gk:hostedNoScript%</p></noscript>',
      '<div id="root" title="Root"></div>',
      '<p>Hosted Login</p>',
      '<script type="module" src="/src/main.tsx">const x = "text";</script>',
      '</body></html>',
    ].join('\n');
    assert.deepEqual(texts(findInHtml(html)), ['5 title="Root"', '6 Hosted Login']);

    const root = await fixture('html', { 'apps/admin-dashboard/index.html': '<title>Gatekeep Admin Dashboard</title>\n' });
    assert.deepEqual(await lint(root), [
      'apps/admin-dashboard/index.html:1: hard-coded text "Gatekeep Admin Dashboard". Add it to the message catalogue (packages/ui/src/messages.tsx).',
    ]);
  });

  it('passes the real repository', async () => {
    assert.deepEqual(await lint(repository), []);
  });
});
