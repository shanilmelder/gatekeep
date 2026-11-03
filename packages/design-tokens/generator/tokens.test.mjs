// One test per row of the Story 1.13 matrix that the generator owns: Generate, Drift, Bad
// source and Scope (the selector the CSS declares; the browser test proves it renders).

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  DESIGN_PATH,
  OUTPUT_PATHS,
  SCHEME_COLORS,
  SCHEME_TOKENS,
  TokenError,
  compareOutput,
  frontmatterOf,
  parseDesign,
  renderAll,
} from './tokens.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const design = readFileSync(path.join(root, DESIGN_PATH), 'utf8').replace(/\r\n/g, '\n');
const cli = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');
const temporary = mkdtempSync(path.join(os.tmpdir(), 'gk-tokens-'));
after(() => rmSync(temporary, { recursive: true, force: true }));

/** A copy of the repository holding only DESIGN.md, or nothing. */
function repositoryCopy(name, withDesign = true) {
  const copy = path.join(temporary, name);
  mkdirSync(path.dirname(path.join(copy, DESIGN_PATH)), { recursive: true });
  if (withDesign) writeFileSync(path.join(copy, DESIGN_PATH), design);
  return copy;
}

function runCli(command, copy) {
  return spawnSync(process.execPath, [cli, command, '--root', copy], { encoding: 'utf8' });
}

describe('Generate', () => {
  const model = parseDesign(design);
  const outputs = renderAll(design);

  it('has the 24 Design System tokens in both schemes', () => {
    assert.equal(SCHEME_TOKENS.length, 24);
    for (const scheme of ['light', 'dark']) {
      assert.deepEqual(Object.keys(model.schemes[scheme]), SCHEME_TOKENS);
    }
    assert.equal(model.schemes.light.bg, '#f6f6f4');
    assert.equal(model.schemes.dark.bg, '#0d0e10');
    assert.equal(model.schemes.dark.sh, '0 1px 2px rgba(0,0,0,.4), 0 10px 30px rgba(0,0,0,.5)');
  });

  it('carries the extensions, type, space, radius and elevation', () => {
    assert.deepEqual(Object.keys(model.colors), ['knob', 'code-muted', 'code-string', 'code-keyword', 'code-gutter']);
    assert.equal(model.typography['hosted-button'].fontWeight, '600');
    assert.equal(model.typography.label.letterSpacing, '0.08em');
    assert.equal(model.spacing['hosted-card-w'], '384px');
    assert.equal(model.rounded.control, '7px');
    assert.equal(model.elevation.scrim, 'rgba(10,10,12,.45)');
    assert.deepEqual(model.elevation.motion, { durationMin: '150ms', durationMax: '200ms', easing: 'ease', rise: '6px' });
  });

  it('maps references and shorthand rather than copying them', () => {
    assert.equal(model.components['focus-ring']['outline-color'], 'var(--gk-color-ac)');
    assert.equal(model.components.tabs['active-underline'], '2px var(--gk-color-tx)');
    assert.equal(model.components['button-primary'].typography, 'var(--gk-font-button)');
    assert.equal(model.components.toggle['size-width'], '28px');
    assert.equal(model.components.toggle['size-height'], '16px');
    assert.match(model.typography.code.fontFamily, /^"Geist Mono", /);
  });

  it('writes every token into each output', () => {
    const css = outputs[OUTPUT_PATHS.css];
    const ts = outputs[OUTPUT_PATHS.ts];
    const cs = outputs[OUTPUT_PATHS.cs];
    for (const name of SCHEME_COLORS) {
      // Light, dark, and dark again for the auto scope under a dark preference.
      assert.equal(css.split('\n').filter((l) => l.trim().startsWith(`--gk-color-${name}:`)).length, 3, name);
      assert.ok(ts.includes(`"${name}": "${model.schemes.dark[name]}"`), name);
    }
    assert.ok(cs.includes('internal const string AcSf = "#e2f3ec";'));
    assert.ok(cs.includes('internal const string AcSf = "#0e2a21";'));
    assert.ok(cs.includes('internal const string Knob = "#ffffff";'));
    assert.ok(cs.includes('internal const string Step48 = "48px";'));
    assert.ok(cs.includes('namespace Gatekeep.Modules.Tenancy.Core.Theme;'));
    assert.ok(!/(^|\s)public\s/m.test(cs), 'C# constants are internal');
  });

  it('emits the body shorthand, and letter spacing beside a shorthand that has it', () => {
    const lines = outputs[OUTPUT_PATHS.css].split('\n').map((l) => l.trim());
    assert.ok(lines.includes('--gk-font-body: 400 13px/20px "Geist", ui-sans-serif, system-ui, sans-serif;'));
    assert.ok(!lines.some((l) => l.startsWith('--gk-font-body-letter-spacing:')));
    assert.ok(lines.includes('--gk-font-label-letter-spacing: 0.08em;'));
  });

  it('generate writes the three outputs, and check passes on them', () => {
    const copy = repositoryCopy('generate');
    const generated = runCli('generate', copy);
    assert.equal(generated.status, 0, generated.stderr);
    for (const [file, content] of Object.entries(outputs)) {
      assert.equal(readFileSync(path.join(copy, file), 'utf8'), content, file);
    }
    const checked = runCli('check', copy);
    assert.equal(checked.status, 0, checked.stderr);
  });

  it('check exits non-zero on drift, naming the file and token', () => {
    const copy = repositoryCopy('drift');
    assert.equal(runCli('generate', copy).status, 0);
    const css = path.join(copy, OUTPUT_PATHS.css);
    writeFileSync(css, readFileSync(css, 'utf8').replace('--gk-radius-card: 10px;', '--gk-radius-card: 12px;'));

    const checked = runCli('check', copy);
    assert.equal(checked.status, 1);
    assert.match(checked.stderr, /packages\/design-tokens\/css\/tokens\.css: token .*--gk-radius-card is/);
  });

  it('names DESIGN.md when it is missing, without a stack', () => {
    const copy = repositoryCopy('empty', false);
    for (const command of ['generate', 'check']) {
      const result = runCli(command, copy);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /DESIGN\.md: cannot be read \(ENOENT\)\./);
      assert.doesNotMatch(result.stderr, /\n\s+at /);
    }
  });
});

describe('Drift', () => {
  const outputs = renderAll(design);

  it('names the file and token of a hand-edited CSS value', () => {
    const css = outputs[OUTPUT_PATHS.css];
    const edited = css.replace('--gk-color-ac: #0b7d62;', '--gk-color-ac: #0b7d63;');
    const problems = compareOutput(OUTPUT_PATHS.css, css, edited);
    assert.equal(problems.length, 1);
    assert.match(problems[0], /^packages\/design-tokens\/css\/tokens\.css: token .*--gk-color-ac is `--gk-color-ac: #0b7d63;`/);
  });

  it('names the TypeScript key path and the C# constant', () => {
    const ts = outputs[OUTPUT_PATHS.ts];
    const [tsProblem] = compareOutput(OUTPUT_PATHS.ts, ts, ts.replace('"gutter": "24px"', '"gutter": "25px"'));
    assert.match(tsProblem, /tokens\.generated\.ts: token tokens\.spacing\.gutter is/);

    const cs = outputs[OUTPUT_PATHS.cs];
    const [csProblem] = compareOutput(OUTPUT_PATHS.cs, cs, cs.replace('Scrim = "rgba(10,10,12,.45)"', 'Scrim = "rgba(0,0,0,.5)"'));
    assert.match(csProblem, /DesignTokens\.g\.cs: token DesignTokens\.Elevation\.Scrim is/);
  });

  it('names the token when DESIGN.md changed without regenerating', () => {
    const changed = renderAll(design.replace("tx2-dark: '#a3a3aa'", "tx2-dark: '#a3a3ab'"));
    const problems = compareOutput(OUTPUT_PATHS.cs, changed[OUTPUT_PATHS.cs], outputs[OUTPUT_PATHS.cs]);
    assert.deepEqual(problems, [
      'src/Modules/Tenancy/Core/Theme/DesignTokens.g.cs: token DesignTokens.Dark.Tx2 is ' +
        '`internal const string Tx2 = "#a3a3aa";`, expected `internal const string Tx2 = "#a3a3ab";`.',
    ]);
  });

  it('reports a missing or removed token and a missing file', () => {
    const css = outputs[OUTPUT_PATHS.css];
    const removed = css.split('\n').filter((l) => !l.includes('--gk-radius-card:')).join('\n');
    assert.match(compareOutput(OUTPUT_PATHS.css, css, removed)[0], /token .*--gk-radius-card is missing/);
    assert.deepEqual(compareOutput(OUTPUT_PATHS.css, css, null), [`${OUTPUT_PATHS.css}: missing. Run the generator.`]);
  });

  it('flags an edit outside any token, and ignores line endings', () => {
    const css = outputs[OUTPUT_PATHS.css];
    assert.deepEqual(compareOutput(OUTPUT_PATHS.css, css, css.replace(/\n/g, '\r\n')), []);
    assert.match(compareOutput(OUTPUT_PATHS.css, css, css.replace('Do not edit', 'Edit freely'))[0], /outside any token/);
  });
});

describe('Bad source', () => {
  const failsNaming = (source, key) =>
    assert.throws(() => parseDesign(source), (error) => error instanceof TokenError && error.message.startsWith(`${key}:`));

  it('fails naming a missing colour', () => {
    failsNaming(design.replace("  bg-dark: '#0d0e10'\n", ''), 'colors.bg-dark');
    failsNaming(design.replace(/\r?\n  info-sf: '#e5edfb'/, ''), 'colors.info-sf');
  });

  it('fails naming an unparseable value', () => {
    failsNaming(design.replace("ac: '#0b7d62'", "ac: 'jade'"), 'colors.ac');
    failsNaming(design.replace('gutter: 24px', 'gutter: wide'), 'spacing.gutter');
    failsNaming(design.replace('card: 10px', 'card: 10'), 'rounded.card');
    failsNaming(design.replace(/fontFamily: Geist Mono/, 'fontFamily: Comic Sans'), 'typography.label.fontFamily');
    failsNaming(design.replace('motion: 150ms-200ms ease', 'motion: quick'), 'elevation.motion');
    failsNaming(design.replace("outlineColor: '{colors.ac}'", "outlineColor: '{colors.jade}'"), 'components.focus-ring.outlineColor');
  });

  it('fails on a missing section or frontmatter', () => {
    failsNaming(design.replace(/^rounded:/m, 'roundedness:'), 'rounded');
    failsNaming('# No frontmatter\n', 'DESIGN.md');
  });

  it('fails when a token the UI depends on is renamed', () => {
    failsNaming(design.replace(/^  body:$/m, '  copy:'), 'typography.body');
    failsNaming(design.replace(/^  focus-ring:$/m, '  focus-outline:'), 'components.focus-ring.outlineWidth');
    failsNaming(design.replace('    outlineOffset: 2px\n', ''), 'components.focus-ring.outlineOffset');
  });

  const component = (yaml) => design.replace(/^components:\n/m, `components:\n${yaml}`);

  it('fails on a component value that would emit broken CSS', () => {
    failsNaming(component("  probe:\n    color: '{colors.ac}; color: red'\n"), 'components.probe.color');
    failsNaming(component("  probe:\n    color: '{spacing.nope}'\n"), 'components.probe.color');
    failsNaming(component('  probe:\n    color: red\n'), 'components.probe.color');
    failsNaming(component('  probe:\n    border: 1px solid red\n'), 'components.probe.border');
    failsNaming(component('  probe:\n    height: 20\n'), 'components.probe.height');
    failsNaming(component("  probe:\n    height: '20'\n"), 'components.probe.height');
    failsNaming(component('  probe:\n    height: .inf\n'), 'components.probe.height');
    failsNaming(component('  probe:\n    Bad_Name: 2px\n'), 'components.probe.Bad_Name');
  });

  it('maps a sh reference to the elevation variable, and keeps colour keywords', () => {
    const model = parseDesign(component(
      "  probe:\n    shadow: '{colors.sh}'\n    background: transparent\n    stroke: currentColor\n    fill: none\n    color: inherit\n"));
    assert.deepEqual(model.components.probe, {
      shadow: 'var(--gk-elevation-sh)', background: 'transparent', stroke: 'currentColor', fill: 'none', color: 'inherit',
    });
  });

  it('fails when two properties or tokens emit the same variable', () => {
    failsNaming(component('  probe:\n    size: 28x16px\n    size-width: 30px\n'), 'components.probe.size-width');
    failsNaming(component('  font:\n    body: 2px\n'), 'components.font.body');
    failsNaming(component('  color:\n    bg: transparent\n'), 'components.color.bg');
  });

  it('fails on names that would not compile as C#', () => {
    failsNaming(design.replace(/^  display:$/m, '  2x:'), 'typography.2x');
    failsNaming(design.replace(/^  tag: 4px$/m, '  9tag: 4px'), 'rounded.9tag');
    failsNaming(design.replace(/^  display:$/m, '  typography:'), 'typography.typography');
    failsNaming(design.replace(/^  display:$/m, '  font-size:'), 'typography.font-size.fontSize');
    failsNaming(design.replace(/^  full: 9999px$/m, '  full: 9999px\n  tag-: 5px'), 'rounded.tag-');
  });

  it('fails when the motion durations are out of order', () => {
    failsNaming(design.replace('motion: 150ms-200ms ease', 'motion: 250ms-200ms ease'), 'elevation.motion');
  });

  it('reads frontmatter with a BOM, and closed at the end of the file', () => {
    assert.equal(frontmatterOf('﻿---\na: 1\n---\nbody'), 'a: 1');
    assert.equal(frontmatterOf('---\na: 1\n---'), 'a: 1');
    assert.deepEqual(parseDesign(`﻿${design}`), parseDesign(design));
  });
});

describe('Scope', () => {
  it('declares light on :root and [data-gk-theme], and dark on [data-gk-scheme="dark"] and dark-preferring auto only', () => {
    const css = renderAll(design)[OUTPUT_PATHS.css];
    assert.ok(
      css.includes(':root,\n[data-gk-theme],\n[data-gk-scheme="light"],\n[data-gk-scheme="auto"] {\n  color-scheme: light;\n  --gk-color-bg: #f6f6f4;'),
    );
    assert.ok(css.includes('[data-gk-scheme="dark"] {\n  color-scheme: dark;\n  --gk-color-bg: #0d0e10;'));
    // Auto follows the device with no script: the dark values only under a dark preference.
    assert.ok(
      css.includes('@media (prefers-color-scheme: dark) {\n  [data-gk-scheme="auto"] {\n    color-scheme: dark;\n    --gk-color-bg: #0d0e10;'),
    );
    assert.equal(css.match(/--gk-color-bg: #0d0e10;/g).length, 2);
    const media = css.slice(css.indexOf('@media'));
    assert.equal(media.slice(0, media.indexOf('\n}\n')).match(/^ {4}--gk-color-[\w-]+: /gm).length, SCHEME_COLORS.length);
    // A hand edit inside the auto scope is drift too, named by its scope.
    const edited = css.replace(/(\[data-gk-scheme="auto"\] \{\n {4}color-scheme: dark;\n {4}--gk-color-bg: )#0d0e10;/, '$1#000000;');
    assert.notEqual(edited, css);
    const [problem] = compareOutput(OUTPUT_PATHS.css, css, edited);
    assert.match(problem, /token @media \(prefers-color-scheme: dark\) \[data-gk-scheme="auto"\] --gk-color-bg is/);
    // Component variables resolve on every scope, so a dark subtree gets a dark focus ring.
    assert.ok(css.includes(':root,\n[data-gk-theme],\n[data-gk-scheme] {\n'));
    assert.ok(/\[data-gk-scheme\] \{[^}]*--gk-focus-ring-outline-color: var\(--gk-color-ac\);/.test(css));
  });
});
