// Story 1.18: every screen in packages/hosted-screens is props-only. What it shows comes from
// its props and the catalogue, with no fetch, storage, navigation, global state, router or
// state library: serving the steps is Story 4.1's. This scans the screens' source for them.

import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { importsIn, packageOf, stripComments } from './check-dependencies.mjs';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const source = path.join(repository, 'packages/hosted-screens/src');

/** What a props-only screen never uses, each with the pattern that finds it outside comments. */
const BANNED = [
  ['fetch(', /\bfetch\s*\(/],
  ['XMLHttpRequest', /\bXMLHttpRequest\b/],
  ['localStorage', /\blocalStorage\b/],
  ['sessionStorage', /\bsessionStorage\b/],
  ['location.', /(?<![\w.])location\s*\./],
  ['history.', /(?<![\w.])history\s*\./],
  ['window.', /\bwindow\s*\./],
];
/** Router and state libraries, by package name. */
const STATE_LIBRARY =
  /^(?:react-router(?:-dom)?|@remix-run\/router|wouter|@tanstack\/.+|redux|react-redux|@reduxjs\/toolkit|zustand|jotai|mobx(?:-react(?:-lite)?)?|recoil|valtio|xstate|@xstate\/react|swr)$/;

/** The banned uses in one file's text, as short names. */
export function impurities(text) {
  const code = stripComments(text);
  const found = BANNED.filter(([, pattern]) => pattern.test(code)).map(([name]) => name);
  for (const specifier of importsIn(text)) {
    if (STATE_LIBRARY.test(packageOf(specifier))) found.push(`import ${specifier}`);
  }
  return found;
}

async function sources(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await sources(full)));
    else if (/\.(?:ts|tsx|mts|js|jsx|mjs)$/.test(entry.name)) files.push(full);
  }
  return files;
}

describe('Props-only screens', () => {
  it('finds no fetch, storage, navigation, global state or router in packages/hosted-screens/src', async () => {
    const files = await sources(source);
    assert.ok(files.length > 0);
    for (const file of files) {
      assert.deepEqual(impurities(await readFile(file, 'utf8')), [], path.relative(repository, file));
    }
  });

  it('catches each banned use, and ignores comments and look-alikes', () => {
    const cases = {
      "const r = await fetch('/api');": ['fetch('],
      'new XMLHttpRequest();': ['XMLHttpRequest'],
      "localStorage.getItem('a');": ['localStorage'],
      "sessionStorage.setItem('a', 'b');": ['sessionStorage'],
      "location.assign('/');": ['location.'],
      'history.back();': ['history.'],
      'window.open();': ['window.'],
      "import { useNavigate } from 'react-router';": ['import react-router'],
      "import { createStore } from 'zustand';": ['import zustand'],
      "import { useQuery } from '@tanstack/react-query';": ['import @tanstack/react-query'],
      "import { configureStore } from '@reduxjs/toolkit';": ['import @reduxjs/toolkit'],
      "import { useState } from 'react';\n// fetch(x) and window.open in a comment\nconst backHref = props.location;": [],
    };
    for (const [text, expected] of Object.entries(cases)) assert.deepEqual(impurities(text), expected, text);
  });
});
