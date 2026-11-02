// Prints the @playwright/test version the catalog in pnpm-workspace.yaml pins, for the tests
// image to install the matching Chromium (deploy/docker/tests.Dockerfile). Reads only the
// top-level catalog map, and fails unless the version is an exact x.y.z.
//
// Usage: node playwright-version.mjs <path to pnpm-workspace.yaml>

import { readFileSync } from 'node:fs';

const file = process.argv[2];
const lines = readFileSync(file, 'utf8').replace(/^﻿/, '').split(/\r?\n/);

const start = lines.findIndex((line) => /^catalog:\s*(#.*)?$/.test(line));
if (start === -1) fail(`${file} has no top-level catalog: map.`);

const versions = [];
for (const line of lines.slice(start + 1)) {
  if (/^\S/.test(line)) break; // the next top-level key ends the catalog
  const match = /^\s+(['"]?)@playwright\/test\1\s*:\s*(['"]?)([^'"\s#]+)\2\s*(#.*)?$/.exec(line);
  if (match) versions.push(match[3]);
}

if (versions.length !== 1) fail(`${file}: the catalog pins @playwright/test ${versions.length} times, not once.`);
if (!/^\d+\.\d+\.\d+$/.test(versions[0])) fail(`${file}: @playwright/test is "${versions[0]}", not an exact x.y.z version.`);
console.log(versions[0]);

function fail(message) {
  console.error(message);
  process.exit(1);
}
