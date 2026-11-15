// Hosted Login's bundle budget (Story 4.1, AR-31): every JavaScript and CSS file the build wrote,
// lazily loaded chunks included, totals at most 150 kB gzip. Fonts are woff2, already compressed, so they don't count, but
// they must come from the same origin, as everything the page loads must. It prints the total, so
// growth is visible, and exits non-zero, naming the total, when it's over.
//
//   node scripts/check-bundle-budget.mjs [dist]

import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

/** The budget, in bytes of gzip: 150 kB. */
export const BUDGET = 150 * 1000;

/** The path the bundle is served under (vite.config.ts `base`). */
export const BASE = '/login/';

const kB = (bytes) => `${(bytes / 1000).toFixed(1)} kB`;

/** Whether `url` leaves the page's origin: a scheme or a protocol-relative URL. */
const elsewhere = (url) => /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(url);

/** Every file under `directory`, as paths relative to it with forward slashes. */
async function filesUnder(directory, prefix = '') {
  const found = [];
  for (const entry of await readdir(path.join(directory, prefix), { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) found.push(...(await filesUnder(directory, relative)));
    else found.push(relative);
  }
  return found.sort();
}

/**
 * Measures the bundle in `dist`: every .js and .css file in it, gzipped, so a lazily imported chunk
 * and its CSS count as much as what index.html loads. Every URL index.html or a stylesheet names
 * must be on the page's own origin under the base, and a stylesheet may load only woff2 fonts.
 * Returns the files, the total and any problem.
 */
export async function measure(dist) {
  const index = await readFile(path.join(dist, 'index.html'), 'utf8');
  const problems = [];
  let loadsScript = false;
  for (const tag of index.matchAll(/<(?:script|link)\b[^>]*>/gi)) {
    const source = /\s(?:src|href)="([^"]+)"/i.exec(tag[0])?.[1];
    if (!source) continue;
    if (elsewhere(source) || !source.startsWith(BASE)) problems.push(`${source} isn't served from ${BASE} on the page's own origin.`);
    else if (/^<script/i.test(tag[0])) loadsScript = true;
  }

  const files = [];
  for (const relative of await filesUnder(dist)) {
    if (!/\.(?:js|css)$/.test(relative)) continue;
    const url = `${BASE}${relative}`;
    const bytes = await readFile(path.join(dist, ...relative.split('/')));
    files.push({ url, gzip: gzipSync(bytes).length });
    if (relative.endsWith('.css')) {
      for (const reference of bytes.toString('utf8').matchAll(/url\(\s*(['"]?)([^)'"]+)\1\s*\)/g)) {
        const target = reference[2];
        if (target.startsWith('#')) continue;
        if (elsewhere(target)) problems.push(`${url} loads ${target}, which isn't on the page's own origin.`);
        else if (!/\.woff2$/.test(target)) problems.push(`${url} loads ${target}: only woff2 fonts may be outside the budget.`);
      }
    }
  }

  if (!loadsScript) problems.push('index.html loads no script.');
  const total = files.reduce((sum, file) => sum + file.gzip, 0);
  return { files, total, problems };
}

/** Checks `dist` against the budget. Returns the lines to print and whether it passed. */
export async function check(dist, budget = BUDGET) {
  const { files, total, problems } = await measure(dist);
  const lines = files.map((file) => `${file.url}: ${kB(file.gzip)} gzip`);
  lines.push(`Total JS and CSS: ${kB(total)} gzip, of a ${kB(budget)} budget.`);
  if (total > budget) problems.push(`Hosted Login's JS and CSS are ${kB(total)} gzip, over the ${kB(budget)} budget.`);
  return { lines, problems, total };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const dist = path.resolve(process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist'));
  const { lines, problems } = await check(dist);
  for (const line of lines) console.log(line);
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    process.exit(1);
  }
}
