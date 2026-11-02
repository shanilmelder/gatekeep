// Fails on any raw colour (hex, or rgb()/hsl() with literal numbers) in packages/ui/src and
// apps/*/src: colours come from the design tokens (AD-22). The one exception is the QR
// encoder, whose modules are always dark on white in every theme so that scanners work
// (DESIGN.md, Hosted Login components).

import { readdir, readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** The QR encoder, relative to the repository: the only file that may hold raw colours. */
export const QR_EXCEPTION = 'packages/ui/src/qr/qr-code.tsx';

const HEX = /(?<![&\w])#(?:[0-9a-f]{8}|[0-9a-f]{6}|[0-9a-f]{3,4})(?![\w-])/gi;
const FUNCTIONAL = /\b(?:rgba?|hsla?)\(\s*[-+]?(?:\d|\.\d)[^)]*\)?/gi;
// A fragment reference such as url(#gradient) names an element, not a colour.
const URL_FRAGMENT = /url\(\s*(['"]?)#[^)'"]*\1\s*\)/gi;

/** Returns each raw colour in a file's text, with its line number. */
export function findRawColours(text) {
  const found = [];
  text.split(/\r?\n/).forEach((raw, index) => {
    const line = raw.replace(URL_FRAGMENT, (match) => ' '.repeat(match.length));
    const matches = [...line.matchAll(HEX), ...line.matchAll(FUNCTIONAL)].sort((a, b) => a.index - b.index);
    for (const match of matches) found.push({ line: index + 1, value: match[0] });
  });
  return found;
}

/** Every file under `directory`, following symlinked directories once each. */
async function* files(directory, visited = new Set()) {
  const real = await realpath(directory);
  if (visited.has(real)) return;
  visited.add(real);
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    const isDirectory = entry.isDirectory() || (entry.isSymbolicLink() && (await stat(full)).isDirectory());
    if (isDirectory) yield* files(full, visited);
    else yield full;
  }
}

/** The directories the lint reads, relative to the repository: packages/ui/src and apps/*\/src. */
export async function lintedDirectories(root) {
  const directories = ['packages/ui/src'];
  const apps = await readdir(path.join(root, 'apps'), { withFileTypes: true }).catch(() => []);
  for (const app of apps) {
    const source = `apps/${app.name}/src`;
    if (await stat(path.join(root, source)).then((s) => s.isDirectory(), () => false)) directories.push(source);
  }
  return directories;
}

/** Lints the repository at `root`. Returns one message per raw colour. */
export async function lint(root) {
  const problems = [];
  for (const directory of await lintedDirectories(root)) {
    if (!(await stat(path.join(root, directory)).then(() => true, () => false))) continue;
    for await (const file of files(path.join(root, directory))) {
      const relative = path.relative(root, file).split(path.sep).join('/');
      if (relative === QR_EXCEPTION) continue;
      const bytes = await readFile(file);
      // Every text file, whatever its extension. A NUL byte marks a binary, such as a font.
      if (bytes.includes(0)) continue;
      for (const { line, value } of findRawColours(bytes.toString('utf8'))) {
        problems.push(`${relative}:${line}: raw colour ${value}. Use a design token.`);
      }
    }
  }
  return problems;
}

async function isMain() {
  if (!process.argv[1]) return false;
  const [argv, self] = await Promise.all([realpath(process.argv[1]), realpath(fileURLToPath(import.meta.url))]);
  return process.platform === 'win32' ? argv.toLowerCase() === self.toLowerCase() : argv === self;
}

if (await isMain()) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
  const problems = await lint(root);
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    process.exit(1);
  }
  console.log('No raw colours in packages/ui/src or apps/*/src.');
}
