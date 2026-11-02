// Copies Geist and Geist Mono, and their licence, from the pinned geist package into
// src/fonts, where styles.css serves them. With --check, fails if the committed copies
// differ from the package's: the fonts in the repository are exactly the pinned release.

import { access, copyFile, mkdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Each bundled file: its path in the geist package and its name in src/fonts. */
export const FONT_FILES = [
  ['dist/fonts/geist-sans/Geist-Variable.woff2', 'Geist-Variable.woff2'],
  ['dist/fonts/geist-mono/GeistMono-Variable.woff2', 'GeistMono-Variable.woff2'],
  ['LICENSE.txt', 'LICENSE.txt'],
];

const TARGET_NAME = 'packages/ui/src/fonts';

async function readOrNull(file) {
  try {
    return await readFile(file);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

async function requirePackage(sourceDir) {
  try {
    await access(sourceDir);
  } catch {
    throw new Error(`The geist package is not installed at ${sourceDir}. Run \`pnpm install\`.`);
  }
}

/** Compares the bundled copies in `targetDir` with the package in `sourceDir`. Returns the problems. */
export async function checkFonts(sourceDir, targetDir) {
  await requirePackage(sourceDir);
  const problems = [];
  for (const [from, name] of FONT_FILES) {
    const expected = await readOrNull(path.join(sourceDir, from));
    if (expected === null) {
      problems.push(`geist/${from}: missing from the geist package.`);
      continue;
    }
    let actual;
    try {
      actual = await readOrNull(path.join(targetDir, name));
    } catch (error) {
      problems.push(`${TARGET_NAME}/${name}: cannot be read (${error.code ?? error.message}).`);
      continue;
    }
    if (actual === null) problems.push(`${TARGET_NAME}/${name}: missing. Run \`pnpm --filter @gatekeep/ui fonts\`.`);
    else if (!expected.equals(actual)) problems.push(`${TARGET_NAME}/${name}: differs from geist/${from}.`);
  }
  return problems;
}

/** Copies the bundled files from the package in `sourceDir` into `targetDir`. */
export async function copyFonts(sourceDir, targetDir) {
  await requirePackage(sourceDir);
  await mkdir(targetDir, { recursive: true });
  for (const [from, name] of FONT_FILES) {
    await copyFile(path.join(sourceDir, from), path.join(targetDir, name));
    console.log(`copied ${from} to src/fonts/${name}`);
  }
}

async function isMain() {
  if (!process.argv[1]) return false;
  const [argv, self] = await Promise.all([realpath(process.argv[1]), realpath(fileURLToPath(import.meta.url))]);
  return process.platform === 'win32' ? argv.toLowerCase() === self.toLowerCase() : argv === self;
}

if (await isMain()) {
  const ui = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const source = path.join(ui, 'node_modules', 'geist');
  const target = path.join(ui, 'src', 'fonts');
  try {
    if (process.argv.includes('--check')) {
      const problems = await checkFonts(source, target);
      if (problems.length > 0) {
        for (const problem of problems) console.error(problem);
        process.exit(1);
      }
      console.log('Bundled fonts match the pinned geist package.');
    } else {
      await copyFonts(source, target);
    }
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
