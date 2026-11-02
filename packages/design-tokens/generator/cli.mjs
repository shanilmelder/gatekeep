// pnpm --filter @gatekeep/design-tokens generate   writes the three outputs from DESIGN.md.
// pnpm --filter @gatekeep/design-tokens check      regenerates in memory and fails, naming
//                                                  the file and token, on any drift.
//
// --root <dir> runs against another copy of the repository (the generator's own tests).

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DESIGN_PATH, TokenError, checkRepository, renderAll } from './tokens.mjs';

const [command, ...options] = process.argv.slice(2);
const rootOption = options.indexOf('--root');
const root = rootOption === -1
  ? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')
  : path.resolve(options[rootOption + 1] ?? '');

async function readDesign() {
  try {
    return await readFile(path.join(root, DESIGN_PATH), 'utf8');
  } catch (error) {
    throw new TokenError(`${DESIGN_PATH}: cannot be read (${error.code ?? error.message}).`);
  }
}

try {
  if (command === 'generate') {
    const outputs = renderAll(await readDesign());
    for (const [file, content] of Object.entries(outputs)) {
      await mkdir(path.dirname(path.join(root, file)), { recursive: true });
      await writeFile(path.join(root, file), content);
      console.log(`wrote ${file}`);
    }
  } else if (command === 'check') {
    await readDesign();
    const problems = await checkRepository(root);
    if (problems.length > 0) {
      for (const problem of problems) console.error(problem);
      console.error(`Design tokens drifted from ${DESIGN_PATH}: run \`pnpm --filter @gatekeep/design-tokens generate\` and commit.`);
      process.exit(1);
    }
    console.log('Design tokens match DESIGN.md.');
  } else {
    console.error('Usage: node generator/cli.mjs generate|check [--root <dir>]');
    process.exit(2);
  }
} catch (error) {
  if (!(error instanceof TokenError)) throw error;
  console.error(error.message);
  process.exit(1);
}
