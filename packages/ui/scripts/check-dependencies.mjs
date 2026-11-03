// Fails if what Hosted Login reaches in @gatekeep/ui uses a third-party runtime package other
// than React and React DOM (Story 1.14, AD-22): no headless or UI library. It walks the
// import graph from each entry point, so only files an entry reaches count, and checks the
// package manifest, so nothing third party is declared for runtime without an entry point
// allowing it. First-party @gatekeep workspace packages are allowed while their own runtime
// dependencies are only React, React DOM and such first-party packages, all the way down.
//
// It checks packages/hosted-screens too (Story 1.18), by what its screens actually reach: it
// follows each @gatekeep import into that package's own files, so a dependency @gatekeep/ui
// declares for its admin entry alone never fails the screens, while anything the hosted
// entry's graph reaches still counts. Of @gatekeep/ui, the screens may import only the hosted
// entry: not the admin entry, the bare package or its files directly. No relative import may
// leave its package.
//
// AD-22 lets @gatekeep/ui/admin use headless accessibility primitives and @gatekeep/ui/hosted
// one reviewed QR encoder. Neither is used, so both allowlists below are empty: adding a
// package to one is the reviewed change that lets that entry reach it. The hosted one stays
// empty for good: architecture review R-8 moved QR encoding to the server, which returns the
// SVG path data the TOTP enrolment screen draws, so Hosted Login needs no client encoder.

import { readdir, readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** The third-party packages every entry point may use at runtime. */
export const ALLOWED_RUNTIME = Object.freeze(['react', 'react-dom']);

/** Each entry point: the files it starts from and the extra packages it may reach. */
export const ENTRY_POINTS = Object.freeze({
  hosted: Object.freeze({ files: ['src/hosted.ts', 'src/styles.css'], allow: Object.freeze([]) }),
  admin: Object.freeze({ files: ['src/admin.ts', 'src/styles.css'], allow: Object.freeze([]) }),
});

/**
 * The Hosted screens package (Story 1.18), relative to the repository, with its entry. It
 * allows nothing extra; of @gatekeep/ui it may import the hosted entry only; and its
 * @gatekeep imports are followed, so what they reach is checked as its own.
 */
export const SCREENS = Object.freeze({
  dir: 'packages/hosted-screens',
  entries: Object.freeze({
    'hosted-screens': Object.freeze({
      files: ['src/index.ts'],
      allow: Object.freeze([]),
      only: Object.freeze({ '@gatekeep/ui': Object.freeze(['@gatekeep/ui/hosted']) }),
      follow: true,
    }),
  }),
});

const RUNTIME_FIELDS = ['dependencies', 'peerDependencies', 'optionalDependencies', 'bundleDependencies', 'bundledDependencies'];

/** The runtime dependency names a manifest declares, in every field that ships. */
export function runtimeDependencies(manifest) {
  const names = new Set();
  for (const field of RUNTIME_FIELDS) {
    const value = manifest[field];
    if (Array.isArray(value)) value.forEach((name) => names.add(name));
    else if (value && typeof value === 'object') Object.keys(value).forEach((name) => names.add(name));
  }
  return [...names];
}

function specOf(manifest, name) {
  for (const field of RUNTIME_FIELDS) {
    const value = manifest[field];
    if (value && !Array.isArray(value) && typeof value === 'object' && name in value) return String(value[name]);
  }
  return '';
}

/** The first-party workspace packages a manifest declares for runtime. */
function firstParty(manifest) {
  return runtimeDependencies(manifest).filter(
    (name) => name.startsWith('@gatekeep/') && specOf(manifest, name).startsWith('workspace:'),
  );
}

/**
 * What a first-party package brings at runtime beyond React, React DOM and first-party
 * packages that are themselves clean, all the way down. A first-party package with no
 * workspace manifest counts as brought. `seen` stops a cycle.
 */
async function brought(manifest, workspaceManifest, seen) {
  const local = new Set(firstParty(manifest));
  const found = [];
  for (const name of runtimeDependencies(manifest)) {
    if (ALLOWED_RUNTIME.includes(name)) continue;
    if (!local.has(name)) {
      found.push(name);
      continue;
    }
    if (seen.has(name)) continue;
    seen.add(name);
    const neighbour = await workspaceManifest(name);
    if (!neighbour) found.push(name);
    else found.push(...(await brought(neighbour, workspaceManifest, seen)));
  }
  return found;
}

/**
 * Checks a manifest's runtime dependencies against React, React DOM and `extra`.
 * `workspaceManifest(name)` returns a first-party package's manifest, or null when there is
 * no such workspace package. With `transitive` (the default) a first-party package's own
 * manifest is walked too; without, the caller checks what the import graph reaches instead.
 */
export async function checkManifest(manifest, workspaceManifest, extra = [], { transitive = true } = {}) {
  const problems = [];
  const local = new Set(firstParty(manifest));
  for (const name of runtimeDependencies(manifest)) {
    if (ALLOWED_RUNTIME.includes(name) || extra.includes(name)) continue;
    if (local.has(name)) {
      const neighbour = await workspaceManifest(name);
      if (!neighbour) {
        problems.push(`${name} is not a workspace package.`);
        continue;
      }
      if (!transitive) continue;
      const found = [...new Set(await brought(neighbour, workspaceManifest, new Set([name])))];
      if (found.length > 0) {
        problems.push(`${name} brings runtime dependencies of its own: ${found.join(', ')}.`);
      }
      continue;
    }
    problems.push(`${name} is a runtime dependency. Only ${ALLOWED_RUNTIME.join(' and ')} are allowed.`);
  }
  return problems;
}

// Strings are kept, so a `//` inside a URL isn't taken for a comment.
const JS_COMMENTS = /("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g;
const CSS_COMMENTS = /("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')|\/\*[\s\S]*?\*\//g;

/** Removes comments, keeping strings. `kind` is 'js' or 'css'. */
export function stripComments(text, kind = 'js') {
  return text.replace(kind === 'css' ? CSS_COMMENTS : JS_COMMENTS, (match, string) => string ?? ' ');
}

const SPECIFIERS = [
  /\bimport\s+(?:type\s+)?[^'"`;]*?\bfrom\s*['"]([^'"]+)['"]/g,
  /\bexport\s+(?:type\s+)?[^'"`;]*?\bfrom\s*['"]([^'"]+)['"]/g,
  /\bimport\s*['"]([^'"]+)['"]/g,
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /@import\s+(?:url\(\s*)?['"]?([^'")\s;]+)/g,
  // CSS Modules: composes: a b from './other.module.css'.
  /\bcomposes\s*:[^;{}]*?\bfrom\s+['"]([^'"]+)['"]/g,
];

/** Every module specifier a source file imports, outside comments. */
export function importsIn(text, kind = 'js') {
  const code = stripComments(text, kind);
  const found = new Set();
  for (const pattern of SPECIFIERS) {
    for (const match of code.matchAll(pattern)) found.add(match[1]);
  }
  return [...found];
}

/** The package a bare specifier names: `react/jsx-runtime` is `react`. */
export function packageOf(specifier) {
  const parts = specifier.split('/');
  return specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
}

const EXTENSIONS = ['.ts', '.tsx', '.mts', '.js', '.jsx', '.mjs', '.css'];

async function isFile(file) {
  return stat(file).then((s) => s.isFile(), () => false);
}

async function resolveRelative(from, specifier) {
  const base = path.resolve(path.dirname(from), specifier.replace(/[?#].*$/, ''));
  const candidates = [base, ...EXTENSIONS.map((ext) => base + ext), ...EXTENSIONS.map((ext) => path.join(base, 'index' + ext))];
  for (const candidate of candidates) if (await isFile(candidate)) return candidate;
  return null;
}

/** The file a package's `exports` maps `specifier` to, relative to the package, or null. */
export function exportedFile(manifest, specifier) {
  const name = packageOf(specifier);
  const key = specifier === name ? '.' : `.${specifier.slice(name.length)}`;
  const exports = manifest.exports;
  let target;
  if (typeof exports === 'string') target = key === '.' ? exports : undefined;
  else if (exports && typeof exports === 'object') target = exports[key];
  if (typeof target === 'string') return target;
  if (target && typeof target === 'object') return target.import ?? target.default ?? null;
  return null;
}

/** Whether `file` is inside the directory `dir`. */
function inside(dir, file) {
  const relative = path.relative(dir, file);
  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
}

/**
 * Walks the import graph of one entry point, and returns a problem for each package outside
 * React, React DOM, the declared first-party packages and the entry's `allow` list; for each
 * import of a package in the entry's `only` map other than the specifiers it lists; and for
 * each relative import that resolves to no file, or to a file outside its package. With the
 * entry's `follow` and a `workspace` ({ manifests, dirs }, by package name), an import of a
 * declared first-party package is followed through that package's `exports` into its files,
 * which are checked against that package's own declared first-party packages.
 */
export async function checkEntry(packageDir, name, entry, manifest, workspace = null) {
  const problems = [];
  const contexts = new Map();
  const contextOf = (dir, own, label) => {
    if (!contexts.has(dir)) {
      // The entry's allowlist is its own package's: a followed package gets none.
      const extra = contexts.size === 0 ? entry.allow : [];
      contexts.set(dir, { dir, label, allowed: new Set([...ALLOWED_RUNTIME, ...extra, ...firstParty(own)]) });
    }
    return contexts.get(dir);
  };
  const start = contextOf(packageDir, manifest, '');
  const seen = new Set();
  const queue = [];
  for (const file of entry.files) {
    const full = path.join(packageDir, file);
    if (await isFile(full)) queue.push({ file: full, context: start });
    else problems.push(`${name}: entry ${file} does not exist.`);
  }
  while (queue.length > 0) {
    const { file, context } = queue.shift();
    if (seen.has(file)) continue;
    seen.add(file);
    const relative = context.label + path.relative(context.dir, file).split(path.sep).join('/');
    const kind = file.endsWith('.css') ? 'css' : 'js';
    for (const specifier of importsIn(await readFile(file, 'utf8'), kind)) {
      if (specifier.startsWith('.') || specifier.startsWith('/')) {
        const target = await resolveRelative(file, specifier);
        if (!target) problems.push(`${name}: ${relative} imports ${specifier}, which resolves to no file.`);
        else if (!inside(context.dir, target)) problems.push(`${name}: ${relative} imports ${specifier}, which is outside its package.`);
        else queue.push({ file: target, context });
        continue;
      }
      const pkg = packageOf(specifier);
      const only = context === start ? entry.only?.[pkg] : undefined;
      if (only && !only.includes(specifier)) {
        problems.push(`${name}: ${relative} imports ${specifier}. Of ${pkg}, only ${only.join(', ')} may be imported.`);
        continue;
      }
      if (!context.allowed.has(pkg)) {
        problems.push(`${name}: ${relative} imports ${specifier}. Only React, React DOM and declared @gatekeep packages are allowed.`);
        continue;
      }
      if (!entry.follow || !workspace || !pkg.startsWith('@gatekeep/')) continue;
      const neighbour = workspace.manifests.get(pkg);
      const dir = workspace.dirs.get(pkg);
      if (!neighbour || !dir) {
        problems.push(`${name}: ${relative} imports ${specifier}, which is not a workspace package.`);
        continue;
      }
      const exported = exportedFile(neighbour, specifier);
      const target = exported ? path.resolve(dir, exported) : null;
      if (!target || !inside(dir, target) || !(await isFile(target))) {
        problems.push(`${name}: ${relative} imports ${specifier}, which ${pkg} doesn't export as a file.`);
        continue;
      }
      queue.push({ file: target, context: contextOf(dir, neighbour, `${pkg}/`) });
    }
  }
  return problems;
}

/** Reads every workspace manifest under packages/ and apps/; a malformed one is a problem. */
async function workspaceManifests(root) {
  const manifests = new Map();
  const dirs = new Map();
  const problems = [];
  for (const group of ['packages', 'apps']) {
    const entries = await readdir(path.join(root, group), { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const file = `${group}/${entry.name}/package.json`;
      const text = await readFile(path.join(root, file), 'utf8').catch(() => null);
      if (text === null) continue;
      try {
        const manifest = JSON.parse(text);
        manifests.set(manifest.name, manifest);
        dirs.set(manifest.name, path.join(root, group, entry.name));
      } catch (error) {
        problems.push(`${file} is not valid JSON: ${error.message}`);
      }
    }
  }
  return { manifests, dirs, problems };
}

/**
 * Checks the package at `packageDir`, inside the workspace at `root`. Entries that `follow`
 * check their first-party packages by what they reach in them, not by those manifests.
 */
export async function check(root, packageDir = path.join(root, 'packages/ui'), entries = ENTRY_POINTS) {
  const { manifests, dirs, problems } = await workspaceManifests(root);
  let manifest;
  try {
    manifest = JSON.parse(await readFile(path.join(packageDir, 'package.json'), 'utf8'));
  } catch (error) {
    return [...problems, `package.json can't be read: ${error.message}`];
  }
  const extra = [...new Set(Object.values(entries).flatMap((entry) => entry.allow))];
  const transitive = !Object.values(entries).every((entry) => entry.follow);
  problems.push(...(await checkManifest(manifest, async (name) => manifests.get(name) ?? null, extra, { transitive })));
  for (const [name, entry] of Object.entries(entries)) {
    problems.push(...(await checkEntry(packageDir, name, entry, manifest, { manifests, dirs })));
  }
  return problems;
}

/** Checks packages/hosted-screens inside the workspace at `root`: its manifest and what its screens reach. */
export async function checkScreens(root) {
  return check(root, path.join(root, SCREENS.dir), SCREENS.entries);
}

async function isMain() {
  if (!process.argv[1]) return false;
  try {
    const [argv, self] = await Promise.all([realpath(process.argv[1]), realpath(fileURLToPath(import.meta.url))]);
    return process.platform === 'win32' ? argv.toLowerCase() === self.toLowerCase() : argv === self;
  } catch {
    // argv[1] isn't a file this module can resolve, so this module isn't the script run.
    return false;
  }
}

if (await isMain()) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
  const problems = [
    ...(await check(root)).map((problem) => `packages/ui: ${problem}`),
    ...(await checkScreens(root)).map((problem) => `${SCREENS.dir}: ${problem}`),
  ];
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    process.exit(1);
  }
  console.log(`packages/ui entry points and ${SCREENS.dir} use no runtime dependency but ${ALLOWED_RUNTIME.join(' and ')}.`);
}
