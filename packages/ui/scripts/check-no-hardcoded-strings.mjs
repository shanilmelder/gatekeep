// Fails on a hard-coded user-facing string in a surface (Story 4.1, UX-DR41, NFR-19): every
// word a user reads comes from the message catalogue (packages/ui/src/messages.tsx), so it can be
// reworded or translated in one place. It reads packages/ui/src, packages/hosted-screens/src,
// apps/*/src and apps/*/index.html, and flags:
//
// - JSX text holding a letter, such as <p>Hello</p>, or a literal holding one as a child
//   expression, such as <p>{'Hello'}</p>, {open ? 'Yes' : 'No'}, {x && 'Hi'}, {`Hi`} or {'Hi ' + name};
// - a string literal holding a letter in an aria-label, aria-description, title, placeholder, alt
//   or label attribute, given directly or as a branch of a conditional, ??, || or &&, a part of a +
//   concatenation, or a template;
// - in index.html, text holding a letter outside script and style, and those attributes, except a
//   %gk:key% placeholder, which the build fills from the catalogue.
//
// The catalogue itself, messages.tsx, is exempt. JSX is parsed with Vite's own parser (Rolldown's),
// so there's no ESLint dependency. Entities such as &nbsp; are not text.

import { readdir, readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseAst } from 'vite';

/** The catalogue, by file name: the one place literal user-facing text belongs. */
export const CATALOGUE = 'messages.tsx';

/** Attributes whose value a user reads or hears. */
export const TEXT_ATTRIBUTES = Object.freeze(['aria-label', 'aria-description', 'title', 'placeholder', 'alt', 'label']);

/** A build-time catalogue placeholder in index.html, such as %gk:hostedNoScript%. */
const PLACEHOLDER = /%gk:[A-Za-z0-9]+%/g;
const ENTITY = /&(?:#\d+|#x[0-9a-f]+|[a-z][a-z0-9]*);/gi;
const LETTER = /\p{L}/u;

const hasLetter = (text) => LETTER.test(text.replace(ENTITY, ' ').replace(PLACEHOLDER, ' '));

/** The line of the character at `offset` in `text`, from 1. */
function lineAt(text, offset) {
  let line = 1;
  for (let index = 0; index < offset && index < text.length; index++) if (text.charCodeAt(index) === 10) line++;
  return line;
}

/** Each string literal an expression can evaluate to or be built from: through conditionals, ??, ||, &&, + and templates only. */
function literals(node, found = []) {
  if (!node) return found;
  switch (node.type) {
    case 'Literal':
      if (typeof node.value === 'string') found.push(node);
      break;
    case 'TemplateLiteral':
      for (const quasi of node.quasis) found.push({ ...quasi, value: quasi.value.cooked ?? quasi.value.raw });
      break;
    case 'ConditionalExpression':
      literals(node.consequent, found);
      literals(node.alternate, found);
      break;
    case 'LogicalExpression':
      literals(node.left, found);
      literals(node.right, found);
      break;
    case 'BinaryExpression':
      if (node.operator === '+') {
        literals(node.left, found);
        literals(node.right, found);
      }
      break;
    case 'ParenthesizedExpression':
    case 'TSAsExpression':
    case 'TSSatisfiesExpression':
    case 'TSNonNullExpression':
      literals(node.expression, found);
      break;
    case 'JSXExpressionContainer':
      literals(node.expression, found);
      break;
    default:
      break;
  }
  return found;
}

function attributeName(node) {
  if (node.name.type === 'JSXIdentifier') return node.name.name;
  if (node.name.type === 'JSXNamespacedName') return `${node.name.namespace.name}:${node.name.name.name}`;
  return '';
}

/** Walks every node of an ESTree program. */
function walk(node, visit) {
  if (!node || typeof node.type !== 'string') return;
  visit(node);
  for (const [key, value] of Object.entries(node)) {
    if (key === 'parent') continue;
    if (Array.isArray(value)) for (const child of value) walk(child, visit);
    else if (value && typeof value === 'object' && typeof value.type === 'string') walk(value, visit);
  }
}

/** Each hard-coded string in a JSX or TSX source, with its line. */
export function findInSource(text, file = 'source.tsx') {
  const lang = /\.(?:tsx|ts|mts|cts)$/.test(file) ? 'tsx' : 'jsx';
  const program = parseAst(text, { lang }, file);
  const found = [];
  walk(program, (node) => {
    if (node.type === 'JSXText' && hasLetter(node.raw ?? node.value)) {
      found.push({ line: lineAt(text, node.start + (node.raw ?? node.value).search(/\S/)), text: (node.value ?? node.raw).trim() });
    } else if (node.type === 'JSXElement' || node.type === 'JSXFragment') {
      // A literal as a child expression is JSX text too: {'Hello'}, {open ? 'Yes' : 'No'}, {x && 'Hi'}.
      for (const child of node.children ?? []) {
        if (child.type !== 'JSXExpressionContainer') continue;
        for (const literal of literals(child.expression)) {
          if (hasLetter(literal.value)) found.push({ line: lineAt(text, literal.start), text: literal.value.trim() });
        }
      }
    } else if (node.type === 'JSXAttribute' && TEXT_ATTRIBUTES.includes(attributeName(node))) {
      for (const literal of literals(node.value)) {
        if (hasLetter(literal.value)) found.push({ line: lineAt(text, literal.start), text: `${attributeName(node)}="${literal.value}"` });
      }
    }
  });
  return found.sort((a, b) => a.line - b.line);
}

/** Each hard-coded string in an index.html, with its line. */
export function findInHtml(text) {
  const found = [];
  // Blank out what holds no user-facing text, keeping offsets: comments, scripts and styles.
  const blank = (match) => match.replace(/[^\n]/g, ' ');
  const html = text
    .replace(/<!--[\s\S]*?-->/g, blank)
    .replace(/<script\b[\s\S]*?<\/script\s*>/gi, blank)
    .replace(/<style\b[\s\S]*?<\/style\s*>/gi, blank);

  for (const tag of html.matchAll(/<[a-z][^>]*>/gi)) {
    for (const attribute of tag[0].matchAll(/\s([a-z-]+)\s*=\s*("([^"]*)"|'([^']*)')/gi)) {
      const [, name, , double, single] = attribute;
      const value = double ?? single ?? '';
      if (TEXT_ATTRIBUTES.includes(name.toLowerCase()) && hasLetter(value)) {
        found.push({ line: lineAt(text, tag.index + attribute.index), text: `${name}="${value}"` });
      }
    }
  }
  for (const segment of html.matchAll(/>([^<]+)</g)) {
    if (hasLetter(segment[1])) {
      found.push({ line: lineAt(text, segment.index + 1 + segment[1].search(/\S/)), text: segment[1].trim() });
    }
  }
  return found.sort((a, b) => a.line - b.line);
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

const exists = (file) => stat(file).then(() => true, () => false);

/**
 * What the lint reads, relative to the repository: the source directories packages/ui/src,
 * packages/hosted-screens/src and apps/*\/src, and each apps/*\/index.html.
 */
export async function lintedPaths(root) {
  const directories = ['packages/ui/src', 'packages/hosted-screens/src'];
  const pages = [];
  const apps = await readdir(path.join(root, 'apps'), { withFileTypes: true }).catch(() => []);
  for (const app of apps.filter((entry) => entry.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) {
    if (await stat(path.join(root, `apps/${app.name}/src`)).then((s) => s.isDirectory(), () => false)) directories.push(`apps/${app.name}/src`);
    if (await exists(path.join(root, `apps/${app.name}/index.html`))) pages.push(`apps/${app.name}/index.html`);
  }
  return { directories, pages };
}

/** Lints the repository at `root`. Returns one message per hard-coded string. */
export async function lint(root) {
  const problems = [];
  const report = (relative, found) => {
    for (const { line, text } of found) {
      problems.push(`${relative}:${line}: hard-coded text "${text}". Add it to the message catalogue (packages/ui/src/messages.tsx).`);
    }
  };
  const { directories, pages } = await lintedPaths(root);
  for (const directory of directories) {
    if (!(await exists(path.join(root, directory)))) continue;
    for await (const file of files(path.join(root, directory))) {
      const relative = path.relative(root, file).split(path.sep).join('/');
      if (!/\.(?:tsx|jsx)$/.test(file) || path.basename(file) === CATALOGUE) continue;
      report(relative, findInSource(await readFile(file, 'utf8'), file));
    }
  }
  for (const page of pages) report(page, findInHtml(await readFile(path.join(root, page), 'utf8')));
  return problems;
}

async function isMain() {
  if (!process.argv[1]) return false;
  const [argv, self] = await Promise.all([realpath(process.argv[1]), realpath(fileURLToPath(import.meta.url))]);
  return process.platform === 'win32' ? argv.toLowerCase() === self.toLowerCase() : argv === self;
}

if (await isMain()) {
  // The repository this script sits in, unless a test names another.
  const root = path.resolve(process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '../../..'));
  const problems = await lint(root);
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    process.exit(1);
  }
  console.log('No hard-coded user-facing text in packages/ui/src, packages/hosted-screens/src, apps/*/src or apps/*/index.html.');
}
