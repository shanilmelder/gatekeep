// Story 4.1: serves the built Hosted Login bundle (apps/hosted-login/dist) the way Host.Hosted does,
// for hosted-step.spec.ts and the hosted-login surface tests. The browser tests run before the
// isolation stage, which has the database a real Host.Hosted needs, so this stands in for it: the
// same two-marker injection into index.html (<!--gk-head--> becomes the theme link, <!--gk-step-->
// the step's JSON data block, with <, >, &, U+2028 and U+2029 escaped), the same <html> tag, the
// default theme stylesheet with the same selectors at /login/theme/{hash}.css, the bundle's assets
// under /login/assets/, the exact AD-21 headers on every response and no-store on step pages.
// HostedStepTests proves the real host sends exactly this shape.
//
// Any other path is a step page. ?fixture= picks its step: generic_error (the default), hostile (a
// Tenant name that tries to close the block), unknown (an unknown step name), broken (unparsable
// JSON) or missing (no data block at all).
//
//   node hosted-step-server.mjs <port>

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tokens } from '@gatekeep/design-tokens';

const [port] = process.argv.slice(2);
if (!port) {
  console.error('usage: node hosted-step-server.mjs <port>');
  process.exit(2);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const dist = path.join(root, 'apps', 'hosted-login', 'dist');
if (!existsSync(path.join(dist, 'index.html'))) {
  console.error('apps/hosted-login/dist/index.html is missing: build the apps first (pnpm -r build).');
  process.exit(1);
}

export const HEAD_MARKER = '<!--gk-head-->';
export const STEP_MARKER = '<!--gk-step-->';
const HTML_TAG = '<html lang="en" data-gk-surface="hosted" data-gk-scheme="auto">';

/**
 * The AD-21 header values, read from their one definition, src/Adapters/Hosting/SecurityHeaders.cs,
 * so the policy under test can't drift from the hosts'. Each constant's string literals, joined.
 */
function readSecurityHeaders() {
  const source = readFileSync(path.join(root, 'src', 'Adapters', 'Hosting', 'SecurityHeaders.cs'), 'utf8');
  const constant = (name) => {
    const declaration = new RegExp(`public const string ${name}\\s*=((?:\\s*"[^"]*"\\s*\\+?)+);`).exec(source);
    const literals = declaration ? [...declaration[1].matchAll(/"([^"]*)"/g)].map((match) => match[1]) : [];
    if (literals.length === 0) {
      console.error(`SecurityHeaders.${name} isn't in src/Adapters/Hosting/SecurityHeaders.cs.`);
      process.exit(1);
    }
    return literals.join('');
  };
  return {
    'Content-Security-Policy': constant('ContentSecurityPolicy'),
    'Referrer-Policy': constant('ReferrerPolicy'),
    'X-Frame-Options': constant('FrameOptions'),
    'X-Content-Type-Options': constant('ContentTypeOptions'),
  };
}

const securityHeaders = readSecurityHeaders();

/** The default theme, as Tenancy's ThemeStylesheet writes it: the same selectors, from the same tokens. */
function themeCss() {
  const names = Object.keys(tokens.schemes.light);
  const rule = (indent, selectors, scheme) =>
    `${indent}${selectors} {\n${indent}  color-scheme: ${scheme};\n` +
    names.map((name) => `${indent}  --gk-${name === 'sh' ? 'elevation-sh' : `color-${name}`}: ${tokens.schemes[scheme][name]};\n`).join('') +
    `${indent}}\n`;
  return (
    '/* Hosted Login theme: the Tenant\'s design tokens (AD-21, AD-22). */\n' +
    rule('', '[data-gk-theme][data-gk-theme],\n[data-gk-theme] [data-gk-scheme],\n[data-gk-theme][data-gk-scheme="light"],\n[data-gk-theme] [data-gk-scheme="light"]', 'light') +
    rule('', '[data-gk-theme][data-gk-scheme="dark"],\n[data-gk-theme] [data-gk-scheme="dark"]', 'dark') +
    '@media (prefers-color-scheme: dark) {\n' +
    rule('  ', '[data-gk-theme][data-gk-scheme="auto"],\n  [data-gk-theme] [data-gk-scheme="auto"]', 'dark') +
    '}\n'
  );
}

const theme = themeCss();
const themeHref = `/login/theme/${createHash('sha256').update(theme, 'utf8').digest('hex').slice(0, 16)}.css`;

const genericError = (tenant) => ({
  step: 'generic_error',
  stepVersion: 1,
  expiresInSeconds: null,
  data: { tenant, code: 'invalid_request', traceId: '4bf92f3577b34da6a3ce929d0e0e4736' },
  csrfToken: null,
});

/** Each fixture's data block text, before escaping; null leaves the block out. */
const fixtures = {
  generic_error: JSON.stringify(genericError('Northwind')),
  hostile: JSON.stringify(genericError('</script><b>x')),
  unknown: JSON.stringify({ ...genericError('Northwind'), step: 'nope' }),
  broken: '{"step": "generic_error", ',
  missing: null,
};

/** JSON safe inside a script element, as StepPageTemplate.EscapeForScript makes it. */
const escapeForScript = (json) =>
  json.replace(/[<>&\u2028\u2029]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);

const index = readFileSync(path.join(dist, 'index.html'), 'utf8');
for (const marker of [HEAD_MARKER, STEP_MARKER]) {
  if (index.split(marker).length !== 2) {
    console.error(`apps/hosted-login/dist/index.html must hold ${marker} once.`);
    process.exit(1);
  }
}

function stepPage(fixture) {
  const json = fixtures[fixture];
  const block = json === null ? '' : `<script type="application/json" id="gk-step">${escapeForScript(json)}</script>`;
  return index
    .replace(/<html(?:\s[^>]*)?>/i, HTML_TAG)
    .replace(HEAD_MARKER, `<link rel="stylesheet" href="${themeHref}">`)
    .replace(STEP_MARKER, block);
}

const types = { '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };

const server = createServer((request, response) => {
  for (const [name, value] of Object.entries(securityHeaders)) response.setHeader(name, value);
  const url = new URL(request.url ?? '/', 'http://localhost');
  const send = (status, type, body, headers = {}) => {
    response.writeHead(status, { ...(type ? { 'Content-Type': type } : {}), ...headers });
    response.end(request.method === 'HEAD' ? undefined : body);
  };

  if (request.method !== 'GET' && request.method !== 'HEAD') return send(404);
  if (url.pathname.startsWith('/login/assets/')) {
    // Only a file directly in dist/assets: no directory, nothing outside it.
    const assets = path.join(dist, 'assets');
    const name = url.pathname.slice('/login/assets/'.length);
    const file = path.resolve(assets, name);
    const isFile = path.dirname(file) === assets && statSync(file, { throwIfNoEntry: false })?.isFile() === true;
    if (!isFile) return send(404);
    return send(200, types[path.extname(name)] ?? 'application/octet-stream', readFileSync(file));
  }
  if (url.pathname.startsWith('/login/theme/')) {
    return url.pathname === themeHref ? send(200, 'text/css; charset=utf-8', theme) : send(404);
  }
  if (url.pathname === '/favicon.ico') return send(404);

  const fixture = url.searchParams.get('fixture') ?? 'generic_error';
  if (!Object.hasOwn(fixtures, fixture)) return send(404);
  return send(400, 'text/html; charset=utf-8', stepPage(fixture), { 'Cache-Control': 'no-store', Pragma: 'no-cache' });
});

server.listen(Number(port), '127.0.0.1', () => console.log(`Hosted Login step pages on http://127.0.0.1:${port}/login/`));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => process.exit(0)));
