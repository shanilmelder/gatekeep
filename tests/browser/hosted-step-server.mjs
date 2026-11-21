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
// JSON), missing (no data block at all), login (Story 4.2's Login step), login_kept (Login with
// the email kept from a restart), or a redirect step to another origin, which the client must never
// follow: redirect_protocol_relative, redirect_absolute, redirect_backslash or redirect_tab.
//
// Story 4.2: Hosted Login's two API requests are stubbed, as Host.Hosted answers them, each refusing
// a request without the fixture's CSRF token or this server's exact Origin with 403:
// - POST /login/api/identifier: "nope" gets Login with the email_invalid field error, redirect@example.com
//   a redirect step to /login/?fixture=generic_error, and any other email Generic error
//   temporarily_unavailable, as a release build answers.
// - POST /login/api/transaction/extend: Login with a fresh 30-minute life.
//
// Story 4.7: sign-up's fixtures and requests, for hosted-signup.spec.ts: login_signup (Login with "Sign up"), signup
// and signup_excellent (Signup under a Good or Excellent policy), verify_email, email_verified_app and
// email_verified_close, link_expired and link_sent. The stubbed requests answer as Host.Hosted does:
// - POST /login/api/signup/open: Signup with the email typed; /login/api/signup/back: Login with the email kept.
// - POST /login/api/signup: "aaaaaaaaaaaa" gets Signup naming the classes rule, anything else Email verification
//   required for the email typed.
// - POST /login/api/verification/resend: Email verification required, resent; /login/api/verification/continue: the
//   same step with not_verified_yet.
// - POST /login/api/verification/new-link: the neutral confirmation, with the link-bound CSRF token in place of the
//   transaction's.
// - POST /login/api/transaction/extend from Signup or Email verification required: that same step with a fresh life.
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

/** The fixture transaction's CSRF token, which the stubbed API requires. */
export const CSRF = 'fixture-csrf-token';

/** A sign-in transaction's sliding life, as SecurityLimits.SignInTransactionLifetime: 30 minutes. */
const LIFE = 1800;

const login = (email = null, error = null, expiresInSeconds = LIFE, signupEnabled = false) => ({
  step: 'login',
  stepVersion: 1,
  expiresInSeconds,
  data: { tenant: 'Northwind', email, error, signupEnabled },
  csrfToken: CSRF,
});

/**
 * Story 4.7: Signup's and Email verification required's CSRF tokens. A real transaction has one token for every step;
 * the harness gives each its own, so "Keep going" (POST /login/api/transaction/extend, whose body is empty) answers the
 * step it was posted from, as Host.Hosted does.
 */
export const SIGNUP_CSRF = 'fixture-csrf-signup';
export const VERIFY_CSRF = 'fixture-csrf-verify';

/** Story 4.7: the link-bound CSRF token Link expired's "Send a new link" carries. */
export const LINK_CSRF = 'fixture-link-csrf-token';

/** Story 4.7: the expired link's own value, which Link expired keeps for "Send a new link". */
export const LINK = 'ten_aaaaaaaaaaaaaaaaaaaaaaaaaa.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const signup = (email = null, strength = 'good', error = null, rules = []) => ({
  step: 'signup',
  stepVersion: 2,
  expiresInSeconds: LIFE,
  data: { tenant: 'Northwind', email, policy: { minLength: 12, strength }, error, rules },
  csrfToken: SIGNUP_CSRF,
});

const verifyEmail = (email = 'new.user@example.com', resent = false, error = null) => ({
  step: 'verify_email',
  stepVersion: 3,
  expiresInSeconds: LIFE,
  data: { tenant: 'Northwind', email, resent, error },
  csrfToken: VERIFY_CSRF,
});

const emailVerified = (location) => ({
  step: 'email_verified',
  stepVersion: 1,
  expiresInSeconds: null,
  data: { tenant: 'Northwind', continueTo: location === null ? 'close' : 'app', location },
  csrfToken: null,
});

const linkSent = { step: 'link_sent', stepVersion: 1, expiresInSeconds: null, data: { tenant: 'Northwind' }, csrfToken: null };

/** Each fixture's data block text, before escaping; null leaves the block out. */
const fixtures = {
  login: JSON.stringify(login()),
  login_kept: JSON.stringify(login('kept@example.com')),
  login_signup: JSON.stringify(login(null, null, LIFE, true)),
  signup: JSON.stringify(signup('new.user@example.com')),
  signup_excellent: JSON.stringify(signup('new.user@example.com', 'excellent')),
  verify_email: JSON.stringify(verifyEmail()),
  email_verified_app: JSON.stringify(emailVerified('/login/?fixture=generic_error')),
  email_verified_close: JSON.stringify(emailVerified(null)),
  link_expired: JSON.stringify({
    step: 'link_expired',
    stepVersion: 1,
    expiresInSeconds: null,
    data: { tenant: 'Northwind', token: LINK },
    csrfToken: LINK_CSRF,
  }),
  link_sent: JSON.stringify(linkSent),
  ...Object.fromEntries(
    Object.entries({
      redirect_protocol_relative: '//evil.example/x',
      redirect_absolute: 'https://evil.example',
      redirect_backslash: '/\\evil.example',
      redirect_tab: '/\t/evil.example',
    }).map(([name, location]) => [
      name,
      JSON.stringify({ step: 'redirect', stepVersion: 2, expiresInSeconds: LIFE, data: { tenant: 'Northwind', location }, csrfToken: null }),
    ]),
  ),
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

/** The stubbed API's answer to one request, as Host.Hosted's /login/api endpoints answer. */
function answer(pathname, body, csrf) {
  if (pathname === '/login/api/transaction/extend') {
    if (csrf === SIGNUP_CSRF) return signup('new.user@example.com');
    if (csrf === VERIFY_CSRF) return verifyEmail();
    return login();
  }
  const email = typeof body.email === 'string' ? body.email.trim() : '';
  switch (pathname) {
    case '/login/api/signup/open':
      return signup(email === '' ? null : email);
    case '/login/api/signup/back':
      return login('new.user@example.com', null, LIFE, true);
    case '/login/api/signup':
      return body.password === 'aaaaaaaaaaaa' ? signup(email, 'good', 'password_rule', ['classes']) : verifyEmail(email);
    case '/login/api/verification/resend':
      return verifyEmail('new.user@example.com', true);
    case '/login/api/verification/continue':
      return verifyEmail('new.user@example.com', false, 'not_verified_yet');
    case '/login/api/verification/new-link':
      return linkSent;
    default:
      break;
  }
  if (email === 'nope') return login(email, 'email_invalid');
  if (email === 'redirect@example.com') {
    return { step: 'redirect', stepVersion: 3, expiresInSeconds: LIFE, data: { tenant: 'Northwind', location: '/login/?fixture=generic_error' }, csrfToken: null };
  }
  return { ...genericError('Northwind'), data: { ...genericError('Northwind').data, code: 'temporarily_unavailable' } };
}

/** The stubbed API's paths: Story 4.2's two, and Story 4.7's sign-up and verification requests. */
const API_PATHS = new Set([
  '/login/api/identifier',
  '/login/api/transaction/extend',
  '/login/api/signup/open',
  '/login/api/signup/back',
  '/login/api/signup',
  '/login/api/verification/resend',
  '/login/api/verification/continue',
  '/login/api/verification/new-link',
]);

/** The fixtures a real step page answers 200 for: every step but Generic error and the unreadable ones. */
const OK_FIXTURES = new Set([
  'login', 'login_kept', 'login_signup', 'signup', 'signup_excellent', 'verify_email',
  'email_verified_app', 'email_verified_close', 'link_expired', 'link_sent',
]);

const types = { '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2', '.svg': 'image/svg+xml' };

const server = createServer((request, response) => {
  for (const [name, value] of Object.entries(securityHeaders)) response.setHeader(name, value);
  const url = new URL(request.url ?? '/', 'http://localhost');
  const send = (status, type, body, headers = {}) => {
    response.writeHead(status, { ...(type ? { 'Content-Type': type } : {}), ...headers });
    response.end(request.method === 'HEAD' ? undefined : body);
  };

  if (request.method === 'POST' && API_PATHS.has(url.pathname)) {
    let raw = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => (raw += chunk));
    request.on('end', () => {
      const json = (status, value) => send(status, 'application/json; charset=utf-8', JSON.stringify(value), { 'Cache-Control': 'no-store', Pragma: 'no-cache' });
      const origin = `http://${request.headers.host}`;
      if (request.headers.origin !== origin) return json(403, { ...genericError('Northwind'), data: { ...genericError('Northwind').data, code: 'origin_mismatch' } });
      const presented = request.headers['x-gatekeep-csrf'];
      const allowed = url.pathname === '/login/api/verification/new-link' ? [LINK_CSRF] : [CSRF, SIGNUP_CSRF, VERIFY_CSRF];
      if (!allowed.includes(presented)) return json(403, { ...genericError('Northwind'), data: { ...genericError('Northwind').data, code: 'csrf_mismatch' } });
      let body;
      try {
        body = JSON.parse(raw);
      } catch {
        body = {};
      }
      return json(200, answer(url.pathname, body ?? {}, presented));
    });
    return;
  }
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
  const status = OK_FIXTURES.has(fixture) ? 200 : 400;
  return send(status, 'text/html; charset=utf-8', stepPage(fixture), { 'Cache-Control': 'no-store', Pragma: 'no-cache' });
});

server.listen(Number(port), '127.0.0.1', () => console.log(`Hosted Login step pages on http://127.0.0.1:${port}/login/`));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => process.exit(0)));
