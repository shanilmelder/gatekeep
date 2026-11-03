// Story 1.20: the built Admin Dashboard, served by the built Host.Admin (admin-host.mjs),
// renders under the exact AD-21 CSP with no violation, loads nothing from another origin,
// sends the four headers on every response, and can't be framed by another origin.

import { expect, test, type Response } from '@playwright/test';

const csp =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; " +
  "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

const expectedHeaders = {
  'content-security-policy': csp,
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
};

/** Each header once, with exactly its value. */
async function expectExactHeaders(response: Response) {
  const headers = await response.headersArray();
  for (const [name, value] of Object.entries(expectedHeaders)) {
    const sent = headers.filter((header) => header.name.toLowerCase() === name).map((header) => header.value);
    expect(sent, `${name} on ${response.url()}`).toEqual([value]);
  }
}

test('renders under the Admin CSP with no violation, loading only from its own origin', async ({ page, baseURL }) => {
  const origin = new URL(baseURL!).origin;
  const requests: string[] = [];
  const consoleViolations: string[] = [];
  page.on('request', (request) => requests.push(request.url()));
  page.on('console', (message) => {
    if (/content security policy|refused to/i.test(message.text())) consoleViolations.push(message.text());
  });
  // Init scripts run outside the page's CSP, from document creation, so nothing is missed.
  await page.addInitScript(() => {
    const violations: string[] = [];
    (window as unknown as { __gkViolations: string[] }).__gkViolations = violations;
    document.addEventListener('securitypolicyviolation', (event) => {
      violations.push(`${event.effectiveDirective} ${event.blockedURI}`);
    });
  });

  const response = await page.goto('/');
  expect(response!.status()).toBe(200);
  // Cookieless, the root's Session request is a 401, which sends it on to sign in (Story 1.23).
  await expect(page).toHaveURL(/\/signin$/);
  await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();

  // The body rule brings in Geist from the bundle, which font-src 'self' must allow.
  const geistLoaded = await page.evaluate(async () => {
    await document.fonts.load('16px "Geist Mono"');
    await document.fonts.ready;
    return [...document.fonts].filter((face) => face.status === 'loaded').map((face) => face.family.replace(/["']/g, ''));
  });
  await page.waitForLoadState('networkidle');

  expect(geistLoaded).toEqual(expect.arrayContaining(['Geist', 'Geist Mono']));
  expect(await page.evaluate(() => (window as unknown as { __gkViolations: string[] }).__gkViolations)).toEqual([]);
  expect(consoleViolations).toEqual([]);
  expect(requests.length).toBeGreaterThan(2);
  expect(requests.filter((url) => new URL(url).origin !== origin)).toEqual([]);
});

test('sends the exact headers on the page and on every asset it loads', async ({ page, baseURL }) => {
  const origin = new URL(baseURL!).origin;
  const responses: Response[] = [];
  page.on('response', (response) => responses.push(response));

  await page.goto('/');
  await page.evaluate(async () => {
    await document.fonts.load('16px "Geist Mono"');
    await document.fonts.ready;
  });
  await page.waitForLoadState('networkidle');

  const types = new Set(responses.map((response) => response.request().resourceType()));
  for (const type of ['document', 'script', 'stylesheet', 'font']) {
    expect(types, `a ${type} was loaded`).toContain(type);
  }
  for (const response of responses) {
    expect(new URL(response.url()).origin).toBe(origin);
    // The root asks for the Session (Story 1.21), which this cookieless page doesn't have: a 401.
    const session = new URL(response.url()).pathname === '/api/v1/deployment/session';
    expect(response.status(), response.url()).toBe(session ? 401 : 200);
    await expectExactHeaders(response);
  }
});

test('sends the headers on a deep link and on a 404', async ({ request }) => {
  for (const [path, status] of [
    ['/tenants/x', 200],
    ['/api/v1/nope', 404],
    ['/assets/missing.js', 404],
  ] as const) {
    const response = await request.get(path);
    expect(response.status(), path).toBe(status);
    const headers = response.headersArray();
    for (const [name, value] of Object.entries(expectedHeaders)) {
      expect(headers.filter((header) => header.name.toLowerCase() === name).map((header) => header.value), `${name} on ${path}`).toEqual([value]);
    }
  }
});

test("can't be framed by a page on another origin", async ({ page, baseURL }) => {
  const origin = new URL(baseURL!).origin;
  // The Hosted Login preview (playwright.config.ts): a real page on another loopback origin
  // that sends no anti-framing header, so the browser's local network rules allow the frame
  // and only the Admin host's own headers can refuse it. Its own page, framed the same way,
  // is the control: it shows an allowed frame does render and is read here.
  const framer = 'http://127.0.0.1:4310';
  await page.goto(`${framer}/`);

  const adminResponse = page.waitForResponse((response) => response.url() === `${origin}/`);
  await page.evaluate(
    ([admin, control]) => {
      for (const [id, src] of [['admin', admin], ['control', control]] as const) {
        const frame = document.createElement('iframe');
        frame.id = id;
        frame.src = src;
        document.body.append(frame);
      }
    },
    [`${origin}/`, `${framer}/`] as const,
  );
  const framed = await adminResponse;

  // The Admin page was asked for and answered, with both anti-framing headers.
  expect(framed.status()).toBe(200);
  await expectExactHeaders(framed);

  await expect(page.frameLocator('#control').locator('#root')).toBeAttached();

  // The browser refused to render it: no frame holds the Admin document.
  await expect
    .poll(() => page.frames().filter((frame) => frame.parentFrame() === page.mainFrame()).length)
    .toBe(2);
  const adminFrame = page.frames().find((frame) => frame.parentFrame() === page.mainFrame() && !frame.url().startsWith(framer));
  expect(adminFrame, 'the Admin frame exists').toBeDefined();
  expect(adminFrame!.url()).not.toBe(`${origin}/`);
  const rendered = await adminFrame!.evaluate(() => document.getElementById('root') !== null).catch(() => false);
  expect(rendered, `frame at ${adminFrame!.url()} rendered the Admin page`).toBe(false);
});
