// Story 9.1: the Signing keys page, in the built Admin Dashboard served by the built Host.Admin
// (admin-host.mjs) under its real CSP, from localhost. The Admin API is answered by route
// interception. The server's rules (the order, signing keys only, no private material, custody
// down) are the Isolation tests' (tests/Isolation/Keys); here, what the page makes of the answers.

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const MY_TENANTS = '/api/v1/deployment/my-tenants';
const CSRF = 'W'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000901';
const TENANT = `ten_${'a'.repeat(25)}a`;
const PAGE = `/tenants/${TENANT}/signing-keys`;
const KEYS = `/api/v1/tenants/${TENANT}/signing-keys`;
const JWKS = `${KEYS}/jwks`;
const URI = 'https://alpha.gatekeep.test/.well-known/jwks';
const TRACE = 'c'.repeat(32);

const TENANT_VIEWER = ['tenant.configuration.read', 'tenant.users.read', 'tenant.logs.read'];

const kid = (n: number) => `sig-01900000-0000-7000-8000-00000000000a-01900000-0000-7000-8000-00000000000${n}.v1`;

const ROWS = [
  { keyId: kid(1), algorithm: 'RS256', state: 'next', createdAt: '2026-11-05T09:00:00.000Z' },
  { keyId: kid(2), algorithm: 'RS256', state: 'current', createdAt: '2026-06-01T09:00:00.000Z' },
  { keyId: kid(3), algorithm: 'RS256', state: 'previous', createdAt: '2026-01-01T09:00:00.000Z' },
  { keyId: kid(4), algorithm: 'RS256', state: 'retired', createdAt: '2025-08-01T09:00:00.000Z' },
  { keyId: kid(5), algorithm: 'RS256', state: 'revoked', createdAt: '2025-07-01T09:00:00.000Z' },
];

// A 3072-bit modulus is 512 base64url characters: the page shows it whole.
const MODULUS = 'u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0'.padEnd(512, 'x');

const SAMPLE = {
  jwksUri: URI,
  keys: [2, 1, 3].map((n) => ({ kty: 'RSA', use: 'sig', alg: 'RS256', kid: kid(n), n: MODULUS, e: 'AQAB' })),
};

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const problem = (route: Route, status: number, code: string) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: TRACE }) });

interface State {
  /** Replaces the list's answer. */
  keys: ((route: Route) => Promise<void>) | null;
  /** Replaces the sample's answer. */
  jwks: ((route: Route) => Promise<void>) | null;
}

/** The Admin API for a Viewer of the Tenant: the page reads with any Tenant Role. */
async function answerApi(page: Page, initial: Partial<State> = {}) {
  const log: string[] = [];
  const state: State = { keys: null, jwks: null, ...initial };
  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      log.push(`${request.method()} ${pathname}`);
      if (pathname === SESSION) {
        return json(route, 200, {
          adminId: ADMIN_ID,
          kind: 'full',
          deploymentOwner: false,
          setupComplete: true,
          credentials: 2,
          recoveryCodeAllowed: false,
          csrfToken: CSRF,
        });
      }
      if (pathname === CAPABILITIES) return json(route, 200, { capabilities: [] });
      if (pathname === MY_TENANTS) return json(route, 200, { tenants: [{ id: TENANT, name: 'Alpha', host: 'alpha.gatekeep.test', label: 'dev' }] });
      if (pathname === `/api/v1/tenants/${TENANT}/capabilities`) return json(route, 200, { capabilities: TENANT_VIEWER });
      if (pathname === KEYS) return state.keys ? state.keys(route) : json(route, 200, { keys: ROWS });
      if (pathname === JWKS) return state.jwks ? state.jwks(route) : json(route, 200, SAMPLE);
      return route.fulfill({ status: 404 });
    },
  );
  return { log, state, count: (entry: string) => log.filter((line) => line === entry).length };
}

async function axe(page: Page) {
  await page.evaluate(() =>
    Promise.allSettled(
      document
        .getAnimations()
        .filter((animation) => animation.effect?.getComputedTiming().iterations !== Infinity)
        .map((animation) => animation.finished),
    ).then(() => undefined),
  );
  // tx3 on sf2 in table heads is DESIGN.md's one recorded contrast exception (Admin table heads
  // only), so only contrast skips those cells, as admin-tenants.spec.ts does.
  const everything = await new AxeBuilder({ page }).disableRules(['color-contrast']).analyze();
  const contrast = await new AxeBuilder({ page }).withRules(['color-contrast']).exclude('thead th').analyze();
  return [...everything.violations, ...contrast.violations].map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
}

const heading = (page: Page) => page.getByRole('heading', { level: 1 });
const nav = (page: Page) => page.getByRole('navigation', { name: 'Main' });
const table = (page: Page) => page.getByTestId('signing-keys').getByRole('table');

test.use({ viewport: { width: 1280, height: 900 } });
watchCsp(test);

test.describe('page', () => {
  test('lists every key with its mono ID and Copy, its algorithm, its state badge and its creation date, then the JWKS sample', async ({
    page,
    context,
  }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const api = await answerApi(page);

    await page.goto(PAGE);

    await expect(heading(page)).toHaveText('Signing keys');
    await expect(page.getByText('Keys used to sign ID and access tokens. Rotate regularly; revoke if compromised.')).toBeVisible();
    await expect(table(page).getByRole('columnheader')).toHaveText(['Key ID', 'Algorithm', 'Status', 'Created']);
    await expect(table(page).getByRole('row')).toHaveCount(ROWS.length + 1);
    await expect(page.getByTestId('signing-key-id')).toHaveText(ROWS.map((row) => row.keyId));
    for (const code of await page.getByTestId('signing-key-id').all()) {
      expect(await code.evaluate((element) => element.tagName)).toBe('CODE');
    }

    // The text carries the state; the tone only repeats it.
    const badges = table(page).locator('[data-badge="key-state"]');
    await expect(badges).toHaveText(['Next', 'Current', 'Previous', 'Retired', 'Revoked']);
    const tones = await badges.evaluateAll((elements) => elements.map((element) => getComputedStyle(element).backgroundColor));
    expect(tones[3]).toBe(tones[2]);
    expect(new Set([tones[0], tones[1], tones[2], tones[4]]).size).toBe(4);

    await expect(table(page).getByRole('cell', { name: 'RS256' })).toHaveCount(ROWS.length);
    const created = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date(ROWS[1]!.createdAt));
    await expect(table(page).getByRole('row').nth(2)).toContainText(created);

    // Each key ID's own Copy, named for what it copies.
    const copies = table(page).getByRole('button', { name: 'Copy key ID' });
    await expect(copies).toHaveCount(ROWS.length);
    await copies.nth(1).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(ROWS[1]!.keyId);

    // The sample, titled with its URI, every modulus whole, so Copy gives a usable JWKS.
    const sample = page.getByTestId('signing-keys-jwks');
    await expect(sample.getByRole('figure', { name: `JWKS · ${URI}` })).toBeVisible();
    const text = await sample.locator('pre').innerText();
    expect(JSON.parse(text)).toEqual({ keys: SAMPLE.keys });
    await sample.getByRole('button', { name: `Copy JWKS · ${URI}` }).click();
    expect(JSON.parse(await page.evaluate(() => navigator.clipboard.readText()))).toEqual({ keys: SAMPLE.keys });

    // No Expires column, and no Rotate or Revoke before Stories 9.2 and 9.3.
    await expect(page.getByRole('columnheader', { name: 'Expires' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /rotate|revoke/i })).toHaveCount(0);
    await expect(page.getByText('You have view-only access to this Tenant.')).toHaveCount(0);
    expect(api.count(`GET ${KEYS}`)).toBe(1);
    expect(api.count(`GET ${JWKS}`)).toBe(1);
  });

  test('a failed sample says so in its place, with its reference, the table stays, and Retry reads the sample again', async ({ page }) => {
    const api = await answerApi(page, { jwks: (route) => problem(route, 503, 'unavailable') });

    await page.goto(PAGE);

    await expect(table(page).getByRole('row')).toHaveCount(ROWS.length + 1);
    const failed = page.getByTestId('signing-keys-jwks-failed');
    await expect(failed).toContainText("Couldn't load the public keys.");
    await expect(failed).toContainText(TRACE);
    await expect(page.getByTestId('signing-keys-jwks')).toHaveCount(0);

    api.state.jwks = null;
    await failed.getByRole('button', { name: 'Retry' }).click();
    await expect(page.getByTestId('signing-keys-jwks')).toBeVisible();
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    expect(api.count(`GET ${JWKS}`)).toBe(2);
    expect(api.count(`GET ${KEYS}`)).toBe(1);
  });

  test('a bodiless 503 on the sample still keeps the table', async ({ page }) => {
    await answerApi(page, { jwks: (route) => route.fulfill({ status: 503 }) });

    await page.goto(PAGE);

    await expect(page.getByTestId('signing-keys-jwks-failed')).toContainText("Couldn't load the public keys.");
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
  });

  test('a failed list shows the load-failed banner with its reference, and Retry reads again', async ({ page }) => {
    const api = await answerApi(page, { keys: (route) => problem(route, 500, 'unavailable') });

    await page.goto(PAGE);

    const banner = page.getByTestId('signing-keys-load-failed');
    await expect(banner).toContainText("We couldn't load this page.");
    await expect(banner).toContainText(TRACE);
    await expect(page.getByTestId('signing-keys')).toHaveCount(0);
    // The sample waits for the list: a failed list asks custody nothing.
    expect(api.count(`GET ${JWKS}`)).toBe(0);

    api.state.keys = null;
    await banner.getByRole('button', { name: 'Retry' }).click();
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await expect(page.getByTestId('signing-keys-jwks')).toBeVisible();
    expect(api.count(`GET ${KEYS}`)).toBe(2);
    expect(api.count(`GET ${JWKS}`)).toBe(1);
  });

  test("a 403 on the list is the forbidden page, with the server's reference, and the sample is never asked for", async ({ page }) => {
    const api = await answerApi(page, { keys: (route) => problem(route, 403, 'access_denied') });

    await page.goto(PAGE);

    await expect(heading(page)).toHaveText("You don't have access to this page.");
    await expect(page.getByTestId('forbidden-reference')).toContainText(TRACE);
    expect(api.count(`GET ${KEYS}`)).toBe(1);
    expect(api.count(`GET ${JWKS}`)).toBe(0);
  });
});

test.describe('sidebar', () => {
  test('Signing keys sits in the Security group, current on its page', async ({ page }) => {
    await answerApi(page);

    await page.goto(PAGE);

    await expect(heading(page)).toHaveText('Signing keys');
    const group = nav(page).getByRole('button', { name: 'Security' });
    await expect(group).toHaveAttribute('aria-expanded', 'true');
    await expect(group).toHaveAttribute('data-current', '');
    const link = nav(page).getByRole('link', { name: 'Signing keys' });
    await expect(link).toHaveAttribute('href', PAGE);
    await expect(link).toHaveAttribute('aria-current', 'page');
    // The Security group comes after Applications (Story 3.1) and before Monitoring (Story 7.4's
    // Logs) and Settings, in EXPERIENCE order.
    expect(await nav(page).locator('button[data-group]').evaluateAll((elements) => elements.map((element) => element.getAttribute('data-group')))).toEqual([
      'applications',
      'security',
      'monitoring',
      'settings',
    ]);
  });
});

for (const scheme of ['light', 'dark'] as const) {
  for (const width of [1100, 768]) {
    test(`axe finds no violations at ${width}px, ${scheme}: the page, a failed sample and a failed list`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      const api = await answerApi(page);

      await page.goto(PAGE);
      await expect(page.getByTestId('signing-keys-jwks')).toBeVisible();
      expect(await axe(page), 'page').toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      api.state.jwks = (route) => problem(route, 503, 'unavailable');
      await page.reload();
      await expect(page.getByTestId('signing-keys-jwks-failed')).toBeVisible();
      expect(await axe(page), 'sample failed').toEqual([]);

      api.state.keys = (route) => problem(route, 500, 'unavailable');
      await page.reload();
      await expect(page.getByTestId('signing-keys-load-failed')).toBeVisible();
      expect(await axe(page), 'list failed').toEqual([]);
    });
  }
}
