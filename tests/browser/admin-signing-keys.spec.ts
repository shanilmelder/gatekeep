// Stories 9.1, 9.2 and 9.3: the Signing keys page, its Rotate now and its per-key Revoke, in the built
// Admin Dashboard served by the built Host.Admin (admin-host.mjs) under its real CSP, from localhost,
// since WebAuthn takes no IP address as an RP ID. The Admin API is answered by route interception; a
// revocation's sheet by a Chromium virtual authenticator over CDP, as in admin-tenant-delete.spec.ts.
// The server's rules (the order, signing keys only, no private material, custody down, the 15-minute
// wait, Owners only, the fresh assertion) are the Isolation tests' (tests/Isolation/Keys); here, what
// the page makes of the answers.

import AxeBuilder from '@axe-core/playwright';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, test, type CDPSession, type Page, type Route } from '@playwright/test';
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
const ROTATE = `${KEYS}/rotate`;
const BEGIN = `/api/v1/tenants/${TENANT}/assertions`;
const COMPLETE = '/api/v1/deployment/assertions/complete';
const REVOKE_ACTION = 'tenant.signing_keys.revoke';
const revokePath = (keyId: string) => `${KEYS}/${encodeURIComponent(keyId)}/revoke`;
const URI = 'https://alpha.gatekeep.test/.well-known/jwks';
const TRACE = 'c'.repeat(32);

const TENANT_VIEWER = ['tenant.configuration.read', 'tenant.users.read', 'tenant.logs.read'];
const TENANT_EDITOR = [...TENANT_VIEWER, 'tenant.log_detail.read', 'tenant.applications.manage', 'tenant.settings.manage'];
const TENANT_OWNER = [...TENANT_EDITOR, 'tenant.label.manage', 'tenant.signing_keys.rotate', 'tenant.signing_keys.revoke'];

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

// What a rotation leaves: a new next, the old next current, the old current previous beside the older one.
const ROTATED = [
  { keyId: kid(6), algorithm: 'RS256', state: 'next', createdAt: '2026-11-14T09:00:00.000Z' },
  { ...ROWS[0]!, state: 'current' },
  { ...ROWS[1]!, state: 'previous' },
  ...ROWS.slice(2),
];

// What revoking the current key leaves: a new next, the old next current, and the old current revoked.
const REVOKED = [
  { keyId: kid(7), algorithm: 'RS256', state: 'next', createdAt: '2026-11-14T10:00:00.000Z' },
  { ...ROWS[0]!, state: 'current' },
  ROWS[2]!,
  { ...ROWS[1]!, state: 'revoked' },
  ...ROWS.slice(3),
];

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const problem = (route: Route, status: number, code: string) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: TRACE }) });

const problemAfter = (route: Route, status: number, code: string, retryAfterSeconds: number) =>
  route.fulfill({
    status,
    contentType: 'application/problem+json',
    headers: { 'Retry-After': String(retryAfterSeconds) },
    body: JSON.stringify({ code, traceId: TRACE, retryAfterSeconds }),
  });

interface State {
  /** The path Tenant's capabilities: a Viewer's unless a test says otherwise. */
  capabilities: string[];
  /** Replaces the list's answer. */
  keys: ((route: Route) => Promise<void>) | null;
  /** Replaces the sample's answer. */
  jwks: ((route: Route) => Promise<void>) | null;
  /** Answers Rotate now: by default the keys a rotation leaves. */
  rotate: ((route: Route) => Promise<void>) | null;
  /** Answers a revocation once its grant is used up: by default the keys revoking the current key leaves. */
  revoke: ((route: Route) => Promise<void>) | null;
  /** Whether a revocation needs a grant: the server's 403 fresh_assertion_required until the sheet is confirmed. */
  needsAssertion: boolean;
  /** The key ID the last confirmed sheet was bound to, used up by the next revocation of it. */
  grant: string | null;
  begunFor: string | null;
}

/** The Admin API for a Viewer of the Tenant, unless a test says otherwise: the page reads with any Tenant Role. */
async function answerApi(page: Page, initial: Partial<State> = {}) {
  const log: string[] = [];
  const headers: Record<string, string>[] = [];
  const bodies: unknown[] = [];
  const begins: unknown[] = [];
  const state: State = {
    capabilities: TENANT_VIEWER,
    keys: null,
    jwks: null,
    rotate: null,
    revoke: null,
    needsAssertion: true,
    grant: null,
    begunFor: null,
    ...initial,
  };
  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      log.push(`${request.method()} ${pathname}`);
      if (request.method() === 'POST') headers.push(request.headers());
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
      if (pathname === `/api/v1/tenants/${TENANT}/capabilities`) return json(route, 200, { capabilities: state.capabilities });
      if (pathname === ROTATE && request.method() === 'POST') return state.rotate ? state.rotate(route) : json(route, 200, { keys: ROTATED });
      if (pathname === BEGIN && request.method() === 'POST') {
        const binding = request.postDataJSON() as { target: string | null };
        begins.push(binding);
        state.begunFor = binding.target;
        return json(route, 200, {
          challenge: randomBytes(32).toString('base64url'),
          rpId: new URL(request.url()).hostname,
          timeout: 300000,
          userVerification: 'required',
          allowCredentials: [],
        });
      }
      if (pathname === COMPLETE && request.method() === 'POST') {
        state.grant = state.begunFor;
        return route.fulfill({ status: 204 });
      }
      const revoke = /^\/api\/v1\/tenants\/[^/]+\/signing-keys\/([^/]+)\/revoke$/.exec(pathname);
      if (revoke && request.method() === 'POST') {
        bodies.push(request.postDataJSON());
        const keyId = decodeURIComponent(revoke[1]!);
        // The checks use up a grant for this key, or refuse with fresh_assertion_required.
        if (state.needsAssertion && state.grant !== keyId) return problem(route, 403, 'fresh_assertion_required');
        state.grant = null;
        return state.revoke ? state.revoke(route) : json(route, 200, { keys: REVOKED });
      }
      if (pathname === KEYS) return state.keys ? state.keys(route) : json(route, 200, { keys: ROWS });
      if (pathname === JWKS) return state.jwks ? state.jwks(route) : json(route, 200, SAMPLE);
      return route.fulfill({ status: 404 });
    },
  );
  return { log, headers, bodies, begins, state, count: (entry: string) => log.filter((line) => line === entry).length };
}

/** A Chromium virtual authenticator holding one passkey for the page's host, so the sheet confirms at once. */
async function authenticator(page: Page, rpId: string) {
  const cdp: CDPSession = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'usb',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  await cdp.send('WebAuthn.addCredential', {
    authenticatorId,
    credential: {
      credentialId: randomBytes(32).toString('base64'),
      isResidentCredential: true,
      rpId,
      privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
      userHandle: randomBytes(64).toString('base64'),
      signCount: 0,
    },
  });
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
const rotate = (page: Page) => page.getByRole('button', { name: 'Rotate now' });
const toast = (page: Page) => page.getByTestId('toast');

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

    // No Expires column. A Viewer manages nothing here: no Rotate (Story 9.2) and no Revoke (9.3), and the view-only banner.
    await expect(page.getByRole('columnheader', { name: 'Expires' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /rotate|revoke/i })).toHaveCount(0);
    await expect(page.getByTestId('tenant-view-only')).toHaveText('You have view-only access to this Tenant.');
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

test.describe('rotate', () => {
  test('an Owner rotates: the toast, the table as the rotation left it, and the sample read again', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-keys-jwks')).toBeVisible();
    await expect(page.getByTestId('tenant-view-only')).toHaveCount(0);
    await expect(page.getByTestId('signing-keys-owner-only')).toHaveCount(0);
    await expect(rotate(page)).not.toHaveAttribute('aria-disabled', 'true');

    await rotate(page).click();

    await expect(toast(page)).toHaveText('Signing key rotated.');
    await expect(page.getByTestId('signing-key-id')).toHaveText(ROTATED.map((row) => row.keyId));
    await expect(table(page).locator('[data-badge="key-state"]')).toHaveText(['Next', 'Current', 'Previous', 'Previous', 'Retired', 'Revoked']);
    await expect.poll(() => api.count(`GET ${JWKS}`)).toBe(2);
    expect(api.count(`POST ${ROTATE}`)).toBe(1);
    // The list isn't read again: the answer is the list.
    expect(api.count(`GET ${KEYS}`)).toBe(1);
    // A state-changing call on the Tenant surface: the CSRF token and the page's Tenant, and no body.
    expect(api.headers[0]?.['x-gatekeep-csrf']).toBe(CSRF);
    expect(api.headers[0]?.['x-gatekeep-tenant']).toBe(TENANT);
  });

  test('a second press while one runs sends nothing more', async ({ page }) => {
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => (release = resolve));
    const api = await answerApi(page, {
      capabilities: TENANT_OWNER,
      rotate: async (route) => {
        await held;
        await json(route, 200, { keys: ROTATED });
      },
    });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await rotate(page).click();
    await expect(rotate(page)).toHaveAttribute('aria-busy', 'true');
    await rotate(page).click({ force: true });
    release();

    await expect(toast(page)).toHaveText('Signing key rotated.');
    expect(api.count(`POST ${ROTATE}`)).toBe(1);
  });

  test('a next key too young is the warn banner with the minutes left and its reference, and the table stays', async ({ page }) => {
    await answerApi(page, { capabilities: TENANT_OWNER, rotate: (route) => problemAfter(route, 409, 'signing_key_not_ready', 600) });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await rotate(page).click();

    const banner = page.getByTestId('signing-keys-rotate-not-ready');
    await expect(banner).toContainText('The next key was published less than 15 minutes ago. Try again in 10 min.');
    await expect(banner).toContainText(TRACE);
    await expect(banner).toHaveAttribute('data-tone', 'warn');
    await expect(page.getByTestId('signing-key-id')).toHaveText(ROWS.map((row) => row.keyId));
    await expect(toast(page)).toHaveCount(0);
  });

  test('a part minute left rounds up', async ({ page }) => {
    await answerApi(page, { capabilities: TENANT_OWNER, rotate: (route) => problemAfter(route, 409, 'signing_key_not_ready', 61) });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await rotate(page).click();

    await expect(page.getByTestId('signing-keys-rotate-not-ready')).toContainText('Try again in 2 min.');
  });

  test('a failure is the bad banner with its reference, and the table is unchanged', async ({ page }) => {
    await answerApi(page, { capabilities: TENANT_OWNER, rotate: (route) => problem(route, 503, 'unavailable') });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await rotate(page).click();

    const banner = page.getByTestId('signing-keys-rotate-failed');
    await expect(banner).toContainText("Couldn't rotate the signing key. Nothing was changed.");
    await expect(banner).toContainText(TRACE);
    await expect(banner).toHaveAttribute('data-tone', 'bad');
    await expect(page.getByTestId('signing-key-id')).toHaveText(ROWS.map((row) => row.keyId));
    await expect(toast(page)).toHaveCount(0);
  });

  test('a 403 says this session can\'t do it, and the table stays', async ({ page }) => {
    await answerApi(page, { capabilities: TENANT_OWNER, rotate: (route) => problem(route, 403, 'access_denied') });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await rotate(page).click();

    await expect(page.getByTestId('signing-keys-rotate-forbidden')).toHaveText("You can't do this in this session.");
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
  });

  test('an Editor sees Rotate now read-only, Tenant Owner only, and pressing it sends nothing', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_EDITOR });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);

    await expect(rotate(page)).toHaveAttribute('aria-disabled', 'true');
    const note = page.getByTestId('signing-keys-owner-only');
    await expect(note).toHaveText('Tenant Owner only');
    await expect(rotate(page)).toHaveAttribute('aria-describedby', (await note.getAttribute('id'))!);
    await expect(rotate(page)).toHaveAccessibleDescription('Tenant Owner only');
    await expect(page.getByTestId('tenant-view-only')).toHaveCount(0);

    // aria-disabled keeps it focusable, so Playwright's actionability check would wait: press it anyway.
    await rotate(page).click({ force: true });
    await expect(toast(page)).toHaveCount(0);
    expect(api.count(`POST ${ROTATE}`)).toBe(0);
  });

  test('a Viewer sees no Rotate and the view-only banner', async ({ page }) => {
    await answerApi(page, { capabilities: TENANT_VIEWER });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);

    await expect(rotate(page)).toHaveCount(0);
    await expect(page.getByTestId('signing-keys-owner-only')).toHaveCount(0);
    await expect(page.getByTestId('tenant-view-only')).toHaveText('You have view-only access to this Tenant.');
  });
});

const revokeButtons = (page: Page) => table(page).getByRole('button', { name: /^Revoke key / });
const revokeButton = (page: Page, keyId: string) => table(page).getByRole('button', { name: `Revoke key ${keyId}` });
const revokeDialog = (page: Page) => page.getByRole('dialog', { name: 'Revoke signing key?' });
const IMPACT = 'Tokens signed with this key stop being trusted. Relying parties that cached the JWKS can accept them for up to 15 minutes.';
const CURRENT_LINE = "The next key becomes current now, even if relying parties haven't fetched it yet.";
const ACCESS = 'Also end every Session and refresh token in this Tenant';

test.describe('revoke', () => {
  test('an Owner sees Revoke on next, current and previous only; the modal states the impact, and Cancel sends nothing', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await expect(table(page).getByRole('columnheader')).toHaveText(['Key ID', 'Algorithm', 'Status', 'Created', 'Revoke']);
    await expect(revokeButtons(page)).toHaveCount(3);
    for (const row of ROWS.slice(0, 3)) await expect(revokeButton(page, row.keyId)).not.toHaveAttribute('aria-disabled', 'true');
    for (const row of ROWS.slice(3)) await expect(revokeButton(page, row.keyId)).toHaveCount(0);

    // A previous key: the impact, no current-key line, and the Sessions box unchecked.
    await revokeButton(page, ROWS[2]!.keyId).click();
    const dialog = revokeDialog(page);
    await expect(dialog).toBeVisible();
    await expect(dialog.getByTestId('revoke-signing-key-id')).toHaveText(ROWS[2]!.keyId);
    expect(await dialog.getByTestId('revoke-signing-key-id').evaluate((element) => element.tagName)).toBe('CODE');
    await expect(dialog).toContainText(IMPACT);
    await expect(dialog.getByTestId('revoke-signing-key-current')).toHaveCount(0);
    await expect(dialog.getByRole('checkbox', { name: ACCESS })).not.toBeChecked();
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toHaveCount(0);

    // The current key adds the promotion line.
    await revokeButton(page, ROWS[1]!.keyId).click();
    await expect(revokeDialog(page).getByTestId('revoke-signing-key-current')).toHaveText(CURRENT_LINE);
    await revokeDialog(page).getByRole('button', { name: 'Cancel' }).click();

    expect(api.bodies).toHaveLength(0);
    expect(api.begins).toHaveLength(0);
  });

  test("an Owner confirms: the sheet inside the modal, bound to the key, then the toast, the table as the revocation left it and the sample read again", async ({
    page,
    baseURL,
  }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, { capabilities: TENANT_OWNER });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-keys-jwks')).toBeVisible();
    await revokeButton(page, ROWS[1]!.keyId).click();
    await revokeDialog(page).getByRole('checkbox', { name: ACCESS }).check();
    await revokeDialog(page).getByRole('button', { name: 'Revoke key' }).click();

    await expect(toast(page)).toHaveText('Signing key revoked.');
    await expect(revokeDialog(page)).toHaveCount(0);
    await expect(page.getByTestId('signing-key-id')).toHaveText(REVOKED.map((row) => row.keyId));
    await expect(table(page).locator('[data-badge="key-state"]')).toHaveText(['Next', 'Current', 'Previous', 'Revoked', 'Retired', 'Revoked']);
    await expect.poll(() => api.count(`GET ${JWKS}`)).toBe(2);
    expect(api.count(`GET ${KEYS}`)).toBe(1);

    // Sent twice: refused for want of a grant, then with it, each with the checkbox's revokeAccess.
    expect(api.count(`POST ${revokePath(ROWS[1]!.keyId)}`)).toBe(2);
    expect(api.bodies).toEqual([{ revokeAccess: true }, { revokeAccess: true }]);
    // The Tenant begin, bound to the key.
    expect(api.begins).toEqual([{ action: REVOKE_ACTION, target: ROWS[1]!.keyId }]);
    const sent = api.headers.at(-1)!;
    expect(sent['x-gatekeep-csrf']).toBe(CSRF);
    expect(sent['x-gatekeep-tenant']).toBe(TENANT);
  });

  test('with a fresh grant already held, it is sent once with revokeAccess false', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER, needsAssertion: false });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await revokeButton(page, ROWS[0]!.keyId).click();
    await revokeDialog(page).getByRole('button', { name: 'Revoke key' }).click();

    await expect(toast(page)).toHaveText('Signing key revoked.');
    expect(api.bodies).toEqual([{ revokeAccess: false }]);
    expect(api.begins).toHaveLength(0);
  });

  test('a cancelled sheet shows inside the same modal, no second modal opens, and the table is unchanged', async ({ page, baseURL }) => {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: false, automaticPresenceSimulation: true },
    });
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    await cdp.send('WebAuthn.addCredential', {
      authenticatorId,
      credential: {
        credentialId: randomBytes(32).toString('base64'),
        isResidentCredential: true,
        rpId: new URL(baseURL!).hostname,
        privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
        userHandle: randomBytes(64).toString('base64'),
        signCount: 0,
      },
    });
    const api = await answerApi(page, { capabilities: TENANT_OWNER });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await revokeButton(page, ROWS[1]!.keyId).click();
    await revokeDialog(page).getByRole('button', { name: 'Revoke key' }).click();

    await expect(revokeDialog(page).getByTestId('revoke-signing-key-failed')).toHaveText('Confirmation cancelled. Nothing was changed.');
    await expect(page.getByRole('dialog')).toHaveCount(1);
    expect(api.count(`POST ${revokePath(ROWS[1]!.keyId)}`)).toBe(1);
    await expect(page.getByTestId('signing-key-id')).toHaveText(ROWS.map((row) => row.keyId));
    await expect(toast(page)).toHaveCount(0);
  });

  test('a failure is the bad banner with its reference inside the modal, which stays open, and the table is unchanged', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    await answerApi(page, { capabilities: TENANT_OWNER, revoke: (route) => problem(route, 503, 'unavailable') });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await revokeButton(page, ROWS[1]!.keyId).click();
    await revokeDialog(page).getByRole('button', { name: 'Revoke key' }).click();

    const failed = revokeDialog(page).getByTestId('revoke-signing-key-failed');
    await expect(failed).toContainText("Couldn't revoke the signing key. Nothing was changed.");
    await expect(failed).toContainText(TRACE);
    await expect(failed).toHaveAttribute('data-tone', 'bad');
    await expect(revokeDialog(page)).toBeVisible();
    await expect(page.getByTestId('signing-key-id')).toHaveText(ROWS.map((row) => row.keyId));
    await expect(toast(page)).toHaveCount(0);
  });

  test('an Editor sees Revoke read-only, Tenant Owner only, and pressing it opens nothing and sends nothing', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_EDITOR });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await expect(revokeButtons(page)).toHaveCount(3);
    const note = page.getByTestId('signing-keys-owner-only');
    await expect(note).toHaveText('Tenant Owner only');
    for (const row of ROWS.slice(0, 3)) {
      await expect(revokeButton(page, row.keyId)).toHaveAttribute('aria-disabled', 'true');
      await expect(revokeButton(page, row.keyId)).toHaveAccessibleDescription('Tenant Owner only');
    }

    // aria-disabled keeps it focusable, so Playwright's actionability check would wait: press it anyway.
    await revokeButton(page, ROWS[1]!.keyId).click({ force: true });
    await expect(revokeDialog(page)).toHaveCount(0);
    expect(api.bodies).toHaveLength(0);
  });

  test('a Viewer sees no Revoke column', async ({ page }) => {
    await answerApi(page, { capabilities: TENANT_VIEWER });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await expect(table(page).getByRole('columnheader')).toHaveText(['Key ID', 'Algorithm', 'Status', 'Created']);
    await expect(revokeButtons(page)).toHaveCount(0);
  });
});

test.describe('revoke refusals', () => {
  test("a 403 access_denied says this session can't do it inside the modal, with no toast", async ({ page }) => {
    await answerApi(page, { capabilities: TENANT_OWNER, needsAssertion: false, revoke: (route) => problem(route, 403, 'access_denied') });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await revokeButton(page, ROWS[1]!.keyId).click();
    await revokeDialog(page).getByRole('button', { name: 'Revoke key' }).click();

    await expect(revokeDialog(page).getByTestId('revoke-signing-key-failed')).toHaveText("You can't do this in this session.");
    await expect(toast(page)).toHaveCount(0);
    await expect(page.getByTestId('signing-key-id')).toHaveText(ROWS.map((row) => row.keyId));
  });

  test('a 409 tenant_mismatch closes the modal with no failure banner and no toast, and the table is unchanged', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER, needsAssertion: false, revoke: (route) => problem(route, 409, 'tenant_mismatch') });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await revokeButton(page, ROWS[1]!.keyId).click();
    await revokeDialog(page).getByRole('button', { name: 'Revoke key' }).click();

    await expect.poll(() => api.bodies.length).toBe(1);
    await expect(revokeDialog(page)).toHaveCount(0);
    await expect(page.getByTestId('revoke-signing-key-failed')).toHaveCount(0);
    await expect(toast(page)).toHaveCount(0);
    await expect(page.getByTestId('signing-key-id')).toHaveText(ROWS.map((row) => row.keyId));
  });

  test('a 404 shows the failure banner with its reference and reads the list again', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER, needsAssertion: false, revoke: (route) => problem(route, 404, 'not_found') });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    expect(api.count(`GET ${KEYS}`)).toBe(1);
    await revokeButton(page, ROWS[1]!.keyId).click();
    await revokeDialog(page).getByRole('button', { name: 'Revoke key' }).click();

    const failed = revokeDialog(page).getByTestId('revoke-signing-key-failed');
    await expect(failed).toContainText("Couldn't revoke the signing key. Nothing was changed.");
    await expect(failed).toContainText(TRACE);
    await expect.poll(() => api.count(`GET ${KEYS}`)).toBe(2);
    await expect(toast(page)).toHaveCount(0);
  });
});

test.describe('rotate refusals the shell handles', () => {
  test('a 409 tenant_mismatch shows none of the page banners and no toast, and the table is unchanged', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER, rotate: (route) => problem(route, 409, 'tenant_mismatch') });

    await page.goto(PAGE);
    await expect(page.getByTestId('signing-key-id')).toHaveCount(ROWS.length);
    await rotate(page).click();

    await expect.poll(() => api.count(`POST ${ROTATE}`)).toBe(1);
    await expect(rotate(page)).not.toHaveAttribute('aria-busy', 'true');
    await expect(page.getByTestId('signing-keys-rotate-failed')).toHaveCount(0);
    await expect(page.getByTestId('signing-keys-rotate-not-ready')).toHaveCount(0);
    await expect(page.getByTestId('signing-keys-rotate-forbidden')).toHaveCount(0);
    await expect(toast(page)).toHaveCount(0);
    await expect(page.getByTestId('signing-key-id')).toHaveText(ROWS.map((row) => row.keyId));
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

    test(`axe finds no violations at ${width}px, ${scheme}: Rotate for an Owner and an Editor, rotated, not ready and failed`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      const api = await answerApi(page, { capabilities: TENANT_OWNER });

      await page.goto(PAGE);
      await expect(page.getByTestId('signing-keys-jwks')).toBeVisible();
      expect(await axe(page), 'owner').toEqual([]);

      await rotate(page).click();
      await expect(toast(page)).toHaveText('Signing key rotated.');
      await expect(page.getByTestId('signing-keys-jwks')).toBeVisible();
      expect(await axe(page), 'rotated').toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      api.state.rotate = (route) => problemAfter(route, 409, 'signing_key_not_ready', 600);
      await rotate(page).click();
      await expect(page.getByTestId('signing-keys-rotate-not-ready')).toBeVisible();
      expect(await axe(page), 'not ready').toEqual([]);

      api.state.rotate = (route) => problem(route, 503, 'unavailable');
      await rotate(page).click();
      await expect(page.getByTestId('signing-keys-rotate-failed')).toBeVisible();
      expect(await axe(page), 'failed').toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      api.state.capabilities = TENANT_EDITOR;
      await page.reload();
      await expect(page.getByTestId('signing-keys-owner-only')).toBeVisible();
      await expect(page.getByTestId('signing-keys-jwks')).toBeVisible();
      expect(await axe(page), 'editor').toEqual([]);

      api.state.capabilities = TENANT_VIEWER;
      await page.reload();
      await expect(page.getByTestId('tenant-view-only')).toBeVisible();
      await expect(page.getByTestId('signing-keys-jwks')).toBeVisible();
      expect(await axe(page), 'viewer').toEqual([]);
    });

    test(`axe finds no violations at ${width}px, ${scheme}: the revoke modal for a previous and the current key, and its failure`, async ({
      page,
      baseURL,
    }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      await authenticator(page, new URL(baseURL!).hostname);
      await answerApi(page, { capabilities: TENANT_OWNER, revoke: (route) => problem(route, 503, 'unavailable') });

      await page.goto(PAGE);
      await expect(page.getByTestId('signing-keys-jwks')).toBeVisible();
      expect(await axe(page), 'owner with Revoke').toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      await revokeButton(page, ROWS[2]!.keyId).click();
      await expect(revokeDialog(page)).toBeVisible();
      expect(await axe(page), 'modal, previous').toEqual([]);
      await revokeDialog(page).getByRole('button', { name: 'Cancel' }).click();
      await expect(revokeDialog(page)).toHaveCount(0);

      await revokeButton(page, ROWS[1]!.keyId).click();
      await expect(revokeDialog(page).getByTestId('revoke-signing-key-current')).toBeVisible();
      expect(await axe(page), 'modal, current').toEqual([]);

      await revokeDialog(page).getByRole('button', { name: 'Revoke key' }).click();
      await expect(revokeDialog(page).getByTestId('revoke-signing-key-failed')).toBeVisible();
      expect(await axe(page), 'modal, failed').toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    });
  }
}
