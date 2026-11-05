// Story 1.25: the Admin shell in the built Admin Dashboard, served by the built Host.Admin
// (admin-host.mjs) under its real CSP, from localhost, since WebAuthn takes no IP address as an
// RP ID. The Admin API is answered by route interception; Session renewal's sheet is answered by
// a Chromium virtual authenticator over CDP, as in signin.spec.ts. The shell's presentational
// parts are shell.spec.ts's, on the fixture; renewal's rules for state-changing requests, which
// no shell page sends yet, are apps/admin-dashboard/test/renewal.test.mjs's. From Story 1.27 the
// Owner's landing reads the Tenants list and, with none, is the Create Tenant form, and the
// sidebar has the Deployment group's Tenants item; their own rules are admin-tenants.spec.ts's.

import AxeBuilder from '@axe-core/playwright';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, test, type CDPSession, type Page, type Request, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const TENANTS = '/api/v1/deployment/tenants';
const BEGIN = '/api/v1/deployment/signin';
const COMPLETE = '/api/v1/deployment/signin/complete';
const MY_TENANTS = '/api/v1/deployment/my-tenants';
const CSRF = 'S'.repeat(43);
const RENEWED_CSRF = 'R'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000123';
const OTHER_ADMIN_ID = '01900000-0000-7000-8000-000000000999';
const SCHEME_KEY = 'gatekeep.admin.scheme';

/** The Deployment Owner's eight Deployment capabilities. */
const OWNER = [
  'deployment.tenants.read',
  'deployment.tenants.create',
  'deployment.tenants.delete',
  'deployment.admins.read',
  'deployment.admins.manage',
  'deployment.email_provider.manage',
  'deployment.incident_response.run',
  'deployment.log.read',
];

/** The Owner's landing with no Tenants yet (Story 1.27): the Create Tenant form, in place. */
const LANDING = 'Create your Tenant';

const EXPIRED = 'Your session expired. Sign in to continue. Nothing you entered has been lost.';
const LOAD_FAILED = "We couldn't load this page.";

const json = (route: Route, status: number, body: unknown, headers?: Record<string, string>) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body), headers });
const problem = (route: Route, status: number, code: string, traceId: string, headers?: Record<string, string>) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId }), headers });

type Answer = (route: Route) => Promise<void>;

interface Api {
  /** Every API request, in order, as "METHOD /path". */
  log: string[];
  requests: Request[];
  state: {
    /** The Session is gone: the Session and capabilities reads answer 401, until a renewal completes. */
    expired: boolean;
    setupComplete: boolean;
    deployment: string[];
    /** Replaces the Deployment capabilities answer, while not expired. */
    deploymentAnswer: Answer | null;
    /** The path Tenant's capabilities, while not expired. */
    tenantAnswer: (route: Route, tenantId: string) => Promise<void>;
    beginAnswer: Answer | null;
    completeAnswer: Answer | null;
    signOutAnswer: Answer | null;
    sessionAnswer: Answer | null;
    /** Replaces the Tenants list's answer (Story 1.28), while not expired. */
    tenantsAnswer: Answer | null;
  };
  /** The Tenants list reads, kept apart from `log`. */
  tenantLog: string[];
  count: (entry: string) => number;
  /** The begin's own answer, for a replacement that only watches or waits. */
  begin: Answer;
}

/**
 * The Admin API as the server answers a signed-in Deployment Owner: the Session, both
 * capability reads, sign-in for renewal, and sign-out. A complete renews the Session with a new
 * CSRF token for the same Admin.
 */
async function answerApi(page: Page, baseURL: string, initial: Partial<Api['state']> = {}): Promise<Api> {
  const log: string[] = [];
  const tenantLog: string[] = [];
  const requests: Request[] = [];
  const state: Api['state'] = {
    expired: false,
    setupComplete: true,
    deployment: OWNER,
    deploymentAnswer: null,
    tenantAnswer: (route) => json(route, 200, { capabilities: ['tenant.configuration.read'] }),
    beginAnswer: null,
    completeAnswer: null,
    signOutAnswer: null,
    sessionAnswer: null,
    tenantsAnswer: null,
    ...initial,
  };
  const begin: Answer = (route) =>
    json(route, 200, {
      challenge: randomBytes(32).toString('base64url'),
      rpId: new URL(baseURL).hostname,
      timeout: 300000,
      userVerification: 'required',
      allowCredentials: [],
    });

  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      // The shell's Tenants list (Story 1.28), read with the capabilities on every navigation:
      // none, refused like them while the Session is gone, and outside the log this spec's rules
      // read. Its own rules are admin-tenant-switcher.spec.ts's.
      if (pathname === MY_TENANTS) {
        tenantLog.push(`${request.method()} ${pathname}`);
        if (state.expired) return route.fulfill({ status: 401 });
        if (state.tenantsAnswer) return state.tenantsAnswer(route);
        return json(route, 200, { tenants: [] });
      }
      log.push(`${request.method()} ${pathname}`);
      requests.push(request);

      if (pathname === SESSION && request.method() === 'DELETE') {
        if (state.signOutAnswer) return state.signOutAnswer(route);
        return route.fulfill({ status: 204 });
      }
      if (pathname === SESSION) {
        if (state.sessionAnswer) return state.sessionAnswer(route);
        if (state.expired) return route.fulfill({ status: 401 });
        return json(route, 200, {
          adminId: ADMIN_ID,
          kind: 'full',
          deploymentOwner: true,
          setupComplete: state.setupComplete,
          credentials: 2,
          csrfToken: CSRF,
        });
      }
      if (pathname === CAPABILITIES) {
        if (state.expired) return route.fulfill({ status: 401 });
        if (state.deploymentAnswer) return state.deploymentAnswer(route);
        return json(route, 200, { capabilities: state.deployment });
      }
      // The landing's Tenants read (Story 1.27): none yet.
      if (pathname === TENANTS && request.method() === 'GET') {
        if (state.expired) return route.fulfill({ status: 401 });
        return json(route, 200, { tenantZone: 'gatekeep.test', tenants: [], nextCursor: null });
      }
      const tenant = /^\/api\/v1\/tenants\/([^/]+)\/capabilities$/.exec(pathname);
      if (tenant) {
        if (state.expired) return route.fulfill({ status: 401 });
        return state.tenantAnswer(route, tenant[1]!);
      }
      if (pathname === BEGIN) {
        if (state.beginAnswer) return state.beginAnswer(route);
        return begin(route);
      }
      if (pathname === COMPLETE) {
        if (state.completeAnswer) return state.completeAnswer(route);
        state.expired = false;
        return json(route, 200, { adminId: ADMIN_ID, csrfToken: RENEWED_CSRF, setupComplete: true });
      }
      return route.fulfill({ status: 404 });
    },
  );

  return { log, tenantLog, requests, state, count: (entry) => log.filter((line) => line === entry).length, begin };
}

/** A virtual CTAP2 authenticator holding the Admin's resident credential, verifying and presenting by itself. */
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
  /** An authenticator that can't verify the user ends the ceremony with NotAllowedError, as a cancel does. */
  const cancelling = (on: boolean) => cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: !on });
  return { cancelling };
}

async function axe(page: Page) {
  await page.evaluate(() => Promise.allSettled(document.getAnimations().map((animation) => animation.finished)).then(() => undefined));
  return (await new AxeBuilder({ page }).analyze()).violations.map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
}

const shell = (page: Page) => page.getByTestId('shell');
const nav = (page: Page) => page.getByRole('navigation', { name: 'Main' });
const heading = (page: Page) => page.getByRole('heading', { level: 1 });
const brand = (page: Page) => page.getByRole('banner').getByRole('link', { name: 'gatekeep' });
const expiredBanner = (page: Page) => page.getByTestId('session-expired');
const failedBanner = (page: Page) => page.getByTestId('load-failed');

async function signOut(page: Page) {
  await page.getByRole('button', { name: 'Account' }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
}

/** Marks the window, the shell's main element and the page's own h1, so a reload or a remount loses a mark. */
async function mark(page: Page) {
  await page.evaluate(() => {
    (window as unknown as { gkMarker: string }).gkMarker = 'same-window';
    (document.querySelector('main') as unknown as { gkMarker: string }).gkMarker = 'same-main';
    (document.querySelector('main h1') as unknown as { gkMarker: string }).gkMarker = 'same-page';
  });
}

async function marks(page: Page) {
  try {
    return await page.evaluate(() => [
      (window as unknown as { gkMarker?: string }).gkMarker ?? null,
      (document.querySelector('main') as unknown as { gkMarker?: string } | null)?.gkMarker ?? null,
      (document.querySelector('main h1') as unknown as { gkMarker?: string } | null)?.gkMarker ?? null,
    ]);
  } catch {
    // The document is being replaced: no answer yet.
    return ['navigating', 'navigating', 'navigating'];
  }
}

test.use({ viewport: { width: 1280, height: 720 } });
watchCsp(test);

test.describe('shell', () => {
  test("a Deployment Owner's shell: the top bar's brand, Tenant switcher, theme toggle and account menu, the Main nav's Deployment group, and the landing page", async ({
    page,
    baseURL,
  }) => {
    await answerApi(page, baseURL!);

    const response = await page.goto('/');
    expect(response!.headers()['content-security-policy']).toContain("default-src 'none'");

    await expect(heading(page)).toHaveText(LANDING);
    await expect(page.getByRole('textbox', { name: 'Name', exact: true })).toBeVisible();
    // First load: focus stays on the document.
    expect(await page.evaluate(() => document.activeElement === document.body)).toBe(true);

    const header = page.getByRole('banner');
    await expect(brand(page)).toHaveAttribute('href', '/');
    // Story 1.28: the Tenant switcher after the brand. The Owner holds no Tenant Role yet, so it
    // names no Tenant; its own rules are admin-tenant-switcher.spec.ts's.
    await expect(header.getByRole('button')).toHaveCount(3);
    await expect(header.getByRole('button', { name: 'Choose a Tenant' })).toBeVisible();
    await expect(header.getByRole('button', { name: 'Dark theme' })).toBeVisible();
    await expect(header.getByRole('button', { name: 'Account' })).toBeVisible();
    await expect(page.getByRole('searchbox')).toHaveCount(0);
    // The only text boxes are the landing's Create Tenant form's: no search in the top bar.
    await expect(header.getByRole('textbox')).toHaveCount(0);
    await expect(page.getByRole('textbox')).toHaveCount(2);
    await expect(header.getByRole('button', { name: /alerts|help/i })).toHaveCount(0);
    await expect(page.getByRole('link', { name: /help|api reference/i })).toHaveCount(0);

    // The registry's one item (Story 1.27): the Deployment group, closed off its page, with Tenants.
    await expect(nav(page)).toBeVisible();
    expect((await nav(page).boundingBox())!.width).toBe(236);
    const deployment = nav(page).getByRole('button', { name: 'Deployment' });
    await expect(nav(page).getByRole('button')).toHaveCount(1);
    await expect(deployment).toHaveAttribute('aria-expanded', 'false');
    await expect(nav(page).getByRole('link')).toHaveCount(0);
    await deployment.click();
    await expect(nav(page).getByRole('link')).toHaveText(['Tenants']);
    await expect(nav(page).getByRole('link', { name: 'Tenants' })).toHaveAttribute('href', '/deployment/tenants');

    // The account menu holds Your credentials, then Sign out (Story 1.26).
    await header.getByRole('button', { name: 'Account' }).click();
    await expect(page.getByRole('menuitem')).toHaveText(['Your credentials', 'Sign out']);
    await page.keyboard.press('Escape');
  });

  test('an Admin with no Deployment capability lands on the no-Tenant text, with an empty nav', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { deployment: [] });

    await page.goto('/');

    await expect(heading(page)).toHaveText('Admin Dashboard');
    await expect(page.getByText("You don't have access to a Tenant yet. Ask a Deployment Owner.")).toBeVisible();
    await expect(page.getByRole('textbox')).toHaveCount(0);
    expect(api.count(`GET ${TENANTS}`)).toBe(0);
    await expect(nav(page).getByRole('link')).toHaveCount(0);
    await expect(nav(page).getByRole('button')).toHaveCount(0);
  });

  test('no Session at boot goes to sign in with no shell and no renewal', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { expired: true });

    await page.goto('/tenants/ten_a/applications');

    await expect(page).toHaveURL(/\/signin$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();
    await expect(shell(page)).toHaveCount(0);
    expect(api.count(`GET ${CAPABILITIES}`)).toBe(0);
    expect(api.count(`POST ${BEGIN}`)).toBe(0);
  });

  test('a Session still without both credentials goes to credential setup', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { setupComplete: false });

    await page.goto('/');

    await expect(page).toHaveURL(/\/setup\/credentials$/);
    await expect(shell(page)).toHaveCount(0);
    expect(api.count(`GET ${CAPABILITIES}`)).toBe(0);
  });

  for (const failure of [
    { name: 'a bodiless 403', answer: (route: Route) => route.fulfill({ status: 403 }), code: 'unavailable' },
    { name: 'a 2xx with no Admin ID', answer: (route: Route) => json(route, 200, { csrfToken: CSRF, setupComplete: true }), code: 'unavailable' },
    { name: 'a 503', answer: (route: Route) => route.fulfill({ status: 503 }), code: 'unavailable' },
  ]) {
    test(`a Session read failing with ${failure.name} shows Generic error and no shell, and its action reloads the path`, async ({ page, baseURL }) => {
      const api = await answerApi(page, baseURL!, { sessionAnswer: failure.answer });

      await page.goto('/nope');

      const error = page.getByTestId('root-error');
      await expect(error.locator('[data-reference="code"]')).toHaveText(failure.code);
      await expect(shell(page)).toHaveCount(0);
      expect(api.count(`GET ${CAPABILITIES}`)).toBe(0);

      api.state.sessionAnswer = null;
      const back = error.getByRole('link', { name: 'Back to Gatekeep' });
      await expect(back).toHaveAttribute('href', '/nope');
      await back.click();
      await expect(heading(page)).toHaveText('This no longer exists.');
    });
  }

  test('nothing renders until the Session read answers, and the content waits under a skeleton for its capabilities', async ({ page, baseURL }) => {
    let releaseSession!: () => void;
    let releaseCapabilities!: () => void;
    const session = new Promise<void>((resolve) => (releaseSession = resolve));
    const capabilities = new Promise<void>((resolve) => (releaseCapabilities = resolve));
    const api = await answerApi(page, baseURL!, {
      deploymentAnswer: async (route) => {
        await capabilities;
        await json(route, 200, { capabilities: OWNER });
      },
    });
    await page.route(
      (url) => url.pathname === SESSION,
      async (route) => {
        await session;
        await route.fallback();
      },
    );

    await page.goto('/', { waitUntil: 'load' });
    await expect.poll(() => api.log.length).toBe(0);
    expect(await page.locator('#root').innerHTML()).toBe('');

    releaseSession();
    await expect(page.getByRole('banner')).toBeVisible();
    await expect(nav(page)).toBeVisible();
    // The skeleton's status says Loading once its 300ms have passed.
    await expect(page.getByRole('status').filter({ hasText: 'Loading' }).first()).toBeAttached();
    await expect(heading(page)).toHaveCount(0);

    releaseCapabilities();
    await expect(heading(page)).toHaveText(LANDING);
  });
});

test.describe('boot', () => {
  test('a path starting with two slashes reloads on this origin: the Generic error action is never protocol-relative', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { sessionAnswer: (route) => route.fulfill({ status: 503 }) });

    await page.goto(`${new URL(baseURL!).origin}//evil.example/x?q=1#part`);

    const back = page.getByTestId('root-error').getByRole('link', { name: 'Back to Gatekeep' });
    await expect(back).toHaveAttribute('href', '/evil.example/x?q=1#part');
    const resolved = await back.evaluate((link) => (link as HTMLAnchorElement).href);
    expect(new URL(resolved).origin).toBe(new URL(baseURL!).origin);
  });

  test('a Session read that never answers times out into Generic error, whose action loads the path again', async ({ page, baseURL }) => {
    await page.clock.install();
    const api = await answerApi(page, baseURL!);
    let hold = true;
    await page.route(
      (url) => url.pathname === SESSION,
      async (route) => {
        if (hold) return; // never answered
        await route.fallback();
      },
    );

    const sent = page.waitForRequest((request) => new URL(request.url()).pathname === SESSION);
    await page.goto('/nope');
    await sent;
    await page.clock.runFor(15_000);

    const error = page.getByTestId('root-error');
    await expect(error.locator('[data-reference="code"]')).toHaveText('unavailable');
    await expect(shell(page)).toHaveCount(0);

    hold = false;
    await page.clock.resume();
    await error.getByRole('link', { name: 'Back to Gatekeep' }).click();
    await expect(heading(page)).toHaveText('This no longer exists.');
    expect(api.count(`GET ${CAPABILITIES}`)).toBeGreaterThan(0);
  });
});

test.describe('widths', () => {
  for (const width of [1280, 1100, 1099, 768]) {
    const wide = width >= 1100;
    test(`at ${width}px the sidebar is ${wide ? 'the full 236px' : 'the 52px rail'} and the window never scrolls`, async ({ page, baseURL }) => {
      await page.setViewportSize({ width, height: 720 });
      await answerApi(page, baseURL!);

      await page.goto('/');
      await expect(heading(page)).toHaveText(LANDING);

      expect((await nav(page).boundingBox())!.width).toBe(wide ? 236 : 52);
      const wordmark = (await brand(page).locator('[data-part="wordmark"]').boundingBox())!;
      if (wide) expect(wordmark.width).toBeGreaterThan(20);
      else expect(wordmark.width).toBeLessThanOrEqual(1);
      await expect(brand(page)).toHaveAccessibleName('gatekeep');
      expect(await page.evaluate(() => document.scrollingElement!.scrollHeight === innerHeight)).toBe(true);
    });
  }

  test('below 768px it is the same rail layout with no notice, and Sign out is still reachable', async ({ page, baseURL }) => {
    await page.setViewportSize({ width: 767, height: 720 });
    const api = await answerApi(page, baseURL!);

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    expect((await nav(page).boundingBox())!.width).toBe(52);
    await expect(page.getByRole('alert')).toHaveCount(0);
    await expect(page.getByText(/unsupported|too narrow|wider/i)).toHaveCount(0);

    await signOut(page);
    await expect(page).toHaveURL(/\/signin$/);
    expect(api.count(`DELETE ${SESSION}`)).toBe(1);
  });
});

test.describe('pages', () => {
  test('a direct URL to a Tenant the server refuses shows the forbidden page with its trace ID, in the shell', async ({ page, baseURL, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const api = await answerApi(page, baseURL!, { tenantAnswer: (route) => problem(route, 403, 'access_denied', 't-1') });

    await page.goto('/tenants/ten_x/applications');

    await expect(heading(page)).toHaveText("You don't have access to this page.");
    await expect(page.getByRole('banner')).toBeVisible();
    await expect(nav(page)).toBeVisible();
    const reference = page.getByTestId('forbidden-reference');
    await expect(reference.locator('[data-reference="code"]')).toHaveText('access_denied');
    await expect(reference.locator('[data-reference="trace"]')).toHaveText('t-1');
    // Nothing more: no hint whether the Tenant exists.
    await expect(page.getByTestId('forbidden')).toHaveText(/^You don't have access to this page\.Codeaccess_deniedTrace IDt-1Copy/);
    await reference.getByRole('button', { name: 'Copy trace ID' }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('t-1');
    expect(api.count('GET /api/v1/tenants/ten_x/capabilities')).toBe(1);
    expect(api.count(`GET ${CAPABILITIES}`)).toBe(1);
  });

  test('a malformed Tenant in the URL goes to the server as it is, and its refusal is the same forbidden page', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { tenantAnswer: (route) => problem(route, 403, 'access_denied', 't-2') });

    await page.goto('/tenants/NOT-AN-ID');

    await expect(heading(page)).toHaveText("You don't have access to this page.");
    await expect(page.getByTestId('forbidden-reference').locator('[data-reference="trace"]')).toHaveText('t-2');
    expect(api.count('GET /api/v1/tenants/NOT-AN-ID/capabilities')).toBe(1);
  });

  test('an allowed Tenant path is not found, since no Tenant page exists yet, only after the server answers', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!);

    await page.goto('/tenants/ten_a/applications');

    await expect(heading(page)).toHaveText('This no longer exists.');
    expect(api.log.indexOf('GET /api/v1/tenants/ten_a/capabilities')).toBeGreaterThan(-1);
  });

  test('an unknown path shows not found, whose link goes back to the landing page in the shell', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!);

    await page.goto('/nope');
    await expect(heading(page)).toHaveText('This no longer exists.');
    await mark(page);

    const back = page.getByRole('link', { name: 'Back to Admin Dashboard' });
    await expect(back).toHaveAttribute('href', '/');
    await back.click();

    await expect(page).toHaveURL(/\/$/);
    await expect(heading(page)).toHaveText(LANDING);
    await expect(heading(page)).toBeFocused();
    expect((await marks(page)).slice(0, 2)).toEqual(['same-window', 'same-main']);
    expect(api.count(`GET ${CAPABILITIES}`)).toBe(2);
  });

  for (const failure of [
    { name: 'a 503', answer: (route: Route) => route.fulfill({ status: 503 }), traceId: '' },
    { name: 'a 404', answer: (route: Route) => route.fulfill({ status: 404 }), traceId: '' },
    { name: 'a 403 that is not access_denied', answer: (route: Route) => route.fulfill({ status: 403 }), traceId: '' },
    { name: 'a lost connection', answer: (route: Route) => route.abort('connectionfailed'), traceId: '' },
    { name: 'a 2xx with no list', answer: (route: Route) => json(route, 200, {}), traceId: '' },
    { name: 'a 429 with its trace ID', answer: (route: Route) => problem(route, 429, 'rate_limited', 'trace-429'), traceId: 'trace-429' },
  ]) {
    test(`a Deployment capabilities read failing with ${failure.name} shows the failure banner, and Retry reads again`, async ({ page, baseURL }) => {
      const api = await answerApi(page, baseURL!, { deploymentAnswer: failure.answer });

      await page.goto('/');

      const banner = failedBanner(page);
      await expect(banner).toContainText(LOAD_FAILED);
      await expect(banner).toHaveAttribute('data-tone', 'bad');
      if (failure.traceId) await expect(banner.locator('[data-reference="trace"]')).toHaveText(failure.traceId);
      else await expect(banner.locator('[data-reference="trace"]')).toHaveCount(0);
      await expect(page.getByTestId('create-tenant')).toHaveCount(0);
      await expect(page.getByText("You don't have access to a Tenant yet. Ask a Deployment Owner.")).toHaveCount(0);
      // The top bar still works.
      await expect(page.getByRole('button', { name: 'Dark theme' })).toBeEnabled();

      api.state.deploymentAnswer = null;
      await banner.getByRole('button', { name: 'Retry' }).click();
      await expect(heading(page)).toHaveText(LANDING);
      await expect(failedBanner(page)).toHaveCount(0);
      expect(api.count(`GET ${CAPABILITIES}`)).toBe(2);

      // And Sign out still works.
      await signOut(page);
      await expect(page).toHaveURL(/\/signin$/);
    });
  }

  test('a Tenant capabilities read failing with a 503 shows the failure banner, not the forbidden page', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { tenantAnswer: (route) => route.fulfill({ status: 503 }) });

    await page.goto('/tenants/ten_a');

    await expect(failedBanner(page)).toContainText(LOAD_FAILED);
    await expect(page.getByText("You don't have access to this page.")).toHaveCount(0);
    api.state.tenantAnswer = (route) => json(route, 200, { capabilities: ['tenant.configuration.read'] });
    await failedBanner(page).getByRole('button', { name: 'Retry' }).click();
    // Story 1.28: an allowed Tenant's landing is its settings page, until Story 3.1.
    await expect(page).toHaveURL(/\/tenants\/ten_a\/settings$/);
    await expect(heading(page)).toHaveText('Tenant settings');
  });

  test('a bodiless 403 on the Tenant read is a failure, never the forbidden page: that needs the server’s access_denied', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { tenantAnswer: (route) => route.fulfill({ status: 403 }) });

    await page.goto('/tenants/ten_a');

    await expect(failedBanner(page)).toContainText(LOAD_FAILED);
    await expect(page.getByText("You don't have access to this page.")).toHaveCount(0);
  });
});

test.describe('Tenant path and Retry', () => {
  test('a percent-encoded Tenant segment is decoded once, then encoded once by the client', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { tenantAnswer: (route) => problem(route, 403, 'access_denied', 't-3') });

    await page.goto('/tenants/ten%20a%2Fb/applications');

    await expect(heading(page)).toHaveText("You don't have access to this page.");
    expect(api.log).toContain('GET /api/v1/tenants/ten%20a%2Fb/capabilities');
    expect(api.log.filter((line) => line.includes('%25'))).toEqual([]);
  });

  test('a Tenant segment whose escapes don’t decode is not found, and nothing is asked about it', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!);

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    await page.evaluate(() => {
      history.pushState(null, '', '/tenants/%E0%A4%A');
      dispatchEvent(new PopStateEvent('popstate'));
    });

    await expect(heading(page)).toHaveText('This no longer exists.');
    expect(api.log.filter((line) => line.includes('/api/v1/tenants/'))).toEqual([]);
  });

  test('Retry is not a navigation: the scroll stays, and focus leaves the gone banner for the h1', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { deploymentAnswer: (route) => route.fulfill({ status: 503 }) });

    await page.goto('/');
    await expect(failedBanner(page)).toContainText(LOAD_FAILED);
    api.state.deploymentAnswer = null;
    await failedBanner(page).getByRole('button', { name: 'Retry' }).focus();
    await page.keyboard.press('Enter');

    await expect(heading(page)).toHaveText(LANDING);
    await expect(failedBanner(page)).toHaveCount(0);
    await expect(heading(page)).toBeFocused();
    expect(await page.locator('[data-part="status"]').textContent()).toBe('');
  });

  test('while a navigation’s reads are pending the page stays, main is aria-busy, and a bar shows after 300ms', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!);

    await page.goto('/nope');
    await expect(heading(page)).toHaveText('This no longer exists.');
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    api.state.deploymentAnswer = async (route) => {
      await held;
      await json(route, 200, { capabilities: OWNER });
    };

    await page.getByRole('link', { name: 'Back to Admin Dashboard' }).click();
    await expect(page.locator('main')).toHaveAttribute('aria-busy', 'true');
    await expect(heading(page)).toHaveText('This no longer exists.');
    await expect(page.locator('[data-part="progress"]')).toBeVisible();
    await expect(page.locator('[data-part="status"]')).toHaveText('Loading');
    // Nothing is blocked: the top bar still answers.
    await page.getByRole('button', { name: 'Account' }).click();
    await expect(page.getByRole('menuitem', { name: 'Sign out' })).toBeVisible();
    await page.keyboard.press('Escape');

    release();
    await expect(heading(page)).toHaveText(LANDING);
    await expect(page.locator('main')).not.toHaveAttribute('aria-busy', /.+/);
    await expect(page.locator('[data-part="progress"]')).toHaveCount(0);
  });
});

test.describe('navigation', () => {
  test('each in-shell navigation reads the capabilities again, from nothing stored, and focus moves to the new h1', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!);

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    expect(api.count(`GET ${CAPABILITIES}`)).toBe(1);

    await brand(page).click();
    await expect.poll(() => api.count(`GET ${CAPABILITIES}`)).toBe(2);
    await expect(heading(page)).toBeFocused();
    await brand(page).focus();
    await brand(page).click();
    await expect.poll(() => api.count(`GET ${CAPABILITIES}`)).toBe(3);
    await expect(heading(page)).toBeFocused();

    // A Tenant Role taken away counts on the next navigation: nothing was kept.
    api.state.deployment = [];
    await brand(page).click();
    await expect(page.getByText("You don't have access to a Tenant yet. Ask a Deployment Owner.")).toBeVisible();

    const stored = await page.evaluate(() => ({
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
      cookie: document.cookie,
      search: location.search,
    }));
    expect(stored).toEqual({ local: [], session: [], cookie: '', search: '' });
  });

  test("the browser's back and forward are in-shell navigations too, each reading again", async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!);

    await page.goto('/tenants/ten_a/applications');
    await expect(heading(page)).toHaveText('This no longer exists.');
    await page.getByRole('link', { name: 'Back to Admin Dashboard' }).click();
    await expect(heading(page)).toHaveText(LANDING);

    await page.goBack();
    await expect(heading(page)).toHaveText('This no longer exists.');
    await expect(heading(page)).toBeFocused();
    expect(api.count('GET /api/v1/tenants/ten_a/capabilities')).toBe(2);
    expect(api.count(`GET ${CAPABILITIES}`)).toBe(3);
  });
});

test.describe('theme', () => {
  test('the toggle chooses dark, stores the choice and keeps it on reload; pressed again it is light', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!);
    await page.emulateMedia({ colorScheme: 'light' });

    await page.goto('/');
    const html = page.locator('html');
    const toggle = page.getByRole('button', { name: 'Dark theme' });
    await expect(html).toHaveAttribute('data-gk-scheme', 'auto');
    await expect(toggle).toHaveAttribute('aria-pressed', 'false');

    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-pressed', 'true');
    await expect(html).toHaveAttribute('data-gk-scheme', 'dark');
    expect(await page.evaluate((key) => localStorage.getItem(key), SCHEME_KEY)).toBe('dark');

    await page.reload();
    await expect(heading(page)).toHaveText(LANDING);
    await expect(html).toHaveAttribute('data-gk-scheme', 'dark');
    await expect(toggle).toHaveAttribute('aria-pressed', 'true');

    await toggle.click();
    await expect(html).toHaveAttribute('data-gk-scheme', 'light');
    await expect(toggle).toHaveAttribute('aria-pressed', 'false');
    expect(await page.evaluate((key) => localStorage.getItem(key), SCHEME_KEY)).toBe('light');
    // The scheme is the only thing ever written to web storage.
    expect(await page.evaluate(() => [Object.keys(localStorage), Object.keys(sessionStorage)])).toEqual([[SCHEME_KEY], []]);
  });

  test('with no stored choice the shell follows the device: auto, dark tokens, and the toggle pressed', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!);
    await page.emulateMedia({ colorScheme: 'dark' });

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    await expect(page.locator('html')).toHaveAttribute('data-gk-scheme', 'auto');
    await expect(page.getByRole('button', { name: 'Dark theme' })).toHaveAttribute('aria-pressed', 'true');
    expect(await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)).toBe('dark');

    // Pressed again from the device's dark, it chooses light.
    await page.getByRole('button', { name: 'Dark theme' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-gk-scheme', 'light');
  });

  test('storage that throws still lets the toggle switch this page, with no error', async ({ page, baseURL }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.addInitScript(() => {
      Object.defineProperty(window, 'localStorage', {
        configurable: true,
        get() {
          throw new DOMException('denied', 'SecurityError');
        },
      });
    });
    await answerApi(page, baseURL!);
    await page.emulateMedia({ colorScheme: 'light' });

    await page.goto('/');
    const toggle = page.getByRole('button', { name: 'Dark theme' });
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('html')).toHaveAttribute('data-gk-scheme', 'dark');
    // In-shell navigation keeps the choice in memory.
    await brand(page).click();
    await expect(page.locator('html')).toHaveAttribute('data-gk-scheme', 'dark');
    expect(errors).toEqual([]);
  });

  test('a pre-Session card follows the device whatever the stored choice', async ({ page, baseURL }) => {
    await page.addInitScript((key) => localStorage.setItem(key, 'dark'), SCHEME_KEY);
    await answerApi(page, baseURL!);
    await page.emulateMedia({ colorScheme: 'light' });

    await page.goto('/');
    await expect(page.locator('html')).toHaveAttribute('data-gk-scheme', 'dark');

    await signOut(page);
    await expect(page).toHaveURL(/\/signin$/);
    await expect(page.locator('html')).toHaveAttribute('data-gk-scheme', 'auto');
    await expect(page.locator('[data-gk-surface="hosted"]').first()).toHaveAttribute('data-gk-scheme', 'auto');
    expect(await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)).toBe('light');

    await page.goto('/signin');
    await expect(page.locator('html')).toHaveAttribute('data-gk-scheme', 'auto');
  });
});

test.describe('sign out', () => {
  test('Sign out selected twice while its DELETE is held sends exactly one, and the item shows disabled meanwhile', async ({ page, baseURL }) => {
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    const api = await answerApi(page, baseURL!, {
      signOutAnswer: async (route) => {
        await held;
        await route.fulfill({ status: 204 });
      },
    });

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    await signOut(page);
    await expect.poll(() => api.count(`DELETE ${SESSION}`)).toBe(1);

    // Its items disabled while signing out, the account menu can't be opened onto them again.
    const account = page.getByRole('button', { name: 'Account' });
    await expect(account).toHaveAttribute('aria-disabled', 'true');
    await account.click({ force: true });
    const item = page.getByRole('menuitem', { name: 'Sign out' });
    if (await item.isVisible()) {
      await expect(item).toHaveAttribute('aria-disabled', 'true');
      await item.click({ force: true });
    }
    await page.waitForTimeout(300);
    expect(api.count(`DELETE ${SESSION}`)).toBe(1);

    release();
    await expect(page).toHaveURL(/\/signin$/);
    expect(api.count(`DELETE ${SESSION}`)).toBe(1);
  });

  for (const status of [204, 401]) {
    test(`Sign out in the avatar menu sends one DELETE with the CSRF token, and a ${status} goes to sign in`, async ({ page, baseURL }) => {
      const api = await answerApi(page, baseURL!, { signOutAnswer: (route) => route.fulfill({ status }) });

      await page.goto('/');
      await expect(heading(page)).toHaveText(LANDING);
      await signOut(page);

      await expect(page).toHaveURL(/\/signin$/);
      expect(api.count(`DELETE ${SESSION}`)).toBe(1);
      const request = api.requests.find((r) => r.method() === 'DELETE')!;
      expect(await request.headerValue('x-gatekeep-csrf')).toBe(CSRF);
      // Sign out never renews.
      expect(api.count(`POST ${BEGIN}`)).toBe(0);
    });
  }

  for (const failure of [
    { name: 'a 503', answer: (route: Route) => route.fulfill({ status: 503 }) },
    { name: 'a lost connection', answer: (route: Route) => route.abort('connectionfailed') },
  ]) {
    test(`a sign-out failing with ${failure.name} shows the banner in the content area, and Sign out stays available`, async ({ page, baseURL }) => {
      const api = await answerApi(page, baseURL!, { signOutAnswer: failure.answer });

      await page.goto('/');
      await expect(heading(page)).toHaveText(LANDING);
      await signOut(page);

      const banner = page.locator('main').getByTestId('signout-failed');
      await expect(banner).toHaveText("You're still signed in: signing out didn't complete. Try again.");
      await expect(page).toHaveURL(/\/$/);

      api.state.signOutAnswer = null;
      await signOut(page);
      await expect(page).toHaveURL(/\/signin$/);
      expect(api.count(`DELETE ${SESSION}`)).toBe(2);
    });
  }
});

test.describe('session renewal', () => {
  test('an expired Session on an act: the banner and the sheet, then the read is sent once more, with no reload or remount', async ({
    page,
    baseURL,
  }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    let bannerSeen = false;
    api.state.beginAnswer = async (route) => {
      bannerSeen = (await expiredBanner(page).count()) === 1;
      await api.begin(route);
    };

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    await mark(page);

    api.state.expired = true;
    await brand(page).click();

    await expect.poll(() => api.count(`POST ${COMPLETE}`)).toBe(1);
    await expect(heading(page)).toHaveText(LANDING);
    await expect(expiredBanner(page)).toHaveCount(0);
    expect(bannerSeen).toBe(true);

    // Initial read, the read refused with 401, and that same read sent once more.
    await expect.poll(() => api.log.filter((line) => line.endsWith(CAPABILITIES)).length).toBe(3);
    expect(api.count(`POST ${BEGIN}`)).toBe(1);
    expect(api.log.slice(-4)).toEqual([`GET ${CAPABILITIES}`, `POST ${BEGIN}`, `POST ${COMPLETE}`, `GET ${CAPABILITIES}`]);
    expect(await marks(page)).toEqual(['same-window', 'same-main', 'same-page']);

    // The renewed Session's CSRF token is the one sent from now on.
    await signOut(page);
    await expect(page).toHaveURL(/\/signin$/);
    const signOutRequest = api.requests.find((request) => request.method() === 'DELETE')!;
    expect(await signOutRequest.headerValue('x-gatekeep-csrf')).toBe(RENEWED_CSRF);
  });

  test('the banner is a live warn banner saying why, while the sheet is open', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    const api = await answerApi(page, baseURL!);
    api.state.beginAnswer = async (route) => {
      await held;
      await api.begin(route);
    };

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    api.state.expired = true;
    await brand(page).click();

    const banner = expiredBanner(page);
    await expect(banner).toHaveText(new RegExp(EXPIRED.replace(/[.]/g, '\\.')));
    await expect(banner).toHaveAttribute('role', 'alert');
    await expect(banner).toHaveAttribute('data-tone', 'warn');
    await expect(banner.getByRole('button', { name: 'Sign in' })).toBeVisible();
    // The banner sits at the top of main, above the page.
    expect(await page.locator('main').getByTestId('session-expired').count()).toBe(1);

    release();
    await expect(banner).toHaveCount(0);
  });

  test('a cancelled sheet keeps the banner and sends nothing again; its Sign in opens the sheet again', async ({ page, baseURL }) => {
    const { cancelling } = await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    await mark(page);
    await cancelling(true);
    api.state.expired = true;
    await brand(page).click();

    await expect.poll(() => api.count(`POST ${BEGIN}`)).toBe(1);
    const banner = expiredBanner(page);
    await expect(banner).toContainText(EXPIRED);
    await expect(banner.getByRole('button', { name: 'Sign in' })).toBeVisible();
    expect(api.count(`POST ${COMPLETE}`)).toBe(0);
    expect(api.log.filter((line) => line.endsWith(CAPABILITIES))).toHaveLength(2);

    await cancelling(false);
    await banner.getByRole('button', { name: 'Sign in' }).click();
    await expect(heading(page)).toHaveText(LANDING);
    await expect(expiredBanner(page)).toHaveCount(0);
    expect(api.count(`POST ${BEGIN}`)).toBe(2);
    await expect.poll(() => api.log.filter((line) => line.endsWith(CAPABILITIES)).length).toBe(3);
    expect(await marks(page)).toEqual(['same-window', 'same-main', 'same-page']);
    // Focus was on the banner's Sign in, which has gone: it moves to the page's h1, and a polite
    // status says the Admin is back.
    await expect(heading(page)).toBeFocused();
    await expect(page.locator('[data-part="status"]')).toHaveText("You're signed in again.");
  });

  test('after a cancel, navigating opens no sheet by itself, and the renewal resends only the current navigation’s read', async ({ page, baseURL }) => {
    const { cancelling } = await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    await cancelling(true);
    api.state.expired = true;
    await brand(page).click();
    await expect.poll(() => api.count(`POST ${BEGIN}`)).toBe(1);
    await expect(expiredBanner(page)).toContainText(EXPIRED);
    await expect(expiredBanner(page).getByRole('button', { name: 'Sign in' })).not.toHaveAttribute('aria-busy', 'true');

    for (let i = 0; i < 3; i++) {
      await brand(page).click();
      await expect.poll(() => api.count(`GET ${CAPABILITIES}`)).toBe(3 + i);
    }
    await page.waitForTimeout(300);
    expect(api.count(`POST ${BEGIN}`)).toBe(1);

    await cancelling(false);
    await expiredBanner(page).getByRole('button', { name: 'Sign in' }).click();
    await expect(expiredBanner(page)).toHaveCount(0);
    // Boot, the first refused read, three more refused, and one resend: the latest navigation's.
    await expect.poll(() => api.count(`GET ${CAPABILITIES}`)).toBe(6);
    await page.waitForTimeout(300);
    expect(api.count(`GET ${CAPABILITIES}`)).toBe(6);
    expect(api.count(`POST ${BEGIN}`)).toBe(2);
    await expect(heading(page)).toHaveText(LANDING);
  });

  test('the banner’s Sign in shows its pending state while a sheet is open', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    const api = await answerApi(page, baseURL!);
    api.state.beginAnswer = async (route) => {
      await held;
      await api.begin(route);
    };

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    api.state.expired = true;
    await brand(page).click();

    const action = expiredBanner(page).getByRole('button', { name: 'Sign in' });
    await expect(action).toHaveAttribute('aria-busy', 'true');
    await action.click({ force: true });
    expect(api.count(`POST ${BEGIN}`)).toBe(1);
    release();
    await expect(expiredBanner(page)).toHaveCount(0);
  });

  test('a begin with options the browser can’t read is the service-failure text, never a refused credential', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!, {
      beginAnswer: (route) => json(route, 200, { challenge: '%%% not base64url %%%', rpId: 'localhost', timeout: 300000, userVerification: 'required' }),
    });

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    api.state.expired = true;
    await brand(page).click();

    await expect(expiredBanner(page)).toContainText(LOAD_FAILED);
    await expect(page.getByText("That credential wasn't recognised.")).toHaveCount(0);
    expect(api.count(`POST ${COMPLETE}`)).toBe(0);
  });

  test('signing out while a sheet is being prepared stops it: one DELETE, and no complete afterwards', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    const api = await answerApi(page, baseURL!);
    api.state.beginAnswer = async (route) => {
      await held;
      await api.begin(route);
    };

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    api.state.expired = true;
    await brand(page).click();
    await expect.poll(() => api.count(`POST ${BEGIN}`)).toBe(1);

    await signOut(page);
    release();
    await expect(page).toHaveURL(/\/signin$/);
    await page.waitForTimeout(300);
    expect(api.count(`DELETE ${SESSION}`)).toBe(1);
    expect(api.count(`POST ${COMPLETE}`)).toBe(0);
    // The DELETE went only once the sign-in had stopped.
    expect(api.log.indexOf(`DELETE ${SESSION}`)).toBeGreaterThan(api.log.indexOf(`POST ${BEGIN}`));
  });

  test("a refused sign-in keeps the page with “That credential wasn't recognised.”, and Sign in retries", async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!, { completeAnswer: (route) => problem(route, 400, 'signin_refused', 'trace-400') });

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    api.state.expired = true;
    await brand(page).click();

    await expect(expiredBanner(page)).toContainText("That credential wasn't recognised.");
    await expect(page.getByText('signin_refused')).toHaveCount(0);
    await expect(page.getByRole('banner')).toBeVisible();

    api.state.completeAnswer = null;
    await expiredBanner(page).getByRole('button', { name: 'Sign in' }).click();
    await expect(heading(page)).toHaveText(LANDING);
    await expect(expiredBanner(page)).toHaveCount(0);
  });

  for (const at of ['begin', 'complete'] as const) {
    test(`a rate-limited ${at} says how long to wait, from Retry-After`, async ({ page, baseURL }) => {
      await authenticator(page, new URL(baseURL!).hostname);
      const limited = (route: Route) => problem(route, 429, 'rate_limited', 'trace-429', { 'Retry-After': '30' });
      const api = await answerApi(page, baseURL!, at === 'begin' ? { beginAnswer: limited } : { completeAnswer: limited });

      await page.goto('/');
      await expect(heading(page)).toHaveText(LANDING);
      api.state.expired = true;
      await brand(page).click();

      await expect(expiredBanner(page)).toContainText('Too many sign-in attempts. Try again in 30 seconds.');
      // Held back for the Retry-After window: no begin, by the banner or by a navigation.
      const action = expiredBanner(page).getByRole('button', { name: 'Sign in' });
      await expect(action).toHaveAttribute('aria-disabled', 'true');
      const begins = api.count(`POST ${BEGIN}`);
      await action.click({ force: true });
      await brand(page).click();
      await page.waitForTimeout(300);
      expect(api.count(`POST ${BEGIN}`)).toBe(begins);
    });
  }

  test('a 429 without a whole-number Retry-After says to try again later, with no time', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!, { beginAnswer: (route) => problem(route, 429, 'rate_limited', 'trace-429') });

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    api.state.expired = true;
    await brand(page).click();

    await expect(expiredBanner(page)).toContainText('Too many sign-in attempts. Try again later.');
    await expect(expiredBanner(page).getByRole('button', { name: 'Sign in' })).not.toHaveAttribute('aria-disabled', 'true');
  });

  for (const failure of [
    { name: 'a 503 begin', at: 'begin' as const, answer: (route: Route) => route.fulfill({ status: 503 }) },
    { name: 'a lost connection on complete', at: 'complete' as const, answer: (route: Route) => route.abort('connectionfailed') },
  ]) {
    test(`${failure.name} shows the service-failure text and keeps the page`, async ({ page, baseURL }) => {
      await authenticator(page, new URL(baseURL!).hostname);
      const api = await answerApi(page, baseURL!, failure.at === 'begin' ? { beginAnswer: failure.answer } : { completeAnswer: failure.answer });

      await page.goto('/');
      await expect(heading(page)).toHaveText(LANDING);
      await mark(page);
      api.state.expired = true;
      await brand(page).click();

      await expect(expiredBanner(page)).toContainText(LOAD_FAILED);
      expect(await marks(page)).toEqual(['same-window', 'same-main', 'same-page']);
    });
  }

  test("another Admin's sign-in is a full load of the root, and nothing is sent again", async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    api.state.completeAnswer = async (route) => {
      api.state.expired = false;
      await json(route, 200, { adminId: OTHER_ADMIN_ID, csrfToken: RENEWED_CSRF, setupComplete: true });
    };

    await page.goto('/nope');
    await expect(heading(page)).toHaveText('This no longer exists.');
    await mark(page);
    api.state.expired = true;
    await page.getByRole('link', { name: 'Back to Admin Dashboard' }).click();

    await expect.poll(() => marks(page)).toEqual([null, null, null]);
    await expect(page).toHaveURL(/\/$/);
    await expect(heading(page)).toHaveText(LANDING);
    // After the complete, the new page boots: the Session first, never the interrupted read.
    const after = api.log.slice(api.log.indexOf(`POST ${COMPLETE}`) + 1);
    expect(after[0]).toBe(`GET ${SESSION}`);
  });

  test('two reads refused together share one renewal, and each is sent once more', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);

    await page.goto('/tenants/ten_a/applications');
    await expect(heading(page)).toHaveText('This no longer exists.');
    await page.getByRole('link', { name: 'Back to Admin Dashboard' }).click();
    await expect(heading(page)).toHaveText(LANDING);

    api.state.expired = true;
    await page.goBack();

    await expect.poll(() => api.count(`POST ${COMPLETE}`)).toBe(1);
    await expect(heading(page)).toHaveText('This no longer exists.');
    expect(api.count(`POST ${BEGIN}`)).toBe(1);
    // Deployment: boot, landing, refused, resent. Tenant: boot, refused, resent.
    expect(api.count(`GET ${CAPABILITIES}`)).toBe(4);
    expect(api.count('GET /api/v1/tenants/ten_a/capabilities')).toBe(3);
  });

  test('a resent read refused again shows the banner again, without opening the sheet by itself', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    // The first renewal completes, but the Session stays refused.
    api.state.completeAnswer = (route) => json(route, 200, { adminId: ADMIN_ID, csrfToken: RENEWED_CSRF, setupComplete: true });

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    api.state.expired = true;
    await brand(page).click();

    await expect.poll(() => api.log.filter((line) => line.endsWith(CAPABILITIES)).length).toBe(3);
    await expect(expiredBanner(page)).toContainText(EXPIRED);
    // No loop: no second sheet until the Admin asks for it.
    await page.waitForTimeout(500);
    expect(api.count(`POST ${BEGIN}`)).toBe(1);
    expect(api.log.filter((line) => line.endsWith(CAPABILITIES))).toHaveLength(3);

    api.state.completeAnswer = null;
    await expiredBanner(page).getByRole('button', { name: 'Sign in' }).click();
    await expect.poll(() => api.log.filter((line) => line.endsWith(CAPABILITIES)).length).toBe(4);
    await expect(expiredBanner(page)).toHaveCount(0);
    await expect(heading(page)).toHaveText(LANDING);
    expect(api.count(`POST ${BEGIN}`)).toBe(2);
  });

  test('a renewal by the same Admin still without both credentials goes to credential setup', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    api.state.completeAnswer = async (route) => {
      api.state.expired = false;
      api.state.setupComplete = false;
      await json(route, 200, { adminId: ADMIN_ID, csrfToken: RENEWED_CSRF, setupComplete: false });
    };
    await page.route(
      (url) => url.pathname.startsWith('/api/v1/deployment/credentials'),
      (route) => route.fulfill({ status: 503 }),
    );

    await page.goto('/');
    await expect(heading(page)).toHaveText(LANDING);
    api.state.expired = true;
    await brand(page).click();

    await expect(page).toHaveURL(/\/setup\/credentials$/);
  });
});

type Mode = 'light' | 'dark, from the device' | 'dark, from the toggle';

for (const mode of ['light', 'dark, from the device', 'dark, from the toggle'] as Mode[]) {
  for (const width of [1100, 768]) {
    test(`axe finds no violations at ${width}px, ${mode}: landing, forbidden, not found, session expired and service failure`, async ({
      page,
      baseURL,
    }) => {
      await page.setViewportSize({ width, height: 720 });
      await page.emulateMedia({ colorScheme: mode === 'dark, from the device' ? 'dark' : 'light' });
      const { cancelling } = await authenticator(page, new URL(baseURL!).hostname);
      const api = await answerApi(page, baseURL!, {
        tenantAnswer: (route) => problem(route, 403, 'access_denied', '4bf92f3577b34da6a3ce929d0e0e4736'),
      });

      await page.goto('/');
      await expect(heading(page)).toHaveText(LANDING);
      if (mode === 'dark, from the toggle') {
        await page.getByRole('button', { name: 'Dark theme' }).click();
        await expect(page.locator('html')).toHaveAttribute('data-gk-scheme', 'dark');
      }
      expect(await axe(page), 'landing').toEqual([]);

      await page.getByRole('button', { name: 'Account' }).click();
      await expect(page.getByRole('menu')).toBeVisible();
      expect(await axe(page), 'account menu open').toEqual([]);
      await page.keyboard.press('Escape');

      await page.goto('/tenants/ten_x/applications');
      await expect(heading(page)).toHaveText("You don't have access to this page.");
      expect(await axe(page), 'forbidden').toEqual([]);

      await page.goto('/nope');
      await expect(heading(page)).toHaveText('This no longer exists.');
      expect(await axe(page), 'not found').toEqual([]);

      await cancelling(true);
      api.state.expired = true;
      await page.getByRole('link', { name: 'Back to Admin Dashboard' }).click();
      await expect(expiredBanner(page)).toContainText(EXPIRED);
      await expect.poll(() => api.count(`POST ${BEGIN}`)).toBe(1);
      expect(await axe(page), 'session expired').toEqual([]);

      api.state.expired = false;
      api.state.deploymentAnswer = (route) => problem(route, 503, 'unavailable', '0af7651916cd43dd8448eb211c80319c');
      await page.goto('/');
      await expect(failedBanner(page)).toContainText(LOAD_FAILED);
      expect(await axe(page), 'service failure').toEqual([]);
    });
  }
}
