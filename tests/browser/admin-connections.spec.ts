// Story 4.12: an Application's Connections tab and the Database page's Applications tab, in the built Admin Dashboard
// served by the built Host.Admin (admin-host.mjs) under its real CSP, from localhost as the other Tenant pages are. The
// Admin API is answered by route interception. The server's rules (the effective rule, the capability, one event per
// change, the system Application never listed) are the Isolation tests' (tests/Isolation/Directory); here, what the pages
// make of the answers.

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const MY_TENANTS = '/api/v1/deployment/my-tenants';
const CSRF = 'W'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000901';
const TENANT = `ten_${'a'.repeat(25)}a`;
const APP = `app_${'b'.repeat(25)}a`;
const OTHER = `app_${'c'.repeat(25)}a`;
const APP_PAGE = `/tenants/${TENANT}/applications/${APP}?tab=connections`;
const DATABASE_PAGE = `/tenants/${TENANT}/database?tab=applications`;
const APPLICATION = `/api/v1/tenants/${TENANT}/applications/${APP}`;
const CONNECTIONS = `${APPLICATION}/connections`;
const TOGGLE = `${CONNECTIONS}/database`;
const CONNECTION = `/api/v1/tenants/${TENANT}/connections/database`;
const DATABASE_APPLICATIONS = `${CONNECTION}/applications`;
const LABEL = `/api/v1/tenants/${TENANT}/label`;
const TRACE = 'c'.repeat(32);

const TENANT_VIEWER = ['tenant.configuration.read', 'tenant.users.read', 'tenant.logs.read'];
const TENANT_EDITOR = [...TENANT_VIEWER, 'tenant.log_detail.read', 'tenant.applications.manage', 'tenant.settings.manage', 'tenant.connections.toggle'];

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const problem = (route: Route, status: number, code: string) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: TRACE }) });

interface State {
  capabilities: string[];
  enabled: boolean;
  tenantEnabled: boolean;
  applications: { id: string; name: string; type: string }[];
  /** Replaces the toggle's answer: by default the server echoes what it was sent. */
  answer: ((route: Route) => Promise<void>) | null;
}

/** The Admin API, for an Editor of a Dev Tenant whose one web Application has the database Connection on. */
async function answerApi(page: Page, initial: Partial<State> = {}) {
  const log: string[] = [];
  const headers: Record<string, string>[] = [];
  const bodies: Record<string, unknown>[] = [];
  const state: State = {
    capabilities: TENANT_EDITOR,
    enabled: true,
    tenantEnabled: true,
    applications: [
      { id: OTHER, name: 'Admin console', type: 'native' },
      { id: APP, name: 'Storefront', type: 'web' },
    ],
    answer: null,
    ...initial,
  };
  const connection = () => ({ connectionId: 'database', name: 'Username-Password', kind: 'database', enabled: state.enabled, tenantEnabled: state.tenantEnabled });
  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const request = route.request();
      const method = request.method();
      const pathname = new URL(request.url()).pathname;
      log.push(`${method} ${pathname}`);
      if (method !== 'GET') {
        headers.push(request.headers());
        bodies.push(request.postDataJSON() as Record<string, unknown>);
      }
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
      if (pathname === LABEL && method === 'GET') return json(route, 200, { label: 'dev', status: 'active' });
      if (pathname === APPLICATION && method === 'GET') {
        return json(route, 200, {
          id: APP,
          clientId: APP,
          name: 'Storefront',
          type: 'web',
          credentialRequired: true,
          createdAt: '2026-11-10T09:00:00.000Z',
          callbackUrls: [],
          logoutUrls: [],
          webOrigins: [],
          grantTypes: ['authorization_code'],
          accessTokenLifetime: 900,
          idTokenLifetime: 900,
          refreshTokenAbsoluteLifetime: 2592000,
          refreshTokenInactivityLifetime: 604800,
        });
      }
      if (pathname === CONNECTIONS && method === 'GET') return json(route, 200, { connections: [connection()] });
      if (pathname === TOGGLE && method === 'PUT') {
        if (state.answer) return state.answer(route);
        state.enabled = bodies.at(-1)!.enabled as boolean;
        return json(route, 200, connection());
      }
      if (pathname === CONNECTION && method === 'GET') {
        return json(route, 200, {
          kind: 'database',
          name: 'Username-Password',
          enabled: state.tenantEnabled,
          signupEnabled: true,
          passwordPolicy: { minLength: 12, strength: 'good', historyCount: 5, dictionary: true, personalData: true },
          updatedAt: '2026-11-16T09:00:00.000Z',
        });
      }
      if (pathname === DATABASE_APPLICATIONS && method === 'GET') return json(route, 200, { applications: state.applications });
      return route.fulfill({ status: 404 });
    },
  );
  return { log, headers, bodies, state, count: (entry: string) => log.filter((line) => line === entry).length };
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
  const result = await new AxeBuilder({ page }).analyze();
  return result.violations.map((violation) => ({ id: violation.id, targets: violation.nodes.map((node) => node.target.join(' ')) }));
}

const toast = (page: Page) => page.getByTestId('toast');
const tab = (page: Page, name: string) => page.getByRole('tab', { name });
const toggle = (page: Page) => page.getByTestId('application-connection-database');
const none = (page: Page) => page.getByTestId('application-connections-none');

test.use({ viewport: { width: 1280, height: 900 } });
watchCsp(test);

test.describe('application connections', () => {
  test('the Connections tab, after Tokens, lists the database Connection with its badge, name, kind and state', async ({ page }) => {
    await answerApi(page);

    await page.goto(APP_PAGE);

    await expect(page.getByRole('tab').last()).toHaveText('Connections');
    await expect(tab(page, 'Connections')).toHaveAttribute('aria-selected', 'true');
    const card = page.getByTestId('application-connections');
    await expect(card.getByRole('heading', { name: 'Connections enabled for this app' })).toBeVisible();
    await expect(card).toContainText('Users can only sign in to Storefront through enabled connections.');
    await expect(card).toContainText('DB');
    await expect(page.getByTestId('application-connection-database-name')).toHaveText('Username-Password');
    await expect(card).toContainText('Database');
    await expect(page.getByTestId('application-connection-database-state')).toHaveText('Enabled');
    await expect(toggle(page)).toHaveAttribute('aria-checked', 'true');
    await expect(none(page)).toHaveCount(0);
    await expect(page.getByTestId('tenant-view-only')).toHaveCount(0);
  });

  test('an Editor turns it off: one PUT at once with the page Tenant and CSRF, "Changes saved", and the no-Connection banner', async ({ page }) => {
    const api = await answerApi(page);

    await page.goto(APP_PAGE);
    await toggle(page).click();

    await expect(toast(page)).toHaveText('Changes saved');
    await expect(toggle(page)).toHaveAttribute('aria-checked', 'false');
    await expect(page.getByTestId('application-connection-database-state')).toHaveText('Disabled');
    await expect(none(page)).toHaveText("No Connections enabled. Users can't sign in.");
    expect(api.bodies).toEqual([{ enabled: false }]);
    expect(api.count(`PUT ${TOGGLE}`)).toBe(1);
    expect(api.headers[0]!['x-gatekeep-csrf']).toBe(CSRF);
    expect(api.headers[0]!['x-gatekeep-tenant']).toBe(TENANT);

    // And on again: the banner goes.
    await toggle(page).click();
    await expect(toggle(page)).toHaveAttribute('aria-checked', 'true');
    await expect(none(page)).toHaveCount(0);
    expect(api.bodies).toEqual([{ enabled: false }, { enabled: true }]);
  });

  test('a refused toggle goes back and shows the error banner', async ({ page }) => {
    await answerApi(page, { answer: (route) => problem(route, 503, 'unavailable') });

    await page.goto(APP_PAGE);
    await toggle(page).click();

    await expect(page.getByTestId('application-connections-save-failed')).toContainText("Couldn't save your changes. Nothing was changed.");
    await expect(page.getByTestId('application-connections-save-failed')).toContainText(TRACE);
    await expect(toggle(page)).toHaveAttribute('aria-checked', 'true');
  });

  test('with the Connection off, or disabled in the Tenant, the banner says Users cannot sign in', async ({ page }) => {
    const api = await answerApi(page, { enabled: false });

    await page.goto(APP_PAGE);
    await expect(none(page)).toBeVisible();

    api.state.enabled = true;
    api.state.tenantEnabled = false;
    await page.reload();
    await expect(toggle(page)).toHaveAttribute('aria-checked', 'true');
    await expect(none(page)).toBeVisible();
  });

  test('a Viewer sees a read-only toggle with the view-only banner', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_VIEWER });

    await page.goto(APP_PAGE);

    await expect(page.getByTestId('tenant-view-only')).toHaveText('You have view-only access to this Tenant.');
    await expect(toggle(page)).toBeDisabled();
    expect(api.count(`PUT ${TOGGLE}`)).toBe(0);
  });
});

test.describe('database applications', () => {
  test('the Applications tab, after Password policy, lists each Application by name with its type, linking to its Connections tab', async ({ page }) => {
    await answerApi(page);

    await page.goto(DATABASE_PAGE);

    await expect(page.getByRole('tab').last()).toHaveText('Applications');
    await expect(tab(page, 'Applications')).toHaveAttribute('aria-selected', 'true');
    const rows = page.getByTestId('database-applications').getByRole('listitem');
    await expect(rows).toHaveCount(2);
    await expect(rows.nth(0)).toContainText('Admin console');
    await expect(rows.nth(0)).toContainText('Native');
    await expect(rows.nth(1)).toContainText('Storefront');
    await expect(rows.nth(1)).toContainText('Regular web');

    await page.getByRole('link', { name: 'Storefront' }).click();
    await expect(page).toHaveURL(new RegExp(`/tenants/${TENANT}/applications/${APP}\\?tab=connections$`));
    await expect(tab(page, 'Connections')).toHaveAttribute('aria-selected', 'true');
    await expect(toggle(page)).toBeVisible();
  });

  test('with no Application it says the Connection is not used by any', async ({ page }) => {
    await answerApi(page, { applications: [] });

    await page.goto(DATABASE_PAGE);

    await expect(page.getByTestId('database-applications-empty')).toContainText('Not used by any application');
  });
});

for (const scheme of ['light', 'dark'] as const) {
  for (const width of [1100, 768]) {
    test(`axe finds no violations at ${width}px, ${scheme}: both tabs, the banner, a Viewer and the empty state`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      const api = await answerApi(page);

      await page.goto(APP_PAGE);
      await expect(toggle(page)).toBeVisible();
      expect(await axe(page), 'connections').toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      await toggle(page).click();
      await expect(none(page)).toBeVisible();
      expect(await axe(page), 'no connection').toEqual([]);

      api.state.capabilities = TENANT_VIEWER;
      await page.reload();
      await expect(page.getByTestId('tenant-view-only')).toBeVisible();
      expect(await axe(page), 'viewer').toEqual([]);

      await page.goto(DATABASE_PAGE);
      await expect(page.getByTestId('database-applications')).toBeVisible();
      expect(await axe(page), 'applications').toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      api.state.applications = [];
      await page.reload();
      await expect(page.getByTestId('database-applications-empty')).toBeVisible();
      expect(await axe(page), 'empty').toEqual([]);
    });
  }
}
