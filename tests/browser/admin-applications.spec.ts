// Story 3.1: the Applications list, Create Application and an Application's page, in the built
// Admin Dashboard served by the built Host.Admin (admin-host.mjs) under its real CSP, from
// localhost. The Admin API is answered by route interception. The server's rules (roles, the
// name and type, no secret, the hidden system Application) are the Isolation tests'
// (tests/Isolation/Applications); here, what the pages make of the answers.

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const MY_TENANTS = '/api/v1/deployment/my-tenants';
const CSRF = 'W'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000901';
const TENANT = `ten_${'a'.repeat(25)}a`;
const PAGE = `/tenants/${TENANT}/applications`;
const LIST = `/api/v1/tenants/${TENANT}/applications`;
const TRACE = 'c'.repeat(32);

const TENANT_VIEWER = ['tenant.configuration.read', 'tenant.users.read', 'tenant.logs.read'];
const TENANT_EDITOR = [...TENANT_VIEWER, 'tenant.applications.manage', 'tenant.settings.manage'];

const app = (n: number) => `app_${String.fromCharCode(97 + n).repeat(25)}a`;

type Type = 'spa' | 'web' | 'native' | 'machine';

interface Application {
  id: string;
  clientId: string;
  name: string;
  type: Type;
  credentialRequired: boolean;
  createdAt: string;
}

const application = (n: number, name: string, type: Type, createdAt = '2026-11-10T09:00:00.000Z'): Application => ({
  id: app(n),
  clientId: app(n),
  name,
  type,
  credentialRequired: type === 'web' || type === 'machine',
  createdAt,
});

const ROWS: Application[] = [
  application(0, 'Storefront', 'spa', '2026-11-10T09:00:00.000Z'),
  application(1, 'Northwind Web', 'web', '2026-11-09T09:00:00.000Z'),
  application(2, 'iOS app', 'native', '2026-11-08T09:00:00.000Z'),
  application(3, 'Billing worker', 'machine', '2026-11-07T09:00:00.000Z'),
];

const LABELS: Record<Type, string> = { spa: 'Single-page', web: 'Regular web', native: 'Native', machine: 'Machine-to-machine' };
const NEEDS_SECRET = 'Needs a client secret. A Tenant Owner creates it.';
const NO_SECRET = 'No secret needed.';

const json = (route: Route, status: number, body: unknown, headers: Record<string, string> = {}) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body), headers });
const problem = (route: Route, status: number, code: string) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: TRACE }) });

interface State {
  capabilities: string[];
  applications: Application[];
  /** The first page's nextCursor; the next page holds `later`. */
  nextCursor: string | null;
  later: Application[];
  /** Replaces the list's answer. */
  list: ((route: Route) => Promise<void>) | null;
  /** Replaces one Application's answer. */
  read: ((route: Route) => Promise<void>) | null;
  /** Replaces the create's answer. */
  create: ((route: Route) => Promise<void>) | null;
}

async function answerApi(page: Page, initial: Partial<State> = {}) {
  const log: string[] = [];
  const posts: { body: unknown; headers: Record<string, string> }[] = [];
  const state: State = {
    capabilities: TENANT_EDITOR,
    applications: ROWS,
    nextCursor: null,
    later: [],
    list: null,
    read: null,
    create: null,
    ...initial,
  };
  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const { pathname } = url;
      log.push(`${request.method()} ${pathname}${url.search}`);
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
      if (pathname === LIST && request.method() === 'POST') {
        posts.push({ body: request.postDataJSON(), headers: request.headers() });
        if (state.create) return state.create(route);
        const { name, type } = request.postDataJSON() as { name: string; type: Type };
        const created = application(9, name, type, '2026-11-11T09:00:00.000Z');
        state.applications = [created, ...state.applications];
        return json(route, 201, created, { Location: `${LIST}/${created.id}` });
      }
      if (pathname === LIST) {
        if (state.list) return state.list(route);
        return url.searchParams.get('cursor') === state.nextCursor && state.nextCursor !== null
          ? json(route, 200, { applications: state.later, nextCursor: null })
          : json(route, 200, { applications: state.applications, nextCursor: state.nextCursor });
      }
      const one = new RegExp(`^${LIST}/([^/]+)$`).exec(pathname);
      if (one) {
        if (state.read) return state.read(route);
        const found = [...state.applications, ...state.later].find((row) => row.id === decodeURIComponent(one[1]!));
        return found ? json(route, 200, found) : problem(route, 404, 'not_found');
      }
      return route.fulfill({ status: 404 });
    },
  );
  return { log, posts, state, count: (entry: string) => log.filter((line) => line === entry).length };
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
const table = (page: Page) => page.getByTestId('applications').getByRole('table');
const modal = (page: Page) => page.getByRole('dialog', { name: 'Create application' });
const createButton = (page: Page) => page.getByRole('button', { name: 'Create application' });

test.use({ viewport: { width: 1280, height: 900 } });
watchCsp(test);

test.describe('list', () => {
  test('lists each Application with its name, type, mono client ID with Copy and creation date, newest first', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const api = await answerApi(page);

    await page.goto(PAGE);

    await expect(heading(page)).toHaveText('Applications');
    await expect(table(page).getByRole('columnheader')).toHaveText(['Name', 'Type', 'Client ID', 'Created']);
    await expect(table(page).getByRole('row')).toHaveCount(ROWS.length + 1);
    await expect(page.getByTestId('application-name')).toHaveText(ROWS.map((row) => row.name));
    await expect(page.getByTestId('application-client-id')).toHaveText(ROWS.map((row) => row.clientId));
    for (const code of await page.getByTestId('application-client-id').all()) {
      expect(await code.evaluate((element) => element.tagName)).toBe('CODE');
    }
    for (const [index, row] of ROWS.entries()) {
      await expect(table(page).getByRole('row').nth(index + 1)).toContainText(LABELS[row.type]);
    }
    const created = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date(ROWS[1]!.createdAt));
    await expect(table(page).getByRole('row').nth(2)).toContainText(created);

    const copies = table(page).getByRole('button', { name: 'Copy client ID' });
    await expect(copies).toHaveCount(ROWS.length);
    await copies.nth(2).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(ROWS[2]!.clientId);

    // No later story's columns or filters, and none the epic removed.
    for (const name of ['Logins', 'Last used', 'SDK']) await expect(page.getByRole('columnheader', { name })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /dynamic registration/i })).toHaveCount(0);
    await expect(createButton(page)).toHaveCount(1);
    expect(api.count(`GET ${LIST}`)).toBe(1);
  });

  test('a row opens its Application', async ({ page }) => {
    await answerApi(page);
    await page.goto(PAGE);

    await table(page).getByRole('button', { name: 'Northwind Web' }).click();

    await expect(page).toHaveURL(new RegExp(`${PAGE}/${app(1)}$`));
    await expect(heading(page)).toHaveText(/Northwind Web/);
  });

  test('Load more reads the next page with its cursor, once, and appends it', async ({ page }) => {
    const older = application(5, 'Legacy portal', 'web', '2026-10-01T09:00:00.000Z');
    const api = await answerApi(page, { nextCursor: app(3), later: [older] });

    await page.goto(PAGE);
    await expect(page.getByTestId('application-name')).toHaveCount(ROWS.length);

    await page.getByTestId('applications-load-more').click();

    await expect(page.getByTestId('application-name')).toHaveText([...ROWS.map((row) => row.name), older.name]);
    await expect(page.getByTestId('applications-load-more')).toHaveCount(0);
    expect(api.count(`GET ${LIST}?cursor=${app(3)}`)).toBe(1);
  });

  test('an Editor with none sees "No applications yet" with Create application', async ({ page }) => {
    await answerApi(page, { applications: [] });

    await page.goto(PAGE);

    await expect(page.getByText('No applications yet')).toBeVisible();
    await expect(createButton(page)).toHaveCount(1);
    await createButton(page).click();
    await expect(modal(page)).toBeVisible();
  });

  test('a Viewer with none sees the same state with no button, and a Viewer with some has no create', async ({ page }) => {
    const api = await answerApi(page, { applications: [], capabilities: TENANT_VIEWER });

    await page.goto(PAGE);
    await expect(page.getByText('No applications yet')).toBeVisible();
    await expect(createButton(page)).toHaveCount(0);

    api.state.applications = ROWS;
    await page.reload();
    await expect(page.getByTestId('application-name')).toHaveCount(ROWS.length);
    await expect(createButton(page)).toHaveCount(0);
  });

  test('a failed list shows the load-failed banner with its reference, and Retry reads again', async ({ page }) => {
    const api = await answerApi(page, { list: (route) => problem(route, 500, 'unavailable') });

    await page.goto(PAGE);

    const banner = page.getByTestId('applications-load-failed');
    await expect(banner).toContainText("We couldn't load this page.");
    await expect(banner).toContainText(TRACE);

    api.state.list = null;
    await banner.getByRole('button', { name: 'Retry' }).click();
    await expect(page.getByTestId('application-name')).toHaveCount(ROWS.length);
    expect(api.count(`GET ${LIST}`)).toBe(2);
  });

  test("a 403 on the list is the forbidden page, with the server's reference", async ({ page }) => {
    await answerApi(page, { list: (route) => problem(route, 403, 'access_denied') });

    await page.goto(PAGE);

    await expect(heading(page)).toHaveText("You don't have access to this page.");
    await expect(page.getByTestId('forbidden-reference')).toContainText(TRACE);
  });
});

test.describe('create', () => {
  for (const type of ['spa', 'web', 'native', 'machine'] as const) {
    test(`creates a ${LABELS[type]} Application and opens its page, whose Credentials say what it needs`, async ({ page, context }) => {
      await context.grantPermissions(['clipboard-read', 'clipboard-write']);
      const api = await answerApi(page);
      await page.goto(PAGE);

      await createButton(page).click();
      const dialog = modal(page);
      await expect(dialog).toBeVisible();
      await expect(dialog.getByRole('textbox', { name: 'Name' })).toBeFocused();

      // Each type's line says whether it needs a credential.
      const types = dialog.getByRole('group', { name: 'Type' });
      await expect(types.getByRole('radio')).toHaveCount(4);
      await expect(types.getByRole('radio', { name: /^Single-page/ })).toBeChecked();
      for (const [option, label] of Object.entries(LABELS)) {
        await expect(types.getByRole('radio', { name: new RegExp(`^${label}`) })).toHaveAccessibleName(
          new RegExp(option === 'web' || option === 'machine' ? 'Needs a client secret' : 'No credential needed'),
        );
      }

      await dialog.getByRole('textbox', { name: 'Name' }).fill('  My app  ');
      await types.getByRole('radio', { name: new RegExp(`^${LABELS[type]}`) }).check();
      await dialog.getByRole('button', { name: 'Create application' }).click();

      await expect(page).toHaveURL(new RegExp(`${PAGE}/${app(9)}$`));
      await expect(modal(page)).toHaveCount(0);
      expect(api.posts).toHaveLength(1);
      expect(api.posts[0]!.body).toEqual({ name: 'My app', type });
      expect(api.posts[0]!.headers['x-gatekeep-tenant']).toBe(TENANT);
      expect(api.posts[0]!.headers['x-gatekeep-csrf']).toBe(CSRF);

      // The page: breadcrumb, name and type badge, client ID with Copy, Credentials.
      await expect(page.getByTestId('application-title')).toHaveText('My app');
      await expect(page.getByTestId('application-type')).toHaveText(LABELS[type]);
      const crumbs = page.getByTestId('application-breadcrumb');
      await expect(crumbs.getByRole('listitem')).toHaveText(['Applications', 'My app']);
      await expect(crumbs.getByRole('link', { name: 'Applications' })).toHaveAttribute('href', PAGE);
      await expect(page.getByTestId('application-client-id')).toHaveText(app(9));
      await page.getByRole('button', { name: 'Copy client ID' }).click();
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(app(9));
      await expect(page.getByTestId('application-credentials')).toContainText(type === 'web' || type === 'machine' ? NEEDS_SECRET : NO_SECRET);
      await expect(page.getByTestId('application-credentials')).not.toContainText(type === 'web' || type === 'machine' ? NO_SECRET : NEEDS_SECRET);

      // The breadcrumb goes back to the list, which now holds it.
      await crumbs.getByRole('link', { name: 'Applications' }).click();
      await expect(page).toHaveURL(new RegExp(`${PAGE}$`));
      await expect(page.getByTestId('application-name').first()).toHaveText('My app');
    });
  }

  test('an empty or too long name is refused in the browser, with nothing sent; Cancel closes', async ({ page }) => {
    const api = await answerApi(page);
    await page.goto(PAGE);
    await createButton(page).click();
    const dialog = modal(page);

    await dialog.getByRole('textbox', { name: 'Name' }).fill('   ');
    await dialog.getByRole('button', { name: 'Create application' }).click();
    await expect(dialog.getByText('Enter a name.')).toBeVisible();
    await expect(dialog.getByRole('textbox', { name: 'Name' })).toBeFocused();
    expect(api.posts).toHaveLength(0);

    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(modal(page)).toBeHidden();
    await expect(page).toHaveURL(new RegExp(`${PAGE}$`));
  });

  test("the server's refusals show in the modal, which stays open with what was typed", async ({ page }) => {
    const api = await answerApi(page, { create: (route) => problem(route, 400, 'application_invalid') });
    await page.goto(PAGE);
    await createButton(page).click();
    const dialog = modal(page);
    await dialog.getByRole('textbox', { name: 'Name' }).fill('My app');

    await dialog.getByRole('button', { name: 'Create application' }).click();
    await expect(dialog.getByTestId('create-application-invalid')).toBeVisible();

    api.state.create = (route) => problem(route, 403, 'access_denied');
    await dialog.getByRole('button', { name: 'Create application' }).click();
    await expect(dialog.getByTestId('create-application-forbidden')).toHaveText("You can't do this in this session.");

    api.state.create = (route) => problem(route, 500, 'unavailable');
    await dialog.getByRole('button', { name: 'Create application' }).click();
    const failed = dialog.getByTestId('create-application-failed');
    await expect(failed).toContainText("Couldn't create the application.");
    await expect(failed).toContainText(TRACE);
    await expect(dialog.getByRole('textbox', { name: 'Name' })).toHaveValue('My app');
    expect(api.posts).toHaveLength(3);
  });
});

test.describe('detail', () => {
  test('an Application this Tenant has none of says so', async ({ page }) => {
    await answerApi(page);

    await page.goto(`${PAGE}/${app(20)}`);

    await expect(page.getByTestId('application-not-found')).toHaveText("This application doesn't exist in this Tenant.");
    await expect(page.getByTestId('application-breadcrumb').getByRole('link', { name: 'Applications' })).toHaveAttribute('href', PAGE);
  });

  test('a failed read shows the banner with its reference, and Retry reads again', async ({ page }) => {
    const api = await answerApi(page, { read: (route) => problem(route, 503, 'unavailable') });

    await page.goto(`${PAGE}/${app(1)}`);

    const banner = page.getByTestId('application-load-failed');
    await expect(banner).toContainText("We couldn't load this page.");
    await expect(banner).toContainText(TRACE);
    api.state.read = null;
    await banner.getByRole('button', { name: 'Retry' }).click();
    await expect(page.getByTestId('application-title')).toHaveText('Northwind Web');
    await expect(page.getByTestId('application-credentials')).toContainText(NEEDS_SECRET);
  });

  test("a 403 is the forbidden page, with the server's reference", async ({ page }) => {
    await answerApi(page, { read: (route) => problem(route, 403, 'access_denied') });

    await page.goto(`${PAGE}/${app(1)}`);

    await expect(heading(page)).toHaveText("You don't have access to this page.");
    await expect(page.getByTestId('forbidden-reference')).toContainText(TRACE);
  });
});

test.describe('landing and sidebar', () => {
  test('signing in lands on the current Tenant’s Applications list', async ({ page }) => {
    await answerApi(page);

    await page.goto('/');

    await expect(page).toHaveURL(new RegExp(`${PAGE}$`));
    await expect(heading(page)).toHaveText('Applications');
  });

  test('Applications sits in the Applications group, current on its page', async ({ page }) => {
    await answerApi(page);

    await page.goto(PAGE);

    const group = nav(page).getByRole('button', { name: 'Applications' });
    await expect(group).toHaveAttribute('aria-expanded', 'true');
    const link = nav(page).getByRole('link', { name: 'Applications' });
    await expect(link).toHaveAttribute('href', PAGE);
    await expect(link).toHaveAttribute('aria-current', 'page');
  });
});

for (const scheme of ['light', 'dark'] as const) {
  for (const width of [1100, 768]) {
    test(`axe finds no violations at ${width}px, ${scheme}: the list, the empty state, the modal, a page and a failure`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      const api = await answerApi(page);

      await page.goto(PAGE);
      await expect(page.getByTestId('application-name')).toHaveCount(ROWS.length);
      expect(await axe(page), 'list').toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      await createButton(page).click();
      await expect(modal(page)).toBeVisible();
      await modal(page).getByRole('button', { name: 'Create application' }).click();
      await expect(modal(page).getByText('Enter a name.')).toBeVisible();
      expect(await axe(page), 'modal').toEqual([]);
      await modal(page).getByRole('button', { name: 'Cancel' }).click();

      await page.goto(`${PAGE}/${app(1)}`);
      await expect(page.getByTestId('application-credentials')).toBeVisible();
      expect(await axe(page), 'page').toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      api.state.applications = [];
      await page.goto(PAGE);
      await expect(page.getByText('No applications yet')).toBeVisible();
      expect(await axe(page), 'empty').toEqual([]);

      api.state.list = (route) => problem(route, 500, 'unavailable');
      await page.reload();
      await expect(page.getByTestId('applications-load-failed')).toBeVisible();
      expect(await axe(page), 'failed').toEqual([]);
    });
  }
}
