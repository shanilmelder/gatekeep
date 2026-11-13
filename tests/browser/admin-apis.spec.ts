// Story 3.6: the APIs list, Create API and an API's page with its Settings and Permissions, in the built Admin Dashboard
// served by the built Host.Admin (admin-host.mjs) under its real CSP, from localhost. The Admin API is answered by route
// interception. The server's rules (roles, the identifier and Permission rules, the built-in API's fixed Permissions) are
// the Isolation tests' (tests/Isolation/Apis); here, what the pages make of the answers.

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const MY_TENANTS = '/api/v1/deployment/my-tenants';
const CSRF = 'W'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000901';
const TENANT = `ten_${'a'.repeat(25)}a`;
const PAGE = `/tenants/${TENANT}/apis`;
const LIST = `/api/v1/tenants/${TENANT}/apis`;
const TRACE = 'c'.repeat(32);

const TENANT_VIEWER = ['tenant.configuration.read', 'tenant.users.read', 'tenant.logs.read'];
const TENANT_EDITOR = [...TENANT_VIEWER, 'tenant.applications.manage', 'tenant.application_callbacks.manage', 'tenant.apis.manage'];

const ADVICE =
  "Use a different identifier in each environment, such as Dev, Staging and Prod, so a token for one is never accepted by another. It can't be changed later.";

const apiId = (n: number) => `api_${String.fromCharCode(97 + n).repeat(25)}a`;

interface Api {
  id: string;
  name: string;
  identifier: string;
  builtIn: boolean;
  offlineAccess: boolean;
  rbac: boolean;
  accessTokenLifetime: number;
  idTokenLifetime: number;
  refreshTokenAbsoluteLifetime: number;
  refreshTokenInactivityLifetime: number;
  createdAt: string;
}

interface Permission {
  value: string;
  description: string;
}

const resource = (n: number, name: string, identifier: string, builtIn = false): Api => ({
  id: apiId(n),
  name,
  identifier,
  builtIn,
  offlineAccess: false,
  rbac: false,
  accessTokenLifetime: 900,
  idTokenLifetime: 900,
  refreshTokenAbsoluteLifetime: 2592000,
  refreshTokenInactivityLifetime: 604800,
  createdAt: '2026-11-14T09:00:00.000Z',
});

const MANAGEMENT = resource(0, 'Gatekeep Management API', 'urn:gatekeep:management', true);
const BILLING = resource(1, 'Billing', 'https://billing.example.com');
const MANAGEMENT_PERMISSIONS: Permission[] = ['apis:manage', 'applications:manage', 'configuration:read'].map((value) => ({ value, description: '' }));

const json = (route: Route, status: number, body: unknown, headers: Record<string, string> = {}) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body), headers });
const problem = (route: Route, status: number, code: string, errors?: unknown[]) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: TRACE, ...(errors ? { errors } : {}) }) });

const MAXIMUMS: Record<string, number> = {
  accessTokenLifetime: 3600,
  idTokenLifetime: 3600,
  refreshTokenAbsoluteLifetime: 7776000,
  refreshTokenInactivityLifetime: 2592000,
};

async function answerApi(page: Page, capabilities = TENANT_EDITOR, options: { removed?: { status: number; code: string }; seeded?: Permission[] } = {}) {
  const log: string[] = [];
  const writes: { method: string; path: string; body: unknown; headers: Record<string, string> }[] = [];
  const apis: Api[] = [MANAGEMENT, BILLING];
  const permissions: Record<string, Permission[]> = { [MANAGEMENT.id]: [...MANAGEMENT_PERMISSIONS], [BILLING.id]: [...(options.seeded ?? [])] };
  const detail = (api: Api) => ({ api, permissions: [...(permissions[api.id] ?? [])].sort((a, b) => a.value.localeCompare(b.value)) });

  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const { pathname } = url;
      const method = request.method();
      log.push(`${method} ${pathname}`);
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
      if (pathname === `/api/v1/tenants/${TENANT}/capabilities`) return json(route, 200, { capabilities });
      if (method !== 'GET') writes.push({ method, path: pathname, body: request.postDataJSON(), headers: request.headers() });

      if (pathname === LIST && method === 'GET') return json(route, 200, { apis, nextCursor: null });
      if (pathname === LIST && method === 'POST') {
        const { name, identifier } = request.postDataJSON() as { name: string; identifier: string };
        if (apis.some((api) => api.identifier === identifier)) return problem(route, 409, 'api_identifier_taken');
        const created = resource(9, name, identifier);
        apis.push(created);
        permissions[created.id] = [];
        return json(route, 201, detail(created), { Location: `${LIST}/${created.id}` });
      }
      const settings = new RegExp(`^${LIST}/([^/]+)/settings$`).exec(pathname);
      if (settings && method === 'PUT') {
        const body = request.postDataJSON() as Record<string, number | boolean>;
        const errors = Object.entries(MAXIMUMS)
          .filter(([field, maximum]) => (body[field] as number) > maximum)
          .map(([field, maximum]) => ({ field, index: null, reason: 'above_maximum', maximum }));
        if (errors.length > 0) return problem(route, 400, 'api_invalid', errors);
        const index = apis.findIndex((api) => api.id === decodeURIComponent(settings[1]!));
        apis[index] = { ...apis[index]!, ...(body as Partial<Api>) };
        return json(route, 200, detail(apis[index]!));
      }
      const added = new RegExp(`^${LIST}/([^/]+)/permissions$`).exec(pathname);
      if (added && method === 'POST') {
        const api = apis.find((row) => row.id === decodeURIComponent(added[1]!))!;
        if (api.builtIn) return problem(route, 409, 'api_built_in');
        const body = request.postDataJSON() as Permission;
        const list = permissions[api.id]!;
        if (list.some((p) => p.value === body.value)) return problem(route, 409, 'permission_taken');
        list.push({ value: body.value, description: body.description ?? '' });
        return json(route, 201, detail(api), { Location: `${LIST}/${api.id}` });
      }
      const removed = new RegExp(`^${LIST}/([^/]+)/permissions/([^/]+)$`).exec(pathname);
      if (removed && method === 'DELETE') {
        const id = decodeURIComponent(removed[1]!);
        const value = decodeURIComponent(removed[2]!);
        if (options.removed) return problem(route, options.removed.status, options.removed.code);
        permissions[id] = (permissions[id] ?? []).filter((p) => p.value !== value);
        return route.fulfill({ status: 204 });
      }
      const one = new RegExp(`^${LIST}/([^/]+)$`).exec(pathname);
      if (one && method === 'GET') {
        const found = apis.find((row) => row.id === decodeURIComponent(one[1]!));
        return found ? json(route, 200, detail(found)) : problem(route, 404, 'not_found');
      }
      return route.fulfill({ status: 404 });
    },
  );
  return { log, writes, count: (entry: string) => log.filter((line) => line === entry).length };
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
  // tx3 on sf2 in table heads is DESIGN.md's one recorded contrast exception, as admin-applications.spec.ts skips it.
  const everything = await new AxeBuilder({ page }).disableRules(['color-contrast']).analyze();
  const contrast = await new AxeBuilder({ page }).withRules(['color-contrast']).exclude('thead th').analyze();
  return [...everything.violations, ...contrast.violations].map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
}

const heading = (page: Page) => page.getByRole('heading', { level: 1 });
const nav = (page: Page) => page.getByRole('navigation', { name: 'Main' });
const table = (page: Page) => page.getByTestId('apis').getByRole('table');
const modal = (page: Page) => page.getByRole('dialog', { name: 'Create API' });
const addModal = (page: Page) => page.getByRole('dialog', { name: 'Add permission' });
const toast = (page: Page) => page.getByTestId('toast');

test.use({ viewport: { width: 1280, height: 900 } });
watchCsp(test);

test('lists the built-in Management API first with its badge, and APIs sits in the Applications group', async ({ page }) => {
  const api = await answerApi(page);

  await page.goto(PAGE);

  await expect(heading(page)).toHaveText('APIs');
  await expect(table(page).getByRole('columnheader')).toHaveText(['Name', 'Identifier', 'RBAC', 'Access token lifetime']);
  await expect(page.getByTestId('api-name')).toHaveText(['Gatekeep Management API', 'Billing']);
  await expect(page.getByTestId('api-identifier')).toHaveText(['urn:gatekeep:management', 'https://billing.example.com']);
  await expect(table(page).getByRole('row').nth(1).getByTestId('api-built-in')).toHaveText('Built-in');
  await expect(table(page).getByRole('row').nth(2).getByTestId('api-built-in')).toHaveCount(0);
  await expect(table(page).getByRole('row').nth(1)).toContainText('15 minutes');
  await expect(table(page).getByRole('row').nth(1)).toContainText('Off');

  const link = nav(page).getByRole('link', { name: 'APIs' });
  await expect(link).toHaveAttribute('href', PAGE);
  await expect(link).toHaveAttribute('aria-current', 'page');
  expect(api.count(`GET ${LIST}`)).toBe(1);
});

test('Create API shows the environment advice, refuses a duplicate inline, then opens the new API', async ({ page }) => {
  const api = await answerApi(page);
  await page.goto(PAGE);

  await page.getByTestId('apis-create').click();
  await expect(modal(page)).toBeVisible();
  await expect(modal(page)).toContainText(ADVICE);

  await modal(page).getByLabel('Name').fill('Billing again');
  await modal(page).getByLabel('Identifier').fill('https://billing.example.com');
  await page.getByTestId('create-api-submit').click();
  await expect(modal(page)).toContainText('Another API in this tenant already uses this identifier.');
  await expect(modal(page).getByLabel('Identifier')).toBeFocused();

  // The browser's own check: no scheme is refused before anything is sent.
  await modal(page).getByLabel('Identifier').fill('api.example.com');
  await page.getByTestId('create-api-submit').click();
  await expect(modal(page)).toContainText('Use an absolute URI');
  expect(api.writes.filter((w) => w.method === 'POST')).toHaveLength(1);

  await modal(page).getByLabel('Identifier').fill('https://api.example.com');
  await page.getByTestId('create-api-submit').click();

  await expect(toast(page)).toHaveText('API created');
  await expect(page).toHaveURL(new RegExp(`${PAGE}/${apiId(9)}$`));
  await expect(page.getByTestId('api-title')).toHaveText('Billing again');
  const post = api.writes.filter((w) => w.method === 'POST').at(-1)!;
  expect(post.body).toEqual({ name: 'Billing again', identifier: 'https://api.example.com' });
  expect(post.headers['x-gatekeep-csrf']).toBe(CSRF);
  expect(post.headers['x-gatekeep-tenant']).toBe(TENANT);
});

test('Settings show the identifier locked, save with a toast, and refuse a lifetime over its limit with "Maximum is {limit}."', async ({ page }) => {
  const api = await answerApi(page);
  await page.goto(`${PAGE}/${BILLING.id}`);

  await expect(page.getByTestId('api-identifier')).toHaveText('https://billing.example.com');
  await expect(page.getByTestId('api-identifier-locked')).toHaveText("Can't be changed.");
  await expect(page.getByText('Issue refresh tokens for this API')).toBeVisible();
  await expect(page.getByTestId('api-rbac')).toHaveAccessibleName('Enable RBAC');

  await page.getByTestId('api-accessTokenLifetime').fill('3601');
  await page.getByTestId('api-settings-save').click();
  await expect(page.getByText('Maximum is 1 hour.')).toBeVisible();
  expect(api.writes).toHaveLength(0);

  await page.getByTestId('api-accessTokenLifetime').fill('600');
  await page.getByTestId('api-rbac').click();
  await page.getByTestId('api-offline-access').click();
  await page.getByTestId('api-settings-save').click();

  await expect(toast(page)).toHaveText('Changes saved');
  expect(api.writes).toHaveLength(1);
  expect(api.writes[0]!.body).toEqual({
    offlineAccess: true,
    rbac: true,
    accessTokenLifetime: 600,
    idTokenLifetime: 900,
    refreshTokenAbsoluteLifetime: 2592000,
    refreshTokenInactivityLifetime: 604800,
  });
});

test('Permissions start empty with Add, then add, refuse a duplicate inline, and remove', async ({ page }) => {
  const api = await answerApi(page);
  await page.goto(`${PAGE}/${BILLING.id}`);

  const permissions = page.getByTestId('api-permissions');
  await expect(permissions).toContainText('No permissions yet');
  await permissions.getByRole('button', { name: 'Add' }).click();
  await expect(addModal(page)).toBeVisible();
  await addModal(page).getByLabel('Permission').fill('invoices:read');
  await addModal(page).getByLabel('Description').fill('Read invoices');
  await page.getByTestId('add-api-permission-submit').click();

  await expect(toast(page)).toHaveText('Permission added');
  await expect(page.getByTestId('api-permission-value')).toHaveText(['invoices:read']);
  await expect(permissions).toContainText('Read invoices');

  await page.getByTestId('api-permission-add').click();
  await addModal(page).getByLabel('Permission').fill('invoices:read');
  await page.getByTestId('add-api-permission-submit').click();
  await expect(addModal(page)).toContainText('This API already has that permission.');

  // A malformed value is refused before anything is sent.
  const sent = api.writes.length;
  await addModal(page).getByLabel('Permission').fill('Invoices');
  await page.getByTestId('add-api-permission-submit').click();
  await expect(addModal(page)).toContainText('Use resource:action');
  expect(api.writes).toHaveLength(sent);
  await addModal(page).getByRole('button', { name: 'Cancel' }).click();

  await page.getByRole('button', { name: 'Remove invoices:read' }).click();
  await expect(toast(page).last()).toHaveText('Permission removed');
  await expect(permissions).toContainText('No permissions yet');
  expect(api.writes.at(-1)!.method).toBe('DELETE');
  expect(api.writes.at(-1)!.path).toBe(`${LIST}/${BILLING.id}/permissions/invoices%3Aread`);
});

test("The built-in API lists its Permissions with no Add or Remove, and its settings still save", async ({ page }) => {
  await answerApi(page);
  await page.goto(`${PAGE}/${MANAGEMENT.id}`);

  await expect(page.getByTestId('api-built-in')).toHaveText('Built-in');
  await expect(page.getByTestId('api-permission-value')).toHaveText(MANAGEMENT_PERMISSIONS.map((p) => p.value));
  await expect(page.getByTestId('api-permissions-fixed')).toBeVisible();
  await expect(page.getByTestId('api-permission-add')).toHaveCount(0);
  await expect(page.getByTestId('api-permission-remove')).toHaveCount(0);
  await expect(page.getByTestId('api-settings-save')).toBeVisible();
});

test('A Viewer sees everything read-only: no Create, Save, Add or Remove', async ({ page }) => {
  const api = await answerApi(page, TENANT_VIEWER);
  await page.goto(PAGE);

  await expect(page.getByTestId('api-name')).toHaveCount(2);
  await expect(page.getByTestId('apis-create')).toHaveCount(0);

  await page.goto(`${PAGE}/${BILLING.id}`);
  await expect(page.getByTestId('api-identifier')).toHaveText('https://billing.example.com');
  await expect(page.getByTestId('api-settings-read-only')).toBeVisible();
  await expect(page.getByTestId('api-settings-save')).toHaveCount(0);
  await expect(page.getByTestId('api-rbac')).toBeDisabled();
  await expect(page.getByTestId('api-accessTokenLifetime')).toHaveAttribute('readonly', '');
  await expect(page.getByTestId('api-permissions')).toContainText('No permissions yet');
  await expect(page.getByTestId('api-permissions').getByRole('button', { name: 'Add' })).toHaveCount(0);
  expect(api.writes).toHaveLength(0);
});

for (const scheme of ['light', 'dark'] as const) {
  test(`axe finds no violations, ${scheme}: the list, the create modal and an API's page`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await answerApi(page);

    await page.goto(PAGE);
    await expect(page.getByTestId('api-name')).toHaveCount(2);
    expect(await axe(page), 'list').toEqual([]);

    await page.getByTestId('apis-create').click();
    await expect(modal(page)).toBeVisible();
    expect(await axe(page), 'create').toEqual([]);
    await modal(page).getByRole('button', { name: 'Cancel' }).click();

    await page.goto(`${PAGE}/${MANAGEMENT.id}`);
    await expect(page.getByTestId('api-permission-value')).toHaveCount(MANAGEMENT_PERMISSIONS.length);
    expect(await axe(page), 'built-in').toEqual([]);

    await page.goto(`${PAGE}/${BILLING.id}`);
    await expect(page.getByTestId('api-permissions')).toContainText('No permissions yet');
    expect(await axe(page), 'detail').toEqual([]);
  });
}

test('A Remove answered 404, already removed elsewhere, drops the row with no banner', async ({ page }) => {
  await answerApi(page, TENANT_EDITOR, {
    removed: { status: 404, code: 'not_found' },
    seeded: [{ value: 'invoices:read', description: 'Read invoices' }],
  });
  await page.goto(`${PAGE}/${BILLING.id}`);

  await expect(page.getByTestId('api-permission-value')).toHaveText(['invoices:read']);
  await page.getByRole('button', { name: 'Remove invoices:read' }).click();
  await expect(page.getByTestId('api-permissions')).toContainText('No permissions yet');
  await expect(page.getByTestId('api-permission-failed')).toHaveCount(0);
  await expect(toast(page)).toHaveCount(0);
});

test('A Remove answered 403 shows the forbidden banner and keeps the row', async ({ page }) => {
  await answerApi(page, TENANT_EDITOR, {
    removed: { status: 403, code: 'access_denied' },
    seeded: [{ value: 'invoices:read', description: 'Read invoices' }],
  });
  await page.goto(`${PAGE}/${BILLING.id}`);

  await page.getByRole('button', { name: 'Remove invoices:read' }).click();
  await expect(page.getByTestId('api-permission-forbidden')).toBeVisible();
  await expect(page.getByTestId('api-permission-failed')).toHaveCount(0);
  await expect(page.getByTestId('api-permission-value')).toHaveText(['invoices:read']);
});
