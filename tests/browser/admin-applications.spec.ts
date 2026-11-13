// Story 3.1: the Applications list, Create Application and an Application's page, in the built
// Admin Dashboard served by the built Host.Admin (admin-host.mjs) under its real CSP, from
// localhost. The Admin API is answered by route interception. The server's rules (roles, the
// name and type, no secret, the hidden system Application) are the Isolation tests'
// (tests/Isolation/Applications); here, what the pages make of the answers.

import AxeBuilder from '@axe-core/playwright';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, test, type CDPSession, type Page, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const MY_TENANTS = '/api/v1/deployment/my-tenants';
const BEGIN = '/api/v1/deployment/signin';
const COMPLETE = '/api/v1/deployment/signin/complete';
const ASSERTION_COMPLETE = '/api/v1/deployment/assertions/complete';
const CSRF = 'W'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000901';
const TENANT = `ten_${'a'.repeat(25)}a`;
const PAGE = `/tenants/${TENANT}/applications`;
const LIST = `/api/v1/tenants/${TENANT}/applications`;
const TRACE = 'c'.repeat(32);

const TENANT_VIEWER = ['tenant.configuration.read', 'tenant.users.read', 'tenant.logs.read'];
const TENANT_EDITOR = [...TENANT_VIEWER, 'tenant.applications.manage', 'tenant.application_callbacks.manage', 'tenant.settings.manage'];
// Story 3.3: only a Tenant Owner holds tenant.client_secrets.manage.
const TENANT_OWNER = [...TENANT_EDITOR, 'tenant.client_secrets.manage', 'tenant.label.manage'];

const app = (n: number) => `app_${String.fromCharCode(97 + n).repeat(25)}a`;

type Type = 'spa' | 'web' | 'native' | 'machine';

interface Application {
  id: string;
  clientId: string;
  name: string;
  type: Type;
  credentialRequired: boolean;
  createdAt: string;
  callbackUrls: string[];
  logoutUrls: string[];
  webOrigins: string[];
  grantTypes: string[];
}

const application = (n: number, name: string, type: Type, createdAt = '2026-11-10T09:00:00.000Z'): Application => ({
  id: app(n),
  clientId: app(n),
  name,
  type,
  credentialRequired: type === 'web' || type === 'machine',
  createdAt,
  callbackUrls: [],
  logoutUrls: [],
  webOrigins: [],
  grantTypes: type === 'machine' ? ['client_credentials'] : type === 'web' ? ['authorization_code'] : [],
});

const ROWS: Application[] = [
  application(0, 'Storefront', 'spa', '2026-11-10T09:00:00.000Z'),
  application(1, 'Northwind Web', 'web', '2026-11-09T09:00:00.000Z'),
  application(2, 'iOS app', 'native', '2026-11-08T09:00:00.000Z'),
  application(3, 'Billing worker', 'machine', '2026-11-07T09:00:00.000Z'),
];

const LABELS: Record<Type, string> = { spa: 'Single-page', web: 'Regular web', native: 'Native', machine: 'Machine-to-machine' };
const NEEDS_SECRET = 'No client secret yet. A Tenant Owner must create one.';
const NO_SECRET = 'No secret needed.';

/** One live client secret (Story 3.3), as the list answers it. */
interface Secret {
  id: string;
  createdAt: string;
  expiresAt: string | null;
}

const sec = (n: number) => `sec_${String.fromCharCode(97 + n).repeat(25)}a`;
const CURRENT: Secret = { id: sec(0), createdAt: '2026-11-12T09:00:00.000Z', expiresAt: null };
const OLD: Secret = { id: sec(1), createdAt: '2026-11-01T09:00:00.000Z', expiresAt: '2026-11-13T09:00:00.000Z' };
/** The value the n-th create answers: the Tenant's ID, a dot, and 43 base64url characters. */
const secretValue = (n: number) => `${TENANT}.${'S'.repeat(42)}${n}`;

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
  /** The Session has expired: every read but the sign-in's is 401 until the renewal completes. */
  expired: boolean;
  /** Story 3.2: the Tenant's label, the Application a fresh assertion was completed for, and the settings save's answer. */
  label: 'dev' | 'staging' | 'prod';
  grant: string | null;
  begunFor: string | null;
  save: ((route: Route) => Promise<void>) | null;
  /** Story 3.3: each Application's live secrets, the creates answered so far, and replacements for the list and a write. */
  secrets: Record<string, Secret[]>;
  created: number;
  secretList: ((route: Route) => Promise<void>) | null;
  secretWrite: ((route: Route) => Promise<void>) | null;
}

async function answerApi(page: Page, initial: Partial<State> = {}) {
  const log: string[] = [];
  const posts: { body: unknown; headers: Record<string, string> }[] = [];
  const puts: { body: Record<string, unknown>; headers: Record<string, string> }[] = [];
  const begins: unknown[] = [];
  const secretWrites: { path: string; headers: Record<string, string> }[] = [];
  const state: State = {
    capabilities: TENANT_EDITOR,
    applications: ROWS,
    nextCursor: null,
    later: [],
    list: null,
    read: null,
    create: null,
    expired: false,
    label: 'dev',
    grant: null,
    begunFor: null,
    save: null,
    secrets: {},
    created: 0,
    secretList: null,
    secretWrite: null,
    ...initial,
  };
  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const { pathname } = url;
      log.push(`${request.method()} ${pathname}${url.search}`);
      if (pathname === BEGIN) {
        return json(route, 200, {
          challenge: randomBytes(32).toString('base64url'),
          rpId: url.hostname,
          timeout: 300000,
          userVerification: 'required',
          allowCredentials: [],
        });
      }
      if (pathname === COMPLETE) {
        state.expired = false;
        return json(route, 200, { adminId: ADMIN_ID, csrfToken: CSRF, setupComplete: true });
      }
      if (state.expired) return route.fulfill({ status: 401 });
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
      if (pathname === MY_TENANTS) return json(route, 200, { tenants: [{ id: TENANT, name: 'Alpha', host: 'alpha.gatekeep.test', label: state.label }] });
      if (pathname === `/api/v1/tenants/${TENANT}/assertions`) {
        const binding = request.postDataJSON() as { target: string | null };
        begins.push(binding);
        state.begunFor = binding.target;
        return json(route, 200, {
          challenge: randomBytes(32).toString('base64url'),
          rpId: url.hostname,
          timeout: 300000,
          userVerification: 'required',
          allowCredentials: [],
        });
      }
      if (pathname === ASSERTION_COMPLETE) {
        state.grant = state.begunFor;
        return route.fulfill({ status: 204 });
      }
      const settings = new RegExp(`^${LIST}/([^/]+)/settings$`).exec(pathname);
      if (settings && request.method() === 'PUT') {
        const body = request.postDataJSON() as Record<string, unknown> & { callbackUrls: string[]; logoutUrls: string[]; webOrigins: string[]; grantTypes: string[] };
        puts.push({ body, headers: request.headers() });
        if (state.save) return state.save(route);
        const id = decodeURIComponent(settings[1]!);
        const found = state.applications.find((row) => row.id === id);
        if (!found) return problem(route, 404, 'not_found');
        const changed = [...body.callbackUrls].sort().join('\n') !== [...found.callbackUrls].sort().join('\n');
        if (state.label === 'prod' && changed) {
          if (state.grant !== id) return problem(route, 403, 'fresh_assertion_required');
          state.grant = null;
        }
        const saved: Application = {
          ...found,
          callbackUrls: body.callbackUrls,
          logoutUrls: body.logoutUrls,
          webOrigins: body.webOrigins,
          grantTypes: [...body.grantTypes].sort(),
        };
        state.applications = state.applications.map((row) => (row.id === id ? saved : row));
        return json(route, 200, saved);
      }
      // Story 3.3: every write needs a fresh assertion bound to the Application, used up by the write.
      const secrets = new RegExp(`^${LIST}/([^/]+)/secrets(?:/([^/]+)/revoke)?$`).exec(pathname);
      if (secrets) {
        const id = decodeURIComponent(secrets[1]!);
        const live = state.secrets[id] ?? [];
        if (request.method() === 'GET') return state.secretList ? state.secretList(route) : json(route, 200, { items: live });
        secretWrites.push({ path: pathname, headers: request.headers() });
        if (state.grant !== id) return problem(route, 403, 'fresh_assertion_required');
        state.grant = null;
        if (state.secretWrite) return state.secretWrite(route);
        if (secrets[2] === undefined) {
          if (live.length >= 2) return problem(route, 409, 'client_secret_limit_reached');
          state.created += 1;
          const made: Secret = { id: sec(10 + state.created), createdAt: '2026-11-13T09:00:00.000Z', expiresAt: null };
          const items = [made, ...live.map((secret) => (secret.expiresAt === null ? { ...secret, expiresAt: '2026-11-14T09:00:00.000Z' } : secret))];
          state.secrets[id] = items;
          return json(route, 201, { secret: secretValue(state.created), items });
        }
        const secretId = decodeURIComponent(secrets[2]);
        if (!live.some((secret) => secret.id === secretId)) return problem(route, 404, 'not_found');
        state.secrets[id] = live.filter((secret) => secret.id !== secretId);
        return json(route, 200, { items: state.secrets[id] });
      }
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
  return { log, posts, puts, begins, secretWrites, state, count: (entry: string) => log.filter((line) => line === entry).length };
}

/** A virtual CTAP2 authenticator holding the Admin's resident credential, so the shell's renewal completes by itself. */
async function authenticator(page: Page, rpId: string) {
  const cdp: CDPSession = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
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

  test('a Load more that fails shows the banner with its reference, keeps the rows, and Retry appends the next page', async ({ page }) => {
    const older = application(5, 'Legacy portal', 'web', '2026-10-01T09:00:00.000Z');
    const api = await answerApi(page, { nextCursor: app(3), later: [older] });
    await page.goto(PAGE);
    await expect(page.getByTestId('application-name')).toHaveCount(ROWS.length);

    api.state.list = (route) =>
      new URL(route.request().url()).searchParams.has('cursor')
        ? problem(route, 500, 'unavailable')
        : json(route, 200, { applications: ROWS, nextCursor: app(3) });
    await page.getByTestId('applications-load-more').click();

    const failed = page.getByTestId('applications-more-failed');
    await expect(failed).toContainText("We couldn't load this page.");
    await expect(failed).toContainText(TRACE);
    await expect(page.getByTestId('application-name')).toHaveText(ROWS.map((row) => row.name));

    api.state.list = null;
    await failed.getByRole('button', { name: 'Retry' }).click();
    await expect(page.getByTestId('application-name')).toHaveText([...ROWS.map((row) => row.name), older.name]);
    await expect(page.getByTestId('applications-more-failed')).toHaveCount(0);
    expect(api.count(`GET ${LIST}?cursor=${app(3)}`)).toBe(2);
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
      // Settings is the tab it opens on (Story 3.2); Credentials is the next.
      await expect(page.getByRole('tab', { name: 'Settings' })).toHaveAttribute('aria-selected', 'true');
      await page.getByRole('tab', { name: 'Credentials' }).click();
      await expect(page.getByTestId('application-credentials')).toContainText(type === 'web' || type === 'machine' ? NEEDS_SECRET : NO_SECRET);
      await expect(page.getByTestId('application-credentials')).not.toContainText(type === 'web' || type === 'machine' ? NO_SECRET : NEEDS_SECRET);

      // The breadcrumb goes back to the list, which now holds it.
      await crumbs.getByRole('link', { name: 'Applications' }).click();
      await expect(page).toHaveURL(new RegExp(`${PAGE}$`));
      await expect(page.getByTestId('application-name').first()).toHaveText('My app');
    });
  }

  test('an empty, too long or control-character name is refused in the browser, with nothing sent; Cancel closes', async ({ page }) => {
    const api = await answerApi(page);
    await page.goto(PAGE);
    await createButton(page).click();
    const dialog = modal(page);
    const name = dialog.getByRole('textbox', { name: 'Name' });
    const submit = dialog.getByRole('button', { name: 'Create application' });

    await name.fill('   ');
    await submit.click();
    await expect(dialog.getByText('Enter a name.')).toBeVisible();
    await expect(name).toBeFocused();

    // 201 characters after trimming: the field doesn't cut it short, the check refuses it.
    await name.fill(`  ${'x'.repeat(201)}  `);
    await expect(name).toHaveValue(`  ${'x'.repeat(201)}  `);
    await submit.click();
    await expect(dialog.getByText('Use at most 200 characters, with no control characters.')).toBeVisible();

    // A pasted control character.
    await name.fill('Myapp');
    await submit.click();
    await expect(dialog.getByText('Use at most 200 characters, with no control characters.')).toBeVisible();
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

test.describe('create refusals the shell handles', () => {
  test('a 409 tenant_mismatch closes the modal, leaves the URL, and opens nothing', async ({ page }) => {
    const api = await answerApi(page, { create: (route) => problem(route, 409, 'tenant_mismatch') });
    await page.goto(PAGE);
    await createButton(page).click();
    await modal(page).getByRole('textbox', { name: 'Name' }).fill('My app');
    await modal(page).getByRole('button', { name: 'Create application' }).click();

    await expect(modal(page)).toBeHidden();
    await expect(page).toHaveURL(new RegExp(`${PAGE}$`));
    await expect(heading(page)).toHaveText('Applications');
    expect(api.posts).toHaveLength(1);
    expect(api.count(`GET ${LIST}/${app(9)}`)).toBe(0);
  });

  test('a 401 the renewal answered keeps the modal, with the sign-in text and what was typed, and is never resent', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page);
    await page.goto(PAGE);
    await createButton(page).click();
    const dialog = modal(page);
    await dialog.getByRole('textbox', { name: 'Name' }).fill('My app');
    api.state.expired = true;
    await dialog.getByRole('button', { name: 'Create application' }).click();

    await expect.poll(() => api.count(`POST ${COMPLETE}`)).toBe(1);

    await expect(dialog.getByTestId('create-application-signed-in-again')).toHaveText(
      "You're signed in again, but nothing was changed. Confirm to try again.",
    );
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('textbox', { name: 'Name' })).toHaveValue('My app');
    await expect(page).toHaveURL(new RegExp(`${PAGE}$`));
    // The refused POST reached no create: the renewal never sends it again.
    expect(api.posts).toHaveLength(0);
    expect(api.count(`POST ${LIST}`)).toBe(1);
  });
});

test.describe('detail', () => {
  for (const segment of ['logs', 'settings', '%E0%A4%A']) {
    test(`/applications/${segment} is an Application's page, which says it doesn't exist`, async ({ page }) => {
      await answerApi(page);

      if (segment.startsWith('%')) {
        // An escape that doesn't decode never reaches the host as a page load, so it arrives
        // as the shell's own navigation, as admin-shell.spec.ts does for a Tenant segment.
        await page.goto(PAGE);
        await expect(heading(page)).toHaveText('Applications');
        await page.evaluate((path) => {
          history.pushState(null, '', path);
          dispatchEvent(new PopStateEvent('popstate'));
        }, `${PAGE}/${segment}`);
      } else {
        await page.goto(`${PAGE}/${segment}`);
      }

      await expect(page.getByTestId('application-not-found')).toHaveText("This application doesn't exist in this Tenant.");
      await expect(page.getByTestId('logs-page')).toHaveCount(0);
      await expect(heading(page)).not.toHaveText('Tenant settings');
      await expect(heading(page)).not.toHaveText('Logs');
    });
  }

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
    await page.getByRole('tab', { name: 'Credentials' }).click();
    await expect(page.getByTestId('application-credentials')).toContainText(NEEDS_SECRET);
  });

  test("a 403 is the forbidden page, with the server's reference", async ({ page }) => {
    await answerApi(page, { read: (route) => problem(route, 403, 'access_denied') });

    await page.goto(`${PAGE}/${app(1)}`);

    await expect(heading(page)).toHaveText("You don't have access to this page.");
    await expect(page.getByTestId('forbidden-reference')).toContainText(TRACE);
  });
});

// Story 3.2: an Application's Settings tab. The server's rules are ApplicationSettingsApiTests'; here,
// what the tab shows for each type and makes of the answers.
test.describe('settings', () => {
  const GRANTS = ['Authorization Code with PKCE', 'Refresh Token', 'Client Credentials'];
  const grant = (page: Page, name: string) => page.getByRole('switch', { name });
  const save = (page: Page) => page.getByTestId('application-save');
  const toast = (page: Page) => page.getByTestId('toast');
  const settingsPuts = (api: Awaited<ReturnType<typeof answerApi>>) => api.log.filter((line) => line.startsWith('PUT '));

  for (const [n, type] of [[0, 'spa'], [1, 'web'], [2, 'native'], [3, 'machine']] as const) {
    test(`a ${LABELS[type]} Application's Settings show its own fields and exactly the three grants`, async ({ page }) => {
      await answerApi(page);

      await page.goto(`${PAGE}/${app(n)}`);

      await expect(page.getByRole('tab', { name: 'Settings' })).toHaveAttribute('aria-selected', 'true');
      await expect(page.getByRole('switch')).toHaveCount(3);
      for (const name of GRANTS) await expect(grant(page, name)).toHaveCount(1);
      for (const removed of [/Implicit/, /Password/, /Device/, /CIBA/, /Token Exchange/, /CORS/, /Wildcards allowed/, /embedded/i]) {
        await expect(page.getByRole('switch', { name: removed })).toHaveCount(0);
        await expect(page.getByRole('checkbox', { name: removed })).toHaveCount(0);
      }
      await expect(page.getByText('Allowed Origins (CORS)')).toHaveCount(0);

      if (type === 'machine') {
        await expect(page.getByTestId('application-urls')).toHaveCount(0);
        await expect(page.getByTestId('application-machine-no-urls')).toHaveText('Machine-to-machine applications have no URLs: they sign no users in.');
        await expect(grant(page, 'Client Credentials')).toBeEnabled();
        await expect(grant(page, 'Client Credentials')).toHaveAttribute('aria-checked', 'true');
        for (const name of GRANTS.slice(0, 2)) await expect(grant(page, name)).toBeDisabled();
        await expect(page.getByTestId('application-grants')).toContainText('Not available for Machine-to-machine.');
      } else {
        const urls = page.getByTestId('application-urls');
        await expect(urls.getByRole('textbox', { name: 'Allowed Callback URLs' })).toBeVisible();
        await expect(urls.getByRole('textbox', { name: 'Allowed Logout URLs' })).toBeVisible();
        await expect(urls.getByRole('textbox', { name: 'Allowed Web Origins' })).toHaveCount(type === 'native' ? 0 : 1);
        // With no URLs, the helper explains exact matching.
        await expect(urls).toContainText('Matched exactly. One per line. No wildcards. Users are only sent back to a URL listed here');
        await expect(grant(page, 'Client Credentials')).toBeDisabled();
        await expect(page.getByTestId('application-grants')).toContainText(`Not available for ${LABELS[type]}.`);
        await expect(grant(page, 'Authorization Code with PKCE')).toBeEnabled();
      }
      await expect(page.getByTestId('application-native-guidance')).toHaveCount(type === 'native' ? 1 : 0);
      if (type === 'native') {
        await expect(page.getByTestId('application-native-guidance')).toHaveText(
          "Open sign-in in the system browser. Embedded web views aren't supported.",
        );
      }
    });
  }

  test('Save sends the full settings once, with the page Tenant, then shows "Changes saved"', async ({ page }) => {
    const api = await answerApi(page);
    await page.goto(`${PAGE}/${app(0)}`);

    await page.getByTestId('application-callbackUrls').fill('  https://store.example/cb  \n\nhttp://127.0.0.1:3000/cb');
    await page.getByTestId('application-webOrigins').fill('https://store.example');
    await expect(grant(page, 'Refresh Token')).toBeDisabled();
    await grant(page, 'Authorization Code with PKCE').click();
    await grant(page, 'Refresh Token').click();
    await save(page).click();

    await expect(toast(page)).toHaveText('Changes saved');
    expect(api.puts).toHaveLength(1);
    expect(api.puts[0]!.body).toEqual({
      callbackUrls: ['https://store.example/cb', 'http://127.0.0.1:3000/cb'],
      logoutUrls: [],
      webOrigins: ['https://store.example'],
      grantTypes: ['authorization_code', 'refresh_token'],
    });
    expect(api.puts[0]!.headers['x-gatekeep-tenant']).toBe(TENANT);
    expect(api.puts[0]!.headers['x-gatekeep-csrf']).toBe(CSRF);
    // Saved as the server answered, one URL per line.
    await expect(page.getByTestId('application-callbackUrls')).toHaveValue('https://store.example/cb\nhttp://127.0.0.1:3000/cb');
    await expect(page.getByTestId('application-urls')).toContainText('Matched exactly. One per line. No wildcards.');
    expect(api.begins).toHaveLength(0);
  });

  test('Refresh Token turns off with Authorization Code, and stays disabled while it is off', async ({ page }) => {
    const api = await answerApi(page);
    await page.goto(`${PAGE}/${app(1)}`);

    await expect(grant(page, 'Authorization Code with PKCE')).toHaveAttribute('aria-checked', 'true');
    await grant(page, 'Refresh Token').click();
    await expect(grant(page, 'Refresh Token')).toHaveAttribute('aria-checked', 'true');
    await grant(page, 'Authorization Code with PKCE').click();
    await expect(grant(page, 'Refresh Token')).toHaveAttribute('aria-checked', 'false');
    await expect(grant(page, 'Refresh Token')).toBeDisabled();
    await expect(page.getByTestId('application-grants')).toContainText('Turn on Authorization Code with PKCE first.');

    await save(page).click();
    await expect(toast(page)).toHaveText('Changes saved');
    expect(api.puts[0]!.body).toMatchObject({ grantTypes: [] });
  });

  test("each refused line shows on its field by its line in the textarea, and focus moves to the first", async ({ page }) => {
    const api = await answerApi(page, {
      save: (route) =>
        route.fulfill({
          status: 400,
          contentType: 'application/problem+json',
          body: JSON.stringify({
            code: 'application_invalid',
            traceId: TRACE,
            errors: [
              { field: 'callbackUrls', index: 1, reason: 'not_absolute' },
              { field: 'callbackUrls', index: 2, reason: 'scheme_not_allowed' },
              { field: 'webOrigins', index: 0, reason: 'not_absolute' },
              { field: 'grantTypes', index: null, reason: 'not_allowed_for_type' },
            ],
          }),
        }),
    });
    await page.goto(`${PAGE}/${app(1)}`);
    const callbacks = page.getByTestId('application-callbackUrls');

    await callbacks.fill('https://ok.example/cb\n\n/cb\nhttp://a.example/cb');
    await page.getByTestId('application-webOrigins').fill('https://a.example/path');
    await save(page).click();

    await expect(callbacks).toBeFocused();
    await expect(page.getByTestId('application-urls')).toContainText('Line 3: Must be an absolute URL, with no fragment or user info.');
    await expect(page.getByTestId('application-urls')).toContainText('Line 4: Use https, or http on 127.0.0.1 or [::1] only.');
    await expect(page.getByTestId('application-urls')).toContainText('Line 1: Must be scheme://host[:port], with no path or query.');
    await expect(page.getByTestId('application-grants-error')).toHaveText("This application type can't have these grants together.");
    await expect(callbacks).toHaveAttribute('aria-invalid', 'true');
    // What was typed is kept, and no toast.
    await expect(callbacks).toHaveValue('https://ok.example/cb\n\n/cb\nhttp://a.example/cb');
    await expect(toast(page)).toHaveCount(0);
    expect(api.puts).toHaveLength(1);
  });

  test('a Prod callback change asks for a fresh assertion bound to the Application, is sent once more, and saves', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, { label: 'prod' });
    await page.goto(`${PAGE}/${app(1)}`);

    await page.getByTestId('application-callbackUrls').fill('https://northwind.example/cb');
    await save(page).click();

    await expect(toast(page)).toHaveText('Changes saved');
    expect(api.log.filter((line) => line.startsWith('PUT') || line.startsWith('POST'))).toEqual([
      `PUT ${LIST}/${app(1)}/settings`,
      `POST /api/v1/tenants/${TENANT}/assertions`,
      `POST ${ASSERTION_COMPLETE}`,
      `PUT ${LIST}/${app(1)}/settings`,
    ]);
    expect(api.begins).toEqual([{ action: 'tenant.application_callbacks.manage', target: app(1) }]);
    expect(api.count('POST /api/v1/deployment/assertions')).toBe(0);

    // A Prod save that keeps the callbacks asks nothing.
    await page.getByTestId('application-logoutUrls').fill('https://northwind.example/');
    await save(page).click();
    await expect.poll(() => settingsPuts(api).length).toBe(3);
    expect(api.begins).toHaveLength(1);
  });

  test('a new Prod custom-scheme URL needs the acknowledgement before Save, which the save then carries', async ({ page }) => {
    const api = await answerApi(page, { label: 'prod' });
    await page.goto(`${PAGE}/${app(2)}`);
    await expect(page.getByTestId('application-custom-scheme')).toHaveCount(0);

    await page.getByTestId('application-logoutUrls').fill('com.example.app:/logout');
    const acknowledge = page.getByRole('checkbox', { name: /custom URL scheme/ });
    await expect(acknowledge).toBeVisible();
    await save(page).click();

    await expect(page.getByTestId('application-custom-scheme-error')).toHaveText('Tick this to save a custom-scheme URL in a Prod Tenant.');
    await expect(acknowledge).toBeFocused();
    expect(api.puts).toHaveLength(0);

    await acknowledge.check();
    await save(page).click();
    await expect(toast(page)).toHaveText('Changes saved');
    expect(api.puts[0]!.body).toMatchObject({ logoutUrls: ['com.example.app:/logout'], acknowledgeCustomScheme: true });

    // In Dev there is nothing to acknowledge.
    api.state.label = 'dev';
    await page.reload();
    await page.getByTestId('application-callbackUrls').fill('com.example.app:/cb');
    await expect(page.getByTestId('application-custom-scheme')).toHaveCount(0);
  });

  test("the server's acknowledgement refusal shows the checkbox's error", async ({ page }) => {
    await answerApi(page, {
      label: 'prod',
      save: (route) => problem(route, 400, 'custom_scheme_acknowledgement_required'),
    });
    await page.goto(`${PAGE}/${app(2)}`);
    await page.getByTestId('application-callbackUrls').fill('com.example.app:/cb');
    await page.getByRole('checkbox', { name: /custom URL scheme/ }).check();

    await save(page).click();

    await expect(page.getByTestId('application-custom-scheme-error')).toBeVisible();
  });

  test('when the page thinks the Tenant isn\'t Prod but the server asks for the acknowledgement, the checkbox shows and the ticked resend saves', async ({ page }) => {
    const api = await answerApi(page, { label: 'dev' });
    api.state.save = (route) => {
      const body = route.request().postDataJSON() as { acknowledgeCustomScheme?: boolean; callbackUrls: string[] };
      if (body.acknowledgeCustomScheme === true) return json(route, 200, { ...ROWS[2]!, callbackUrls: body.callbackUrls });
      return problem(route, 400, 'custom_scheme_acknowledgement_required');
    };
    await page.goto(`${PAGE}/${app(2)}`);
    await page.getByTestId('application-callbackUrls').fill('com.example.app:/cb');
    await expect(page.getByTestId('application-custom-scheme')).toHaveCount(0);

    await save(page).click();

    const acknowledge = page.getByRole('checkbox', { name: /custom URL scheme/ });
    await expect(acknowledge).toBeVisible();
    await expect(acknowledge).toBeFocused();
    await expect(page.getByTestId('application-custom-scheme-error')).toBeVisible();
    await acknowledge.check();
    await save(page).click();

    await expect(toast(page)).toHaveText('Changes saved');
    expect(api.puts).toHaveLength(2);
    expect(api.puts[0]!.body).not.toHaveProperty('acknowledgeCustomScheme');
    expect(api.puts[1]!.body).toMatchObject({ callbackUrls: ['com.example.app:/cb'], acknowledgeCustomScheme: true });
  });

  test('a Viewer sees every field read-only, the switches off-limits, and no Save', async ({ page }) => {
    await answerApi(page, { capabilities: TENANT_VIEWER });

    await page.goto(`${PAGE}/${app(1)}`);

    await expect(page.getByTestId('application-callbackUrls')).toHaveAttribute('readonly', '');
    await expect(page.getByTestId('application-logoutUrls')).toHaveAttribute('readonly', '');
    for (const name of GRANTS) await expect(grant(page, name)).toBeDisabled();
    await expect(save(page)).toHaveCount(0);
    await expect(page.getByTestId('application-settings-read-only')).toHaveText('Only Tenant Editors and Owners can change these.');
  });

  test('leaving Settings with unsaved changes asks first: Keep editing stays, Discard and leave goes', async ({ page }) => {
    await answerApi(page);
    await page.goto(`${PAGE}/${app(1)}`);
    await page.getByTestId('application-callbackUrls').fill('https://northwind.example/cb');

    await page.getByRole('tab', { name: 'Credentials' }).click();
    const prompt = page.getByRole('dialog', { name: 'Discard unsaved changes?' });
    await expect(prompt).toBeVisible();
    await prompt.getByRole('button', { name: 'Keep editing' }).click();
    await expect(prompt).toBeHidden();
    await expect(page.getByRole('tab', { name: 'Settings' })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByTestId('application-callbackUrls')).toHaveValue('https://northwind.example/cb');

    await page.getByRole('tab', { name: 'Credentials' }).click();
    await page.getByRole('dialog', { name: 'Discard unsaved changes?' }).getByRole('button', { name: 'Discard and leave' }).click();
    await expect(page.getByTestId('application-credentials')).toBeVisible();

    // Back on Settings, the stored settings show.
    await page.getByRole('tab', { name: 'Settings' }).click();
    await expect(page.getByTestId('application-callbackUrls')).toHaveValue('');
  });

  test('a refused or failed save shows its banner and keeps what was typed', async ({ page }) => {
    const api = await answerApi(page, { save: (route) => problem(route, 403, 'access_denied') });
    await page.goto(`${PAGE}/${app(1)}`);
    await page.getByTestId('application-callbackUrls').fill('https://northwind.example/cb');

    await save(page).click();
    await expect(page.getByTestId('application-save-forbidden')).toHaveText("You can't do this in this session.");

    api.state.save = (route) => problem(route, 500, 'unavailable');
    await save(page).click();
    const failed = page.getByTestId('application-save-failed');
    await expect(failed).toContainText("Couldn't save the changes. Try again.");
    await expect(failed).toContainText(TRACE);
    await expect(page.getByTestId('application-callbackUrls')).toHaveValue('https://northwind.example/cb');
    expect(api.puts).toHaveLength(2);
  });

  test('a 401 the renewal answered keeps what was typed and is never resent', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page);
    await page.goto(`${PAGE}/${app(1)}`);
    await page.getByTestId('application-callbackUrls').fill('https://northwind.example/cb');
    api.state.expired = true;

    await save(page).click();

    await expect.poll(() => api.count(`POST ${COMPLETE}`)).toBe(1);
    await expect(page.getByTestId('application-callbackUrls')).toHaveValue('https://northwind.example/cb');
    await expect(toast(page)).toHaveCount(0);
    expect(api.puts).toHaveLength(0);
    expect(settingsPuts(api)).toHaveLength(1);
  });
});

test.describe('credentials (Story 3.3)', () => {
  const toast = (page: Page) => page.getByTestId('toast');
  const reveal = (page: Page) => page.getByRole('dialog', { name: 'Client secret' });
  const credentials = (page: Page) => page.getByTestId('application-credentials');
  const SECRETS = (id: string) => `${LIST}/${id}/secrets`;
  const writes = (api: Awaited<ReturnType<typeof answerApi>>) => api.log.filter((line) => line.startsWith('POST'));

  /** Closes the reveal: Close does nothing until "I've copied this" is ticked. */
  async function closeReveal(page: Page) {
    const dialog = reveal(page);
    const close = dialog.getByRole('button', { name: 'Close' });
    await expect(close).toHaveAttribute('aria-disabled', 'true');
    await close.click({ force: true });
    await expect(dialog).toBeVisible();
    await dialog.getByRole('checkbox', { name: "I've copied this" }).check();
    await expect(close).not.toHaveAttribute('aria-disabled', 'true');
    await close.click();
    await expect(dialog).toHaveCount(0);
  }

  test("an Owner creates the first secret: confirmed, shown once, Close waits for \"I've copied this\", and never shown again", async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, { capabilities: TENANT_OWNER });
    await page.goto(`${PAGE}/${app(1)}?tab=credentials`);

    await expect(page.getByTestId('application-secrets-none')).toHaveText('No client secret yet.');
    await credentials(page).getByRole('button', { name: 'Create secret' }).click();

    const dialog = reveal(page);
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('code')).toHaveText(secretValue(1));
    await expect(dialog).toContainText("This is the only time it's shown.");
    await closeReveal(page);

    await expect(toast(page)).toHaveText('Secret created');
    await expect(page.getByTestId('application-secret-current')).toContainText('Current secret · Created');
    await expect(page.locator('body')).not.toContainText(secretValue(1));
    expect(writes(api)).toEqual([
      `POST ${SECRETS(app(1))}`,
      `POST /api/v1/tenants/${TENANT}/assertions`,
      `POST ${ASSERTION_COMPLETE}`,
      `POST ${SECRETS(app(1))}`,
    ]);
    expect(api.begins).toEqual([{ action: 'tenant.client_secrets.manage', target: app(1) }]);
    expect(api.secretWrites[1]!.headers['x-gatekeep-tenant']).toBe(TENANT);
    expect(api.secretWrites[1]!.headers['x-gatekeep-csrf']).toBe(CSRF);

    // Read again, the list shows the secret's row and never its value.
    await page.reload();
    await expect(page.getByTestId('application-secret-current')).toBeVisible();
    await expect(page.locator('body')).not.toContainText(secretValue(1));
    await expect(page.getByRole('button', { name: /reveal/i })).toHaveCount(0);
  });

  test('rotating shows the new secret once, then the 24h toast; Rotate waits while the old one overlaps, and End old secret now ends it', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, { capabilities: TENANT_OWNER, secrets: { [app(3)]: [CURRENT] } });
    await page.goto(`${PAGE}/${app(3)}?tab=credentials`);

    await credentials(page).getByRole('button', { name: 'Rotate secret' }).click();
    await expect(reveal(page).locator('code')).toHaveText(secretValue(1));
    await closeReveal(page);
    await expect(toast(page)).toHaveText('New secret created. Old secret valid for 24h.');

    const old = page.getByTestId('application-secret-old');
    await expect(old).toContainText('Old secret · Valid until');
    await expect(page.getByTestId('application-secret-current')).toContainText('Current secret · Created');
    const rotate = credentials(page).getByRole('button', { name: 'Rotate secret' });
    await expect(rotate).toHaveAttribute('aria-disabled', 'true');
    await expect(page.getByTestId('application-secret-rotate-blocked')).toHaveText('End the old secret before rotating again.');
    await rotate.click({ force: true });
    expect(api.secretWrites).toHaveLength(2);

    await old.getByRole('button', { name: 'End old secret now' }).click();
    await expect(toast(page)).toHaveText('Old secret ended');
    await expect(page.getByTestId('application-secret-old')).toHaveCount(0);
    await expect(rotate).not.toHaveAttribute('aria-disabled', 'true');
    expect(api.secretWrites.at(-1)!.path).toBe(`${SECRETS(app(3))}/${CURRENT.id}/revoke`);
    expect(api.begins).toHaveLength(2);
  });

  test("Revoke opens a confirming modal that says what it stops, and revoking leaves no secret", async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, { capabilities: TENANT_OWNER, secrets: { [app(1)]: [CURRENT] } });
    await page.goto(`${PAGE}/${app(1)}?tab=credentials`);

    await page.getByTestId('application-secret-current').getByRole('button', { name: 'Revoke' }).click();
    const confirm = page.getByRole('dialog', { name: 'Revoke the current secret?' });
    await expect(confirm).toContainText("It stops working at once. The application can't get tokens until a new secret is created.");
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    await expect(confirm).toHaveCount(0);
    expect(api.secretWrites).toHaveLength(0);

    await page.getByTestId('application-secret-current').getByRole('button', { name: 'Revoke' }).click();
    await page.getByRole('dialog', { name: 'Revoke the current secret?' }).getByRole('button', { name: 'Revoke secret' }).click();

    await expect(toast(page)).toHaveText('Secret revoked');
    await expect(page.getByRole('dialog', { name: 'Revoke the current secret?' })).toHaveCount(0);
    await expect(page.getByTestId('application-secrets-none')).toHaveText('No client secret yet.');
    await expect(credentials(page).getByRole('button', { name: 'Create secret' })).toBeVisible();
    expect(api.secretWrites.at(-1)!.path).toBe(`${SECRETS(app(1))}/${CURRENT.id}/revoke`);
  });

  test('a failed rotation shows the banner with its reference, and nothing changes', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, {
      capabilities: TENANT_OWNER,
      secrets: { [app(1)]: [CURRENT] },
      secretWrite: (route) => problem(route, 500, 'unavailable'),
    });
    await page.goto(`${PAGE}/${app(1)}?tab=credentials`);

    await credentials(page).getByRole('button', { name: 'Rotate secret' }).click();

    const failed = page.getByTestId('application-secret-failed');
    await expect(failed).toContainText("Couldn't change the client secret. Nothing was changed.");
    await expect(failed).toContainText(TRACE);
    await expect(reveal(page)).toHaveCount(0);
    await expect(page.getByTestId('application-secret-old')).toHaveCount(0);
    expect(api.secretWrites).toHaveLength(2);
  });

  test('a rotation refused as over the limit shows the banner and reads the secrets again, which show the old one', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, { capabilities: TENANT_OWNER, secrets: { [app(3)]: [CURRENT] } });
    // Another tab rotated meanwhile: this rotation is over the limit, and the list now holds two.
    api.state.secretWrite = (route) => {
      api.state.secrets[app(3)] = [{ id: sec(5), createdAt: '2026-11-13T08:00:00.000Z', expiresAt: null }, { ...CURRENT, expiresAt: '2026-11-14T08:00:00.000Z' }];
      return problem(route, 409, 'client_secret_limit_reached');
    };
    await page.goto(`${PAGE}/${app(3)}?tab=credentials`);
    await expect(page.getByTestId('application-secret-current')).toBeVisible();
    expect(api.count(`GET ${SECRETS(app(3))}`)).toBe(1);

    await credentials(page).getByRole('button', { name: 'Rotate secret' }).click();

    const failed = page.getByTestId('application-secret-failed');
    await expect(failed).toContainText("Couldn't change the client secret. Nothing was changed.");
    await expect(failed).toContainText('client_secret_limit_reached');
    await expect.poll(() => api.count(`GET ${SECRETS(app(3))}`)).toBe(2);
    await expect(page.getByTestId('application-secret-old')).toContainText('Old secret · Valid until');
    await expect(page.getByTestId('application-secret-rotate-blocked')).toHaveText('End the old secret before rotating again.');
    await expect(reveal(page)).toHaveCount(0);
  });

  test('an Editor reads that a Tenant Owner must create the secret, and every write control is Tenant Owner only', async ({ page }) => {
    const api = await answerApi(page, { secrets: { [app(3)]: [CURRENT, OLD] } });
    await page.goto(`${PAGE}/${app(1)}?tab=credentials`);

    await expect(page.getByTestId('application-secrets-none')).toHaveText(NEEDS_SECRET);
    const create = credentials(page).getByRole('button', { name: 'Create secret' });
    await expect(create).toHaveAttribute('aria-disabled', 'true');
    await expect(create).toHaveAccessibleDescription('Tenant Owner only');
    await create.click({ force: true });

    await page.goto(`${PAGE}/${app(3)}?tab=credentials`);
    await expect(page.getByTestId('application-secret-current')).toBeVisible();
    for (const name of ['Rotate secret', 'Revoke', 'End old secret now']) {
      const control = credentials(page).getByRole('button', { name });
      await expect(control).toHaveAttribute('aria-disabled', 'true');
      await expect(control).toHaveAccessibleDescription('Tenant Owner only');
      await control.click({ force: true });
    }
    await expect(page.getByRole('dialog')).toHaveCount(0);
    expect(api.secretWrites).toHaveLength(0);
    expect(api.begins).toHaveLength(0);
  });

  for (const n of [0, 2]) {
    test(`a ${ROWS[n]!.type} Application needs no secret, and nothing is read`, async ({ page }) => {
      const api = await answerApi(page, { capabilities: TENANT_OWNER });
      await page.goto(`${PAGE}/${app(n)}?tab=credentials`);

      await expect(page.getByTestId('application-credentials-none')).toHaveText(NO_SECRET);
      await expect(credentials(page).getByRole('button')).toHaveCount(0);
      expect(api.log.filter((line) => line.includes('/secrets'))).toEqual([]);
    });
  }

  test("an Owner's create of a type that needs a secret opens Credentials, confirms, and shows the secret once", async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, { capabilities: TENANT_OWNER });
    await page.goto(PAGE);

    await createButton(page).click();
    const dialog = modal(page);
    await dialog.getByRole('textbox', { name: 'Name' }).fill('Payments worker');
    await dialog.getByRole('group', { name: 'Type' }).getByRole('radio', { name: /^Machine-to-machine/ }).check();
    await dialog.getByRole('button', { name: 'Create application' }).click();

    await expect(page).toHaveURL(new RegExp(`${PAGE}/${app(9)}\\?tab=credentials$`));
    await expect(page.getByRole('tab', { name: 'Credentials' })).toHaveAttribute('aria-selected', 'true');
    await expect(reveal(page).locator('code')).toHaveText(secretValue(1));
    await closeReveal(page);
    await expect(page.getByTestId('application-secret-current')).toBeVisible();
    expect(api.begins).toEqual([{ action: 'tenant.client_secrets.manage', target: app(9) }]);
    expect(api.secretWrites).toHaveLength(2);

    // Read again, the page asks for no second secret.
    await page.reload();
    await expect(page.getByTestId('application-secret-current')).toBeVisible();
    await expect(reveal(page)).toHaveCount(0);
    expect(api.secretWrites).toHaveLength(2);
  });

  test("an Owner's single-page Application opens on Settings, with no secret asked for", async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER });
    await page.goto(PAGE);

    await createButton(page).click();
    await modal(page).getByRole('textbox', { name: 'Name' }).fill('Storefront 2');
    await modal(page).getByRole('button', { name: 'Create application' }).click();

    await expect(page).toHaveURL(new RegExp(`${PAGE}/${app(9)}$`));
    await expect(page.getByRole('tab', { name: 'Settings' })).toHaveAttribute('aria-selected', 'true');
    expect(api.secretWrites).toHaveLength(0);
  });

  for (const scheme of ['light', 'dark'] as const) {
    for (const width of [1100, 768]) {
      test(`axe finds no violations at ${width}px, ${scheme}: the secrets, the reveal, the revoke modal and a failure`, async ({ page, baseURL }) => {
        await authenticator(page, new URL(baseURL!).hostname);
        await page.setViewportSize({ width, height: 900 });
        await page.emulateMedia({ colorScheme: scheme });
        const api = await answerApi(page, { capabilities: TENANT_OWNER, secrets: { [app(3)]: [CURRENT, OLD], [app(1)]: [] } });

        await page.goto(`${PAGE}/${app(3)}?tab=credentials`);
        await expect(page.getByTestId('application-secret-old')).toBeVisible();
        expect(await axe(page), 'secrets').toEqual([]);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

        await page.getByTestId('application-secret-current').getByRole('button', { name: 'Revoke' }).click();
        await expect(page.getByRole('dialog', { name: 'Revoke the current secret?' })).toBeVisible();
        expect(await axe(page), 'revoke modal').toEqual([]);
        await page.getByRole('dialog', { name: 'Revoke the current secret?' }).getByRole('button', { name: 'Cancel' }).click();

        await page.goto(`${PAGE}/${app(1)}?tab=credentials`);
        await credentials(page).getByRole('button', { name: 'Create secret' }).click();
        await expect(reveal(page).locator('code')).toBeVisible();
        expect(await axe(page), 'reveal').toEqual([]);
        await closeReveal(page);

        api.state.secretWrite = (route) => problem(route, 500, 'unavailable');
        await credentials(page).getByRole('button', { name: 'Rotate secret' }).click();
        await expect(page.getByTestId('application-secret-failed')).toBeVisible();
        expect(await axe(page), 'failure').toEqual([]);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

        // An Editor's view.
        api.state.capabilities = TENANT_EDITOR;
        await page.goto(`${PAGE}/${app(3)}?tab=credentials`);
        await expect(page.getByTestId('application-secrets-owner-only')).toBeVisible();
        expect(await axe(page), 'editor').toEqual([]);
      });
    }
  }
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
      await expect(page.getByTestId('application-settings')).toBeVisible();
      expect(await axe(page), 'settings').toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      // Story 3.2: a refused line on its field, a native Application's guidance, and Credentials.
      api.state.save = (route) =>
        route.fulfill({
          status: 400,
          contentType: 'application/problem+json',
          body: JSON.stringify({ code: 'application_invalid', traceId: TRACE, errors: [{ field: 'callbackUrls', index: 0, reason: 'wildcard' }] }),
        });
      await page.getByTestId('application-callbackUrls').fill('https://*.a.example/cb');
      await page.getByTestId('application-save').click();
      await expect(page.getByText("Line 1: Wildcards aren't allowed.")).toBeVisible();
      expect(await axe(page), 'settings error').toEqual([]);
      api.state.save = null;
      // Back to what is stored, so leaving asks nothing.
      await page.getByTestId('application-callbackUrls').fill('');

      await page.goto(`${PAGE}/${app(2)}`);
      await expect(page.getByTestId('application-native-guidance')).toBeVisible();
      expect(await axe(page), 'native').toEqual([]);

      await page.getByRole('tab', { name: 'Credentials' }).click();
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
