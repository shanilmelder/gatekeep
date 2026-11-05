// Story 1.27: creating and listing Tenants in the built Admin Dashboard, served by the built
// Host.Admin (admin-host.mjs) under its real CSP, from localhost, since WebAuthn takes no IP
// address as an RP ID. The Admin API is answered by route interception; Session renewal's sheet is
// answered by a Chromium virtual authenticator over CDP, as in admin-shell.spec.ts. The server's
// rules are the Isolation tests' (tests/Isolation/Tenancy); the browser's subdomain rule,
// apps/admin-dashboard/test/tenantSubdomain.test.mjs's.

import AxeBuilder from '@axe-core/playwright';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, test, type CDPSession, type Page, type Request, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const TENANTS = '/api/v1/deployment/tenants';
const BEGIN = '/api/v1/deployment/signin';
const COMPLETE = '/api/v1/deployment/signin/complete';
const CSRF = 'T'.repeat(43);
const RENEWED_CSRF = 'U'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000127';
const ZONE = 'gatekeep.test';
const MY_TENANTS = '/api/v1/deployment/my-tenants';

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

const NO_ACCESS = "You don't have access to a Tenant yet. Ask a Deployment Owner.";
const RULE = 'Lowercase letters, numbers and hyphens.';
const REFUSED = "This subdomain can't be used. Choose another.";
const SAVE_FAILED = "Couldn't create the Tenant. Try again.";
const CREATION_FAILED = "We couldn't finish creating this Tenant.";
const NAME_INVALID = 'Remove control or invisible characters from the name.';
const POLL_TROUBLE = "We can't check on this Tenant's creation right now. We'll keep trying.";
const FORBIDDEN = "You can't do this in this session.";
const LOAD_FAILED = "We couldn't load this page.";

const json = (route: Route, status: number, body: unknown, headers?: Record<string, string>) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body), headers });
const problem = (route: Route, status: number, code: string) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: 'a'.repeat(32) }) });

type Answer = (route: Route) => Promise<void>;

const ten = (n: number) => `ten_${String.fromCharCode(97 + n).repeat(25)}a`;
const opr = (n: number) => `opr_${String.fromCharCode(97 + n).repeat(25)}a`;

/** Story 1.28: a created Tenant's success opens it, whose landing is its settings page until Story 3.1. */
const CREATED_LANDING = new RegExp(`/tenants/${ten(9)}/settings$`);

interface TenantRow {
  id: string;
  name: string;
  host: string;
  label: 'dev' | 'staging' | 'prod';
  status: 'creating' | 'active';
  createdAt: string;
  creation: { operationId: string; status: 'running' | 'failed' } | null;
}

const tenant = (n: number, extra: Partial<TenantRow> = {}): TenantRow => ({
  id: ten(n),
  name: `Tenant ${n}`,
  host: `tenant-${n}.${ZONE}`,
  label: 'dev',
  status: 'active',
  createdAt: `2026-11-0${n + 1}T10:00:00Z`,
  creation: null,
  ...extra,
});

type OperationStatus = 'running' | 'failed' | 'succeeded';

const operation = (status: OperationStatus, resultCode: string | null = null) => ({
  id: opr(0),
  type: 'tenancy.tenant.create',
  tenantId: ten(9),
  status,
  createdAt: '2026-11-04T10:00:00Z',
  updatedAt: '2026-11-04T10:00:01Z',
  finishedAt: status === 'running' ? null : '2026-11-04T10:00:01Z',
  steps: [
    {
      stage: 'keys.secret_classes',
      tenantId: ten(9),
      status: status === 'running' ? 'running' : status,
      resultCode,
      attempts: 1,
      updatedAt: '2026-11-04T10:00:01Z',
    },
  ],
});

const created = (name = 'Acme Dev', subdomain = 'acme-dev', label: TenantRow['label'] = 'dev') => ({
  tenant: tenant(9, { name, host: `${subdomain}.${ZONE}`, label, status: 'creating', creation: { operationId: opr(0), status: 'running' } }),
  operation: operation('running'),
});

interface State {
  expired: boolean;
  deployment: string[];
  tenants: TenantRow[];
  nextCursor: string | null;
  /** Replaces the list answer, while not expired. */
  listAnswer: ((route: Route, cursor: string | null) => Promise<void>) | null;
  /** The create's answer. A 202 with the created Tenant by default. */
  createAnswer: Answer | null;
  /** The Operation's status at each read, in turn; the last one repeats. */
  operations: ReturnType<typeof operation>[];
  /** Replaces the Operation read's answer, such as a 403 or a 503. */
  operationAnswer: Answer | null;
  retryAnswer: Answer | null;
  /** Runs as a sign-in begin arrives, before it is answered. */
  onBegin: (() => Promise<void>) | null;
  /** The switcher's list (Story 1.28): the active Tenants this Admin holds a role in. */
  mine: { id: string; name: string; host: string; label: TenantRow['label'] }[];
}

interface Api {
  log: string[];
  requests: Request[];
  state: State;
  count: (entry: string) => number;
}

/** The Admin API as the server answers a signed-in Deployment Owner, with the Tenants routes. */
async function answerApi(page: Page, baseURL: string, initial: Partial<State> = {}): Promise<Api> {
  const log: string[] = [];
  const requests: Request[] = [];
  const state: State = {
    expired: false,
    deployment: OWNER,
    tenants: [],
    nextCursor: null,
    listAnswer: null,
    createAnswer: null,
    operations: [operation('running')],
    operationAnswer: null,
    retryAnswer: null,
    onBegin: null,
    mine: [],
    ...initial,
  };

  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const pathname = url.pathname;
      // The shell's Tenants list (Story 1.28), outside the log this spec's rules read: the Tenants
      // this Admin holds a role in, none until a test says so. Its own rules are admin-tenant-switcher.spec.ts's.
      if (pathname === MY_TENANTS) {
        if (state.expired) return route.fulfill({ status: 401 });
        return json(route, 200, { tenants: state.mine });
      }
      log.push(`${request.method()} ${pathname}${url.search}`);
      requests.push(request);

      if (pathname === SESSION && request.method() === 'DELETE') return route.fulfill({ status: 204 });
      if (pathname === SESSION) {
        if (state.expired) return route.fulfill({ status: 401 });
        return json(route, 200, {
          adminId: ADMIN_ID,
          kind: 'full',
          deploymentOwner: true,
          setupComplete: true,
          credentials: 2,
          recoveryCodeAllowed: false,
          csrfToken: CSRF,
        });
      }
      if (pathname === BEGIN) {
        if (state.onBegin) await state.onBegin();
        return json(route, 200, {
          challenge: randomBytes(32).toString('base64url'),
          rpId: new URL(baseURL).hostname,
          timeout: 300000,
          userVerification: 'required',
          allowCredentials: [],
        });
      }
      if (pathname === COMPLETE) {
        state.expired = false;
        return json(route, 200, { adminId: ADMIN_ID, csrfToken: RENEWED_CSRF, setupComplete: true });
      }
      if (state.expired) return route.fulfill({ status: 401 });
      if (pathname === CAPABILITIES) return json(route, 200, { capabilities: state.deployment });
      if (pathname === TENANTS && request.method() === 'GET') {
        const cursor = url.searchParams.get('cursor');
        if (state.listAnswer) return state.listAnswer(route, cursor);
        return json(route, 200, { tenantZone: ZONE, tenants: state.tenants, nextCursor: state.nextCursor });
      }
      if (pathname === TENANTS && request.method() === 'POST') {
        if (state.createAnswer) return state.createAnswer(route);
        return json(route, 202, created(), { Location: `/api/v1/tenants/${ten(9)}/operations/${opr(0)}` });
      }
      if (/^\/api\/v1\/tenants\/[^/]+\/operations\/[^/]+$/.test(pathname)) {
        if (state.operationAnswer) return state.operationAnswer(route);
        const next = state.operations.length > 1 ? state.operations.shift()! : state.operations[0]!;
        return json(route, 200, next);
      }
      // The created Tenant's own page (Story 1.28): its Owner's capabilities and its label.
      if (/^\/api\/v1\/tenants\/[^/]+\/capabilities$/.test(pathname)) {
        return json(route, 200, { capabilities: ['tenant.configuration.read', 'tenant.settings.manage', 'tenant.label.manage'] });
      }
      if (/^\/api\/v1\/tenants\/[^/]+\/label$/.test(pathname) && request.method() === 'GET') return json(route, 200, { label: 'dev', status: 'active' });
      if (/^\/api\/v1\/deployment\/operations\/[^/]+\/retry$/.test(pathname)) {
        if (state.retryAnswer) return state.retryAnswer(route);
        return json(route, 202, operation('running'));
      }
      return route.fulfill({ status: 404 });
    },
  );

  return { log, requests, state, count: (entry) => log.filter((line) => line === entry).length };
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
}

async function axe(page: Page) {
  // Only finite animations settle: a pending button's spinner runs until the request answers.
  await page.evaluate(() =>
    Promise.allSettled(
      document
        .getAnimations()
        .filter((animation) => animation.effect?.getComputedTiming().iterations !== Infinity)
        .map((animation) => animation.finished),
    ).then(() => undefined),
  );
  // tx3 on sf2 in table heads is DESIGN.md's one recorded contrast exception (Admin table heads
  // only), so only contrast skips those cells, as data.spec.ts does.
  const everything = await new AxeBuilder({ page }).disableRules(['color-contrast']).analyze();
  const contrast = await new AxeBuilder({ page }).withRules(['color-contrast']).exclude('thead th').analyze();
  return [...everything.violations, ...contrast.violations].map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
}

const heading = (page: Page) => page.getByRole('heading', { level: 1 });
const nav = (page: Page) => page.getByRole('navigation', { name: 'Main' });
const nameField = (page: Page) => page.getByRole('textbox', { name: 'Name', exact: true });
const subdomainField = (page: Page) => page.getByRole('textbox', { name: 'Tenant Subdomain' });
const submit = (page: Page) => page.getByRole('button', { name: 'Create Tenant' });
const progress = (page: Page) => page.getByTestId('create-tenant-progress');
const posts = (api: Api) => api.count(`POST ${TENANTS}`);

async function fill(page: Page, name = 'Acme Dev', subdomain = 'acme-dev') {
  await nameField(page).fill(name);
  await subdomainField(page).fill(subdomain);
}

test.use({ viewport: { width: 1280, height: 720 } });
watchCsp(test);

test.describe('landing', () => {
  test('with no Tenants, the Owner lands on the Create Tenant form: Name, Tenant Subdomain with the zone, Environment, and no Region', async ({
    page,
    baseURL,
  }) => {
    const api = await answerApi(page, baseURL!);

    await page.goto('/');

    await expect(heading(page)).toHaveText('Create your Tenant');
    await expect(page.getByText('A Tenant is an isolated directory of Users, Applications and settings.')).toBeVisible();
    await expect(page).toHaveURL(/\/$/);
    await expect(nameField(page)).toHaveAttribute('maxlength', '100');
    await expect(nameField(page)).toHaveAttribute('autocomplete', 'off');
    const subdomain = subdomainField(page);
    for (const [name, value] of [['autocapitalize', 'none'], ['autocorrect', 'off'], ['spellcheck', 'false'], ['autocomplete', 'off']]) {
      await expect(subdomain).toHaveAttribute(name!, value!);
    }
    await expect(page.getByTestId('create-tenant-zone')).toHaveText(`.${ZONE}`);
    await expect(page.getByText("Lowercase letters, numbers and hyphens. Can't be changed later.")).toBeVisible();

    await subdomain.fill('acme-dev');
    await expect(page.getByTestId('create-tenant-host')).toHaveText(`acme-dev.${ZONE}`);

    const group = page.getByRole('group', { name: 'Environment' });
    await expect(group.getByRole('radio')).toHaveCount(3);
    await expect(group.getByRole('radio', { name: /^Development/ })).toBeChecked();
    await expect(group.getByRole('radio', { name: /^Staging/ })).not.toBeChecked();
    await expect(group.getByRole('radio', { name: /^Production/ })).not.toBeChecked();
    await expect(group.locator('[data-badge="environment"]')).toHaveText(['DEV', 'STG', 'PROD']);
    expect(await group.locator('[data-badge="environment"]').evaluateAll((badges) => badges.map((b) => b.getAttribute('data-environment')))).toEqual([
      'dev',
      'staging',
      'prod',
    ]);

    await expect(page.getByText(/region|custom domain|promote/i)).toHaveCount(0);
    // There is no Cancel on the landing.
    await expect(page.getByRole('button', { name: 'Cancel' })).toHaveCount(0);
    expect(api.count(`GET ${TENANTS}`)).toBe(1);
  });

  test('with any Tenant, the landing becomes the Tenants page, replacing the URL', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { tenants: [tenant(0)] });

    await page.goto('/');

    await expect(page).toHaveURL(/\/deployment\/tenants$/);
    await expect(heading(page)).toHaveText('Tenants');
    await expect(nameField(page)).toHaveCount(0);

    // The redirect took the landing's place in the history: Back never returns to /.
    await page.goBack();
    expect(page.url() === 'about:blank' || new URL(page.url()).pathname !== '/', `Back went to ${page.url()}`).toBe(true);
  });

  test('an Admin with no Deployment capability keeps the holding text, and has no Deployment group', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { deployment: [] });

    await page.goto('/');

    await expect(heading(page)).toHaveText('Admin Dashboard');
    await expect(page.getByText(NO_ACCESS)).toBeVisible();
    await expect(nav(page).getByRole('button', { name: 'Deployment' })).toHaveCount(0);
    await expect(nav(page).getByRole('link')).toHaveCount(0);
    expect(api.count(`GET ${TENANTS}`)).toBe(0);
  });

  test('a failed Tenants read shows the load-failed banner, and Retry reads again', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { listAnswer: (route) => route.fulfill({ status: 503 }) });

    await page.goto('/');

    const banner = page.getByTestId('tenants-load-failed');
    await expect(banner).toContainText("We couldn't load this page.");
    api.state.listAnswer = null;
    await banner.getByRole('button', { name: 'Retry' }).click();
    await expect(heading(page)).toHaveText('Create your Tenant');
    expect(api.count(`GET ${TENANTS}`)).toBe(2);
  });

  test('the Deployment page paths need their capability: without it, the forbidden page, and nothing is asked', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { deployment: [] });

    await page.goto('/deployment/tenants');
    await expect(heading(page)).toHaveText("You don't have access to this page.");
    await page.goto('/deployment/tenants/new');
    await expect(heading(page)).toHaveText("You don't have access to this page.");
    expect(api.count(`GET ${TENANTS}`)).toBe(0);
  });
});

test.describe('sidebar', () => {
  test('the Owner has the Deployment group with Tenants, current on the Tenants page', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { tenants: [tenant(0)] });

    await page.goto('/deployment/tenants');

    await expect(heading(page)).toHaveText('Tenants');
    const group = nav(page).getByRole('button', { name: 'Deployment' });
    await expect(group).toHaveAttribute('aria-expanded', 'true');
    const link = nav(page).getByRole('link', { name: 'Tenants' });
    await expect(link).toHaveAttribute('href', '/deployment/tenants');
    await expect(link).toHaveAttribute('aria-current', 'page');
    await expect(nav(page).getByRole('link')).toHaveCount(1);
  });
});

test.describe('create', () => {
  test('a malformed subdomain is refused in the browser: the rule under the field, focus there, and no request', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!);
    await page.goto('/');
    await expect(heading(page)).toHaveText('Create your Tenant');

    await fill(page, 'Acme Dev', 'Acme');
    await submit(page).click();

    await expect(page.getByText(RULE, { exact: true })).toBeVisible();
    await expect(subdomainField(page)).toHaveAttribute('aria-invalid', 'true');
    await expect(subdomainField(page)).toBeFocused();
    await page.waitForTimeout(200);
    expect(posts(api)).toBe(0);

    // A name that is empty once trimmed is refused the same way, first.
    await nameField(page).fill('   ');
    await subdomainField(page).fill('acme');
    await submit(page).click();
    await expect(page.getByText('Enter a name.')).toBeVisible();
    await expect(nameField(page)).toBeFocused();
    expect(posts(api)).toBe(0);
  });

  test('a name with a zero-width character is refused in the browser, as the server would: no request', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!);
    await page.goto('/');
    await expect(heading(page)).toHaveText('Create your Tenant');

    await fill(page, 'Acme\u200bDev', 'acme-dev');
    await submit(page).click();

    await expect(page.getByText(NAME_INVALID)).toBeVisible();
    await expect(nameField(page)).toHaveAttribute('aria-invalid', 'true');
    await expect(nameField(page)).toBeFocused();
    await page.waitForTimeout(200);
    expect(posts(api)).toBe(0);

    // A bidi control is refused the same way.
    await nameField(page).fill('Acme\u202eDev');
    await submit(page).click();
    await expect(page.getByText(NAME_INVALID)).toBeVisible();
    expect(posts(api)).toBe(0);
  });

  test('an Operation read answered 403 stops reading and shows the forbidden banner, the form still read-only', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { operationAnswer: (route) => problem(route, 403, 'access_denied') });
    await page.goto('/');
    await fill(page);
    await submit(page).click();

    await expect(page.getByTestId('create-tenant-poll-forbidden')).toHaveText(FORBIDDEN);
    await expect(nameField(page)).toHaveAttribute('readonly', '');
    const reads = api.count(`GET /api/v1/tenants/${ten(9)}/operations/${opr(0)}`);
    expect(reads).toBe(1);
    await page.waitForTimeout(2500);
    expect(api.count(`GET /api/v1/tenants/${ten(9)}/operations/${opr(0)}`)).toBe(reads);
    expect(posts(api)).toBe(1);
  });

  test('an Operation read answered 404 stops reading and shows load-failed, whose Retry reads it again', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { operationAnswer: (route) => route.fulfill({ status: 404 }) });
    await page.goto('/');
    await fill(page);
    await submit(page).click();

    const banner = page.getByTestId('create-tenant-poll-load-failed');
    await expect(banner).toContainText(LOAD_FAILED);
    await expect(banner.locator('[data-reference="code"]')).toHaveText('not_found');

    api.state.operationAnswer = null;
    api.state.operations = [operation('succeeded')];
    await banner.getByRole('button', { name: 'Retry' }).click();
    await expect(page.getByTestId('toast')).toHaveText('Tenant created.');
    await expect(page).toHaveURL(CREATED_LANDING);
  });

  test('Operation reads answered 503 back off, say so after three, and go on until it succeeds', async ({ page, baseURL }) => {
    test.setTimeout(60_000);
    const api = await answerApi(page, baseURL!, { operationAnswer: (route) => problem(route, 503, 'unavailable') });
    await page.goto('/');
    await fill(page);
    await submit(page).click();

    const trouble = page.getByTestId('create-tenant-poll-trouble');
    await expect(trouble).toContainText(POLL_TROUBLE, { timeout: 15_000 });
    await expect(trouble.locator('[data-reference="code"]')).toHaveText('unavailable');
    expect(api.count(`GET /api/v1/tenants/${ten(9)}/operations/${opr(0)}`)).toBe(3);
    await expect(progress(page)).toHaveText('Creating Acme Dev…');

    // Backed off: the fourth read waits longer than the poll interval.
    await page.waitForTimeout(1500);
    expect(api.count(`GET /api/v1/tenants/${ten(9)}/operations/${opr(0)}`)).toBe(3);

    api.state.operationAnswer = null;
    api.state.operations = [operation('succeeded')];
    await expect(page.getByTestId('toast')).toHaveText('Tenant created.', { timeout: 15_000 });
    await expect(page).toHaveURL(CREATED_LANDING);
  });

  for (const [status, testId] of [
    [403, 'create-tenant-forbidden'],
    [503, 'create-tenant-save-failed'],
  ] as const) {
    test(`a Retry answered ${status} shows its banner and keeps the failed Operation's Retry`, async ({ page, baseURL }) => {
      const api = await answerApi(page, baseURL!, {
        operations: [operation('failed', 'custody_unavailable')],
        retryAnswer: (route) => problem(route, status, status === 403 ? 'access_denied' : 'unavailable'),
      });
      await page.goto('/');
      await fill(page);
      await submit(page).click();
      const failed = page.getByTestId('create-tenant-failed');
      await expect(failed).toBeVisible();

      await failed.getByRole('button', { name: 'Retry' }).click();

      const banner = page.getByTestId(testId);
      if (status === 403) {
        await expect(banner).toHaveText(FORBIDDEN);
      } else {
        await expect(banner).toContainText(SAVE_FAILED);
        await expect(banner.locator('[data-reference="code"]')).toHaveText('unavailable');
        await expect(banner.locator('[data-reference="trace"]')).toHaveText('a'.repeat(32));
      }
      await expect(failed.getByRole('button', { name: 'Retry' })).toBeVisible();
      expect(api.count(`POST /api/v1/deployment/operations/${opr(0)}/retry`)).toBe(1);
    });
  }

  test("the server's subdomain_refused says only that it can't be used, under the field, with the values kept", async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { createAnswer: (route) => problem(route, 400, 'subdomain_refused') });
    await page.goto('/');
    await expect(heading(page)).toHaveText('Create your Tenant');

    await fill(page, 'Acme Dev', 'admin');
    await page.getByRole('radio', { name: /^Staging/ }).check();
    await submit(page).click();

    await expect(page.getByText(REFUSED)).toBeVisible();
    await expect(subdomainField(page)).toBeFocused();
    await expect(page.getByText(/taken|reserved/i)).toHaveCount(0);
    await expect(nameField(page)).toHaveValue('Acme Dev');
    await expect(subdomainField(page)).toHaveValue('admin');
    await expect(page.getByRole('radio', { name: /^Staging/ })).toBeChecked();
    expect(posts(api)).toBe(1);
    const body = api.requests.find((request) => request.method() === 'POST')!.postDataJSON();
    expect(body).toEqual({ name: 'Acme Dev', subdomain: 'admin', label: 'staging' });
    expect(await api.requests.find((request) => request.method() === 'POST')!.headerValue('x-gatekeep-csrf')).toBe(CSRF);
  });

  test('a 202 shows the status line while the Operation runs, then the toast and the new Tenant', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { operations: [operation('running'), operation('succeeded')] });
    await page.goto('/');
    await expect(heading(page)).toHaveText('Create your Tenant');

    await fill(page);
    await submit(page).click();

    await expect(progress(page)).toHaveText('Creating Acme Dev…');
    await expect(progress(page)).toHaveAttribute('role', 'status');
    await expect(nameField(page)).toHaveAttribute('readonly', '');
    await expect(submit(page)).toHaveAttribute('aria-busy', 'true');

    api.state.tenants = [tenant(9, { name: 'Acme Dev', host: `acme-dev.${ZONE}` })];
    api.state.mine = [{ id: ten(9), name: 'Acme Dev', host: `acme-dev.${ZONE}`, label: 'dev' }];
    await expect(page.getByTestId('toast')).toHaveText('Tenant created.');
    await expect(page).toHaveURL(CREATED_LANDING);
    await expect(heading(page)).toHaveText('Tenant settings');
    // The new Tenant is the current one in the top bar, as the next reads list it.
    await expect(page.getByTestId('tenant-switcher').locator('[data-menu-trigger]')).toHaveAccessibleName('Acme Dev DEV, switch Tenant');
    expect(api.count(`GET /api/v1/tenants/${ten(9)}/operations/${opr(0)}`)).toBe(2);
    expect(posts(api)).toBe(1);
  });

  test('a failed Operation shows the banner with its step code and Retry, which runs it again to success', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { operations: [operation('failed', 'custody_unavailable')] });
    await page.goto('/');
    await expect(heading(page)).toHaveText('Create your Tenant');

    await fill(page);
    await submit(page).click();

    const banner = page.getByTestId('create-tenant-failed');
    await expect(banner).toContainText(CREATION_FAILED);
    await expect(banner.locator('[data-reference="code"]')).toHaveText('custody_unavailable');
    await expect(banner).toHaveAttribute('data-tone', 'bad');

    api.state.operations = [operation('succeeded')];
    await banner.getByRole('button', { name: 'Retry' }).click();
    await expect(page.getByTestId('toast')).toHaveText('Tenant created.');
    await expect(page).toHaveURL(CREATED_LANDING);
    expect(api.count(`POST /api/v1/deployment/operations/${opr(0)}/retry`)).toBe(1);
    expect(posts(api)).toBe(1);
  });

  test('a Retry answered 409 reads the Operation again', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, {
      operations: [operation('failed', 'custody_unavailable')],
      retryAnswer: (route) => problem(route, 409, 'operation_not_failed'),
    });
    await page.goto('/');
    await fill(page);
    await submit(page).click();
    await expect(page.getByTestId('create-tenant-failed')).toBeVisible();

    api.state.operations = [operation('succeeded')];
    await page.getByTestId('create-tenant-failed').getByRole('button', { name: 'Retry' }).click();
    await expect(page).toHaveURL(CREATED_LANDING);
  });

  for (const failure of [
    { name: 'a 503', answer: (route: Route) => route.fulfill({ status: 503 }) },
    { name: 'a 400 tenant_invalid', answer: (route: Route) => problem(route, 400, 'tenant_invalid') },
    { name: 'a lost connection', answer: (route: Route) => route.abort('connectionfailed') },
  ]) {
    test(`${failure.name} is the Save failed banner above the form, with the values kept and the form editable`, async ({ page, baseURL }) => {
      const api = await answerApi(page, baseURL!, { createAnswer: failure.answer });
      await page.goto('/');
      await fill(page);
      await submit(page).click();

      const banner = page.getByTestId('create-tenant-save-failed');
      await expect(banner).toContainText(SAVE_FAILED);
      await expect(banner).toHaveAttribute('data-tone', 'bad');
      await expect(nameField(page)).toHaveValue('Acme Dev');
      await expect(subdomainField(page)).toHaveValue('acme-dev');
      await expect(nameField(page)).not.toHaveAttribute('readonly', /.*/);
      await expect(submit(page)).not.toHaveAttribute('aria-busy', 'true');
      // The banner is above the form's fields.
      const bannerBox = (await banner.boundingBox())!;
      expect(bannerBox.y).toBeLessThan((await nameField(page).boundingBox())!.y);

      api.state.createAnswer = null;
      await submit(page).click();
      await expect(progress(page)).toHaveText('Creating Acme Dev…');
    });
  }

  test("a 403 is the server's refusal of the action", async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { createAnswer: (route) => problem(route, 403, 'access_denied') });
    await page.goto('/');
    await fill(page);
    await submit(page).click();
    await expect(page.getByTestId('create-tenant-forbidden')).toHaveText("You can't do this in this session.");
  });

  test('Create Tenant from the Tenants page has Cancel back to Tenants', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { tenants: [tenant(0)] });
    await page.goto('/deployment/tenants');
    await page.getByTestId('tenants-create').click();

    await expect(page).toHaveURL(/\/deployment\/tenants\/new$/);
    await expect(heading(page)).toHaveText('Create your Tenant');
    await expect(page.getByTestId('create-tenant-zone')).toHaveText(`.${ZONE}`);
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page).toHaveURL(/\/deployment\/tenants$/);
  });
});

test.describe('renewal', () => {
  test('a 401 on the POST keeps the same nodes, values and focus, is never resent, and the next press sends it', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    await page.goto('/');
    await expect(heading(page)).toHaveText('Create your Tenant');

    await fill(page);
    await page.getByRole('radio', { name: /^Production/ }).check();
    await nameField(page).focus();
    await page.evaluate(() => {
      for (const input of document.querySelectorAll('main input')) (input as unknown as { gkMarker: string }).gkMarker = 'same';
    });

    let bannerSeen = false;
    api.state.onBegin = async () => {
      bannerSeen = (await page.getByTestId('session-expired').count()) === 1;
    };
    api.state.expired = true;
    await page.keyboard.press('Enter');

    await expect.poll(() => api.count(`POST ${COMPLETE}`)).toBe(1);
    await expect(page.getByTestId('session-expired')).toHaveCount(0);
    expect(bannerSeen).toBe(true);
    await expect(submit(page)).not.toHaveAttribute('aria-busy', 'true');
    await expect(nameField(page)).not.toHaveAttribute('readonly', /.*/);

    expect(posts(api)).toBe(1);
    await expect(nameField(page)).toHaveValue('Acme Dev');
    await expect(subdomainField(page)).toHaveValue('acme-dev');
    await expect(page.getByRole('radio', { name: /^Production/ })).toBeChecked();
    await expect(nameField(page)).toBeFocused();
    expect(
      await page.evaluate(() => [...document.querySelectorAll('main input')].every((input) => (input as unknown as { gkMarker?: string }).gkMarker === 'same')),
    ).toBe(true);
    await page.waitForTimeout(300);
    expect(posts(api)).toBe(1);

    await submit(page).click();
    await expect(progress(page)).toHaveText('Creating Acme Dev…');
    expect(posts(api)).toBe(2);
    const second = api.requests.filter((request) => request.method() === 'POST' && new URL(request.url()).pathname === TENANTS)[1]!;
    expect(await second.headerValue('x-gatekeep-csrf')).toBe(RENEWED_CSRF);
    expect(second.postDataJSON()).toEqual({ name: 'Acme Dev', subdomain: 'acme-dev', label: 'prod' });
  });
});

test.describe('tenants page', () => {
  test('lists each Tenant with its tag, host and badges; Retry only on the failed row; rows are not links', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, {
      tenants: [
        tenant(0, { name: 'Acme', label: 'dev' }),
        tenant(1, { name: 'Beta', label: 'staging', status: 'creating', creation: { operationId: opr(1), status: 'running' } }),
        tenant(2, { name: 'Gamma', label: 'prod', status: 'creating', creation: { operationId: opr(2), status: 'failed' } }),
      ],
    });

    await page.goto('/deployment/tenants');

    await expect(heading(page)).toHaveText('Tenants');
    await expect(page.getByText('Deployment', { exact: true }).first()).toBeVisible();
    const table = page.getByRole('table');
    await expect(table.getByRole('columnheader')).toHaveText(['Name', 'Tenant Subdomain', 'Environment', 'Created', 'Retry']);
    await expect(table.getByRole('rowheader')).toHaveText([/^Acme$/, /^Beta\s*Creating$/, /^Gamma\s*Creation failed$/]);
    const tags = table.locator('[data-badge="environment"]');
    await expect(tags).toHaveText(['DEV', 'STG', 'PROD']);
    expect(await tags.evaluateAll((badges) => badges.map((b) => b.getAttribute('data-environment')))).toEqual(['dev', 'staging', 'prod']);
    await expect(table.locator('code')).toHaveText([`tenant-0.${ZONE}`, `tenant-1.${ZONE}`, `tenant-2.${ZONE}`]);
    await expect(table.getByTestId('tenant-creating')).toHaveCount(1);
    await expect(table.getByTestId('tenant-creation-failed')).toHaveAttribute('data-status', 'blocked');
    await expect(table.getByRole('button')).toHaveCount(1);
    await expect(table.getByRole('button', { name: 'Retry creating Gamma' })).toBeVisible();
    await expect(table.getByRole('link')).toHaveCount(0);
    await expect(page.getByTestId('tenants-create')).toHaveText('Create Tenant');

    // Creating rows are read again every 2s too, so the retry's own read is counted from here.
    const before = api.count(`GET ${TENANTS}`);
    await table.getByRole('button', { name: 'Retry creating Gamma' }).click();
    await expect.poll(() => api.count(`POST /api/v1/deployment/operations/${opr(2)}/retry`)).toBe(1);
    await expect.poll(() => api.count(`GET ${TENANTS}`)).toBeGreaterThan(before);
  });

  test('a creating row is read again until it is active, then the reads stop', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, {
      tenants: [tenant(0, { name: 'Beta', status: 'creating', creation: { operationId: opr(0), status: 'running' } })],
    });

    await page.goto('/deployment/tenants');
    await expect(page.getByTestId('tenant-creating')).toHaveCount(1);

    api.state.tenants = [tenant(0, { name: 'Beta' })];
    await expect(page.getByTestId('tenant-creating')).toHaveCount(0, { timeout: 10_000 });
    const reads = api.count(`GET ${TENANTS}`);
    expect(reads).toBeGreaterThanOrEqual(2);
    await page.waitForTimeout(3000);
    expect(api.count(`GET ${TENANTS}`)).toBe(reads);
  });

  for (const [status, testId] of [
    [403, 'tenants-retry-forbidden'],
    [503, 'tenants-retry-failed'],
  ] as const) {
    test(`a row's Retry answered ${status} shows its banner over the list`, async ({ page, baseURL }) => {
      const api = await answerApi(page, baseURL!, {
        tenants: [tenant(2, { name: 'Gamma', status: 'creating', creation: { operationId: opr(2), status: 'failed' } })],
        retryAnswer: (route) => problem(route, status, status === 403 ? 'access_denied' : 'unavailable'),
      });

      await page.goto('/deployment/tenants');
      await page.getByRole('button', { name: 'Retry creating Gamma' }).click();

      const banner = page.getByTestId(testId);
      await expect(banner).toContainText(status === 403 ? FORBIDDEN : SAVE_FAILED);
      if (status === 503) await expect(banner.locator('[data-reference="code"]')).toHaveText('unavailable');
      expect(api.count(`POST /api/v1/deployment/operations/${opr(2)}/retry`)).toBe(1);
    });
  }

  test('empty, it says so with the one Create Tenant action', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!);

    await page.goto('/deployment/tenants');

    await expect(heading(page)).toHaveText('Tenants');
    await expect(page.getByText('No Tenants yet.')).toBeVisible();
    await page.getByRole('main').getByRole('button', { name: 'Create Tenant' }).last().click();
    await expect(page).toHaveURL(/\/deployment\/tenants\/new$/);
  });

  test('Load more reads the next page from its cursor and adds its rows', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, {
      listAnswer: (route, cursor) =>
        json(route, 200, cursor === null
          ? { tenantZone: ZONE, tenants: [tenant(0)], nextCursor: ten(0) }
          : { tenantZone: ZONE, tenants: [tenant(1)], nextCursor: null }),
    });

    await page.goto('/deployment/tenants');
    await expect(page.getByRole('rowheader')).toHaveText(['Tenant 0']);
    await page.getByTestId('tenants-load-more').click();

    await expect(page.getByRole('rowheader')).toHaveText(['Tenant 0', 'Tenant 1']);
    await expect(page.getByTestId('tenants-load-more')).toHaveCount(0);
    expect(api.log).toContain(`GET ${TENANTS}?cursor=${ten(0)}`);
  });
});

for (const scheme of ['light', 'dark'] as const) {
  for (const width of [1100, 768]) {
    test(`axe finds no violations at ${width}px, ${scheme}: Create Tenant's states and the Tenants page`, async ({ page, baseURL }) => {
      // Seven axe runs on one page.
      test.setTimeout(120_000);
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      let release!: () => void;
      const held = new Promise<void>((resolve) => (release = resolve));
      const api = await answerApi(page, baseURL!, {
        createAnswer: async (route) => {
          await held;
          await json(route, 202, created());
        },
      });

      await page.goto('/');
      await expect(heading(page)).toHaveText('Create your Tenant');
      expect(await axe(page), 'initial').toEqual([]);

      await nameField(page).fill('   ');
      await subdomainField(page).fill('Acme');
      await submit(page).click();
      await expect(page.getByText('Enter a name.')).toBeVisible();
      await nameField(page).fill('Acme Dev');
      await submit(page).click();
      await expect(page.getByText(RULE, { exact: true })).toBeVisible();
      expect(await axe(page), 'inline errors').toEqual([]);

      await subdomainField(page).fill('acme-dev');
      await submit(page).click();
      await expect(submit(page)).toHaveAttribute('aria-busy', 'true');
      await expect(nameField(page)).toHaveAttribute('readonly', '');
      expect(await axe(page), 'pending').toEqual([]);

      release();
      await expect(progress(page)).toHaveText('Creating Acme Dev…');
      expect(await axe(page), 'progress').toEqual([]);

      api.state.operations = [operation('failed', 'custody_unavailable')];
      await expect(page.getByTestId('create-tenant-failed')).toBeVisible();
      expect(await axe(page), 'failed').toEqual([]);

      api.state.tenants = [
        tenant(0, { name: 'Acme', label: 'dev' }),
        tenant(1, { name: 'Beta', label: 'staging', status: 'creating', creation: { operationId: opr(1), status: 'running' } }),
        tenant(2, { name: 'Gamma', label: 'prod', status: 'creating', creation: { operationId: opr(2), status: 'failed' } }),
      ];
      await page.goto('/deployment/tenants');
      await expect(page.getByRole('rowheader')).toHaveCount(3);
      expect(await axe(page), 'tenants').toEqual([]);

      api.state.tenants = [];
      await page.goto('/deployment/tenants');
      await expect(page.getByText('No Tenants yet.')).toBeVisible();
      expect(await axe(page), 'tenants empty').toEqual([]);
    });
  }
}
