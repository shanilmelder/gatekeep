// Story 1.28: the Tenant switcher, the current Tenant in the top bar, the landing rules, Tenant
// settings' environment and the Tenant mismatch banner, in the built Admin Dashboard served by the
// built Host.Admin (admin-host.mjs) under its real CSP, from localhost, since WebAuthn takes no IP
// address as an RP ID. The Admin API is answered by route interception; the Prod removal's sheet
// by a Chromium virtual authenticator over CDP, as in admin-credentials.spec.ts. The server's
// rules are the Isolation tests' (tests/Isolation/Tenancy, tests/Isolation/Admins); the current
// Tenant's, apps/admin-dashboard/test/currentTenant.test.mjs's.

import AxeBuilder from '@axe-core/playwright';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, test, type CDPSession, type Page, type Request, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const MY_TENANTS = '/api/v1/deployment/my-tenants';
const TENANTS = '/api/v1/deployment/tenants';
const CREDENTIALS = '/api/v1/deployment/credentials';
const COMPLETE = '/api/v1/deployment/assertions/complete';
const SIGNIN = '/api/v1/deployment/signin';
const SIGNIN_COMPLETE = '/api/v1/deployment/signin/complete';
const CSRF = 'W'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000128';
const ZONE = 'gatekeep.test';
const REMEMBERED = `gatekeep.admin.lastTenant.${ADMIN_ID}`;

const OWNER = ['deployment.tenants.read', 'deployment.tenants.create', 'deployment.tenants.delete', 'deployment.admins.read'];
const TENANT_OWNER = ['tenant.configuration.read', 'tenant.applications.manage', 'tenant.settings.manage', 'tenant.label.manage'];
const TENANT_EDITOR = ['tenant.configuration.read', 'tenant.applications.manage', 'tenant.settings.manage'];
const TENANT_VIEWER = ['tenant.configuration.read', 'tenant.users.read', 'tenant.logs.read'];

const NO_ACCESS = "You don't have access to a Tenant yet. Ask a Deployment Owner.";
const SAVED = 'Environment saved.';
const SAVE_FAILED = "Couldn't save the environment. Try again.";
const CANCELLED = 'Confirmation cancelled. Nothing was changed.';
const VIEW_ONLY = 'You have view-only access to this Tenant.';

type Label = 'dev' | 'staging' | 'prod';

interface Listed {
  id: string;
  name: string;
  host: string;
  label: Label;
}

const ten = (n: number) => `ten_${String.fromCharCode(97 + n).repeat(25)}a`;
const listed = (n: number, name: string, label: Label): Listed => ({ id: ten(n), name, host: `${name.toLowerCase()}.${ZONE}`, label });

const A = listed(0, 'Alpha', 'prod');
const C = listed(2, 'Gamma', 'dev');

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const problem = (route: Route, status: number, code: string) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: 'b'.repeat(32) }) });

interface State {
  deployment: string[];
  mine: Listed[];
  /** The Deployment's Tenants page, for the landing's read. */
  deploymentTenants: number;
  /** Each path Tenant's capabilities. */
  tenantCapabilities: (tenantId: string) => string[];
  /** Holds a path Tenant's capability read until released, for the mismatch test. */
  holdTenant: string | null;
  /** The PUT's answer, before the default: a mismatch, a grant check and the change. */
  putAnswer: ((route: Route, tenantId: string, label: Label) => Promise<void>) | null;
  /** Whether a grant for tenant.label.manage in that Tenant is held: set by a passed complete. */
  grant: string | null;
  /** The Tenant the last begin was for. */
  begunFor: string | null;
  /** Replaces the switcher list's answer, such as a 503. */
  mineAnswer: ((route: Route) => Promise<void>) | null;
  /** Replaces the Tenant begin's answer, such as a 429. */
  beginAnswer: ((route: Route) => Promise<void>) | null;
  /** Each Tenant's status, as its label read says it: active unless set. */
  creating: string[];
  /** The Session is gone: every read but the Session's answers 401 until a sign-in completes. */
  expired: boolean;
}

interface Api {
  log: string[];
  requests: Request[];
  state: State;
  count: (entry: string) => number;
  release: () => void;
}

/** The Admin API as the server answers a signed-in Admin with the Tenants in `mine`. */
async function answerApi(page: Page, baseURL: string, initial: Partial<State> = {}): Promise<Api> {
  const log: string[] = [];
  const requests: Request[] = [];
  let release = () => {};
  const held = new Promise<void>((resolve) => (release = resolve));
  const state: State = {
    deployment: OWNER,
    mine: [A, C],
    deploymentTenants: 0,
    tenantCapabilities: () => TENANT_OWNER,
    holdTenant: null,
    putAnswer: null,
    grant: null,
    begunFor: null,
    mineAnswer: null,
    beginAnswer: null,
    creating: [],
    expired: false,
    ...initial,
  };

  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      const method = request.method();
      log.push(`${method} ${pathname}`);
      requests.push(request);

      if (pathname === SESSION && method === 'DELETE') return route.fulfill({ status: 204 });
      if (pathname === SESSION) {
        return json(route, 200, {
          adminId: ADMIN_ID,
          kind: 'full',
          deploymentOwner: state.deployment.length > 0,
          setupComplete: true,
          credentials: 2,
          recoveryCodeAllowed: false,
          csrfToken: CSRF,
        });
      }
      if (pathname === SIGNIN) {
        return json(route, 200, {
          challenge: randomBytes(32).toString('base64url'),
          rpId: new URL(baseURL).hostname,
          timeout: 300000,
          userVerification: 'required',
          allowCredentials: [],
        });
      }
      if (pathname === SIGNIN_COMPLETE) {
        state.expired = false;
        return json(route, 200, { adminId: ADMIN_ID, csrfToken: CSRF, setupComplete: true });
      }
      if (state.expired) return route.fulfill({ status: 401 });
      if (pathname === CAPABILITIES) return json(route, 200, { capabilities: state.deployment });
      if (pathname === MY_TENANTS) {
        if (state.mineAnswer) return state.mineAnswer(route);
        return json(route, 200, { tenants: state.mine });
      }
      if (pathname === TENANTS && method === 'GET') {
        const tenants = Array.from({ length: state.deploymentTenants }, (_, n) => ({
          id: ten(10 + n),
          name: `Other ${n}`,
          host: `other-${n}.${ZONE}`,
          label: 'dev',
          status: 'active',
          createdAt: '2026-11-04T10:00:00Z',
          creation: null,
        }));
        return json(route, 200, { tenantZone: ZONE, tenants, nextCursor: null });
      }
      if (pathname === CREDENTIALS && method === 'GET') return json(route, 200, { credentials: [], recoveryCode: false });
      if (pathname === COMPLETE) {
        state.grant = state.begunFor;
        return route.fulfill({ status: 204 });
      }
      // Story 3.1: a Tenant's landing reads its Applications, none here.
      if (/^\/api\/v1\/tenants\/[^/]+\/applications$/.test(pathname) && method === 'GET') return json(route, 200, { applications: [], nextCursor: null });
      const tenantPath = /^\/api\/v1\/tenants\/([^/]+)\/(capabilities|label|assertions)$/.exec(pathname);
      if (tenantPath) {
        const tenantId = decodeURIComponent(tenantPath[1]!);
        const what = tenantPath[2];
        if (what === 'capabilities') {
          if (state.holdTenant === tenantId) await held;
          return json(route, 200, { capabilities: state.tenantCapabilities(tenantId) });
        }
        if (what === 'assertions') {
          if (state.beginAnswer) return state.beginAnswer(route);
          state.begunFor = tenantId;
          return json(route, 200, {
            challenge: randomBytes(32).toString('base64url'),
            rpId: new URL(baseURL).hostname,
            timeout: 300000,
            userVerification: 'required',
            allowCredentials: [],
          });
        }
        const tenant = state.mine.find((t) => t.id === tenantId);
        if (method === 'GET') return json(route, 200, { label: tenant?.label ?? 'dev', status: state.creating.includes(tenantId) ? 'creating' : 'active' });
        const label = (JSON.parse(request.postData() ?? '{}') as { label: Label }).label;
        if (state.putAnswer) return state.putAnswer(route, tenantId, label);
        if (request.headers()['x-gatekeep-tenant'] !== tenantId) return problem(route, 409, 'tenant_mismatch');
        if (tenant?.label === 'prod' && label !== 'prod') {
          if (state.grant !== tenantId) return problem(route, 403, 'fresh_assertion_required');
          state.grant = null;
        }
        state.mine = state.mine.map((t) => (t.id === tenantId ? { ...t, label } : t));
        return json(route, 200, { label });
      }
      return route.fulfill({ status: 404 });
    },
  );

  return { log, requests, state, count: (entry) => log.filter((line) => line === entry).length, release: () => release() };
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
  // Only finite animations settle: a pending button's spinner runs until the request answers.
  await page.evaluate(() =>
    Promise.allSettled(
      document
        .getAnimations()
        .filter((animation) => animation.effect?.getComputedTiming().iterations !== Infinity)
        .map((animation) => animation.finished),
    ).then(() => undefined),
  );
  return (await new AxeBuilder({ page }).analyze()).violations.map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
}

const heading = (page: Page) => page.getByRole('heading', { level: 1 });
const switcher = (page: Page) => page.getByTestId('tenant-switcher').locator('[data-menu-trigger]');
const environment = (page: Page) => page.getByRole('group', { name: 'Environment' });
const save = (page: Page) => page.getByRole('button', { name: 'Save' });
const puts = (api: Api, tenant: string) => api.count(`PUT /api/v1/tenants/${tenant}/label`);

/** Marks the window, so a full document load loses the mark. */
const markWindow = (page: Page) => page.evaluate(() => ((window as unknown as { gkMarker: string }).gkMarker = 'same-window'));
const windowMark = (page: Page) => page.evaluate(() => (window as unknown as { gkMarker?: string }).gkMarker ?? null);

async function openSettings(page: Page, tenant: Listed) {
  await page.goto(`/tenants/${tenant.id}/settings`);
  await expect(heading(page)).toHaveText('Tenant settings');
  await expect(environment(page)).toBeVisible();
}

test.use({ viewport: { width: 1280, height: 720 } });
watchCsp(test);
// A page with unsaved changes asks the browser before it unloads: these tests leave on purpose.
test.beforeEach(({ page }) => {
  page.on('dialog', (dialog) => void dialog.accept());
});

test.describe('switcher', () => {
  test('names the current Tenant with its Prod badge, and lists the listed Tenants with hosts and tags, then + Create Tenant', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!);

    await openSettings(page, A);

    const trigger = switcher(page);
    await expect(trigger).toHaveAccessibleName('Alpha PROD, switch Tenant');
    await expect(trigger.locator('bdi')).toHaveText('Alpha');
    const badge = trigger.locator('[data-badge="environment"]');
    await expect(badge).toHaveText('PROD');
    await expect(badge).toHaveAttribute('data-environment', 'prod');
    // The brand, the / separator, then the switcher.
    await expect(page.getByRole('banner').getByText('/', { exact: true })).toBeVisible();

    await trigger.click();
    const items = page.getByRole('menuitem');
    await expect(items).toHaveCount(3);
    await expect(items.nth(0)).toContainText('Alpha');
    await expect(items.nth(0)).toContainText(`alpha.${ZONE}`);
    await expect(items.nth(0)).toHaveAttribute('aria-current', 'true');
    await expect(items.nth(1)).toContainText('Gamma');
    await expect(items.nth(1)).toContainText(`gamma.${ZONE}`);
    await expect(items.nth(1)).not.toHaveAttribute('aria-current', 'true');
    await expect(items.nth(0).locator('[data-badge="environment"]')).toHaveText('PROD');
    await expect(items.nth(1).locator('[data-badge="environment"]')).toHaveText('DEV');
    await expect(items.nth(2)).toHaveText('+ Create Tenant');
    await expect(page.getByRole('menu').getByRole('separator')).toHaveCount(1);
    // No environments page, organization heading or initials tile.
    await expect(page.getByRole('menu')).not.toContainText(/compare|promote|northwind/i);

    await items.nth(2).click();
    await expect(page).toHaveURL(/\/deployment\/tenants\/new$/);
  });

  test('without deployment.tenants.create there is no + Create Tenant', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { deployment: [] });

    await openSettings(page, A);
    await switcher(page).click();

    await expect(page.getByRole('menuitem')).toHaveCount(2);
    await expect(page.getByRole('menuitem', { name: /create tenant/i })).toHaveCount(0);
  });

  test('an Admin with no Tenant and no Deployment capability sees no switcher', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { deployment: [], mine: [] });

    await page.goto('/');

    await expect(page.getByText(NO_ACCESS)).toBeVisible();
    await expect(page.getByTestId('tenant-switcher')).toHaveCount(0);
  });

  test('the keyboard: Enter opens, the arrows move, Esc closes and returns focus', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!);
    await openSettings(page, A);

    await switcher(page).focus();
    await page.keyboard.press('Enter');
    const items = page.getByRole('menuitem');
    await expect(items.nth(0)).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(items.nth(1)).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(items.nth(2)).toBeFocused();
    await page.keyboard.press('ArrowUp');
    await expect(items.nth(1)).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('menu')).toBeHidden();
    await expect(switcher(page)).toBeFocused();
  });

  test('the name and badge show on every page: a Tenant page, a Deployment page and Your credentials, which show the remembered one', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!);

    await openSettings(page, C);
    await expect(switcher(page)).toHaveAccessibleName('Gamma DEV, switch Tenant');
    expect(await page.evaluate((key) => localStorage.getItem(key), REMEMBERED)).toBe(C.id);

    await page.goto('/deployment/tenants');
    await expect(heading(page)).toHaveText('Tenants');
    await expect(switcher(page)).toHaveAccessibleName('Gamma DEV, switch Tenant');

    await page.goto('/account/credentials');
    await expect(heading(page)).toHaveText('Your credentials');
    await expect(switcher(page)).toHaveAccessibleName('Gamma DEV, switch Tenant');

    // A remembered Tenant no longer listed falls back to the first.
    await page.evaluate((key) => localStorage.setItem(key, 'ten_gone'), REMEMBERED);
    await page.goto('/account/credentials');
    await expect(switcher(page)).toHaveAccessibleName('Alpha PROD, switch Tenant');
  });

  test('the tags take their tones: DEV info, STG warn, PROD bad', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { mine: [listed(0, 'Alpha', 'dev'), listed(1, 'Beta', 'staging'), listed(2, 'Gamma', 'prod')] });
    await openSettings(page, listed(0, 'Alpha', 'dev'));

    await switcher(page).click();
    const badges = page.getByRole('menu').locator('[data-badge="environment"]');
    await expect(badges).toHaveText(['DEV', 'STG', 'PROD']);
    expect(await badges.evaluateAll((all) => all.map((b) => b.getAttribute('data-environment')))).toEqual(['dev', 'staging', 'prod']);
    const colours = await badges.evaluateAll((all) => all.map((b) => getComputedStyle(b).color));
    const tokens = await page.evaluate(() => {
      const probe = document.createElement('span');
      document.body.append(probe);
      const colour = (name: string) => {
        probe.style.color = `var(${name})`;
        return getComputedStyle(probe).color;
      };
      const result = [colour('--gk-color-info'), colour('--gk-color-warn'), colour('--gk-color-bad')];
      probe.remove();
      return result;
    });
    expect(colours).toEqual(tokens);
  });

  test('choosing another Tenant loads the same page in it as a new document; the current one only closes the menu', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!);
    await openSettings(page, A);
    await markWindow(page);

    await switcher(page).click();
    await page.getByRole('menuitem').nth(0).click();
    await expect(page.getByRole('menu')).toBeHidden();
    expect(await windowMark(page)).toBe('same-window');

    await switcher(page).click();
    await page.getByRole('menuitem', { name: /Gamma/ }).click();

    await expect(page).toHaveURL(new RegExp(`/tenants/${C.id}/settings$`));
    await expect(switcher(page)).toHaveAccessibleName('Gamma DEV, switch Tenant');
    expect(await windowMark(page)).toBeNull();
  });

  test('with unsaved changes it asks first: Keep editing stays, Discard and switch loads the other Tenant', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!);
    await openSettings(page, A);
    await markWindow(page);
    await environment(page).getByRole('radio', { name: /^Staging/ }).check();

    await switcher(page).click();
    await page.getByRole('menuitem', { name: /Gamma/ }).click();
    const modal = page.getByRole('dialog', { name: 'Discard unsaved changes?' });
    await expect(modal).toBeVisible();
    await expect(modal).toContainText("Your changes on this page aren't saved.");
    await modal.getByRole('button', { name: 'Keep editing' }).click();
    await expect(modal).toBeHidden();
    await expect(environment(page).getByRole('radio', { name: /^Staging/ })).toBeChecked();
    expect(await windowMark(page)).toBe('same-window');

    await switcher(page).click();
    await page.getByRole('menuitem', { name: /Gamma/ }).click();
    await page.getByRole('dialog', { name: 'Discard unsaved changes?' }).getByRole('button', { name: 'Discard and switch' }).click();
    await expect(page).toHaveURL(new RegExp(`/tenants/${C.id}/settings$`));
    expect(await windowMark(page)).toBeNull();
  });
});

test.describe('landing', () => {
  test('with a listed Tenant, it opens the remembered one, else the first, replacing the URL', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!);

    await page.goto('/');
    await expect(page).toHaveURL(new RegExp(`/tenants/${A.id}/applications$`));
    await expect(heading(page)).toHaveText('Applications');

    await page.evaluate((key) => localStorage.setItem(key, 'ten_' + 'c'.repeat(25) + 'a'), REMEMBERED);
    await page.goto('/');
    await expect(page).toHaveURL(new RegExp(`/tenants/${C.id}/applications$`));
  });

  test('a Deployment Owner with Tenants but no role lands on Tenants', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { mine: [], deploymentTenants: 2 });
    await page.goto('/');
    await expect(page).toHaveURL(/\/deployment\/tenants$/);
    await expect(heading(page)).toHaveText('Tenants');
  });

  test('a Deployment Owner with no Tenants lands on Create Tenant in place', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { mine: [] });
    await page.goto('/');
    await expect(page).toHaveURL(/\/$/);
    await expect(heading(page)).toHaveText('Create your Tenant');
    await expect(switcher(page)).toHaveAccessibleName('Choose a Tenant');
  });

  test('any other Admin with no Tenant Role is told to ask a Deployment Owner', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { mine: [], deployment: [] });
    await page.goto('/');
    await expect(heading(page)).toHaveText('Admin Dashboard');
    await expect(page.getByText(NO_ACCESS)).toBeVisible();
  });

  test('/tenants/{tenantId} is replaced by its Applications list, and the sidebar has Applications and Settings, Tenant', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!);
    await page.goto(`/tenants/${A.id}`);
    await expect(page).toHaveURL(new RegExp(`/tenants/${A.id}/applications$`));
    const nav = page.getByRole('navigation', { name: 'Main' });
    const applications = nav.getByRole('link', { name: 'Applications' });
    await expect(applications).toHaveAttribute('href', `/tenants/${A.id}/applications`);
    await expect(applications).toHaveAttribute('aria-current', 'page');
    await nav.getByRole('button', { name: 'Settings' }).click();
    await expect(nav.getByRole('link', { name: 'Tenant' })).toHaveAttribute('href', `/tenants/${A.id}/settings`);
  });
});

test.describe('environment', () => {
  test('Dev to Staging saves with no confirmation: the toast, and the badge becomes STG', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!);
    await openSettings(page, C);

    await expect(page.getByRole('main').locator('code')).toHaveText(`gamma.${ZONE}`);
    const group = environment(page);
    await expect(group.getByRole('radio', { name: /^Development/ })).toBeChecked();
    await expect(group.locator('[data-badge="environment"]')).toHaveText(['DEV', 'STG', 'PROD']);
    await expect(page.getByText("Removing the Prod label needs you to confirm it's you.")).toBeVisible();

    // Nothing to send while the choice is the loaded label.
    await save(page).click();
    await page.waitForTimeout(200);
    expect(puts(api, C.id)).toBe(0);

    await group.getByRole('radio', { name: /^Staging/ }).check();
    await save(page).click();

    await expect(page.getByTestId('toast')).toHaveText(SAVED);
    await expect(switcher(page)).toHaveAccessibleName('Gamma STG, switch Tenant');
    expect(puts(api, C.id)).toBe(1);
    const put = api.requests.find((r) => r.method() === 'PUT')!;
    expect(put.headers()['x-gatekeep-tenant']).toBe(C.id);
    expect(put.postDataJSON()).toEqual({ label: 'staging' });
    expect(api.count(`POST /api/v1/tenants/${C.id}/assertions`)).toBe(0);
  });

  test('removing Prod: the modal, the sheet inside it, then the toast and DEV; the begin is on the Tenant surface', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    await openSettings(page, A);

    await environment(page).getByRole('radio', { name: /^Development/ }).check();
    await save(page).click();
    const modal = page.getByRole('dialog', { name: 'Remove the Prod label?' });
    await expect(modal).toContainText('Alpha will no longer be marked Prod. No other setting changes.');
    expect(puts(api, A.id)).toBe(0);

    await modal.getByRole('button', { name: 'Remove Prod label' }).click();

    await expect(page.getByTestId('toast')).toHaveText(SAVED);
    await expect(modal).toBeHidden();
    await expect(switcher(page)).toHaveAccessibleName('Alpha DEV, switch Tenant');
    expect(api.log.filter((line) => line.startsWith('PUT') || line.startsWith('POST'))).toEqual([
      `PUT /api/v1/tenants/${A.id}/label`,
      `POST /api/v1/tenants/${A.id}/assertions`,
      `POST ${COMPLETE}`,
      `PUT /api/v1/tenants/${A.id}/label`,
    ]);
    const begin = api.requests.find((r) => r.url().endsWith('/assertions'))!;
    expect(begin.postDataJSON()).toEqual({ action: 'tenant.label.manage', target: null });
    expect(begin.headers()['x-gatekeep-tenant']).toBe(A.id);
    expect(api.count('POST /api/v1/deployment/assertions')).toBe(0);
  });

  test('a cancelled sheet says so inside the same modal, and the label stays PROD', async ({ page, baseURL }) => {
    const { cancelling } = await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    await openSettings(page, A);
    await cancelling(true);

    await environment(page).getByRole('radio', { name: /^Staging/ }).check();
    await save(page).click();
    const modal = page.getByRole('dialog', { name: 'Remove the Prod label?' });
    await modal.getByRole('button', { name: 'Remove Prod label' }).click();

    await expect(modal.getByTestId('fresh-assertion-failed')).toHaveText(CANCELLED);
    await expect(switcher(page)).toHaveAccessibleName('Alpha PROD, switch Tenant');
    expect(puts(api, A.id)).toBe(1);
    expect(api.count(`POST ${COMPLETE}`)).toBe(0);
  });

  for (const failure of [
    { name: 'a 503', answer: (route: Route) => route.fulfill({ status: 503 }), testId: 'tenant-settings-save-failed', text: SAVE_FAILED },
    { name: 'a 400', answer: (route: Route) => problem(route, 400, 'tenant_invalid'), testId: 'tenant-settings-save-failed', text: SAVE_FAILED },
    { name: 'a lost connection', answer: (route: Route) => route.abort('connectionfailed'), testId: 'tenant-settings-save-failed', text: SAVE_FAILED },
    { name: 'a 409 tenant_not_active', answer: (route: Route) => problem(route, 409, 'tenant_not_active'), testId: 'tenant-settings-not-active', text: 'This Tenant is still being created.' },
    { name: 'a 403 access_denied', answer: (route: Route) => problem(route, 403, 'access_denied'), testId: 'tenant-settings-forbidden', text: "You can't do this in this session." },
    { name: 'a bodiless 403', answer: (route: Route) => route.fulfill({ status: 403 }), testId: 'tenant-settings-forbidden', text: "You can't do this in this session." },
  ]) {
    test(`${failure.name} shows its banner above the form, with the choice kept`, async ({ page, baseURL }) => {
      await answerApi(page, baseURL!, { putAnswer: (route) => failure.answer(route) });
      await openSettings(page, C);

      await environment(page).getByRole('radio', { name: /^Staging/ }).check();
      await save(page).click();

      await expect(page.getByTestId(failure.testId)).toContainText(failure.text);
      await expect(environment(page).getByRole('radio', { name: /^Staging/ })).toBeChecked();
      await expect(switcher(page)).toHaveAccessibleName('Gamma DEV, switch Tenant');
    });
  }

  test('an Editor sees it read-only, Tenant Owner only; a Viewer also sees the view-only banner', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { tenantCapabilities: () => TENANT_EDITOR });
    await openSettings(page, C);

    for (const radio of await environment(page).getByRole('radio').all()) await expect(radio).toBeDisabled();
    await expect(page.getByText('Tenant Owner only')).toBeVisible();
    await expect(save(page)).toHaveCount(0);
    await expect(page.getByText(VIEW_ONLY)).toHaveCount(0);

    api.state.tenantCapabilities = () => TENANT_VIEWER;
    await page.goto(`/tenants/${A.id}/settings`);
    await expect(page.getByText(VIEW_ONLY)).toBeVisible();
    await expect(page.getByText('Tenant Owner only')).toBeVisible();
  });
});

test.describe('mismatch', () => {
  test("an action for another Tenant than the page shows: the banner names both, with Reload, and the PUT carried the page's Tenant", async ({ page, baseURL }) => {
    const devA: Listed = { ...A, label: 'dev' };
    const api = await answerApi(page, baseURL!, { mine: [devA, C] });
    await openSettings(page, devA);

    // A's form is still mounted while C's reads hang at /tenants/C/settings.
    api.state.holdTenant = C.id;
    await page.evaluate((to) => {
      history.pushState(null, '', to);
      dispatchEvent(new PopStateEvent('popstate'));
    }, `/tenants/${C.id}/settings`);
    await expect(page).toHaveURL(new RegExp(`/tenants/${C.id}/settings$`));
    await expect(heading(page)).toHaveText('Tenant settings');

    await environment(page).getByRole('radio', { name: /^Staging/ }).check();
    await save(page).click();

    const banner = page.getByTestId('tenant-mismatch');
    await expect(banner).toHaveText(/This action was for Alpha, but this page shows Gamma\. Nothing was changed\./);
    await expect(banner.locator('bdi')).toHaveText(['Alpha', 'Gamma']);
    await expect(banner.getByRole('button', { name: 'Reload' })).toBeVisible();
    const put = api.requests.find((r) => r.method() === 'PUT')!;
    expect(new URL(put.url()).pathname).toBe(`/api/v1/tenants/${A.id}/label`);
    expect(put.headers()['x-gatekeep-tenant']).toBe(C.id);
    // The page keeps its values and stops pending.
    await expect(environment(page).getByRole('radio', { name: /^Staging/ })).toBeChecked();
    await expect(save(page)).not.toHaveAttribute('aria-busy', 'true');

    api.release();
    await banner.getByRole('button', { name: 'Reload' }).click();
    await expect(page).toHaveURL(new RegExp(`/tenants/${C.id}/settings$`));
    await expect(switcher(page)).toHaveAccessibleName('Gamma DEV, switch Tenant');
  });
});

test.describe('review', () => {
  test('a label made Prod elsewhere: the plain save is answered fresh_assertion_required, the label is read again and the modal opens', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const stg = listed(1, 'Beta', 'staging');
    const api = await answerApi(page, baseURL!, { mine: [stg] });
    await openSettings(page, stg);

    // Another Owner raised it to Prod since this page read it.
    api.state.mine = [{ ...stg, label: 'prod' }];
    await environment(page).getByRole('radio', { name: /^Development/ }).check();
    await save(page).click();

    const modal = page.getByRole('dialog', { name: 'Remove the Prod label?' });
    await expect(modal).toBeVisible();
    await expect(page.getByTestId('tenant-settings-forbidden')).toHaveCount(0);
    expect(api.count(`GET /api/v1/tenants/${stg.id}/label`)).toBe(2);
    await modal.getByRole('button', { name: 'Remove Prod label' }).click();
    await expect(page.getByTestId('toast')).toHaveText(SAVED);
    expect(api.count(`POST /api/v1/tenants/${stg.id}/assertions`)).toBe(1);
  });

  for (const [name, answer, text] of [
    ['a 429 with Retry-After', (route: Route) => route.fulfill({ status: 429, contentType: 'application/problem+json', headers: { 'Retry-After': '42' }, body: JSON.stringify({ code: 'rate_limited', traceId: 't' }) }), 'Too many attempts. Try again in 42 seconds.'],
    ['a 429 without a whole-number Retry-After', (route: Route) => route.fulfill({ status: 429, contentType: 'application/problem+json', headers: { 'Retry-After': 'soon' }, body: JSON.stringify({ code: 'rate_limited', traceId: 't' }) }), 'Too many attempts. Try again later.'],
    ['a 503', (route: Route) => route.fulfill({ status: 503 }), "We couldn't confirm it's you. Try again."],
    ['a 400', (route: Route) => problem(route, 400, 'assertion_refused'), "That credential wasn't recognised."],
  ] as const) {
    test(`the Prod modal shows ${name} on the begin inside the modal, and the label stays PROD`, async ({ page, baseURL }) => {
      await authenticator(page, new URL(baseURL!).hostname);
      await answerApi(page, baseURL!, { beginAnswer: answer });
      await openSettings(page, A);

      await environment(page).getByRole('radio', { name: /^Staging/ }).check();
      await save(page).click();
      const modal = page.getByRole('dialog', { name: 'Remove the Prod label?' });
      await modal.getByRole('button', { name: 'Remove Prod label' }).click();

      await expect(modal.getByTestId('fresh-assertion-failed')).toHaveText(text);
      await expect(switcher(page)).toHaveAccessibleName('Alpha PROD, switch Tenant');
    });
  }

  test('a 401 on the PUT renews in place: one PUT, no Save failed banner, and the choice kept', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    await openSettings(page, C);

    await environment(page).getByRole('radio', { name: /^Staging/ }).check();
    api.state.expired = true;
    await save(page).click();

    await expect.poll(() => api.count(`POST ${SIGNIN_COMPLETE}`)).toBe(1);
    await page.waitForTimeout(300);
    expect(puts(api, C.id)).toBe(1);
    await expect(page.getByTestId('tenant-settings-save-failed')).toHaveCount(0);
    await expect(environment(page).getByRole('radio', { name: /^Staging/ })).toBeChecked();
    await expect(heading(page)).toHaveText('Tenant settings');
  });

  test('+ Create Tenant and a sidebar link with an unsaved choice ask first; Discard and leave goes', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!);
    await openSettings(page, C);
    await environment(page).getByRole('radio', { name: /^Staging/ }).check();

    await switcher(page).click();
    await page.getByRole('menuitem', { name: '+ Create Tenant' }).click();
    const modal = page.getByRole('dialog', { name: 'Discard unsaved changes?' });
    await expect(modal).toBeVisible();
    await expect(modal.getByRole('button', { name: 'Discard and leave' })).toBeVisible();
    await modal.getByRole('button', { name: 'Keep editing' }).click();
    await expect(page).toHaveURL(new RegExp(`/tenants/${C.id}/settings$`));

    const nav = page.getByRole('navigation', { name: 'Main' });
    await nav.getByRole('button', { name: 'Deployment' }).click();
    await nav.getByRole('link', { name: 'Tenants' }).click();
    await expect(modal).toBeVisible();
    await expect(page).toHaveURL(new RegExp(`/tenants/${C.id}/settings$`));
    await modal.getByRole('button', { name: 'Discard and leave' }).click();
    await expect(page).toHaveURL(/\/deployment\/tenants$/);
    await expect(heading(page)).toHaveText('Tenants');
  });

  for (const [name, answer] of [
    ['a 503', (route: Route) => route.fulfill({ status: 503 })],
    ['a malformed entry', (route: Route) => json(route, 200, { tenants: [{ id: ten(0), name: 'Alpha', host: 'alpha.gatekeep.test', label: 'production' }] })],
  ] as const) {
    test(`a switcher list failing with ${name} degrades only the switcher and the landing`, async ({ page, baseURL }) => {
      const api = await answerApi(page, baseURL!, { mineAnswer: answer });

      // Your credentials still works, with no load-failed banner.
      await page.goto('/account/credentials');
      await expect(heading(page)).toHaveText('Your credentials');
      await expect(page.getByTestId('load-failed')).toHaveCount(0);
      await switcher(page).click();
      await expect(page.getByRole('menuitem', { name: "Couldn't load your Tenants. Retry" })).toBeVisible();
      await page.keyboard.press('Escape');

      // The landing can't tell where to go: the banner, and Retry reads again.
      await page.goto('/');
      const banner = page.getByTestId('landing-tenants-failed');
      await expect(banner).toContainText("We couldn't load this page.");
      await expect(page.getByText(NO_ACCESS)).toHaveCount(0);
      await expect(page.getByTestId('create-tenant')).toHaveCount(0);
      const before = api.count(`GET ${MY_TENANTS}`);
      api.state.mineAnswer = null;
      await banner.getByRole('button', { name: 'Retry' }).click();
      await expect(page).toHaveURL(new RegExp(`/tenants/${A.id}/applications$`));
      expect(api.count(`GET ${MY_TENANTS}`)).toBeGreaterThan(before);
    });
  }

  test('a Tenant still being created shows its environment disabled, with the note', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { creating: [C.id] });
    await page.goto(`/tenants/${C.id}/settings`);
    await expect(heading(page)).toHaveText('Tenant settings');

    await expect(page.getByTestId('tenant-settings-creating')).toHaveText('This Tenant is still being created.');
    for (const radio of await environment(page).getByRole('radio').all()) await expect(radio).toBeDisabled();
    await expect(save(page)).toHaveCount(0);
  });

  for (const width of [1099, 768]) {
    test(`at ${width}px a long name truncates with an ellipsis, and the badge stays whole`, async ({ page, baseURL }) => {
      await page.setViewportSize({ width, height: 720 });
      const long = { ...A, name: 'Alpha Production Tenant With A Very Long Name Indeed' };
      await answerApi(page, baseURL!, { mine: [long, C] });
      await openSettings(page, long);

      const name = switcher(page).locator('bdi');
      expect(await name.evaluate((element) => getComputedStyle(element).textOverflow)).toBe('ellipsis');
      expect(await name.evaluate((element) => element.scrollWidth > element.clientWidth)).toBe(true);
      const badge = switcher(page).locator('[data-badge="environment"]');
      await expect(badge).toBeVisible();
      expect(await badge.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
      await expect(switcher(page)).toHaveAccessibleName(`${long.name} PROD, switch Tenant`);
    });
  }
});

for (const scheme of ['light', 'dark'] as const) {
  for (const width of [1100, 768]) {
    test(`axe finds no violations at ${width}px, ${scheme}: the switcher, Tenant settings, the Prod modal, a failure, the mismatch banner and the landings`, async ({
      page,
      baseURL,
    }) => {
      test.setTimeout(120_000);
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      const { cancelling } = await authenticator(page, new URL(baseURL!).hostname);
      const api = await answerApi(page, baseURL!, { mine: [{ ...A, name: 'Alpha Production Tenant With A Long Name' }, C] });

      await openSettings(page, A);
      expect(await axe(page), 'editable').toEqual([]);
      const box = await switcher(page).boundingBox();
      expect(box!.width).toBeLessThan(width);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      await switcher(page).click();
      await expect(page.getByRole('menu')).toBeVisible();
      expect(await axe(page), 'switcher open').toEqual([]);
      await page.keyboard.press('Escape');

      await cancelling(true);
      await environment(page).getByRole('radio', { name: /^Development/ }).check();
      await save(page).click();
      const modal = page.getByRole('dialog', { name: 'Remove the Prod label?' });
      await expect(modal).toBeVisible();
      expect(await axe(page), 'prod modal').toEqual([]);
      await modal.getByRole('button', { name: 'Remove Prod label' }).click();
      await expect(modal.getByTestId('fresh-assertion-failed')).toHaveText(CANCELLED);
      expect(await axe(page), 'prod modal failure').toEqual([]);
      await modal.getByRole('button', { name: 'Cancel' }).click();

      api.state.putAnswer = (route) => route.fulfill({ status: 503 });
      await openSettings(page, C);
      await environment(page).getByRole('radio', { name: /^Staging/ }).check();
      await save(page).click();
      await expect(page.getByTestId('tenant-settings-save-failed')).toBeVisible();
      expect(await axe(page), 'save failed').toEqual([]);

      api.state.putAnswer = (route) => problem(route, 409, 'tenant_mismatch');
      await save(page).click();
      await expect(page.getByTestId('tenant-mismatch')).toBeVisible();
      expect(await axe(page), 'mismatch').toEqual([]);

      api.state.putAnswer = null;
      api.state.tenantCapabilities = () => TENANT_VIEWER;
      await openSettings(page, C);
      await expect(page.getByText(VIEW_ONLY)).toBeVisible();
      expect(await axe(page), 'read-only').toEqual([]);

      api.state.mine = [];
      await page.goto('/');
      await expect(heading(page)).toHaveText('Create your Tenant');
      expect(await axe(page), 'landing create').toEqual([]);

      api.state.deployment = [];
      await page.goto('/');
      await expect(page.getByText(NO_ACCESS)).toBeVisible();
      expect(await axe(page), 'landing no access').toEqual([]);
    });
  }
}
