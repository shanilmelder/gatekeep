// Story 1.29: deleting a Tenant, retrying its deletion, and the lost-Tenant banner, in the built
// Admin Dashboard served by the built Host.Admin (admin-host.mjs) under its real CSP, from
// localhost, since WebAuthn takes no IP address as an RP ID. The Admin API is answered by route
// interception; the deletion's sheet by a Chromium virtual authenticator over CDP, as in
// admin-credentials.spec.ts. The server's rules are the Isolation tests'
// (tests/Isolation/Tenancy/TenantDeletionTests.cs); the lost Tenant's,
// apps/admin-dashboard/test/lostTenant.test.mjs's.

import AxeBuilder from '@axe-core/playwright';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, test, type CDPSession, type Page, type Request, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const MY_TENANTS = '/api/v1/deployment/my-tenants';
const TENANTS = '/api/v1/deployment/tenants';
const BEGIN = '/api/v1/deployment/assertions';
const COMPLETE = '/api/v1/deployment/assertions/complete';
const CSRF = 'X'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000129';
const ZONE = 'gatekeep.test';
const REMEMBERED = `gatekeep.admin.lastTenant.${ADMIN_ID}`;
const ACTION = 'deployment.tenants.delete';

const OWNER = ['deployment.tenants.read', 'deployment.tenants.create', 'deployment.tenants.delete', 'deployment.admins.read'];
const TENANT_OWNER = ['tenant.configuration.read', 'tenant.settings.manage', 'tenant.label.manage'];

const PROMPT = "Confirm it's you with your security key or passkey.";
const CANCELLED = 'Confirmation cancelled. Nothing was changed.';
const STARTED = 'Tenant deletion started.';
const BUSY = 'This Tenant is still being created. Try again once it finishes.';
const FAILED = "Couldn't delete the Tenant. Try again.";
const FORBIDDEN = "You can't do this in this session.";
const BODY =
  "This permanently removes its Users, Sessions and settings, and destroys its keys. {host} stops answering and can never be used again. Its Logs are kept for 90 days. This can't be undone.";
const LOST = (name: string) => `You no longer have access to ${name}. It was deleted, or your role in it was removed.`;

type Label = 'dev' | 'staging' | 'prod';

interface Row {
  id: string;
  name: string;
  host: string;
  label: Label;
  status: 'creating' | 'active' | 'deleting';
  createdAt: string;
  creation: { operationId: string; status: 'running' | 'failed' } | null;
  deletion: { operationId: string; status: 'running' | 'failed' } | null;
}

interface Listed {
  id: string;
  name: string;
  host: string;
  label: Label;
}

const ten = (n: number) => `ten_${String.fromCharCode(97 + n).repeat(25)}a`;
const opr = (n: number) => `opr_${String.fromCharCode(97 + n).repeat(25)}a`;

const row = (n: number, name: string, extra: Partial<Row> = {}): Row => ({
  id: ten(n),
  name,
  host: `${name.toLowerCase()}.${ZONE}`,
  label: 'dev',
  status: 'active',
  createdAt: `2026-11-0${n + 1}T10:00:00Z`,
  creation: null,
  deletion: null,
  ...extra,
});

const listed = (r: Row): Listed => ({ id: r.id, name: r.name, host: r.host, label: r.label });

const ACME = row(0, 'Acme');
const BETA = row(1, 'Beta');
const GAMMA = row(2, 'Gamma');

const deletionOperation = (tenantId: string, status: 'running' | 'failed' | 'succeeded' = 'running') => ({
  id: opr(0),
  type: 'tenancy.tenant.delete',
  tenantId,
  status,
  createdAt: '2026-11-05T10:00:00Z',
  updatedAt: '2026-11-05T10:00:00Z',
  finishedAt: null,
  steps: [
    { stage: 'tenancy.tenant.purge', tenantId, status: 'pending', resultCode: null, attempts: 0, updatedAt: '2026-11-05T10:00:00Z' },
    { stage: 'keys.secret_classes.destroy', tenantId, status: 'pending', resultCode: null, attempts: 0, updatedAt: '2026-11-05T10:00:00Z' },
  ],
});

const json = (route: Route, status: number, body: unknown, headers?: Record<string, string>) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body), headers });
const problem = (route: Route, status: number, code: string) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: 'c'.repeat(32) }) });

interface State {
  deployment: string[];
  tenants: Row[];
  mine: Listed[];
  /** Tenants whose every Tenant-surface request is the 403 access_denied, as a deleted one's is. */
  denied: string[];
  /** The grant a passed complete leaves, for the target the last begin named. */
  grant: string | null;
  begunFor: string | null;
  /** Holds each begin until released, so the sheet's prompt stays in view. */
  holdBegin: Promise<void> | null;
  /** Replaces the deletion POST's answer, after the grant is checked and used. */
  deleteAnswer: ((route: Route) => Promise<void>) | null;
  /** Replaces the deletion retry's answer, after the grant is checked and used. */
  retryAnswer: ((route: Route) => Promise<void>) | null;
  /** Replaces the label PUT's answer. */
  putAnswer: ((route: Route) => Promise<void>) | null;
  /** Replaces the my-tenants read's answer, such as with a 503. */
  mineAnswer: ((route: Route) => Promise<void>) | null;
}

interface Api {
  log: string[];
  requests: Request[];
  state: State;
  count: (entry: string) => number;
}

/** The Admin API as the server answers a signed-in Deployment Owner, with the deletion routes. */
async function answerApi(page: Page, baseURL: string, initial: Partial<State> = {}): Promise<Api> {
  const log: string[] = [];
  const requests: Request[] = [];
  const state: State = {
    deployment: OWNER,
    tenants: [ACME, BETA],
    mine: [],
    denied: [],
    grant: null,
    begunFor: null,
    holdBegin: null,
    deleteAnswer: null,
    retryAnswer: null,
    putAnswer: null,
    mineAnswer: null,
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
      if (pathname === CAPABILITIES) return json(route, 200, { capabilities: state.deployment });
      if (pathname === MY_TENANTS) return state.mineAnswer ? state.mineAnswer(route) : json(route, 200, { tenants: state.mine });
      if (pathname === TENANTS && method === 'GET') return json(route, 200, { tenantZone: ZONE, tenants: state.tenants, nextCursor: null });
      if (pathname === BEGIN) {
        if (state.holdBegin) await state.holdBegin;
        state.begunFor = (JSON.parse(request.postData() ?? '{}') as { target?: string }).target ?? null;
        return json(route, 200, {
          challenge: randomBytes(32).toString('base64url'),
          rpId: new URL(baseURL).hostname,
          timeout: 300000,
          userVerification: 'required',
          allowCredentials: [],
        });
      }
      if (pathname === COMPLETE) {
        state.grant = state.begunFor;
        return route.fulfill({ status: 204 });
      }
      const deletion = /^\/api\/v1\/deployment\/tenants\/([^/]+)\/deletion(\/retry)?$/.exec(pathname);
      if (deletion && method === 'POST') {
        const tenantId = decodeURIComponent(deletion[1]!);
        // The checks use up a grant for this Tenant, or refuse with fresh_assertion_required.
        if (state.grant !== tenantId) return problem(route, 403, 'fresh_assertion_required');
        state.grant = null;
        const retry = deletion[2] !== undefined;
        const answer = retry ? state.retryAnswer : state.deleteAnswer;
        if (answer) return answer(route);
        state.tenants = state.tenants.map((t): Row =>
          t.id === tenantId ? { ...t, status: 'deleting', creation: null, deletion: { operationId: opr(0), status: 'running' } } : t,
        );
        state.mine = state.mine.filter((t) => t.id !== tenantId);
        return json(route, 202, deletionOperation(tenantId), { Location: `/api/v1/deployment/tenants/${tenantId}/deletion` });
      }
      const tenantPath = /^\/api\/v1\/tenants\/([^/]+)\/(capabilities|label)$/.exec(pathname);
      if (tenantPath) {
        const tenantId = decodeURIComponent(tenantPath[1]!);
        if (state.denied.includes(tenantId)) return problem(route, 403, 'access_denied');
        if (tenantPath[2] === 'capabilities') return json(route, 200, { capabilities: TENANT_OWNER });
        if (method === 'GET') return json(route, 200, { label: 'dev', status: 'active' });
        if (state.putAnswer) return state.putAnswer(route);
        const label = (JSON.parse(request.postData() ?? '{}') as { label: Label }).label;
        return json(route, 200, { label });
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
const table = (page: Page) => page.getByRole('table');
const deleteDialog = (page: Page, name: string) => page.getByRole('dialog', { name: `Delete ${name}?` });
const retryDialog = (page: Page, name: string) => page.getByRole('dialog', { name: `Retry deleting ${name}?` });
const typed = (page: Page, name: string) => deleteDialog(page, name).getByRole('textbox', { name: 'Tenant subdomain' });
const confirm = (page: Page, name: string) => deleteDialog(page, name).getByRole('button', { name: 'Delete Tenant' });
const deletionPosts = (api: Api, tenantId: string) => api.count(`POST ${TENANTS}/${tenantId}/deletion`);

async function openTenants(page: Page) {
  await page.goto('/deployment/tenants');
  await expect(heading(page)).toHaveText('Tenants');
  await expect(table(page)).toBeVisible();
}

async function openDelete(page: Page, tenant: Row) {
  await table(page).getByRole('button', { name: `Delete ${tenant.name}` }).click();
  await expect(deleteDialog(page, tenant.name)).toBeVisible();
}

test.use({ viewport: { width: 1280, height: 720 } });
watchCsp(test);
// A page with unsaved changes asks the browser before it unloads: these tests leave on purpose.
test.beforeEach(({ page }) => {
  page.on('dialog', (dialog) => void dialog.accept());
});

test.describe('delete', () => {
  test('Delete opens the destructive modal, whose Confirm stays disabled until the host is typed exactly', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!);
    await openTenants(page);
    await expect(table(page).getByRole('columnheader').last()).toHaveText('Delete');

    await openDelete(page, ACME);

    const dialog = deleteDialog(page, ACME.name);
    await expect(dialog.getByRole('heading').locator('bdi')).toHaveText(ACME.name);
    await expect(dialog).toContainText(BODY.replace('{host}', ACME.host));
    await expect(dialog.locator('p code')).toHaveText(ACME.host);
    await expect(dialog.getByText(`Type ${ACME.host} to confirm.`)).toBeVisible();
    await expect(confirm(page, ACME.name)).toHaveAttribute('aria-disabled', 'true');

    // Exactly: no case folding, no trimming, no prefix.
    for (const value of [ACME.host.toUpperCase(), ` ${ACME.host}`, `${ACME.host} `, 'acme']) {
      await typed(page, ACME.name).fill(value);
      await expect(confirm(page, ACME.name)).toHaveAttribute('aria-disabled', 'true');
      await confirm(page, ACME.name).click({ force: true });
    }
    await page.waitForTimeout(200);
    expect(deletionPosts(api, ACME.id)).toBe(0);

    await typed(page, ACME.name).fill(ACME.host);
    await expect(confirm(page, ACME.name)).not.toHaveAttribute('aria-disabled', 'true');

    // Cancel sends nothing.
    await deleteDialog(page, ACME.name).getByRole('button', { name: 'Cancel' }).click();
    await expect(deleteDialog(page, ACME.name)).toHaveCount(0);
    expect(deletionPosts(api, ACME.id)).toBe(0);
  });

  test('Confirm sends the host, confirms inside the modal on the Deployment begin bound to the Tenant, then starts the deletion', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    let release!: () => void;
    const api = await answerApi(page, baseURL!, {
      mine: [listed(ACME), listed(BETA)],
      holdBegin: new Promise<void>((resolve) => (release = resolve)),
    });
    await openTenants(page);
    const mineBefore = api.count(`GET ${MY_TENANTS}`);
    await openDelete(page, ACME);
    // Typed key by key, as an Admin types it: what the field holds is what goes out.
    await typed(page, ACME.name).pressSequentially(ACME.host);
    const typedValue = await typed(page, ACME.name).inputValue();

    await confirm(page, ACME.name).click();

    // The sheet's status is inside the same modal.
    await expect(deleteDialog(page, ACME.name).getByTestId('fresh-assertion-prompt')).toHaveText(PROMPT);
    release();

    await expect(page.getByTestId('toast')).toHaveText(STARTED);
    await expect(deleteDialog(page, ACME.name)).toHaveCount(0);
    await expect(table(page).getByRole('rowheader').first()).toHaveText(/^Acme\s*Deleting$/);
    await expect(table(page).getByRole('button', { name: 'Delete Acme' })).toHaveCount(0);

    // Sent twice: refused for want of a grant, then with it. Each carried the typed host and the CSRF token, and no page Tenant.
    expect(deletionPosts(api, ACME.id)).toBe(2);
    const sent = api.requests.filter((r) => r.method() === 'POST' && new URL(r.url()).pathname === `${TENANTS}/${ACME.id}/deletion`);
    for (const request of sent) {
      // What the Admin typed, sent as typed: the modal passes the field's value out, never the row's host.
      expect(request.postDataJSON()).toEqual({ confirmation: typedValue });
      expect(await request.headerValue('x-gatekeep-csrf')).toBe(CSRF);
      expect(await request.headerValue('x-gatekeep-tenant')).toBeNull();
    }
    // The Deployment begin, with the Tenant as the target, never a Tenant-surface begin.
    const begin = api.requests.find((r) => new URL(r.url()).pathname === BEGIN)!;
    expect(begin.postDataJSON()).toEqual({ action: ACTION, target: ACME.id });
    expect(api.log.some((line) => /\/api\/v1\/tenants\/[^/]+\/assertions$/.test(line))).toBe(false);
    // The shell's lists are read again, so the switcher drops the Tenant at once.
    await expect.poll(() => api.count(`GET ${MY_TENANTS}`)).toBeGreaterThan(mineBefore);
  });

  test('a cancelled sheet says so in the same modal, and the row is unchanged', async ({ page, baseURL }) => {
    const { cancelling } = await authenticator(page, new URL(baseURL!).hostname);
    await cancelling(true);
    const api = await answerApi(page, baseURL!);
    await openTenants(page);
    await openDelete(page, ACME);
    await typed(page, ACME.name).fill(ACME.host);

    await confirm(page, ACME.name).click();

    await expect(deleteDialog(page, ACME.name).getByTestId('delete-tenant-failed')).toHaveText(CANCELLED);
    expect(deletionPosts(api, ACME.id)).toBe(1);
    await deleteDialog(page, ACME.name).getByRole('button', { name: 'Cancel' }).click();
    await expect(table(page).getByRole('rowheader').first()).toHaveText(/^Acme$/);
    await expect(table(page).getByRole('button', { name: 'Delete Acme' })).toBeVisible();
  });

  for (const outcome of [
    { name: '409 tenant_busy', answer: (route: Route) => problem(route, 409, 'tenant_busy'), text: BUSY, reference: false },
    { name: '403 access_denied', answer: (route: Route) => problem(route, 403, 'access_denied'), text: FORBIDDEN, reference: false },
    { name: 'the bodiless 403', answer: (route: Route) => route.fulfill({ status: 403 }), text: FORBIDDEN, reference: false },
    { name: '400 confirmation_mismatch', answer: (route: Route) => problem(route, 400, 'confirmation_mismatch'), text: FAILED, reference: true },
    { name: 'a 503', answer: (route: Route) => route.fulfill({ status: 503 }), text: FAILED, reference: true },
    { name: 'a lost connection', answer: (route: Route) => route.abort('connectionfailed'), text: FAILED, reference: true },
  ]) {
    test(`${outcome.name} after the confirmation shows inside the modal, which stays open`, async ({ page, baseURL }) => {
      await authenticator(page, new URL(baseURL!).hostname);
      const api = await answerApi(page, baseURL!, { deleteAnswer: outcome.answer });
      await openTenants(page);
      await openDelete(page, ACME);
      await typed(page, ACME.name).fill(ACME.host);

      await confirm(page, ACME.name).click();

      const failed = deleteDialog(page, ACME.name).getByTestId('delete-tenant-failed');
      await expect(failed).toContainText(outcome.text);
      if (outcome.reference) await expect(failed.locator('[data-reference="code"]')).toBeVisible();
      await expect(deleteDialog(page, ACME.name)).toBeVisible();
      await expect(typed(page, ACME.name)).toHaveValue(ACME.host);
      expect(deletionPosts(api, ACME.id)).toBe(2);
      await expect(page.getByTestId('toast')).toHaveCount(0);
    });
  }

  test('409 tenant_deleted closes the modal and reads the list again', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!, {
      deleteAnswer: async (route) => {
        api.state.tenants = [BETA];
        await problem(route, 409, 'tenant_deleted');
      },
    });
    await openTenants(page);
    const reads = api.count(`GET ${TENANTS}`);
    await openDelete(page, ACME);
    await typed(page, ACME.name).fill(ACME.host);

    await confirm(page, ACME.name).click();

    await expect(deleteDialog(page, ACME.name)).toHaveCount(0);
    await expect(table(page).getByRole('rowheader')).toHaveText(['Beta']);
    expect(api.count(`GET ${TENANTS}`)).toBeGreaterThan(reads);
    await expect(page.getByTestId('toast')).toHaveCount(0);
  });

  test('a failed deletion says so with Retry, which confirms again and runs it: Deletion failed, then Deleting', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const failedAcme = row(0, 'Acme', { status: 'deleting', deletion: { operationId: opr(0), status: 'failed' } });
    const api = await answerApi(page, baseURL!, { tenants: [failedAcme, BETA] });
    await openTenants(page);
    await expect(table(page).getByRole('rowheader').first()).toHaveText(/^Acme\s*Deletion failed$/);
    await expect(table(page).getByRole('button', { name: 'Delete Acme' })).toHaveCount(0);

    await table(page).getByRole('button', { name: 'Retry deleting Acme' }).click();
    const dialog = retryDialog(page, 'Acme');
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText("Only the steps that didn't finish run again.");
    await expect(dialog.getByRole('textbox')).toHaveCount(0);
    await dialog.getByRole('button', { name: 'Retry deletion' }).click();

    await expect(dialog).toHaveCount(0);
    await expect(table(page).getByRole('rowheader').first()).toHaveText(/^Acme\s*Deleting$/);
    expect(api.count(`POST ${TENANTS}/${ACME.id}/deletion/retry`)).toBe(2);
    expect(api.requests.find((r) => new URL(r.url()).pathname === BEGIN)!.postDataJSON()).toEqual({ action: ACTION, target: ACME.id });
  });

  test('a Retry answered 409 operation_not_failed closes and reads the list again', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const failedAcme = row(0, 'Acme', { status: 'deleting', deletion: { operationId: opr(0), status: 'failed' } });
    const api = await answerApi(page, baseURL!, {
      tenants: [failedAcme],
      retryAnswer: async (route) => {
        api.state.tenants = [row(0, 'Acme', { status: 'deleting', deletion: { operationId: opr(0), status: 'running' } })];
        await problem(route, 409, 'operation_not_failed');
      },
    });
    await openTenants(page);
    await table(page).getByRole('button', { name: 'Retry deleting Acme' }).click();
    await retryDialog(page, 'Acme').getByRole('button', { name: 'Retry deletion' }).click();

    await expect(retryDialog(page, 'Acme')).toHaveCount(0);
    await expect(table(page).getByRole('rowheader').first()).toHaveText(/^Acme\s*Deleting$/);
  });

  test('without deployment.tenants.delete there is no Delete column', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { deployment: ['deployment.tenants.read', 'deployment.tenants.create'] });
    await openTenants(page);

    await expect(table(page).getByRole('columnheader')).toHaveText(['Name', 'Tenant Subdomain', 'Environment', 'Created']);
    await expect(table(page).getByRole('button')).toHaveCount(0);
  });
});

test.describe('lost Tenant', () => {
  test("a Tenant listed a moment ago whose next navigation's reads are refused returns to the landing, with the banner", async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { mine: [listed(ACME), listed(GAMMA)], tenants: [ACME, GAMMA] });
    await page.goto(`/tenants/${ACME.id}/settings`);
    await expect(heading(page)).toHaveText('Tenant settings');
    // Its own label read answered too: a read still in flight would find the Tenant lost before the click.
    await expect(page.getByRole('radio', { name: /^Staging/ })).toBeVisible();

    // Deleted: its every request is refused, and the Admin's list lacks it.
    api.state.denied = [ACME.id];
    api.state.mine = [listed(GAMMA)];
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Tenant', exact: true }).click();

    // The landing's rules: the one Tenant left is opened, and the banner survives that redirect.
    await expect(page).toHaveURL(new RegExp(`/tenants/${GAMMA.id}/settings$`));
    const banner = page.getByTestId('tenant-lost');
    await expect(banner).toHaveText(LOST('Acme'));
    await expect(banner.locator('bdi')).toHaveText('Acme');
    await expect(banner).toHaveAttribute('data-tone', 'warn');
    await expect(page.getByText("You don't have access to this page.")).toHaveCount(0);
    // The remembered Tenant is no longer the lost one.
    expect(await page.evaluate((key) => window.localStorage.getItem(key), REMEMBERED)).not.toBe(ACME.id);

    // The Admin's next navigation clears it.
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Tenant', exact: true }).click();
    await expect(page.getByTestId('tenant-lost')).toHaveCount(0);
    await expect(heading(page)).toHaveText('Tenant settings');
  });

  test('a save refused with access_denied, once the lists lack the Tenant, returns to the landing with the banner and no unsaved prompt', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, {
      mine: [listed(ACME)],
      tenants: [ACME],
      putAnswer: async (route) => {
        api.state.denied = [ACME.id];
        api.state.mine = [];
        await problem(route, 403, 'access_denied');
      },
    });
    await page.goto(`/tenants/${ACME.id}/settings`);
    await expect(heading(page)).toHaveText('Tenant settings');

    await page.getByRole('radio', { name: /^Staging/ }).check();
    await page.getByRole('button', { name: 'Save' }).click();

    // No Tenant left: the landing's rules for a Deployment Owner with Tenants, the Tenants page.
    await expect(page).toHaveURL(/\/deployment\/tenants$/);
    await expect(page.getByTestId('tenant-lost')).toHaveText(LOST('Acme'));
    await expect(page.getByRole('dialog', { name: 'Discard unsaved changes?' })).toHaveCount(0);
  });

  test('the remembered Tenant opened by URL and refused is lost too, named by its ID when it was never listed here', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { mine: [listed(GAMMA)], tenants: [GAMMA], denied: [ACME.id] });
    await page.addInitScript(([key, value]) => window.localStorage.setItem(key, value), [REMEMBERED, ACME.id] as const);

    await page.goto(`/tenants/${ACME.id}/settings`);

    await expect(page).toHaveURL(new RegExp(`/tenants/${GAMMA.id}/settings$`));
    const banner = page.getByTestId('tenant-lost');
    await expect(banner).toHaveText(LOST(ACME.id));
    await expect(banner.locator('code')).toHaveText(ACME.id);
  });

  test('a my-tenants read that fails decides nothing: no banner, no redirect, the remembered Tenant kept, the forbidden page', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { mine: [listed(ACME), listed(GAMMA)], tenants: [ACME, GAMMA] });
    await page.goto(`/tenants/${ACME.id}/settings`);
    await expect(heading(page)).toHaveText('Tenant settings');
    await expect(page.getByRole('radio', { name: /^Staging/ })).toBeVisible();
    expect(await page.evaluate((key) => window.localStorage.getItem(key), REMEMBERED)).toBe(ACME.id);

    api.state.denied = [ACME.id];
    api.state.mine = [listed(GAMMA)];
    api.state.mineAnswer = (route) => route.fulfill({ status: 503 });
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Tenant', exact: true }).click();

    await expect(heading(page)).toHaveText("You don't have access to this page.");
    await expect(page).toHaveURL(new RegExp(`/tenants/${ACME.id}/settings$`));
    await expect(page.getByTestId('tenant-lost')).toHaveCount(0);
    expect(await page.evaluate((key) => window.localStorage.getItem(key), REMEMBERED)).toBe(ACME.id);
  });

  test('a page whose every request is refused makes the shell read its lists again once, not over and over', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!, { mine: [listed(ACME)], tenants: [ACME] });
    await page.goto(`/tenants/${ACME.id}/settings`);
    await expect(page.getByRole('radio', { name: /^Staging/ })).toBeVisible();
    const before = api.count(`GET ${MY_TENANTS}`);

    // Refused, but still listed: not lost, so the forbidden page, and one read of the lists more.
    api.state.denied = [ACME.id];
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Tenant', exact: true }).click();
    await expect(heading(page)).toHaveText("You don't have access to this page.");
    await page.waitForTimeout(1500);
    expect(api.count(`GET ${MY_TENANTS}`) - before).toBeLessThanOrEqual(2);
  });

  test('a Tenant never listed or remembered is the forbidden page, unchanged, with no banner', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { mine: [listed(GAMMA)], tenants: [GAMMA], denied: [ACME.id] });

    await page.goto(`/tenants/${ACME.id}/settings`);

    await expect(heading(page)).toHaveText("You don't have access to this page.");
    await expect(page).toHaveURL(new RegExp(`/tenants/${ACME.id}/settings$`));
    await expect(page.getByTestId('tenant-lost')).toHaveCount(0);
  });
});

for (const scheme of ['light', 'dark'] as const) {
  for (const width of [1100, 768]) {
    test(`axe finds no violations at ${width}px, ${scheme}: the Delete column, badges, both modals and the lost banner`, async ({ page, baseURL }) => {
      // Eight axe runs on one page.
      test.setTimeout(150_000);
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      await authenticator(page, new URL(baseURL!).hostname);
      let release!: () => void;
      const api = await answerApi(page, baseURL!, {
        tenants: [
          ACME,
          row(1, 'Beta', { status: 'deleting', deletion: { operationId: opr(1), status: 'running' } }),
          row(2, 'Gamma', { status: 'deleting', deletion: { operationId: opr(2), status: 'failed' } }),
          row(3, 'Delta', { status: 'creating', creation: { operationId: opr(3), status: 'failed' } }),
        ],
        deleteAnswer: (route) => route.fulfill({ status: 503 }),
      });

      await openTenants(page);
      expect(await axe(page), 'tenants').toEqual([]);

      await openDelete(page, ACME);
      expect(await axe(page), 'delete, empty').toEqual([]);
      await typed(page, ACME.name).fill(ACME.host);
      expect(await axe(page), 'delete, matching').toEqual([]);

      api.state.holdBegin = new Promise<void>((resolve) => (release = resolve));
      await confirm(page, ACME.name).click();
      await expect(deleteDialog(page, ACME.name).getByTestId('fresh-assertion-prompt')).toBeVisible();
      expect(await axe(page), 'delete, sheet').toEqual([]);
      release();
      await expect(deleteDialog(page, ACME.name).getByTestId('delete-tenant-failed')).toContainText(FAILED);
      expect(await axe(page), 'delete, failure').toEqual([]);
      await deleteDialog(page, ACME.name).getByRole('button', { name: 'Cancel' }).click();

      await table(page).getByRole('button', { name: 'Retry deleting Gamma' }).click();
      await expect(retryDialog(page, 'Gamma')).toBeVisible();
      expect(await axe(page), 'retry').toEqual([]);
      await retryDialog(page, 'Gamma').getByRole('button', { name: 'Cancel' }).click();

      api.state.mine = [listed(ACME), listed(GAMMA)];
      await page.goto(`/tenants/${ACME.id}/settings`);
      await expect(heading(page)).toHaveText('Tenant settings');
      await expect(page.getByRole('radio', { name: /^Staging/ })).toBeVisible();
      api.state.denied = [ACME.id];
      api.state.mine = [listed(GAMMA)];
      // At 768px the sidebar is the rail: the same item, found by its address.
      await page.getByTestId('sidebar').locator(`a[href="/tenants/${ACME.id}/settings"]:visible`).first().click();
      await expect(page.getByTestId('tenant-lost')).toBeVisible();
      await expect(heading(page)).toHaveText('Tenant settings');
      expect(await axe(page), 'lost banner').toEqual([]);
    });
  }
}
