// Story 4.6: the Database page, its Settings and Password policy tabs with their own Saves, the "what users see"
// preview, and the Tenant settings page's Sign-up card, in the built Admin Dashboard served by the built Host.Admin
// (admin-host.mjs) under its real CSP, from localhost as the other Tenant pages are. The Admin API is answered by route
// interception. The server's rules (the floor, the capabilities, one event per change) are the Isolation tests'
// (tests/Isolation/Directory and Tenancy); here, what the page makes of the answers.

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const MY_TENANTS = '/api/v1/deployment/my-tenants';
const CSRF = 'W'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000901';
const TENANT = `ten_${'a'.repeat(25)}a`;
const PAGE = `/tenants/${TENANT}/database`;
const SETTINGS_PAGE = `/tenants/${TENANT}/settings`;
const CONNECTION = `/api/v1/tenants/${TENANT}/connections/database`;
const SIGNUP = `${CONNECTION}/settings`;
const POLICY = `${CONNECTION}/password-policy`;
const TENANT_SETTINGS = `/api/v1/tenants/${TENANT}/settings`;
const APIS = `/api/v1/tenants/${TENANT}/apis`;
const LABEL = `/api/v1/tenants/${TENANT}/label`;
const TRACE = 'c'.repeat(32);
const API_CURSOR = `api_${'c'.repeat(25)}a`;

const TENANT_VIEWER = ['tenant.configuration.read', 'tenant.users.read', 'tenant.logs.read'];
const TENANT_EDITOR = [...TENANT_VIEWER, 'tenant.log_detail.read', 'tenant.applications.manage', 'tenant.settings.manage', 'tenant.connections.toggle'];
const TENANT_OWNER = [...TENANT_EDITOR, 'tenant.label.manage', 'tenant.password_policy.manage'];

const DEFAULT_POLICY = { minLength: 12, strength: 'good', historyCount: 5, dictionary: true, personalData: true };

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const problem = (route: Route, status: number, code: string, errors?: unknown[]) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: TRACE, ...(errors ? { errors } : {}) }) });

interface State {
  capabilities: string[];
  label: 'dev' | 'staging' | 'prod';
  connection: { signupEnabled: boolean; passwordPolicy: Record<string, unknown> };
  settings: { termsUrl: string | null; emailVerificationOff: boolean; defaultAudience: string | null };
  /** Replaces a save's answer: by default the server echoes what it was sent. */
  answer: ((route: Route, pathname: string) => Promise<void>) | null;
}

/** The Admin API, for a Viewer of a Dev Tenant with the default Connection unless a test says otherwise. */
async function answerApi(page: Page, initial: Partial<State> = {}) {
  const log: string[] = [];
  const headers: Record<string, string>[] = [];
  const bodies: Record<string, unknown>[] = [];
  const apiCursors: (string | null)[] = [];
  const state: State = {
    capabilities: TENANT_VIEWER,
    label: 'dev',
    connection: { signupEnabled: true, passwordPolicy: DEFAULT_POLICY },
    settings: { termsUrl: null, emailVerificationOff: false, defaultAudience: null },
    answer: null,
    ...initial,
  };
  const connection = () => ({
    kind: 'database',
    name: 'Username-Password',
    enabled: true,
    ...state.connection,
    updatedAt: '2026-11-16T09:00:00.000Z',
  });
  const settings = () => ({ ...state.settings, emailVerificationOff: state.settings.emailVerificationOff && state.label === 'dev', emailVerificationOffAvailable: state.label === 'dev' });
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
      if (pathname === MY_TENANTS) return json(route, 200, { tenants: [{ id: TENANT, name: 'Alpha', host: 'alpha.gatekeep.test', label: state.label }] });
      if (pathname === `/api/v1/tenants/${TENANT}/capabilities`) return json(route, 200, { capabilities: state.capabilities });
      if (pathname === LABEL && method === 'GET') return json(route, 200, { label: state.label, status: 'active' });
      if (pathname === CONNECTION && method === 'GET') return json(route, 200, connection());
      if (pathname === TENANT_SETTINGS && method === 'GET') return json(route, 200, settings());
      if (pathname === APIS && method === 'GET') {
        // Two pages: the second only for the first's cursor.
        const cursor = new URL(request.url()).searchParams.get('cursor');
        apiCursors.push(cursor);
        if (cursor === null) {
          return json(route, 200, {
            apis: [
              { id: `api_${'b'.repeat(25)}a`, name: 'Gatekeep Management API', identifier: 'urn:gatekeep:management', builtIn: true },
              { id: `api_${'c'.repeat(25)}a`, name: 'Billing', identifier: 'https://api.example.com', builtIn: false },
            ],
            nextCursor: API_CURSOR,
          });
        }
        if (cursor === API_CURSOR) {
          return json(route, 200, {
            apis: [{ id: `api_${'d'.repeat(25)}a`, name: 'Ledger', identifier: 'https://ledger.example.com', builtIn: false }],
            nextCursor: null,
          });
        }
        return problem(route, 400, 'invalid_request');
      }
      if ((pathname === SIGNUP || pathname === POLICY || pathname === TENANT_SETTINGS) && method === 'PUT') {
        if (state.answer) return state.answer(route, pathname);
        const sent = bodies.at(-1)!;
        if (pathname === SIGNUP) state.connection = { ...state.connection, signupEnabled: sent.signupEnabled as boolean };
        else if (pathname === POLICY) state.connection = { ...state.connection, passwordPolicy: sent };
        else state.settings = sent as State['settings'];
        return json(route, 200, pathname === TENANT_SETTINGS ? settings() : connection());
      }
      return route.fulfill({ status: 404 });
    },
  );
  return { log, headers, bodies, apiCursors, state, count: (entry: string) => log.filter((line) => line === entry).length };
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

const heading = (page: Page) => page.getByRole('heading', { level: 1 });
const nav = (page: Page) => page.getByRole('navigation', { name: 'Main' });
const toast = (page: Page) => page.getByTestId('toast');
const tab = (page: Page, name: string) => page.getByRole('tab', { name });
const signupToggle = (page: Page) => page.getByTestId('database-signup');

test.use({ viewport: { width: 1280, height: 900 } });
watchCsp(test);

test.describe('settings', () => {
  test('the header shows DB Username-Password, and Settings is the default tab with the one sign-up row', async ({ page }) => {
    await answerApi(page, { capabilities: TENANT_EDITOR });

    await page.goto(PAGE);

    await expect(heading(page)).toContainText('Username-Password');
    await expect(page.getByTestId('database-badge')).toHaveText('DB');
    await expect(tab(page, 'Settings')).toHaveAttribute('aria-selected', 'true');
    await expect(tab(page, 'Password policy')).toHaveAttribute('aria-selected', 'false');
    await expect(page.getByRole('group', { name: 'Allow sign up' })).toContainText(
      'When off, the Sign up link is hidden and no one can create an account.',
    );
    await expect(signupToggle(page)).toHaveAttribute('aria-checked', 'true');
  });

  test('an Editor turns sign-up off and saves: one PUT with the page Tenant and CSRF, then "Changes saved"', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_EDITOR });

    await page.goto(PAGE);
    await signupToggle(page).click();
    await page.getByTestId('database-settings-save').click();

    await expect(toast(page)).toHaveText('Changes saved');
    await expect(signupToggle(page)).toHaveAttribute('aria-checked', 'false');
    expect(api.bodies).toEqual([{ signupEnabled: false }]);
    expect(api.count(`PUT ${SIGNUP}`)).toBe(1);
    expect(api.headers[0]!['x-gatekeep-csrf']).toBe(CSRF);
    expect(api.headers[0]!['x-gatekeep-tenant']).toBe(TENANT);
  });

  test('a Viewer sees everything read-only with the view-only banner and no Save', async ({ page }) => {
    await answerApi(page);

    await page.goto(PAGE);

    await expect(page.getByTestId('tenant-view-only')).toHaveText('You have view-only access to this Tenant.');
    await expect(signupToggle(page)).toBeDisabled();
    await expect(page.getByTestId('database-settings-save')).toHaveCount(0);

    await tab(page, 'Password policy').click();
    await expect(page.getByTestId('password-min-length')).toHaveAttribute('readonly', '');
    await expect(page.getByTestId('password-strength-good')).toBeDisabled();
    await expect(page.getByTestId('database-policy-owner-only')).toHaveText('Tenant Owner only');
    await expect(page.getByTestId('database-policy-save')).toHaveCount(0);
  });
});

test.describe('password policy', () => {
  test('an Editor sees the policy read-only, labelled Tenant Owner only, with no view-only banner', async ({ page }) => {
    await answerApi(page, { capabilities: TENANT_EDITOR });

    await page.goto(`${PAGE}?tab=password-policy`);

    await expect(tab(page, 'Password policy')).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByTestId('password-min-length')).toHaveValue('12');
    await expect(page.getByTestId('password-min-length')).toHaveAttribute('readonly', '');
    await expect(page.getByTestId('password-strength-good')).toBeChecked();
    await expect(page.getByTestId('password-history')).toBeDisabled();
    await expect(page.getByTestId('password-history-count')).toHaveValue('5');
    await expect(page.getByTestId('database-policy-owner-only')).toHaveText('Tenant Owner only');
    await expect(page.getByTestId('database-policy-save')).toHaveCount(0);
    await expect(page.getByTestId('tenant-view-only')).toHaveCount(0);
  });

  test('an Owner saves Excellent with a longer minimum and history off: one PUT, then "Changes saved"', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER });

    await page.goto(`${PAGE}?tab=password-policy`);
    await page.getByTestId('password-min-length').fill('16');
    await page.getByTestId('password-strength-excellent').check();
    await page.getByTestId('password-history').click();
    await expect(page.getByTestId('password-history-count')).toHaveCount(0);
    await page.getByTestId('password-dictionary').click();
    await page.getByTestId('database-policy-save').click();

    await expect(toast(page)).toHaveText('Changes saved');
    expect(api.bodies).toEqual([{ minLength: 16, strength: 'excellent', historyCount: 0, dictionary: false, personalData: true }]);
    expect(api.headers[0]!['x-gatekeep-tenant']).toBe(TENANT);
  });

  test('a minimum below 12 shows the server\'s "Minimum is 12 characters." on the field, focused', async ({ page }) => {
    const api = await answerApi(page, {
      capabilities: TENANT_OWNER,
      answer: (route) => problem(route, 400, 'connection_invalid', [{ field: 'minLength', index: null, reason: 'below_minimum', detail: 'Minimum is 12 characters.' }]),
    });

    await page.goto(`${PAGE}?tab=password-policy`);
    // The browser's own check refuses 11 before sending; past it, the server's text shows as it is.
    await page.getByTestId('password-min-length').fill('11');
    await page.getByTestId('database-policy-save').click();
    await expect(page.getByTestId('password-min-length')).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByTestId('password-min-length')).toBeFocused();
    await expect(page.getByTestId('database-policy')).toContainText('Minimum is 12 characters.');
    expect(api.count(`PUT ${POLICY}`)).toBe(0);

    await page.getByTestId('password-min-length').fill('12');
    await page.getByTestId('password-strength-excellent').check();
    await page.getByTestId('database-policy-save').click();
    await expect(page.getByTestId('database-policy')).toContainText('Minimum is 12 characters.');
    await expect(page.getByTestId('password-min-length')).toHaveAttribute('aria-invalid', 'true');
    await expect(toast(page)).toHaveCount(0);
    expect(api.count(`PUT ${POLICY}`)).toBe(1);
  });

  test('the preview lists each rule as met or not for a sample that is never sent', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER });

    await page.goto(`${PAGE}?tab=password-policy`);
    const sample = page.getByTestId('password-preview-sample');
    await expect(page.getByTestId('password-rule-length')).toContainText('At least 12 characters');
    await expect(page.getByTestId('password-rule-length')).toHaveAttribute('data-met', 'false');
    await expect(page.getByTestId('password-rule-repeats')).toHaveCount(0);

    await sample.fill('correct-Horse1');
    await expect(page.getByTestId('password-rule-length')).toHaveAttribute('data-met', 'true');
    await expect(page.getByTestId('password-rule-classes')).toHaveAttribute('data-met', 'true');
    await expect(page.getByTestId('password-rule-classes')).toContainText('Met');

    await page.getByTestId('password-strength-excellent').check();
    await sample.fill('Passsword-123');
    await expect(page.getByTestId('password-rule-repeats')).toHaveAttribute('data-met', 'false');
    await expect(page.getByTestId('password-rule-repeats')).toContainText('Not met');

    await page.getByTestId('password-min-length').fill('20');
    await expect(page.getByTestId('password-rule-length')).toContainText('At least 20 characters');

    await page.getByTestId('database-policy-save').click();
    await expect(toast(page)).toHaveText('Changes saved');
    expect(JSON.stringify(api.bodies)).not.toContain('Passsword-123');
  });

  test("a switch of tab keeps each tab's draft", async ({ page }) => {
    await answerApi(page, { capabilities: TENANT_OWNER });

    await page.goto(PAGE);
    await signupToggle(page).click();
    await tab(page, 'Password policy').click();
    await page.getByTestId('password-min-length').fill('20');
    await tab(page, 'Settings').click();
    await expect(signupToggle(page)).toHaveAttribute('aria-checked', 'false');
    await tab(page, 'Password policy').click();
    await expect(page.getByTestId('password-min-length')).toHaveValue('20');
  });
});

test.describe('sidebar', () => {
  test('Database sits in the Authentication group, current on its page', async ({ page }) => {
    await answerApi(page);

    await page.goto(PAGE);

    const group = nav(page).getByRole('button', { name: 'Authentication' });
    await expect(group).toHaveAttribute('aria-expanded', 'true');
    await expect(group).toHaveAttribute('data-current', '');
    const link = nav(page).getByRole('link', { name: 'Database' });
    await expect(link).toHaveAttribute('href', PAGE);
    await expect(link).toHaveAttribute('aria-current', 'page');
  });
});

test.describe('tenant settings', () => {
  test('an Editor of a Dev Tenant saves the terms URL, a default audience and verification off', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_EDITOR });

    await page.goto(SETTINGS_PAGE);
    const card = page.getByTestId('tenant-signup');
    await expect(card.getByRole('heading', { name: 'Sign-up' })).toBeVisible();
    // The Tenant's own APIs and None, never the built-in Management API.
    // Both pages of APIs are read: the second with the first's cursor.
    await expect(page.getByTestId('tenant-default-audience').locator('option')).toHaveText([
      'None',
      'Billing (https://api.example.com)',
      'Ledger (https://ledger.example.com)',
    ]);
    expect(api.apiCursors).toEqual([null, API_CURSOR]);

    await page.getByTestId('tenant-terms-url').fill('https://example.com/terms');
    await page.getByTestId('tenant-default-audience').selectOption('https://ledger.example.com');
    await page.getByTestId('tenant-email-verification-off').click();
    await page.getByTestId('tenant-signup-save').click();

    await expect(toast(page)).toHaveText('Changes saved');
    expect(api.bodies).toEqual([{ termsUrl: 'https://example.com/terms', emailVerificationOff: true, defaultAudience: 'https://ledger.example.com' }]);
    expect(api.headers[0]!['x-gatekeep-tenant']).toBe(TENANT);
  });

  test('a stored audience whose API is gone stays selected by its identifier, and a save keeps it', async ({ page }) => {
    const api = await answerApi(page, {
      capabilities: TENANT_EDITOR,
      settings: { termsUrl: null, emailVerificationOff: false, defaultAudience: 'https://gone.example.com' },
    });

    await page.goto(SETTINGS_PAGE);
    const select = page.getByTestId('tenant-default-audience');
    await expect(select).toHaveValue('https://gone.example.com');
    await expect(select.locator('option:checked')).toHaveText('https://gone.example.com');

    await page.getByTestId('tenant-terms-url').fill('https://example.com/terms');
    await page.getByTestId('tenant-signup-save').click();

    await expect(toast(page)).toHaveText('Changes saved');
    expect(api.bodies).toEqual([{ termsUrl: 'https://example.com/terms', emailVerificationOff: false, defaultAudience: 'https://gone.example.com' }]);
  });

  test('a Tenant that isn\'t Dev shows no verification switch, and an http URL is refused on its field before sending', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_EDITOR, label: 'staging' });

    await page.goto(SETTINGS_PAGE);
    await expect(page.getByTestId('tenant-terms-url')).toBeVisible();
    await expect(page.getByTestId('tenant-email-verification-off')).toHaveCount(0);

    await page.getByTestId('tenant-terms-url').fill('http://example.com/terms');
    await page.getByTestId('tenant-signup-save').click();
    await expect(page.getByTestId('tenant-terms-url')).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByTestId('tenant-signup')).toContainText('Enter an https URL.');
    expect(api.count(`PUT ${TENANT_SETTINGS}`)).toBe(0);
  });

  test("the server's refusal shows on its field with its rule text", async ({ page }) => {
    const api = await answerApi(page, {
      capabilities: TENANT_EDITOR,
      answer: (route) =>
        problem(route, 400, 'tenant_settings_invalid', [{ field: 'defaultAudience', index: null, reason: 'not_found', detail: "Choose one of the Tenant's APIs." }]),
    });

    await page.goto(SETTINGS_PAGE);
    await page.getByTestId('tenant-default-audience').selectOption('https://api.example.com');
    await page.getByTestId('tenant-signup-save').click();

    await expect(page.getByTestId('tenant-default-audience')).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByTestId('tenant-signup')).toContainText("Choose one of the Tenant's APIs.");
    expect(api.count(`PUT ${TENANT_SETTINGS}`)).toBe(1);
  });

  test('a Viewer sees the card read-only with no Save', async ({ page }) => {
    await answerApi(page);

    await page.goto(SETTINGS_PAGE);

    await expect(page.getByTestId('tenant-terms-url')).toHaveAttribute('readonly', '');
    await expect(page.getByTestId('tenant-default-audience')).toBeDisabled();
    await expect(page.getByTestId('tenant-signup-save')).toHaveCount(0);
  });
});

for (const scheme of ['light', 'dark'] as const) {
  for (const width of [1100, 768]) {
    test(`axe finds no violations at ${width}px, ${scheme}: both tabs for an Owner, the floor error, an Editor, a Viewer and the Sign-up card`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      const api = await answerApi(page, {
        capabilities: TENANT_OWNER,
        answer: (route) => problem(route, 400, 'connection_invalid', [{ field: 'minLength', index: null, reason: 'below_minimum', detail: 'Minimum is 12 characters.' }]),
      });

      await page.goto(PAGE);
      await expect(signupToggle(page)).toBeVisible();
      expect(await axe(page), 'settings').toEqual([]);

      await tab(page, 'Password policy').click();
      await page.getByTestId('password-preview-sample').fill('Passsword-123');
      expect(await axe(page), 'policy').toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      await page.getByTestId('password-strength-excellent').check();
      await page.getByTestId('database-policy-save').click();
      await expect(page.getByTestId('database-policy')).toContainText('Minimum is 12 characters.');
      expect(await axe(page), 'floor error').toEqual([]);

      api.state.capabilities = TENANT_EDITOR;
      await page.reload();
      await expect(page.getByTestId('database-policy-owner-only')).toBeVisible();
      expect(await axe(page), 'editor').toEqual([]);

      api.state.capabilities = TENANT_VIEWER;
      await page.reload();
      await expect(page.getByTestId('tenant-view-only')).toBeVisible();
      expect(await axe(page), 'viewer').toEqual([]);

      api.state.capabilities = TENANT_EDITOR;
      await page.goto(SETTINGS_PAGE);
      await expect(page.getByTestId('tenant-email-verification-off')).toBeVisible();
      expect(await axe(page), 'sign-up card').toEqual([]);
    });
  }
}
