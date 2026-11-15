// Story 4.4: the Email provider page, its kind cards, its write-only secret, Save and Remove, in the built Admin
// Dashboard served by the built Host.Admin (admin-host.mjs) under its real CSP, from localhost, since WebAuthn takes no
// IP address as an RP ID. The Admin API is answered by route interception; the fresh assertion's sheet by a Chromium
// virtual authenticator over CDP, as in admin-signing-keys.spec.ts. The server's rules (each kind's settings, the
// secret's encryption, Owners only, the fresh assertion) are the Isolation tests' (tests/Isolation/Notifications);
// here, what the page makes of the answers.

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
const PAGE = `/tenants/${TENANT}/email-provider`;
const PROVIDER = `/api/v1/tenants/${TENANT}/email-provider`;
const BEGIN = `/api/v1/tenants/${TENANT}/assertions`;
const COMPLETE = '/api/v1/deployment/assertions/complete';
const ACTION = 'tenant.email_provider.manage';
const TRACE = 'c'.repeat(32);

const TENANT_VIEWER = ['tenant.configuration.read', 'tenant.users.read', 'tenant.logs.read'];
const TENANT_EDITOR = [...TENANT_VIEWER, 'tenant.log_detail.read', 'tenant.applications.manage', 'tenant.settings.manage'];
const TENANT_OWNER = [...TENANT_EDITOR, 'tenant.label.manage', 'tenant.email_provider.manage'];

const SMTP = {
  configured: true,
  kind: 'smtp',
  settings: { host: 'smtp.example.com', port: 587, tls: 'starttls', username: 'mailer' },
  fromAddress: 'no-reply@example.com',
  fromName: 'Example',
  updatedAt: '2026-11-16T09:00:00.000Z',
  secretSet: true,
};

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const problem = (route: Route, status: number, code: string, errors?: unknown[]) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: TRACE, ...(errors ? { errors } : {}) }) });

interface State {
  capabilities: string[];
  provider: Record<string, unknown>;
  /** Replaces a save's answer once its grant is used up: by default the provider as sent, with a secret stored. */
  save: ((route: Route) => Promise<void>) | null;
  /** Whether a change needs a grant: the server's 403 fresh_assertion_required until the sheet is confirmed. */
  needsAssertion: boolean;
  granted: boolean;
}

/** The Admin API, for a Viewer of a Tenant with no provider unless a test says otherwise. */
async function answerApi(page: Page, initial: Partial<State> = {}) {
  const log: string[] = [];
  const headers: Record<string, string>[] = [];
  const bodies: Record<string, unknown>[] = [];
  const begins: unknown[] = [];
  const state: State = { capabilities: TENANT_VIEWER, provider: { configured: false }, save: null, needsAssertion: true, granted: false, ...initial };
  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      log.push(`${request.method()} ${pathname}`);
      if (request.method() !== 'GET') headers.push(request.headers());
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
      if (pathname === BEGIN && request.method() === 'POST') {
        begins.push(request.postDataJSON());
        return json(route, 200, {
          challenge: randomBytes(32).toString('base64url'),
          rpId: new URL(request.url()).hostname,
          timeout: 300000,
          userVerification: 'required',
          allowCredentials: [],
        });
      }
      if (pathname === COMPLETE && request.method() === 'POST') {
        state.granted = true;
        return route.fulfill({ status: 204 });
      }
      if (pathname === PROVIDER && request.method() === 'GET') return json(route, 200, state.provider);
      if (pathname === PROVIDER && (request.method() === 'PUT' || request.method() === 'DELETE')) {
        if (request.method() === 'PUT') bodies.push(request.postDataJSON() as Record<string, unknown>);
        // The checks use up the grant, or refuse with fresh_assertion_required.
        if (state.needsAssertion && !state.granted) return problem(route, 403, 'fresh_assertion_required');
        state.granted = false;
        if (request.method() === 'DELETE') {
          state.provider = { configured: false };
          return route.fulfill({ status: 204 });
        }
        if (state.save) return state.save(route);
        const sent = bodies.at(-1)!;
        state.provider = {
          configured: true,
          kind: sent.kind,
          settings: sent.settings,
          fromAddress: sent.fromAddress,
          ...(sent.fromName ? { fromName: sent.fromName } : {}),
          updatedAt: '2026-11-16T10:00:00.000Z',
          secretSet: sent.kind !== 'smtp' || Boolean((sent.settings as Record<string, unknown>).username),
        };
        return json(route, 200, state.provider);
      }
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
  const result = await new AxeBuilder({ page }).analyze();
  return result.violations.map((violation) => ({ id: violation.id, targets: violation.nodes.map((node) => node.target.join(' ')) }));
}

const heading = (page: Page) => page.getByRole('heading', { level: 1 });
const nav = (page: Page) => page.getByRole('navigation', { name: 'Main' });
const toast = (page: Page) => page.getByTestId('toast');
const field = (page: Page, name: string) => page.getByTestId(`email-provider-${name}`);
const save = (page: Page) => page.getByRole('button', { name: 'Save' });
const removeDialog = (page: Page) => page.getByRole('dialog', { name: 'Remove email provider?' });

/** Each kind's card, what is typed into its fields, the secret's label and the settings the save sends. */
const CARDS = [
  {
    kind: 'smtp',
    fill: { host: 'smtp.example.com', port: '2525', username: 'mailer' },
    select: { tls: 'implicit' },
    secret: 'Password',
    settings: { host: 'smtp.example.com', port: 2525, tls: 'implicit', username: 'mailer' },
  },
  { kind: 'sendgrid', fill: {}, select: { region: 'eu' }, secret: 'API key', settings: { region: 'eu' } },
  { kind: 'postmark', fill: { messageStream: 'outbound' }, select: {}, secret: 'Server token', settings: { messageStream: 'outbound' } },
  { kind: 'mailgun', fill: { domain: 'mg.example.com' }, select: { region: 'eu' }, secret: 'API key', settings: { domain: 'mg.example.com', region: 'eu' } },
  {
    kind: 'ses',
    fill: { region: 'eu-west-1', accessKeyId: 'AKIAIOSFODNN7EXAMPLE' },
    select: {},
    secret: 'Secret access key',
    settings: { region: 'eu-west-1', accessKeyId: 'AKIAIOSFODNN7EXAMPLE' },
  },
  {
    kind: 'custom_http',
    fill: { endpoint: 'https://mail.example.com/send', authHeaderName: 'X-Api-Key' },
    select: {},
    secret: 'Auth header value',
    settings: { endpoint: 'https://mail.example.com/send', authHeaderName: 'X-Api-Key' },
  },
] as const;

test.use({ viewport: { width: 1280, height: 900 } });
watchCsp(test);

test.describe('empty', () => {
  test('with no provider an Owner sees "No provider set" with Add, which opens the SMTP card', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER });

    await page.goto(PAGE);

    await expect(heading(page)).toHaveText('Email provider');
    await expect(page.getByText('How this tenant sends verification and password reset emails.')).toBeVisible();
    const empty = page.getByTestId('email-provider-empty');
    await expect(empty).toContainText('No provider set');
    await empty.getByRole('button', { name: 'Add' }).click();

    await expect(page.getByRole('group', { name: 'Provider' }).getByRole('radio')).toHaveCount(6);
    await expect(field(page, 'kind-smtp')).toBeChecked();
    await expect(field(page, 'port')).toHaveValue('587');
    await expect(field(page, 'tls')).toHaveValue('starttls');
    await expect(page.getByTestId('email-provider-secret')).toHaveValue('');
    expect(api.count(`GET ${PROVIDER}`)).toBe(1);
  });

  test('with no provider a Viewer sees "No provider set", no Add and Tenant Owner only', async ({ page }) => {
    await answerApi(page);

    await page.goto(PAGE);

    await expect(page.getByTestId('email-provider-empty')).toContainText('No provider set');
    await expect(page.getByRole('button', { name: 'Add' })).toHaveCount(0);
    await expect(page.getByTestId('email-provider-owner-only')).toHaveText('Tenant Owner only');
  });
});

test.describe('save', () => {
  for (const card of CARDS) {
    test(`an Owner saves a ${card.kind} provider: the sheet when the server asks, then the toast and the stored secret`, async ({ page, baseURL }) => {
      await authenticator(page, new URL(baseURL!).hostname);
      const api = await answerApi(page, { capabilities: TENANT_OWNER });

      await page.goto(PAGE);
      await page.getByRole('button', { name: 'Add' }).click();
      await field(page, `kind-${card.kind}`).check();
      for (const [name, value] of Object.entries(card.fill)) await field(page, name).fill(value);
      for (const [name, value] of Object.entries(card.select)) await field(page, name).selectOption(value);
      await page.getByLabel(card.secret, { exact: true }).fill('cnry-browser-secret');
      await field(page, 'from-address').fill('no-reply@example.com');
      await save(page).click();

      await expect(toast(page)).toHaveText('Email provider saved');
      await expect(page.getByTestId('email-provider-secret')).toHaveValue('');
      await expect(page.getByTestId('email-provider-form')).toContainText('Saved – enter a new value to replace it');

      // Sent twice: refused for want of a grant, then with it; the Tenant begin has no target.
      expect(api.bodies).toHaveLength(2);
      expect(api.bodies[1]).toEqual({ kind: card.kind, settings: card.settings, fromAddress: 'no-reply@example.com', secret: 'cnry-browser-secret' });
      expect(api.begins).toEqual([{ action: ACTION, target: null }]);
      const sent = api.headers.at(-1)!;
      expect(sent['x-gatekeep-csrf']).toBe(CSRF);
      expect(sent['x-gatekeep-tenant']).toBe(TENANT);
    });
  }

  test('a stored secret is kept for a sender change: the field says so, and a save with it empty sends none', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER, provider: SMTP, needsAssertion: false });

    await page.goto(PAGE);
    await expect(field(page, 'host')).toHaveValue('smtp.example.com');
    await expect(page.getByTestId('email-provider-form')).toContainText('Saved – enter a new value to replace it');
    await field(page, 'from-name').fill('Other');
    await save(page).click();

    await expect(toast(page)).toHaveText('Email provider saved');
    expect(api.bodies).toEqual([
      {
        kind: 'smtp',
        settings: { host: 'smtp.example.com', port: 587, tls: 'starttls', username: 'mailer' },
        fromAddress: 'no-reply@example.com',
        fromName: 'Other',
      },
    ]);
  });

  test('a changed host needs a new secret: refused here, with nothing sent', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER, provider: SMTP, needsAssertion: false });

    await page.goto(PAGE);
    await field(page, 'host').fill('smtp.other.example');
    await save(page).click();

    await expect(page.getByTestId('email-provider-form')).toContainText('Enter a value: a new provider, or changed settings, need a new one.');
    await expect(page.getByTestId('email-provider-secret')).toBeFocused();
    expect(api.bodies).toHaveLength(0);
  });

  test('a change of kind needs a new secret: refused here, with nothing sent', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER, provider: SMTP, needsAssertion: false });

    await page.goto(PAGE);
    await field(page, 'kind-sendgrid').check();
    await save(page).click();

    await expect(page.getByTestId('email-provider-form')).toContainText('Enter a value: a new provider, or changed settings, need a new one.');
    await expect(page.getByTestId('email-provider-secret')).toBeFocused();
    expect(api.bodies).toHaveLength(0);
  });

  test("the server's field errors show on their fields, the first focused, and nothing is saved", async ({ page }) => {
    await answerApi(page, {
      capabilities: TENANT_OWNER,
      provider: SMTP,
      needsAssertion: false,
      save: (route) => problem(route, 400, 'email_provider_invalid', [{ field: 'settings.host', index: null, reason: 'invalid' }]),
    });

    await page.goto(PAGE);
    await field(page, 'host').fill('10.0.0.1');
    await page.getByTestId('email-provider-secret').fill('cnry-browser-secret');
    await save(page).click();

    await expect(page.getByText('Use a DNS name or a public IP address.')).toBeVisible();
    await expect(field(page, 'host')).toBeFocused();
    await expect(field(page, 'host')).toHaveAttribute('aria-invalid', 'true');
    await expect(toast(page)).toHaveCount(0);
  });

  test('a failure is the bad banner with its reference, and what was typed stays', async ({ page }) => {
    await answerApi(page, { capabilities: TENANT_OWNER, provider: SMTP, needsAssertion: false, save: (route) => route.fulfill({ status: 503 }) });

    await page.goto(PAGE);
    await field(page, 'from-name').fill('Other');
    await save(page).click();

    await expect(page.getByTestId('email-provider-save-failed')).toContainText("Couldn't save the email provider. Nothing was changed.");
    await expect(field(page, 'from-name')).toHaveValue('Other');
  });
});

test.describe('read-only', () => {
  test('an Editor sees the provider read-only, Tenant Owner only, with no Save or Remove and no secret', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_EDITOR, provider: SMTP });

    await page.goto(PAGE);

    await expect(field(page, 'host')).toHaveValue('smtp.example.com');
    await expect(field(page, 'host')).toHaveAttribute('readonly', '');
    await expect(field(page, 'kind-smtp')).toBeDisabled();
    await expect(field(page, 'tls')).toBeDisabled();
    await expect(page.getByTestId('email-provider-secret')).toHaveValue('');
    await expect(page.getByTestId('email-provider-owner-only')).toHaveText('Tenant Owner only');
    await expect(page.getByRole('button', { name: /save|remove/i })).toHaveCount(0);
    expect(api.bodies).toHaveLength(0);
  });
});

test.describe('remove', () => {
  test('an Owner removes: the confirmation, the sheet inside it, then the toast and the empty state', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, { capabilities: TENANT_OWNER, provider: SMTP });

    await page.goto(PAGE);
    await page.getByRole('button', { name: 'Remove provider' }).click();
    await expect(removeDialog(page)).toContainText("Verification and password reset emails can't be sent until a provider is added again.");
    await removeDialog(page).getByRole('button', { name: 'Remove' }).click();

    await expect(toast(page)).toHaveText('Email provider removed');
    await expect(removeDialog(page)).toHaveCount(0);
    await expect(page.getByTestId('email-provider-empty')).toContainText('No provider set');
    expect(api.count(`DELETE ${PROVIDER}`)).toBe(2);
    expect(api.begins).toEqual([{ action: ACTION, target: null }]);
  });

  test('Cancel sends nothing', async ({ page }) => {
    const api = await answerApi(page, { capabilities: TENANT_OWNER, provider: SMTP });

    await page.goto(PAGE);
    await page.getByRole('button', { name: 'Remove provider' }).click();
    await removeDialog(page).getByRole('button', { name: 'Cancel' }).click();

    await expect(removeDialog(page)).toHaveCount(0);
    expect(api.count(`DELETE ${PROVIDER}`)).toBe(0);
  });
});

test.describe('sidebar', () => {
  test('Email provider sits in the Branding group, current on its page', async ({ page }) => {
    await answerApi(page);

    await page.goto(PAGE);

    const group = nav(page).getByRole('button', { name: 'Branding' });
    await expect(group).toHaveAttribute('aria-expanded', 'true');
    const link = nav(page).getByRole('link', { name: 'Email provider' });
    await expect(link).toHaveAttribute('href', PAGE);
    await expect(link).toHaveAttribute('aria-current', 'page');
  });
});

for (const scheme of ['light', 'dark'] as const) {
  for (const width of [1100, 768]) {
    test(`axe finds no violations at ${width}px, ${scheme}: empty, the form for an Owner and an Editor, an error and the remove modal`, async ({
      page,
    }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      const api = await answerApi(page, { capabilities: TENANT_OWNER, needsAssertion: false });

      await page.goto(PAGE);
      await expect(page.getByTestId('email-provider-empty')).toBeVisible();
      expect(await axe(page), 'empty').toEqual([]);

      await page.getByRole('button', { name: 'Add' }).click();
      await save(page).click();
      await expect(field(page, 'host')).toHaveAttribute('aria-invalid', 'true');
      expect(await axe(page), 'errors').toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

      api.state.provider = SMTP;
      await page.reload();
      await expect(field(page, 'host')).toHaveValue('smtp.example.com');
      expect(await axe(page), 'owner').toEqual([]);

      await page.getByRole('button', { name: 'Remove provider' }).click();
      await expect(removeDialog(page)).toBeVisible();
      expect(await axe(page), 'remove modal').toEqual([]);
      await removeDialog(page).getByRole('button', { name: 'Cancel' }).click();

      api.state.capabilities = TENANT_EDITOR;
      await page.reload();
      await expect(page.getByTestId('email-provider-owner-only')).toBeVisible();
      expect(await axe(page), 'editor').toEqual([]);
    });
  }
}
