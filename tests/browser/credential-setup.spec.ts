// Story 1.22: Admin credential setup in the built Admin Dashboard, served by the built Host.Admin
// (admin-host.mjs) under its real CSP, from localhost, since WebAuthn takes no IP address as an RP
// ID. The Admin API is answered by route interception, as in bootstrap.spec.ts; the browser's own
// passkey sheet is answered by a Chromium virtual authenticator over CDP. The server's
// verification is the Isolation tests' (tests/Isolation/Admins/CredentialRegistrationTests.cs).

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type CDPSession, type Page, type Request, type Route } from '@playwright/test';

const SESSION = '/api/v1/deployment/session';
const BEGIN = '/api/v1/deployment/credentials/registration';
const COMPLETE = '/api/v1/deployment/credentials/registration/complete';
const CSRF = 'C'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000122';

const path = (pathname: string) => (url: URL) => url.pathname === pathname;

const base64Url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const random = (length: number) => base64Url(crypto.getRandomValues(new Uint8Array(length)));

/** Every CSP violation from document creation on. */
async function watchViolations(page: Page) {
  const consoleViolations: string[] = [];
  page.on('console', (message) => {
    if (/content security policy|refused to/i.test(message.text())) consoleViolations.push(message.text());
  });
  await page.addInitScript(() => {
    const violations: string[] = [];
    (window as unknown as { __gkViolations: string[] }).__gkViolations = violations;
    document.addEventListener('securitypolicyviolation', (event) => violations.push(`${event.effectiveDirective} ${event.blockedURI}`));
  });
  return async () => {
    expect(await page.evaluate(() => (window as unknown as { __gkViolations: string[] }).__gkViolations)).toEqual([]);
    expect(consoleViolations).toEqual([]);
  };
}

/** A virtual CTAP2 authenticator that verifies the user and presents automatically. */
async function authenticator(page: Page) {
  const cdp: CDPSession = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const add = async () =>
    (
      await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'usb',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      })
    ).authenticatorId;
  return { cdp, add };
}

interface ApiOptions {
  /** Credentials already registered. */
  credentials?: number;
  /** The Session's kind, when not what the count implies. */
  kind?: 'setup' | 'full';
  /** Replaces the begin's answer. */
  beginAnswer?: (route: Route) => Promise<void>;
  /** Replaces the complete's answer. */
  completeAnswer?: (route: Route) => Promise<void>;
}

/**
 * The Admin API's credential setup, as the server answers it: the Session with `credentials`
 * registered, options for this origin's RP ID that exclude what's registered with its
 * transports, and a complete that counts.
 */
async function answerApi(page: Page, baseURL: string, { credentials = 0, kind, beginAnswer, completeAnswer }: ApiOptions = {}) {
  const state = { credentials, ids: [] as string[] };
  const begins: Request[] = [];
  const completes: Request[] = [];
  const challenges: string[] = [];

  await page.route(path(SESSION), (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        adminId: ADMIN_ID,
        kind: kind ?? (state.credentials >= 2 ? 'full' : 'setup'),
        deploymentOwner: true,
        setupComplete: state.credentials >= 2,
        credentials: state.credentials,
        csrfToken: CSRF,
      }),
    }),
  );

  await page.route(path(BEGIN), (route) => {
    begins.push(route.request());
    if (beginAnswer) return beginAnswer(route);
    const challenge = random(32);
    challenges.push(challenge);
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        rp: { id: new URL(baseURL).hostname, name: 'Gatekeep' },
        user: { id: random(64), name: 'Deployment Owner', displayName: 'Deployment Owner' },
        challenge,
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        timeout: 300000,
        attestation: 'none',
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
        excludeCredentials: state.ids.map((id) => ({ type: 'public-key', id, transports: ['usb'] })),
      }),
    });
  });

  await page.route(path(COMPLETE), async (route) => {
    completes.push(route.request());
    if (completeAnswer) return completeAnswer(route);
    state.credentials += 1;
    state.ids.push((route.request().postDataJSON() as { rawId: string }).rawId);
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ credentials: state.credentials, setupComplete: state.credentials >= 2 }),
    });
  });

  return { begins, completes, challenges, state };
}

const registerButton = (page: Page) => page.getByRole('button', { name: 'Register passkey' });
const step = (page: Page) => page.getByTestId('credential-setup-step');

async function axe(page: Page) {
  await page.evaluate(() => Promise.allSettled(document.getAnimations().map((animation) => animation.finished)).then(() => undefined));
  return (await new AxeBuilder({ page }).analyze()).violations.map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
}

test('two registrations, step 1 of 2 then 2 of 2, end at the landing page', async ({ page, baseURL }) => {
  const noViolations = await watchViolations(page);
  const { cdp, add } = await authenticator(page);
  const first = await add();
  const api = await answerApi(page, baseURL!);

  const response = await page.goto('/setup/credentials');
  expect(response!.headers()['content-security-policy']).toContain("default-src 'none'");
  await expect(page.getByRole('heading', { level: 1, name: 'Set up your credentials' })).toBeVisible();
  await expect(step(page)).toHaveText('Step 1 of 2');
  await expect(page.getByRole('link')).toHaveCount(0);

  await registerButton(page).click();
  await expect(step(page)).toHaveText('Step 2 of 2');

  // The begin carries the CSRF token; the complete is the credential the browser made, for this
  // origin and the begin's challenge, and not cross-origin.
  expect(api.begins).toHaveLength(1);
  expect(await api.begins[0]!.headerValue('x-gatekeep-csrf')).toBe(CSRF);
  expect(api.completes).toHaveLength(1);
  expect(await api.completes[0]!.headerValue('x-gatekeep-csrf')).toBe(CSRF);
  const body = api.completes[0]!.postDataJSON() as {
    id: string;
    rawId: string;
    type: string;
    response: { clientDataJSON: string; attestationObject: string; transports: string[] };
  };
  expect(body.type).toBe('public-key');
  expect(body.id).toBe(body.rawId);
  expect(body.response.attestationObject.length).toBeGreaterThan(0);
  const clientData = JSON.parse(Buffer.from(body.response.clientDataJSON, 'base64url').toString('utf8')) as Record<string, unknown>;
  expect(clientData.type).toBe('webauthn.create');
  expect(clientData.origin).toBe(new URL(baseURL!).origin);
  expect(clientData.challenge).toBe(api.challenges[0]);
  expect(clientData.crossOrigin ?? false).toBe(false);

  // A second authenticator, as the first's credential is excluded.
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: first });
  await add();
  await registerButton(page).click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText('Admin Dashboard')).toBeVisible();
  expect(api.completes).toHaveLength(2);
  expect((api.completes[1]!.postDataJSON() as { rawId: string }).rawId).not.toBe(body.rawId);
  await noViolations();
});

test('a cancelled ceremony leaves the step as it was, with no error, and Register works again', async ({ page, baseURL }) => {
  const { cdp, add } = await authenticator(page);
  const id = await add();
  const api = await answerApi(page, baseURL!);

  await page.goto('/setup/credentials');
  await expect(step(page)).toHaveText('Step 1 of 2');

  // An authenticator that can't verify the user ends the ceremony with NotAllowedError, as a cancel does.
  await cdp.send('WebAuthn.setUserVerified', { authenticatorId: id, isUserVerified: false });
  await registerButton(page).click();

  await expect.poll(() => api.begins.length).toBe(1);
  await expect(registerButton(page)).not.toHaveAttribute('aria-busy', 'true');
  await expect(step(page)).toHaveText('Step 1 of 2');
  await expect(page.getByTestId('credential-setup-error')).toHaveCount(0);
  await expect(page.getByRole('alert')).toHaveCount(0);
  expect(api.completes).toHaveLength(0);

  await cdp.send('WebAuthn.setUserVerified', { authenticatorId: id, isUserVerified: true });
  await registerButton(page).click();

  await expect(step(page)).toHaveText('Step 2 of 2');
  expect(api.completes).toHaveLength(1);
});

test('a refused registration shows Generic error with its code and trace ID, and its action returns to try again', async ({ page, baseURL }) => {
  const noViolations = await watchViolations(page);
  const { add } = await authenticator(page);
  await add();
  const traceId = '4bf92f3577b34da6a3ce929d0e0e4736';
  await answerApi(page, baseURL!, {
    completeAnswer: (route) =>
      route.fulfill({ status: 400, contentType: 'application/problem+json', body: JSON.stringify({ code: 'credential_refused', traceId }) }),
  });

  await page.goto('/setup/credentials');
  await registerButton(page).click();

  const error = page.getByTestId('credential-setup-error');
  await expect(error.getByRole('heading', { level: 1, name: 'Something went wrong' })).toBeVisible();
  await expect(error.locator('[data-reference="code"]')).toHaveText('credential_refused');
  await expect(error.locator('[data-reference="trace"]')).toHaveText(traceId);

  const back = error.getByRole('link', { name: 'Back to Gatekeep' });
  await expect(back).toHaveAttribute('href', '/setup/credentials');
  await back.click();
  await expect(step(page)).toHaveText('Step 1 of 2');
  await expect(registerButton(page)).toBeVisible();
  await noViolations();
});

test('setup can not be left: the root sends an Admin with one credential back to step 2 of 2', async ({ page, baseURL }) => {
  const sessions: Request[] = [];
  page.on('request', (request) => {
    if (new URL(request.url()).pathname === SESSION) sessions.push(request);
  });
  await answerApi(page, baseURL!, { credentials: 1 });

  await page.goto('/');

  await expect(page).toHaveURL(/\/setup\/credentials$/);
  await expect(step(page)).toHaveText('Step 2 of 2');
  await expect(page.getByRole('link')).toHaveCount(0);
  expect(sessions.length).toBeGreaterThanOrEqual(1);
});

test('an Admin whose setup is complete is sent from credential setup to the landing page', async ({ page, baseURL }) => {
  await answerApi(page, baseURL!, { credentials: 2 });

  await page.goto('/setup/credentials');

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByTestId('credential-setup')).toHaveCount(0);
});

test('a full Session of an Admin with one credential is sent from the root back to step 2 of 2', async ({ page, baseURL }) => {
  await answerApi(page, baseURL!, { credentials: 1, kind: 'full' });

  await page.goto('/');

  await expect(page).toHaveURL(/\/setup\/credentials$/);
  await expect(step(page)).toHaveText('Step 2 of 2');
});

test('the same authenticator a second time shows how to go on, and sends no complete', async ({ page, baseURL }) => {
  const { add } = await authenticator(page);
  await add();
  const api = await answerApi(page, baseURL!);

  await page.goto('/setup/credentials');
  await registerButton(page).click();
  await expect(step(page)).toHaveText('Step 2 of 2');
  expect(api.completes).toHaveLength(1);

  // The begin excludes the first credential, which this authenticator holds: InvalidStateError.
  await registerButton(page).click();

  const notice = page.getByTestId('credential-setup-registered');
  await expect(notice).toHaveText('This passkey or security key is already registered. Use a different security key or device.');
  await expect(step(page)).toHaveText('Step 2 of 2');
  await expect(registerButton(page)).not.toHaveAttribute('aria-busy', 'true');
  await expect(page.getByTestId('credential-setup-error')).toHaveCount(0);
  expect(api.begins).toHaveLength(2);
  expect(api.completes).toHaveLength(1);
});

test('a 401 from the complete goes to /bootstrap', async ({ page, baseURL }) => {
  const { add } = await authenticator(page);
  await add();
  await answerApi(page, baseURL!, { completeAnswer: (route) => route.fulfill({ status: 401 }) });
  await page.route((url) => url.pathname === '/bootstrap', (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<p>bootstrap</p>' }));

  await page.goto('/setup/credentials');
  await registerButton(page).click();

  await expect(page).toHaveURL(/\/bootstrap$/);
});

test('a rate-limited begin shows Generic error with rate_limited and sends no complete', async ({ page, baseURL }) => {
  const { add } = await authenticator(page);
  await add();
  const traceId = '0af7651916cd43dd8448eb211c80319c';
  const api = await answerApi(page, baseURL!, {
    beginAnswer: (route) =>
      route.fulfill({
        status: 429,
        contentType: 'application/problem+json',
        headers: { 'Retry-After': '600' },
        body: JSON.stringify({ code: 'rate_limited', traceId }),
      }),
  });

  await page.goto('/setup/credentials');
  await registerButton(page).click();

  const error = page.getByTestId('credential-setup-error');
  await expect(error.locator('[data-reference="code"]')).toHaveText('rate_limited');
  await expect(error.locator('[data-reference="trace"]')).toHaveText(traceId);
  expect(api.completes).toHaveLength(0);
});

test('a 403 from the begin, setup finished elsewhere, goes to the landing page', async ({ page, baseURL }) => {
  // Finished elsewhere: the Session now says so too, so the landing page keeps the Admin.
  const api: Awaited<ReturnType<typeof answerApi>> = await answerApi(page, baseURL!, {
    beginAnswer: (route) => {
      api.state.credentials = 2;
      return route.fulfill({ status: 403 });
    },
  });

  await page.goto('/setup/credentials');
  await registerButton(page).click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText('Admin Dashboard')).toBeVisible();
});

for (const scheme of ['light', 'dark'] as const) {
  test(`axe finds no violations on credential setup's two steps, ${scheme}`, async ({ page, baseURL }) => {
    await page.emulateMedia({ colorScheme: scheme });
    const { add } = await authenticator(page);
    await add();
    await answerApi(page, baseURL!);

    await page.goto('/setup/credentials');
    await expect(step(page)).toHaveText('Step 1 of 2');
    expect(await axe(page), 'step 1').toEqual([]);

    await registerButton(page).click();
    await expect(step(page)).toHaveText('Step 2 of 2');
    expect(await axe(page), 'step 2').toEqual([]);
  });
}
