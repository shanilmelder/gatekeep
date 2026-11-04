// Story 1.23: Admin sign-in and sign-out in the built Admin Dashboard, served by the built
// Host.Admin (admin-host.mjs) under its real CSP, from localhost, since WebAuthn takes no IP
// address as an RP ID. The Admin API is answered by route interception, as in
// credential-setup.spec.ts; the browser's own passkey sheet is answered by a Chromium virtual
// authenticator over CDP, holding a resident credential added with WebAuthn.addCredential. The
// server's verification is the Isolation tests' (tests/Isolation/Admins/AdminSignInTests.cs).

import AxeBuilder from '@axe-core/playwright';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, test, type CDPSession, type Page, type Request, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

// Every test, not only those that check it in place, fails on a CSP violation (Story 1.25).
watchCsp(test);

const BEGIN = '/api/v1/deployment/signin';
const COMPLETE = '/api/v1/deployment/signin/complete';
const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const CSRF = 'S'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000123';
const REFUSED = "That credential wasn't recognised.";

const path = (pathname: string) => (url: URL) => url.pathname === pathname;

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

/**
 * A virtual CTAP2 authenticator that verifies the user and presents automatically, holding one
 * resident credential for this origin's RP ID: the Admin's, with its user handle.
 */
async function authenticator(page: Page, rpId: string, { withCredential = true } = {}) {
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
  const credentialId = randomBytes(32);
  const userHandle = randomBytes(64);
  if (withCredential) {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    await cdp.send('WebAuthn.addCredential', {
      authenticatorId,
      credential: {
        credentialId: credentialId.toString('base64'),
        isResidentCredential: true,
        rpId,
        privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
        userHandle: userHandle.toString('base64'),
        signCount: 0,
      },
    });
  }
  return { cdp, authenticatorId, credentialId: credentialId.toString('base64url'), userHandle: userHandle.toString('base64url') };
}

interface ApiOptions {
  /** Replaces the begin's answer. */
  beginAnswer?: (route: Route) => Promise<void>;
  /** Replaces the complete's answer. */
  completeAnswer?: (route: Route) => Promise<void>;
  /** Replaces the sign-out's answer. */
  signOutAnswer?: (route: Route) => Promise<void>;
  /** The RP ID the begin names, when not this origin's. */
  rpId?: string;
  /** Whether the signed-in Admin has their two credentials: true unless set. */
  setupComplete?: boolean;
}

/**
 * The Admin API's sign-in, as the server answers it: options for this origin's RP ID with no
 * credential listed, a complete that starts a Session, the Session endpoint for a signed-in
 * Admin past setup, and a sign-out.
 */
async function answerApi(page: Page, baseURL: string, { beginAnswer, completeAnswer, signOutAnswer, rpId, setupComplete = true }: ApiOptions = {}) {
  const begins: Request[] = [];
  const completes: Request[] = [];
  const signOuts: Request[] = [];
  const challenges: string[] = [];
  const state = { signedIn: false };
  await answerCapabilities(page);

  await page.route(path(BEGIN), (route) => {
    begins.push(route.request());
    if (beginAnswer) return beginAnswer(route);
    const challenge = randomBytes(32).toString('base64url');
    challenges.push(challenge);
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ challenge, rpId: rpId ?? new URL(baseURL).hostname, timeout: 300000, userVerification: 'required', allowCredentials: [] }),
    });
  });

  await page.route(path(COMPLETE), async (route) => {
    completes.push(route.request());
    if (completeAnswer) return completeAnswer(route);
    state.signedIn = true;
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ adminId: ADMIN_ID, csrfToken: CSRF, setupComplete }) });
  });

  await page.route(path(SESSION), async (route) => {
    if (route.request().method() === 'DELETE') {
      signOuts.push(route.request());
      if (signOutAnswer) return signOutAnswer(route);
      state.signedIn = false;
      return route.fulfill({ status: 204 });
    }
    if (!state.signedIn) return route.fulfill({ status: 401 });
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ adminId: ADMIN_ID, kind: 'full', deploymentOwner: true, setupComplete, credentials: setupComplete ? 2 : 1, csrfToken: CSRF }),
    });
  });

  return { begins, completes, signOuts, challenges, state };
}

const problem = (status: number, code: string, traceId: string) => (route: Route) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId }) });

const signInButton = (page: Page) => page.getByRole('button', { name: 'Sign in' });

/** Sign out, in the shell's avatar menu since Story 1.25. */
async function signOut(page: Page) {
  await page.getByRole('button', { name: 'Account' }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
}

/** The shell's Deployment capabilities read (Story 1.25), for a signed-in Admin. */
const answerCapabilities = (page: Page) =>
  page.route(path(CAPABILITIES), (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ capabilities: [] }) }),
  );

async function axe(page: Page) {
  await page.evaluate(() => Promise.allSettled(document.getAnimations().map((animation) => animation.finished)).then(() => undefined));
  return (await new AxeBuilder({ page }).analyze()).violations.map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
}

test('the screen asks for no email, password or username, only the passkey sheet', async ({ page }) => {
  const noViolations = await watchViolations(page);

  const response = await page.goto('/signin');

  expect(response!.headers()['content-security-policy']).toContain("default-src 'none'");
  const card = page.getByTestId('signin');
  await expect(card.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();
  await expect(card.getByText('Sign in with your security key or passkey.')).toBeVisible();
  await expect(signInButton(page)).toBeVisible();
  await expect(page.locator('input, textarea, select')).toHaveCount(0);
  await expect(page.getByRole('textbox')).toHaveCount(0);
  await expect(page.getByRole('link')).toHaveCount(0);
  await noViolations();
});

test('a sign-in sends the assertion for this origin and goes to the root, whose Sign out returns here', async ({ page, baseURL }) => {
  const noViolations = await watchViolations(page);
  const { credentialId, userHandle } = await authenticator(page, new URL(baseURL!).hostname);
  const api = await answerApi(page, baseURL!);

  await page.goto('/signin');
  await signInButton(page).click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole('heading', { level: 1, name: 'Admin Dashboard' })).toBeVisible();

  // Begin needs no Session or CSRF token; the complete is the credential the browser chose
  // itself, as none was listed: for this origin and the begin's challenge, with its user handle.
  expect(api.begins).toHaveLength(1);
  expect(await api.begins[0]!.headerValue('x-gatekeep-csrf')).toBeNull();
  expect(api.completes).toHaveLength(1);
  const body = api.completes[0]!.postDataJSON() as {
    id: string;
    rawId: string;
    type: string;
    response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle: string | null };
  };
  expect(body.type).toBe('public-key');
  expect(body.rawId).toBe(credentialId);
  expect(body.id).toBe(body.rawId);
  expect(body.response.userHandle).toBe(userHandle);
  expect(body.response.signature.length).toBeGreaterThan(0);
  const clientData = JSON.parse(Buffer.from(body.response.clientDataJSON, 'base64url').toString('utf8')) as Record<string, unknown>;
  expect(clientData.type).toBe('webauthn.get');
  expect(clientData.origin).toBe(new URL(baseURL!).origin);
  expect(clientData.challenge).toBe(api.challenges[0]);
  expect(clientData.crossOrigin ?? false).toBe(false);
  // UP and UV are both set in the authenticator data's flags.
  expect(Buffer.from(body.response.authenticatorData, 'base64url')[32]! & 0x05).toBe(0x05);

  // Sign out carries the Session's CSRF token, and lands back on sign-in.
  await signOut(page);
  await expect(page).toHaveURL(/\/signin$/);
  await expect(signInButton(page)).toBeVisible();
  expect(api.signOuts).toHaveLength(1);
  expect(await api.signOuts[0]!.headerValue('x-gatekeep-csrf')).toBe(CSRF);
  await noViolations();
});

test('a cancelled sheet leaves the page as it was, with no error, and Sign in works again', async ({ page, baseURL }) => {
  const { cdp, authenticatorId } = await authenticator(page, new URL(baseURL!).hostname);
  const api = await answerApi(page, baseURL!);

  await page.goto('/signin');
  // An authenticator that can't verify the user ends the ceremony with NotAllowedError, as a cancel does.
  await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: false });
  await signInButton(page).click();

  await expect.poll(() => api.begins.length).toBe(1);
  await expect(signInButton(page)).not.toHaveAttribute('aria-busy', 'true');
  await expect(page.getByTestId('signin-refused')).toHaveCount(0);
  await expect(page.getByTestId('signin-error')).toHaveCount(0);
  await expect(page.getByRole('alert')).toHaveCount(0);
  expect(api.completes).toHaveLength(0);

  await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: true });
  await signInButton(page).click();
  await expect(page).toHaveURL(/\/$/);
});

test('a refused sign-in keeps the screen with one banner that says nothing more, and Sign in works again', async ({ page, baseURL }) => {
  const noViolations = await watchViolations(page);
  await authenticator(page, new URL(baseURL!).hostname);
  let refuse = true;
  const api: Awaited<ReturnType<typeof answerApi>> = await answerApi(page, baseURL!, {
    completeAnswer: async (route) => {
      if (refuse) return problem(400, 'signin_refused', '4bf92f3577b34da6a3ce929d0e0e4736')(route);
      api.state.signedIn = true;
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ adminId: ADMIN_ID, csrfToken: CSRF, setupComplete: true }) });
    },
  });

  await page.goto('/signin');
  await signInButton(page).click();

  const banner = page.getByTestId('signin-refused');
  await expect(banner).toHaveText(REFUSED);
  await expect(page.getByTestId('signin')).toBeVisible();
  await expect(page.getByText('signin_refused')).toHaveCount(0);
  await expect(signInButton(page)).not.toHaveAttribute('aria-busy', 'true');

  refuse = false;
  await signInButton(page).click();
  await expect(page).toHaveURL(/\/$/);
  expect(api.completes).toHaveLength(2);
  await noViolations();
});

test('a WebAuthn error other than a cancel shows the same banner and sends no complete', async ({ page, baseURL }) => {
  await authenticator(page, new URL(baseURL!).hostname);
  // An RP ID this origin can't claim: the browser refuses it with SecurityError.
  const api = await answerApi(page, baseURL!, { rpId: 'elsewhere.example' });

  await page.goto('/signin');
  await signInButton(page).click();

  await expect(page.getByTestId('signin-refused')).toHaveText(REFUSED);
  await expect(signInButton(page)).not.toHaveAttribute('aria-busy', 'true');
  expect(api.begins).toHaveLength(1);
  expect(api.completes).toHaveLength(0);
});

const failures: { name: string; status: number | 'network'; at: 'begin' | 'complete'; code: string; traceId?: string }[] = [
  { name: 'a rate-limited begin', status: 429, at: 'begin', code: 'rate_limited', traceId: '0af7651916cd43dd8448eb211c80319c' },
  { name: 'a rate-limited complete', status: 429, at: 'complete', code: 'rate_limited', traceId: '0af7651916cd43dd8448eb211c80319d' },
  { name: 'an unavailable begin', status: 503, at: 'begin', code: 'unavailable' },
  { name: 'an unavailable complete', status: 503, at: 'complete', code: 'unavailable' },
  { name: 'a refused Origin', status: 403, at: 'begin', code: 'origin_refused' },
  { name: 'sign-in before bootstrap', status: 404, at: 'begin', code: 'signin_unavailable' },
  { name: 'an unexpected 401', status: 401, at: 'complete', code: 'unavailable' },
  { name: 'a lost connection', status: 'network', at: 'begin', code: 'unavailable' },
];

for (const failure of failures) {
  test(`${failure.name} shows Generic error with ${failure.code}, whose action comes back to sign in`, async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const answer = (route: Route) => {
      if (failure.status === 'network') return route.abort('connectionfailed');
      if (failure.traceId) return problem(failure.status, failure.code, failure.traceId)(route);
      return route.fulfill({ status: failure.status });
    };
    await answerApi(page, baseURL!, failure.at === 'begin' ? { beginAnswer: answer } : { completeAnswer: answer });

    await page.goto('/signin');
    await signInButton(page).click();

    const error = page.getByTestId('signin-error');
    await expect(error.getByRole('heading', { level: 1, name: 'Something went wrong' })).toBeVisible();
    await expect(error.locator('[data-reference="code"]')).toHaveText(failure.code);
    if (failure.traceId) await expect(error.locator('[data-reference="trace"]')).toHaveText(failure.traceId);

    const back = error.getByRole('link', { name: 'Back to Gatekeep' });
    await expect(back).toHaveAttribute('href', '/signin');
    await back.click();
    await expect(signInButton(page)).toBeVisible();
  });
}

test('an Admin still without two credentials who signs in goes on to credential setup', async ({ page, baseURL }) => {
  await authenticator(page, new URL(baseURL!).hostname);
  await answerApi(page, baseURL!, { setupComplete: false });

  await page.goto('/signin');
  await signInButton(page).click();

  await expect(page).toHaveURL(/\/setup\/credentials$/);
  await expect(page.getByTestId('credential-setup-step')).toHaveText('Step 2 of 2');
  await expect(page.getByRole('button', { name: 'Account' })).toHaveCount(0);
});

test('a begin that answers 2xx with no options shows Generic error, and sends no complete', async ({ page, baseURL }) => {
  await authenticator(page, new URL(baseURL!).hostname);
  const api = await answerApi(page, baseURL!, { beginAnswer: (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '' }) });

  await page.goto('/signin');
  await signInButton(page).click();

  const error = page.getByTestId('signin-error');
  await expect(error.locator('[data-reference="code"]')).toHaveText('unavailable');
  expect(api.completes).toHaveLength(0);
});

for (const answer of [
  { name: 'a 503', fulfill: (route: Route) => route.fulfill({ status: 503 }), code: 'unavailable' },
  { name: 'a 429', fulfill: problem(429, 'rate_limited', '0af7651916cd43dd8448eb211c80319e'), code: 'rate_limited' },
  { name: 'a 2xx with no CSRF token', fulfill: (route: Route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }), code: 'unavailable' },
  { name: 'a lost connection', fulfill: (route: Route) => route.abort('connectionfailed'), code: 'unavailable' },
]) {
  test("the root's Session read failing with " + answer.name + ' shows Generic error with no Sign out, and its action loads the root again', async ({ page }) => {
    let failing = true;
    await answerCapabilities(page);
    await page.route(path(SESSION), (route) =>
      failing
        ? answer.fulfill(route)
        : route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ adminId: ADMIN_ID, kind: 'full', deploymentOwner: true, setupComplete: true, credentials: 2, csrfToken: CSRF }),
          }),
    );

    await page.goto('/');

    const error = page.getByTestId('root-error');
    await expect(error.getByRole('heading', { level: 1, name: 'Something went wrong' })).toBeVisible();
    await expect(error.locator('[data-reference="code"]')).toHaveText(answer.code);
    await expect(page.getByRole('button', { name: 'Account' })).toHaveCount(0);

    failing = false;
    const back = error.getByRole('link', { name: 'Back to Gatekeep' });
    await expect(back).toHaveAttribute('href', '/');
    await back.click();
    await page.getByRole('button', { name: 'Account' }).click();
    await expect(page.getByRole('menuitem', { name: 'Sign out' })).toBeVisible();
  });
}

test('the root with no Session goes to sign in', async ({ page, baseURL }) => {
  await answerApi(page, baseURL!);

  await page.goto('/');

  await expect(page).toHaveURL(/\/signin$/);
  await expect(signInButton(page)).toBeVisible();
});

test('a refused sign-out keeps the Admin on the root with a banner, and a gone Session goes to sign in', async ({ page, baseURL }) => {
  await authenticator(page, new URL(baseURL!).hostname);
  let status = 403;
  const api = await answerApi(page, baseURL!, { signOutAnswer: (route) => route.fulfill({ status }) });

  await page.goto('/signin');
  await signInButton(page).click();
  await expect(page).toHaveURL(/\/$/);

  await signOut(page);
  await expect(page.getByTestId('signout-failed')).toBeVisible();
  await expect(page).toHaveURL(/\/$/);

  status = 401;
  await signOut(page);
  await expect(page).toHaveURL(/\/signin$/);
  expect(api.signOuts).toHaveLength(2);
});

for (const scheme of ['light', 'dark'] as const) {
  test(`axe finds no violations on sign in, at rest and refused, ${scheme}`, async ({ page, baseURL }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await authenticator(page, new URL(baseURL!).hostname);
    await answerApi(page, baseURL!, { completeAnswer: problem(400, 'signin_refused', '4bf92f3577b34da6a3ce929d0e0e4736') });

    await page.goto('/signin');
    await expect(signInButton(page)).toBeVisible();
    expect(await axe(page), 'at rest').toEqual([]);

    await signInButton(page).click();
    await expect(page.getByTestId('signin-refused')).toBeVisible();
    expect(await axe(page), 'refused').toEqual([]);
  });
}
