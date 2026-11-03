// Story 1.21: the Bootstrap screen in the built Admin Dashboard, served by the built Host.Admin
// (admin-host.mjs) under its real CSP, with the Admin API answered by route interception. That
// host has no database, so it can't tell whether bootstrap is open: the /bootstrap document is
// the host's own index.html, fetched from it with its own headers. The server-side checks are
// the Isolation tests' (tests/Isolation/Admins).

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Request, type Route } from '@playwright/test';

const CLAIM = '/api/v1/deployment/bootstrap';
const SESSION = '/api/v1/deployment/session';
const TOKEN = 'a'.repeat(32) + '0123456789abcdef'.repeat(2);
const CSRF = 'C'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000121';

const path = (pathname: string) => (url: URL) => url.pathname === pathname;

/** Every CSP violation from document creation on: init scripts run outside the page's CSP. */
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

/** The /bootstrap document, as the host serves it while bootstrap is open. */
async function servePage(page: Page, baseURL: string) {
  await page.route(path('/bootstrap'), async (route) => {
    if (route.request().resourceType() !== 'document') return route.fallback();
    const response = await route.fetch({ url: new URL('/', baseURL).toString() });
    await route.fulfill({ response });
  });
}

/** Answers the claim with `answer`, recording each claim request. */
async function answerClaim(page: Page, answer: (route: Route) => Promise<void>) {
  const requests: Request[] = [];
  await page.route(path(CLAIM), async (route) => {
    requests.push(route.request());
    await answer(route);
  });
  return requests;
}

const created = (route: Route) =>
  route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ csrfToken: CSRF, adminId: ADMIN_ID }) });

const problem = (status: number, code: string, traceId: string) => (route: Route) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId }) });

/**
 * Answers the Session endpoint as a setup Session, with the claim's CSRF token: the token is
 * derived from the Session ID, so the server returns the same one every time. Or with `status`
 * and no body, as a 401.
 */
async function answerSession(page: Page, status = 200) {
  const requests: Request[] = [];
  await page.route(path(SESSION), async (route) => {
    requests.push(route.request());
    if (status !== 200) return route.fulfill({ status });
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ adminId: ADMIN_ID, kind: 'setup', deploymentOwner: true, setupComplete: false, credentials: 0, csrfToken: CSRF }),
    });
  });
  return requests;
}

const tokenField = (page: Page) => page.getByLabel('One-time token');
const claimButton = (page: Page) => page.getByRole('button', { name: 'Claim' });

async function axe(page: Page) {
  await page.evaluate(() => Promise.allSettled(document.getAnimations().map((animation) => animation.finished)).then(() => undefined));
  return (await new AxeBuilder({ page }).analyze()).violations.map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
}

test('a pasted token is trimmed, claimed, and leads to credential setup with the CSRF token in memory only', async ({ page, baseURL }) => {
  const noViolations = await watchViolations(page);
  await servePage(page, baseURL!);
  const claims = await answerClaim(page, created);
  const sessions = await answerSession(page);

  const response = await page.goto('/bootstrap');
  expect(response!.status()).toBe(200);
  expect(response!.headers()['content-security-policy']).toContain("default-src 'none'");

  await expect(page.getByRole('heading', { level: 1, name: 'Claim this Deployment' })).toBeVisible();
  await expect(tokenField(page)).toHaveAttribute('autocomplete', 'off');
  await tokenField(page).focus();
  await page.keyboard.insertText(`  ${TOKEN}\n `);
  await claimButton(page).click();

  await expect(page).toHaveURL(/\/setup\/credentials$/);
  await expect(page.getByTestId('credential-setup')).toBeVisible();
  await expect(page.getByRole('heading', { level: 1, name: 'Set up your credentials' })).toBeVisible();

  expect(claims).toHaveLength(1);
  expect(claims[0]!.method()).toBe('POST');
  expect(claims[0]!.postDataJSON()).toEqual({ token: TOKEN });
  expect(await claims[0]!.headerValue('x-gatekeep-csrf')).toBeNull();

  // Credential setup asks for the Session, with no CSRF header: it's a GET.
  await expect.poll(() => sessions.length).toBe(1);
  expect(await sessions[0]!.headerValue('x-gatekeep-csrf')).toBeNull();

  // The tokens are nowhere but memory: not in the URL, web storage or a script-readable cookie.
  const stored = await page.evaluate(() => ({
    url: location.href,
    local: localStorage.length,
    session: sessionStorage.length,
    cookie: document.cookie,
  }));
  expect(stored.url).not.toContain(CSRF);
  expect(stored).toMatchObject({ local: 0, session: 0, cookie: '' });

  await noViolations();
});

test('the Claim button shows its pending state while the claim is under way', async ({ page, baseURL }) => {
  await servePage(page, baseURL!);
  let release!: () => void;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  await answerClaim(page, async (route) => {
    await released;
    await created(route);
  });
  await answerSession(page);

  await page.goto('/bootstrap');
  await tokenField(page).fill(TOKEN);
  await claimButton(page).click();

  await expect(claimButton(page)).toHaveAttribute('aria-busy', 'true');
  await expect(claimButton(page)).toHaveAttribute('aria-disabled', 'true');
  await expect(claimButton(page)).toHaveAccessibleDescription('Loading');

  release();
  await expect(page).toHaveURL(/\/setup\/credentials$/);
});

for (const { name, status, code } of [
  { name: 'refused', status: 400, code: 'bootstrap_refused' },
  { name: 'rate limited', status: 429, code: 'rate_limited' },
] as const) {
  test(`a ${name} claim shows Generic error with its code and trace ID, and its action returns to an empty field`, async ({ page, baseURL }) => {
    const noViolations = await watchViolations(page);
    await servePage(page, baseURL!);
    const traceId = `0HNTRACE:0000000${status}`;
    await answerClaim(page, problem(status, code, traceId));

    await page.goto('/bootstrap');
    await tokenField(page).fill(TOKEN);
    await claimButton(page).click();

    const error = page.getByTestId('bootstrap-error');
    await expect(error.getByRole('heading', { level: 1, name: 'Something went wrong' })).toBeVisible();
    await expect(error.locator('[data-reference="code"]')).toHaveText(code);
    await expect(error.locator('[data-reference="trace"]')).toHaveText(traceId);
    await expect(page).toHaveURL(/\/bootstrap$/);
    await expect(page.getByText(TOKEN)).toHaveCount(0);

    const back = error.getByRole('link', { name: 'Back to Gatekeep' });
    await expect(back).toHaveAttribute('href', '/bootstrap');
    await back.click();

    await expect(tokenField(page)).toBeVisible();
    await expect(tokenField(page)).toHaveValue('');
    await noViolations();
  });
}

test('a 404 shows the bootstrap-unavailable card with its code and no way back', async ({ page, baseURL }) => {
  const noViolations = await watchViolations(page);
  await servePage(page, baseURL!);
  await answerClaim(page, (route) => route.fulfill({ status: 404 }));

  await page.goto('/bootstrap');
  await tokenField(page).fill(TOKEN);
  await claimButton(page).click();

  const card = page.getByTestId('bootstrap-unavailable');
  await expect(card.getByRole('heading', { level: 1, name: "This Deployment can't be claimed here" })).toBeVisible();
  await expect(card.locator('[data-reference="code"]')).toHaveText('bootstrap_unavailable');
  await expect(page.getByRole('link')).toHaveCount(0);
  await expect(page.getByTestId('bootstrap-error')).toHaveCount(0);
  await noViolations();
});

for (const { name, answer, code } of [
  { name: 'a 403', answer: (route: Route) => route.fulfill({ status: 403 }), code: 'origin_refused' },
  { name: 'a 503', answer: (route: Route) => route.fulfill({ status: 503 }), code: 'unavailable' },
  { name: 'a network failure', answer: (route: Route) => route.abort('connectionfailed'), code: 'unavailable' },
  {
    name: 'a 2xx with no CSRF token',
    answer: (route: Route) => route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ adminId: ADMIN_ID }) }),
    code: 'unavailable',
  },
] as const) {
  test(`${name} shows Generic error with the code ${code} and its action returns to the field`, async ({ page, baseURL }) => {
    await servePage(page, baseURL!);
    const claims = await answerClaim(page, answer);
    const sessions = await answerSession(page);

    await page.goto('/bootstrap');
    await tokenField(page).fill(TOKEN);
    await claimButton(page).click();

    const error = page.getByTestId('bootstrap-error');
    await expect(error.getByRole('heading', { level: 1, name: 'Something went wrong' })).toBeVisible();
    await expect(error.locator('[data-reference="code"]')).toHaveText(code);
    await expect(page).toHaveURL(/\/bootstrap$/);
    expect(claims).toHaveLength(1);
    expect(sessions).toHaveLength(0);

    await error.getByRole('link', { name: 'Back to Gatekeep' }).click();
    await expect(tokenField(page)).toHaveValue('');
    await expect(claimButton(page)).not.toHaveAttribute('aria-busy', 'true');
  });
}

test('a second click or Enter while the claim is pending sends no second claim', async ({ page, baseURL }) => {
  await servePage(page, baseURL!);
  let release!: () => void;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  const claims = await answerClaim(page, async (route) => {
    await released;
    await created(route);
  });
  await answerSession(page);

  await page.goto('/bootstrap');
  await tokenField(page).fill(TOKEN);
  await claimButton(page).click();
  await expect(claimButton(page)).toHaveAttribute('aria-busy', 'true');

  await claimButton(page).click({ force: true });
  await tokenField(page).press('Enter');
  await page.keyboard.press('Enter');

  release();
  await expect(page).toHaveURL(/\/setup\/credentials$/);
  expect(claims).toHaveLength(1);
});

test('credential setup without a Session goes to /bootstrap and never shows the setup text', async ({ page, baseURL }) => {
  await servePage(page, baseURL!);
  const sessions = await answerSession(page, 401);

  await page.goto('/setup/credentials');

  await expect(page).toHaveURL(/\/bootstrap$/);
  await expect(tokenField(page)).toBeVisible();
  expect(sessions).toHaveLength(1);
  await expect(page.getByTestId('credential-setup')).toHaveCount(0);
  await expect(page.getByText('Set up your credentials')).toHaveCount(0);
});

test('a returning setup Session at the root goes on to credential setup', async ({ page }) => {
  const noViolations = await watchViolations(page);
  const sessions = await answerSession(page);

  await page.goto('/');

  await expect(page).toHaveURL(/\/setup\/credentials$/);
  await expect(page.getByTestId('credential-setup')).toBeVisible();
  await expect.poll(() => sessions.length).toBeGreaterThanOrEqual(1);
  await noViolations();
});

for (const scheme of ['light', 'dark'] as const) {
  test(`axe finds no violations on Bootstrap, Generic error and credential setup, ${scheme}`, async ({ page, baseURL }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await servePage(page, baseURL!);
    let refuse = true;
    await answerClaim(page, (route) => (refuse ? problem(400, 'bootstrap_refused', '0HNTRACE:1')(route) : created(route)));
    await answerSession(page);

    await page.goto('/bootstrap');
    await expect(tokenField(page)).toBeVisible();
    expect(await axe(page), 'Bootstrap').toEqual([]);

    await tokenField(page).fill(TOKEN);
    await claimButton(page).click();
    await expect(page.getByTestId('bootstrap-error')).toBeVisible();
    expect(await axe(page), 'Generic error').toEqual([]);

    await page.getByRole('link', { name: 'Back to Gatekeep' }).click();
    refuse = false;
    await tokenField(page).fill(TOKEN);
    await claimButton(page).click();
    await expect(page.getByTestId('credential-setup')).toBeVisible();
    expect(await axe(page), 'credential setup').toEqual([]);
  });
}
