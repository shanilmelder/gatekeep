// Story 1.26: Admin Recovery Codes in the built Admin Dashboard, served by the built Host.Admin
// (admin-host.mjs) under its real CSP, from localhost. The Admin API is answered by route
// interception: the Recovery Code entry on sign-in, the code's choice and one-time display at
// credential setup, and credential setup in a recovery Session. The server's rules are the
// Isolation tests' (tests/Isolation/Admins/AdminRecoveryCodeTests.cs).

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Request, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const REDEEM = '/api/v1/deployment/signin/recovery-code';
const ISSUE = '/api/v1/deployment/credentials/recovery-code';
const CSRF = 'Q'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000127';
const CODE = '7K3M-QX2P-4RT8-WV6N';
const ISSUE_ID = '01900000-0000-7000-8000-0000000001aa';

const json = (route: Route, status: number, body: unknown, headers?: Record<string, string>) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body), headers });
const problem = (route: Route, status: number, code: string, headers?: Record<string, string>) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: 'e'.repeat(32) }), headers });

interface Session {
  kind: 'setup' | 'full' | 'recovery';
  credentials: number;
  setupComplete: boolean;
  recoveryCodeAllowed: boolean;
}

/** The Admin API for the pre-Session pages: the Session as `session` says, redeem, issue and confirm. */
async function answerApi(
  page: Page,
  initial: Partial<Session> = {},
  redeem?: (route: Route) => Promise<void>,
  confirm?: (route: Route) => Promise<void>,
) {
  const session: Session = { kind: 'setup', credentials: 1, setupComplete: false, recoveryCodeAllowed: true, ...initial };
  const log: string[] = [];
  const requests: Request[] = [];
  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      // The shell's Tenants list (Story 1.28): none, and outside the log this spec's rules read.
      if (pathname === '/api/v1/deployment/my-tenants') return json(route, 200, { tenants: [] });
      log.push(`${request.method()} ${pathname}`);
      requests.push(request);
      if (pathname === SESSION && request.method() === 'DELETE') return route.fulfill({ status: 204 });
      if (pathname === SESSION) {
        return json(route, 200, { adminId: ADMIN_ID, csrfToken: CSRF, deploymentOwner: false, ...session });
      }
      if (pathname === '/api/v1/deployment/capabilities') return json(route, 200, { capabilities: [] });
      if (pathname === REDEEM) {
        if (redeem) return redeem(route);
        Object.assign(session, { kind: 'recovery', setupComplete: false, recoveryCodeAllowed: false });
        return json(route, 200, { adminId: ADMIN_ID, csrfToken: CSRF, setupComplete: false });
      }
      if (pathname === ISSUE) return json(route, 200, { code: CODE, issueId: ISSUE_ID });
      if (pathname === `${ISSUE}/confirm`) {
        if (confirm) return confirm(route);
        Object.assign(session, { kind: 'full', setupComplete: true, recoveryCodeAllowed: false });
        return route.fulfill({ status: 204 });
      }
      return route.fulfill({ status: 404 });
    },
  );
  return { log, requests, session, count: (entry: string) => log.filter((line) => line === entry).length };
}

async function axe(page: Page) {
  // Finite animations only: a pending button's spinner runs until its action settles.
  await page.evaluate(() =>
    Promise.allSettled(
      document
        .getAnimations()
        .filter((animation) => animation.effect?.getComputedTiming().iterations !== Infinity)
        .map((animation) => animation.finished),
    ).then(() => undefined),
  );
  // tx3 on sf2 in table heads is DESIGN.md's one recorded contrast exception, as data.spec.ts has it.
  const everything = await new AxeBuilder({ page }).disableRules(['color-contrast']).analyze();
  const contrast = await new AxeBuilder({ page }).withRules(['color-contrast']).exclude('thead th').analyze();
  return [...everything.violations, ...contrast.violations].map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
}

/** axe in light and dark, at 1100 and 768px wide, on what the page shows now. */
async function axeEverywhere(page: Page) {
  for (const width of [1100, 768]) {
    for (const colorScheme of ['light', 'dark'] as const) {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme });
      expect(await axe(page), `${colorScheme} at ${width}px`).toEqual([]);
    }
  }
}

const codeField = (page: Page) => page.getByRole('textbox', { name: 'Recovery code' });
const continueButton = (page: Page) => page.getByRole('button', { name: 'Continue' });

watchCsp(test);

test.describe('Use a recovery code', () => {
  test('sign-in links to it, and it asks for the code in one field, with a way back', async ({ page }) => {
    await answerApi(page);

    await page.goto('/signin');
    await page.getByRole('link', { name: 'Use a recovery code' }).click();

    await expect(page).toHaveURL(/\/signin\/recovery$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Use a recovery code' })).toBeVisible();
    await expect(page.getByText('Enter the offline recovery code you saved when you set up your credentials. It lets you register a new passkey.')).toBeVisible();
    await expect(codeField(page)).toHaveAttribute('inputmode', 'text');
    await expect(codeField(page)).toHaveAttribute('autocapitalize', 'characters');
    await expect(codeField(page)).toHaveAttribute('autocomplete', 'off');
    await expect(codeField(page)).toHaveAttribute('spellcheck', 'false');
    await expect(codeField(page)).toHaveAccessibleDescription('Format: XXXX-XXXX-XXXX-XXXX');
    await expect(page.getByRole('link', { name: 'Sign in with a passkey instead' })).toHaveAttribute('href', '/signin');
    await axeEverywhere(page);
  });

  test('a refused code and a rate limit keep the page, with their reason', async ({ page }) => {
    let answer: (route: Route) => Promise<void> = (route) => problem(route, 400, 'recovery_code_refused');
    const api = await answerApi(page, {}, (route) => answer(route));

    await page.goto('/signin/recovery');
    await codeField(page).fill('zzzz-zzzz');
    await continueButton(page).click();
    await expect(page.getByTestId('recovery-refused')).toHaveText("That code isn't valid.");
    expect(api.requests.find((r) => new URL(r.url()).pathname === REDEEM)!.postDataJSON()).toEqual({ code: 'zzzz-zzzz' });
    await axeEverywhere(page);

    answer = (route) => problem(route, 429, 'rate_limited', { 'Retry-After': '30' });
    await continueButton(page).click();
    await expect(page.getByTestId('recovery-refused')).toHaveText('Too many attempts. Try again in 30 seconds.');
    await expect(page).toHaveURL(/\/signin\/recovery$/);
  });

  test('an outage shows Generic error, whose action comes back here', async ({ page }) => {
    await answerApi(page, {}, (route) => route.fulfill({ status: 503 }));

    await page.goto('/signin/recovery');
    await codeField(page).fill(CODE);
    await continueButton(page).click();

    await expect(page.getByTestId('recovery-error')).toBeVisible();
    await expect(page.getByRole('link', { name: /Gatekeep/ })).toHaveAttribute('href', '/signin/recovery');
  });

  test('a redeemed code goes to credential setup, which offers only a new passkey', async ({ page }) => {
    const api = await answerApi(page, { kind: 'full', credentials: 2, setupComplete: true, recoveryCodeAllowed: false });

    await page.goto('/signin/recovery');
    await codeField(page).fill(CODE.toLowerCase());
    await continueButton(page).click();

    await expect(page).toHaveURL(/\/setup\/credentials$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Set up a new passkey' })).toBeVisible();
    await expect(page.getByText('Your recovery code has been used. Register a new passkey or security key to continue.')).toBeVisible();
    await expect(page.getByTestId('credential-setup-step')).toHaveCount(0);
    await expect(page.getByRole('button')).toHaveText(['Register passkey', 'Sign out']);
    expect(api.count(`POST ${REDEEM}`)).toBe(1);
    await axeEverywhere(page);
  });
});

test.describe('An offline Recovery Code at credential setup', () => {
  test('is offered at step 2 when the Session allows it, and not otherwise', async ({ page }) => {
    await answerApi(page, { recoveryCodeAllowed: false });
    await page.goto('/setup/credentials');
    await expect(page.getByTestId('credential-setup-step')).toHaveText('Step 2 of 2');
    await expect(page.getByRole('button', { name: 'Use an offline recovery code instead' })).toHaveCount(0);
  });

  test('is shown once, Continue needs the checkbox, and confirming goes to the landing page', async ({ page }) => {
    const api = await answerApi(page);

    await page.goto('/setup/credentials');
    await page.getByRole('button', { name: 'Use an offline recovery code instead' }).click();

    const card = page.getByTestId('recovery-code');
    await expect(card.getByText("If you lose your device, this code works once. We won't show it again.")).toBeVisible();
    await expect(page.getByTestId('recovery-code-value')).toHaveText(CODE);
    await expect(card.getByRole('button', { name: 'Copy recovery code' })).toBeVisible();
    await expect(card.getByRole('checkbox', { name: "I've saved this code" })).not.toBeChecked();
    // Copy only: nothing to download.
    await expect(card.getByRole('link')).toHaveCount(0);
    await axeEverywhere(page);

    await continueButton(page).click();
    await expect(page.getByTestId('recovery-code-unsaved')).toHaveText("Confirm you've saved your code.");
    await expect(card.getByRole('checkbox')).toHaveAttribute('aria-invalid', 'true');
    expect(api.count(`POST ${ISSUE}/confirm`)).toBe(0);
    await axeEverywhere(page);

    await card.getByRole('checkbox', { name: "I've saved this code" }).check();
    await expect(page.getByTestId('recovery-code-unsaved')).toHaveCount(0);
    await continueButton(page).click();

    await expect(page).toHaveURL(/\/$/);
    expect(api.count(`POST ${ISSUE}/confirm`)).toBe(1);
    expect(api.requests.find((r) => new URL(r.url()).pathname === `${ISSUE}/confirm`)!.postDataJSON()).toEqual({ issueId: ISSUE_ID });
    expect(await page.evaluate(() => [Object.keys(localStorage), Object.keys(sessionStorage)])).toEqual([[], []]);
  });

  test('a reload before confirming shows no code, and offers the choice again', async ({ page }) => {
    const api = await answerApi(page);

    await page.goto('/setup/credentials');
    await page.getByRole('button', { name: 'Use an offline recovery code instead' }).click();
    await expect(page.getByTestId('recovery-code-value')).toHaveText(CODE);

    await page.reload();

    await expect(page.getByTestId('credential-setup-step')).toHaveText('Step 2 of 2');
    await expect(page.getByText(CODE)).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Use an offline recovery code instead' })).toBeVisible();
    expect(api.count(`POST ${ISSUE}`)).toBe(1);
  });

  for (const [status, reason] of [
    [409, 'A newer recovery code replaced this one, so it was not saved. Start again to get a new code.'],
    [403, 'This recovery code can no longer be confirmed. Start again.'],
  ] as const) {
    test(`a ${status} on confirm takes the code away and says why, and Continue starts again`, async ({ page }) => {
      await answerApi(page, {}, undefined, (route) =>
        status === 409 ? problem(route, 409, 'recovery_code_superseded') : route.fulfill({ status: 403 }),
      );

      await page.goto('/setup/credentials');
      await page.getByRole('button', { name: 'Use an offline recovery code instead' }).click();
      await page.getByRole('checkbox', { name: "I've saved this code" }).check();
      await continueButton(page).click();

      const stale = page.getByTestId('recovery-code-stale');
      await expect(stale).toContainText(reason);
      await expect(page.getByText(CODE)).toHaveCount(0);
      await axeEverywhere(page);

      await continueButton(page).click();
      await expect(page.getByRole('button', { name: 'Use an offline recovery code instead' })).toBeVisible();
    });
  }

  test('a recovery or setup card can sign out, which goes to sign in', async ({ page }) => {
    const api = await answerApi(page, { kind: 'recovery' });

    await page.goto('/setup/credentials');
    await page.getByRole('button', { name: 'Sign out' }).click();

    await expect(page).toHaveURL(/\/signin$/);
    expect(api.count(`DELETE ${SESSION}`)).toBe(1);
    expect(await api.requests.find((r) => r.method() === 'DELETE')!.headerValue('x-gatekeep-csrf')).toBe(CSRF);
  });
});
