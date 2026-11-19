// Story 4.7: sign-up and email verification's steps on the built Hosted Login bundle served as Host.Hosted serves it
// (hosted-step-server.mjs), its requests stubbed as Host.Hosted answers them: Login's "Sign up", Signup with the strength
// meter, which follows the typing with no request until Create account, a refused rule named under the password,
// Email verification required with the resend countdown, Email verified in both browsers, Link expired and the neutral
// confirmation. Each in light and dark, with axe and the CSP watch. Expected text comes from the catalogue's defaults.

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Request } from '@playwright/test';
import { watchCsp } from './csp-watch';

watchCsp(test);

/** The catalogue's defaults (packages/ui/src/messages.tsx) these steps show. */
const text = {
  signupLink: 'Sign up',
  signupTitle: 'Create your account',
  emailLabel: 'Email address',
  passwordLabel: 'Password',
  create: 'Create account',
  logIn: 'Log in',
  notStrongEnough: 'Password strength: Not strong enough',
  good: 'Password strength: Good',
  excellent: 'Password strength: Excellent',
  met: 'Met',
  notMet: 'Not met',
  classesError: 'Use 3 of: lower case, upper case, number, special character.',
  verifyTitle: 'Verify your email to continue',
  verifyBody: 'We sent a link to new.user@example.com. Click it, then come back here.',
  verifyContinue: "I've verified — continue",
  notYet: "We haven't seen that yet. Check your inbox.",
  resend: 'Resend email',
  emailSent: 'Email sent',
  verifiedTitle: 'Email verified',
  verifiedContinue: 'Continue',
  verifiedClose: 'You can close this page.',
  expiredTitle: 'This link has expired or was already used.',
  sendNew: 'Send a new link',
  sentBody: "If an account exists for that email, we've sent a link.",
};

/** The harness's tokens (hosted-step-server.mjs). */
const CSRF = 'fixture-csrf-token';
const SIGNUP_CSRF = 'fixture-csrf-signup';
const VERIFY_CSRF = 'fixture-csrf-verify';
const LINK_CSRF = 'fixture-link-csrf-token';
const LINK = 'ten_aaaaaaaaaaaaaaaaaaaaaaaaaa.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const TENANT = 'Northwind';

const card = (page: Page) => page.locator('[data-hosted-card]');
const heading = (page: Page) => page.getByRole('heading', { level: 1 });
const meter = (page: Page) => page.getByTestId('strength-meter');

/** Every fetch the page makes from now on. */
function fetches(page: Page) {
  const seen: Request[] = [];
  page.on('request', (request) => {
    if (request.resourceType() === 'fetch' || request.resourceType() === 'xhr') seen.push(request);
  });
  return seen;
}

async function open(page: Page, fixture: string) {
  const response = await page.goto(`/login/?fixture=${fixture}`);
  await expect(card(page)).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  return response!;
}

/** Waits for one Hosted Login API post, and returns it. */
const apiPost = (page: Page, path: string) =>
  page.waitForRequest((request) => request.method() === 'POST' && new URL(request.url()).pathname === path);

async function expectAxe(page: Page) {
  await page.evaluate(() => Promise.allSettled(document.getAnimations().map((animation) => animation.finished)));
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations.map((violation) => ({ id: violation.id, nodes: violation.nodes.map((node) => node.target) }))).toEqual([]);
}

for (const scheme of ['light', 'dark'] as const) {
  test.describe(`Sign-up in ${scheme}`, () => {
    test.use({ colorScheme: scheme });

    test('Login: "Sign up" shows while sign-up is open, and opens Signup carrying the email', async ({ page }) => {
      await open(page, 'login_signup');
      await page.getByLabel(text.emailLabel).fill('new.user@example.com');
      await expectAxe(page);

      const posted = apiPost(page, '/login/api/signup/open');
      await card(page).getByRole('button', { name: text.signupLink }).click();
      const request = await posted;

      expect(request.headers()['x-gatekeep-csrf']).toBe(CSRF);
      expect(request.postDataJSON()).toEqual({ stepVersion: 1, email: 'new.user@example.com' });
      await expect(heading(page)).toHaveText(text.signupTitle);
      await expect(page.getByLabel(text.emailLabel)).toHaveValue('new.user@example.com');
      await expect(page).toHaveTitle(`${text.signupTitle} – ${TENANT}`);
    });

    test('Signup: the fields, the meter and its checklist, and axe passes, with no deferred control', async ({ page }) => {
      await open(page, 'signup');

      await expect(heading(page)).toHaveText(text.signupTitle);
      const email = page.getByLabel(text.emailLabel);
      await expect(email).toHaveAttribute('autocomplete', 'username');
      await expect(email).toBeFocused();
      const password = page.getByLabel(text.passwordLabel, { exact: true });
      await expect(password).toHaveAttribute('type', 'password');
      await expect(password).toHaveAttribute('autocomplete', 'new-password');
      await expect(meter(page)).toContainText(text.notStrongEnough);
      await expect(meter(page).locator('li')).toHaveCount(2);
      await expect(meter(page).locator('li[data-met="false"]')).toHaveCount(2);
      await expect(meter(page).locator('li').first()).toContainText(text.notMet);
      await expect(card(page).getByRole('button', { name: text.create })).toBeVisible();
      await expect(card(page).getByRole('button', { name: text.logIn })).toBeVisible();
      await expect(card(page).getByRole('checkbox')).toHaveCount(0);
      await expect(page.locator('a')).toHaveCount(0);

      await page.setViewportSize({ width: 320, height: 720 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
      await expectAxe(page);
    });

    test('Signup: the meter follows the typing from the step policy, sends nothing, and announces the label after a pause', async ({ page }) => {
      const seen = fetches(page);
      await open(page, 'signup_excellent');
      const password = page.getByLabel(text.passwordLabel, { exact: true });
      const status = page.getByTestId('strength-meter-status');

      // Excellent lists the repeats rule too.
      await expect(meter(page).locator('li')).toHaveCount(3);
      await password.fill('aaaaaaaaaaaa');
      await expect(meter(page)).toHaveAttribute('data-filled', '2');
      await expect(meter(page).locator('li[data-rule="length"]')).toHaveAttribute('data-met', 'true');
      await expect(meter(page).locator('li[data-rule="classes"]')).toHaveAttribute('data-met', 'false');
      await expect(meter(page).locator('li[data-rule="repeats"]')).toHaveAttribute('data-met', 'false');
      await expect(status).toHaveText(text.notStrongEnough);

      await password.fill('Correct-Horse-7battery');
      await expect(meter(page)).toHaveAttribute('data-filled', '4');
      await expect(meter(page).locator('li[data-met="true"]')).toHaveCount(3);
      await expect(page.getByTestId('strength-meter-label')).toHaveText(text.excellent);
      await expect(status).toHaveText(text.excellent);
      await expect(meter(page).locator('li').first()).toContainText(text.met);
      expect(seen).toEqual([]);
      await expectAxe(page);
    });

    test('Create account: a refused rule is named under the password, focused, with "Error:" in the title', async ({ page }) => {
      await open(page, 'signup');
      const password = page.getByLabel(text.passwordLabel, { exact: true });
      await password.fill('aaaaaaaaaaaa');
      const posted = apiPost(page, '/login/api/signup');
      await card(page).getByRole('button', { name: text.create }).click();
      const request = await posted;

      expect(request.headers()['x-gatekeep-csrf']).toBe(SIGNUP_CSRF);
      expect(request.postDataJSON()).toEqual({ stepVersion: 2, email: 'new.user@example.com', password: 'aaaaaaaaaaaa' });
      await expect(card(page)).toContainText(text.classesError);
      await expect(password).toHaveAttribute('aria-invalid', 'true');
      await expect(password).toBeFocused();
      await expect(page).toHaveTitle(`Error: ${text.signupTitle} – ${TENANT}`);
      await expectAxe(page);
    });

    test('Create account: Email verification required follows, with its countdown before Resend', async ({ page }) => {
      await page.clock.install();
      await open(page, 'signup');
      await page.getByLabel(text.passwordLabel, { exact: true }).fill('Correct-Horse-7battery');
      await card(page).getByRole('button', { name: text.create }).click();

      await expect(heading(page)).toHaveText(text.verifyTitle);
      await expect(card(page)).toContainText(text.verifyBody);
      const resend = page.getByTestId('verify-resend-button');
      await expect(resend).toHaveAttribute('aria-disabled', 'true');
      await expect(page.getByTestId('verify-resend-countdown')).toBeVisible();
      await expectAxe(page);
    });

    test('Email verification required: the warning icon, Continue before the link, and Resend after its countdown', async ({ page }) => {
      await page.clock.install();
      await open(page, 'verify_email');

      await expect(heading(page)).toHaveText(text.verifyTitle);
      await expect(card(page).locator('[data-status="warning"]')).toHaveText('@');
      const resend = page.getByTestId('verify-resend-button');
      const countdown = page.getByTestId('verify-resend-countdown');
      await expect(resend).toHaveAttribute('aria-disabled', 'true');
      await expect(countdown).toBeVisible();
      // The countdown is outside every live region.
      expect(await countdown.evaluate((element) => element.closest('[role="status"], [role="alert"], [aria-live]') === null)).toBe(true);
      await expectAxe(page);

      // A click while it counts down does nothing, and focus stays.
      const seen = fetches(page);
      await resend.focus();
      // Playwright treats aria-disabled as disabled and would wait for it: the click is forced, as a user's would land.
      await resend.click({ force: true });
      await expect(resend).toBeFocused();
      expect(seen).toEqual([]);

      const continued = apiPost(page, '/login/api/verification/continue');
      await card(page).getByRole('button', { name: text.verifyContinue }).click();
      expect((await continued).postDataJSON()).toEqual({ stepVersion: 3 });
      await expect(page.getByRole('alert')).toHaveText(text.notYet);

      await page.clock.runFor(30_000);
      await expect(resend).not.toHaveAttribute('aria-disabled', 'true');
      await expect(countdown).toHaveCount(0);
      const resent = apiPost(page, '/login/api/verification/resend');
      await resend.click();
      expect((await resent).headers()['x-gatekeep-csrf']).toBe(VERIFY_CSRF);
      await expect(resend).toHaveAttribute('aria-disabled', 'true');
      // "Email sent" is written into its status region a moment after the answer, so it is announced.
      await page.clock.runFor(200);
      await expect(page.getByRole('status').filter({ hasText: text.emailSent })).toHaveCount(1);
      await expect(resend).toHaveAttribute('aria-disabled', 'true');
      await expectAxe(page);
    });

    test('Signup: the expiry warning shows, and Keep going keeps the step and the typed password', async ({ page }) => {
      await page.clock.install();
      await open(page, 'signup');
      const password = page.getByLabel(text.passwordLabel, { exact: true });
      await password.fill('Correct-Horse-7battery');

      await page.clock.runFor(1800_000 - 120_000);
      const warning = page.getByRole('alertdialog');
      await expect(warning).toBeVisible();
      await expectAxe(page);

      const posted = apiPost(page, '/login/api/transaction/extend');
      await warning.getByRole('button', { name: 'Keep going' }).click();
      expect((await posted).headers()['x-gatekeep-csrf']).toBe(SIGNUP_CSRF);

      await expect(warning).toHaveCount(0);
      await expect(heading(page)).toHaveText(text.signupTitle);
      await expect(password).toHaveValue('Correct-Horse-7battery');
      await expect(meter(page)).toHaveAttribute('data-filled', '4');
    });

    test('Email verified in the browser that signed up: Continue is a top-level GET back to the request', async ({ page }) => {
      await open(page, 'email_verified_app');
      // The link's token leaves the address bar once the page has it.
      await expect.poll(() => new URL(page.url()).search).toBe('');

      await expect(heading(page)).toHaveText(text.verifiedTitle);
      await expect(card(page).locator('[data-status="success"]')).toHaveText('✓');
      await expectAxe(page);
      await page.getByRole('link', { name: text.verifiedContinue }).click();
      await page.waitForURL('**/login/?fixture=generic_error');
    });

    test('Email verified in another browser: "You can close this page." with no action', async ({ page }) => {
      await open(page, 'email_verified_close');
      await expect.poll(() => new URL(page.url()).search).toBe('');

      await expect(heading(page)).toHaveText(text.verifiedTitle);
      await expect(card(page)).toContainText(text.verifiedClose);
      await expect(card(page).getByRole('button')).toHaveCount(0);
      await expect(card(page).getByRole('link')).toHaveCount(0);
      await expectAxe(page);
    });

    test('Link expired: Send a new link posts the link with its own CSRF token and shows the neutral confirmation', async ({ page }) => {
      await open(page, 'link_expired');
      await expect.poll(() => new URL(page.url()).search).toBe('');

      await expect(heading(page)).toHaveText(text.expiredTitle);
      await expectAxe(page);
      const posted = apiPost(page, '/login/api/verification/new-link');
      await card(page).getByRole('button', { name: text.sendNew }).click();
      const request = await posted;

      expect(request.headers()['x-gatekeep-csrf']).toBe(LINK_CSRF);
      expect(request.postDataJSON()).toEqual({ token: LINK });
      await expect(card(page)).toContainText(text.sentBody);
      await expectAxe(page);
    });
  });
}
