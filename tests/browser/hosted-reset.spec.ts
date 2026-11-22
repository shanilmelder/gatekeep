// Story 4.11: password reset's steps on the built Hosted Login bundle served as Host.Hosted serves it
// (hosted-step-server.mjs), its requests stubbed as Host.Hosted answers them: the Password step's "Forgot password?",
// Forgot password with its email carried and its field error, the neutral confirmation with "Back to login", Reset
// password with its strength meter, the confirmation's mismatch and a named rule, Password changed with "Log in" or "You
// can close this page.", and a reset link's Link expired, whose "Send a new link" posts to the reset path. Each in light
// and dark, with axe and the CSP watch. Expected text comes from the catalogue's defaults.

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { watchCsp } from './csp-watch';

watchCsp(test);

/** The catalogue's defaults (packages/ui/src/messages.tsx) these steps show. */
const text = {
  loginTitle: 'Welcome back',
  forgotLink: 'Forgot password?',
  forgotTitle: 'Forgot your password?',
  forgotBody: "Enter your email and we'll send a reset link.",
  emailLabel: 'Email address',
  send: 'Send reset link',
  back: 'Back to login',
  emailInvalid: 'Enter a valid email address.',
  linkSentTitle: 'Check your email',
  linkSentBody: "If an account exists for that email, we've sent a link.",
  resetTitle: 'Choose a new password',
  newLabel: 'New password',
  confirmLabel: 'Confirm password',
  submit: 'Reset password',
  mismatch: "Passwords don't match.",
  classesError: 'Use 3 of: lower case, upper case, number, special character.',
  changedTitle: 'Password changed',
  changedBody: "You've been signed out everywhere for your security.",
  logIn: 'Log in',
  close: 'You can close this page.',
  linkExpiredTitle: 'This link has expired or was already used.',
  sendNew: 'Send a new link',
  good: 'Password strength: Good',
  notStrongEnough: 'Password strength: Not strong enough',
};

/** The harness's values (hosted-step-server.mjs). */
const PASSWORD_CSRF = 'fixture-csrf-password';
const FORGOT_CSRF = 'fixture-csrf-forgot';
const RESET_SENT_CSRF = 'fixture-csrf-reset-sent';
const RESET_CSRF = 'fixture-reset-csrf-token';
const RESET_LINK = 'ten_aaaaaaaaaaaaaaaaaaaaaaaaaa.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
const NEW_PASSWORD = 'Fresh-Lantern-4orbit';
const TENANT = 'Northwind';

const card = (page: Page) => page.locator('[data-hosted-card]');
const heading = (page: Page) => page.getByRole('heading', { level: 1 });
const newPassword = (page: Page) => page.getByLabel(text.newLabel, { exact: true });
const confirmPassword = (page: Page) => page.getByLabel(text.confirmLabel, { exact: true });

async function open(page: Page, fixture: string, query = '') {
  const response = await page.goto(`/login/?fixture=${fixture}${query}`);
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
  test.describe(`Password reset in ${scheme}`, () => {
    test.use({ colorScheme: scheme });

    test('"Forgot password?" sits on the password label row and leads to Forgot password with the email carried', async ({ page }) => {
      await open(page, 'password');
      const forgot = card(page).getByRole('button', { name: text.forgotLink });
      await expect(forgot).toBeVisible();
      const [label, link] = await Promise.all([
        page.locator('label', { hasText: /^Password$/ }).boundingBox(),
        forgot.boundingBox(),
      ]);
      expect(link!.x).toBeGreaterThan(label!.x + label!.width);
      expect(Math.abs(link!.y + link!.height / 2 - (label!.y + label!.height / 2))).toBeLessThan(12);
      await expectAxe(page);

      const posted = apiPost(page, '/login/api/reset/open');
      await forgot.click();
      const request = await posted;
      expect(request.headers()['x-gatekeep-csrf']).toBe(PASSWORD_CSRF);
      expect(request.postDataJSON()).toEqual({ stepVersion: 2 });

      await expect(heading(page)).toHaveText(text.forgotTitle);
      await expect(heading(page)).toBeFocused();
      await expect(card(page)).toContainText(text.forgotBody);
      const email = page.getByLabel(text.emailLabel);
      await expect(email).toHaveValue('known@example.com');
      await expect(email).toHaveAttribute('autocomplete', 'email');
      await expect(page).toHaveTitle(`${text.forgotTitle} – ${TENANT}`);
      await expectAxe(page);
    });

    test('Forgot password: an invalid email is named and focused, with "Error:" in the title', async ({ page }) => {
      await open(page, 'forgot_password');
      const email = page.getByLabel(text.emailLabel);
      await email.fill('nope');
      const posted = apiPost(page, '/login/api/reset');
      await card(page).getByRole('button', { name: text.send }).click();
      const request = await posted;

      expect(request.headers()['x-gatekeep-csrf']).toBe(FORGOT_CSRF);
      expect(request.postDataJSON()).toEqual({ stepVersion: 3, email: 'nope' });
      await expect(card(page)).toContainText(text.emailInvalid);
      await expect(email).toHaveAttribute('aria-invalid', 'true');
      await expect(email).toBeFocused();
      await expect(page).toHaveTitle(`Error: ${text.forgotTitle} – ${TENANT}`);
      await expectAxe(page);
    });

    test('Send reset link answers the neutral confirmation, whose "Back to login" returns to Login with the email', async ({ page }) => {
      await open(page, 'forgot_password');
      await page.getByLabel(text.emailLabel).fill('anyone@example.com');
      await card(page).getByRole('button', { name: text.send }).click();

      await expect(heading(page)).toHaveText(text.linkSentTitle);
      await expect(card(page)).toContainText(text.linkSentBody);
      const back = card(page).getByRole('button', { name: text.back });
      await expect(back).toBeVisible();
      await expectAxe(page);

      const posted = apiPost(page, '/login/api/reset/back');
      await back.click();
      const request = await posted;
      expect(request.headers()['x-gatekeep-csrf']).toBe(RESET_SENT_CSRF);
      expect(request.postDataJSON()).toEqual({ stepVersion: 4 });
      await expect(heading(page)).toHaveText(text.loginTitle);
      await expect(page.getByLabel(text.emailLabel)).toHaveValue('known@example.com');
    });

    test('Forgot password\'s "Back to login" posts its own step and returns to Login', async ({ page }) => {
      await open(page, 'forgot_password');
      const posted = apiPost(page, '/login/api/reset/back');
      await card(page).getByRole('button', { name: text.back }).click();
      expect((await posted).headers()['x-gatekeep-csrf']).toBe(FORGOT_CSRF);
      await expect(heading(page)).toHaveText(text.loginTitle);
    });

    test('The neutral confirmation after "Send a new link" has no "Back to login"', async ({ page }) => {
      await open(page, 'link_sent');
      await expect(heading(page)).toHaveText(text.linkSentTitle);
      await expect(card(page).getByRole('button')).toHaveCount(0);
    });

    test('Reset password: the two new-password fields, the meter from the step policy, and the link gone from the address bar', async ({ page }) => {
      const response = await open(page, 'reset_password', `&token=${encodeURIComponent(RESET_LINK)}`);
      expect(response.status()).toBe(200);
      await expect.poll(() => new URL(page.url()).search).toBe('');

      await expect(heading(page)).toHaveText(text.resetTitle);
      await expect(heading(page)).toBeFocused();
      await expect(page).toHaveTitle(`${text.resetTitle} – ${TENANT}`);
      for (const field of [newPassword(page), confirmPassword(page)]) {
        await expect(field).toHaveAttribute('type', 'password');
        await expect(field).toHaveAttribute('autocomplete', 'new-password');
      }

      // The link User's email in a hidden read-only username field in the same form, for password managers.
      const username = page.getByTestId('password-field-username');
      await expect(username).toHaveAttribute('autocomplete', 'username');
      await expect(username).toHaveAttribute('readonly', '');
      await expect(username).toHaveAttribute('tabindex', '-1');
      await expect(username).toHaveValue('known@example.com');

      const meter = page.getByTestId('strength-meter');
      await expect(meter).toContainText(text.notStrongEnough);
      await newPassword(page).fill(NEW_PASSWORD);
      await expect(meter).toHaveAttribute('data-filled', '4');
      await expect(meter).toContainText(text.good);
      await expect(page.locator('a')).toHaveCount(0);

      await page.setViewportSize({ width: 320, height: 720 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
      await expectAxe(page);
    });

    test('Reset password: a confirmation that differs is refused in the browser, under Confirm, with no request', async ({ page }) => {
      await open(page, 'reset_password', `&token=${encodeURIComponent(RESET_LINK)}`);
      const posts: string[] = [];
      page.on('request', (request) => {
        if (request.method() === 'POST') posts.push(new URL(request.url()).pathname);
      });
      await newPassword(page).fill(NEW_PASSWORD);
      await confirmPassword(page).fill(`${NEW_PASSWORD}x`);
      await card(page).getByRole('button', { name: text.submit }).click();

      await expect(card(page)).toContainText(text.mismatch);
      await expect(confirmPassword(page)).toHaveAttribute('aria-invalid', 'true');
      await expect(confirmPassword(page)).toBeFocused();
      await expect(page).toHaveTitle(`Error: ${text.resetTitle} – ${TENANT}`);
      expect(posts).toEqual([]);
      await expectAxe(page);
    });

    test('Reset password: a refused rule is named under New password, focused', async ({ page }) => {
      await open(page, 'reset_password', `&token=${encodeURIComponent(RESET_LINK)}`);
      await newPassword(page).fill('aaaaaaaaaaaa');
      await confirmPassword(page).fill('aaaaaaaaaaaa');
      const posted = apiPost(page, '/login/api/reset/complete');
      await card(page).getByRole('button', { name: text.submit }).click();
      const request = await posted;

      expect(request.headers()['x-gatekeep-csrf']).toBe(RESET_CSRF);
      expect(request.postDataJSON()).toEqual({ token: RESET_LINK, password: 'aaaaaaaaaaaa', confirm: 'aaaaaaaaaaaa' });
      await expect(card(page)).toContainText(text.classesError);
      await expect(newPassword(page)).toHaveAttribute('aria-invalid', 'true');
      await expect(newPassword(page)).toBeFocused();
      await expect(page).toHaveTitle(`Error: ${text.resetTitle} – ${TENANT}`);
      await expectAxe(page);
    });

    test('Reset password with a good password shows Password changed, which can be closed', async ({ page }) => {
      await open(page, 'reset_password', `&token=${encodeURIComponent(RESET_LINK)}`);
      await newPassword(page).fill(NEW_PASSWORD);
      await confirmPassword(page).fill(NEW_PASSWORD);
      await confirmPassword(page).press('Enter');

      await expect(heading(page)).toHaveText(text.changedTitle);
      await expect(card(page)).toContainText(text.changedBody);
      await expect(card(page)).toContainText(text.close);
      await expect(page.locator('a')).toHaveCount(0);
      await expect(page).toHaveTitle(`${text.changedTitle} – ${TENANT}`);
      await expectAxe(page);
    });

    test('Password changed in the browser that asked offers "Log in", a top-level GET to Login', async ({ page }) => {
      await open(page, 'password_changed_login');
      await expect(heading(page)).toHaveText(text.changedTitle);
      await expect(card(page)).toContainText(text.changedBody);
      const logIn = card(page).getByRole('link', { name: text.logIn });
      await expect(logIn).toHaveAttribute('href', '/login');
      await expect(card(page)).not.toContainText(text.close);
      await expectAxe(page);
    });

    test('A reset link\'s Link expired sends a new link through the reset path with its link-bound token', async ({ page }) => {
      await open(page, 'reset_link_expired');
      await expect(heading(page)).toHaveText(text.linkExpiredTitle);
      await expectAxe(page);

      const posted = apiPost(page, '/login/api/reset/new-link');
      await card(page).getByRole('button', { name: text.sendNew }).click();
      const request = await posted;
      expect(request.headers()['x-gatekeep-csrf']).toBe(RESET_CSRF);
      expect(request.postDataJSON()).toEqual({ token: RESET_LINK });
      await expect(heading(page)).toHaveText(text.linkSentTitle);
      await expect(card(page).getByRole('button')).toHaveCount(0);
    });
  });
}
