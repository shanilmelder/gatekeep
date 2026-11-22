// Story 4.9: the Password step on the built Hosted Login bundle served as Host.Hosted serves it (hosted-step-server.mjs),
// its requests stubbed as Host.Hosted answers them: the identifier chip, which wraps at 320px and whose Edit goes back to
// Login with the email kept, the read-only username field and the masked current-password field, no deferred control,
// "Incorrect email or password." focused with "Error:" in the title, the redirect after the correct password, and a 429
// shown as Generic error. Each in light and dark, with axe and the CSP watch. Expected text comes from the catalogue's
// defaults.

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { watchCsp } from './csp-watch';

watchCsp(test);

/** The catalogue's defaults (packages/ui/src/messages.tsx) this step shows. */
const text = {
  loginTitle: 'Welcome back',
  passwordTitle: 'Enter your password',
  emailLabel: 'Email address',
  passwordLabel: 'Password',
  logIn: 'Log in',
  edit: 'Edit',
  show: 'Show password',
  incorrect: 'Incorrect email or password.',
  genericErrorTitle: 'Something went wrong',
};

/** The harness's values (hosted-step-server.mjs). */
const PASSWORD_CSRF = 'fixture-csrf-password';
const CORRECT_PASSWORD = 'Correct-Horse-7battery';
const LONG_EMAIL = 'a.very.long.first.name.and.a.very.long.last.name.for.wrapping@subdomain.northwind-example.com';
const TENANT = 'Northwind';

const card = (page: Page) => page.locator('[data-hosted-card]');
const heading = (page: Page) => page.getByRole('heading', { level: 1 });
const passwordField = (page: Page) => page.getByLabel(text.passwordLabel, { exact: true });
const chip = (page: Page) => page.getByTestId('identifier-chip');

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
  test.describe(`Password sign-in in ${scheme}`, () => {
    test.use({ colorScheme: scheme });

    test('Continue from Login leads to the Password step for the email typed', async ({ page }) => {
      await open(page, 'login');
      await page.getByLabel(text.emailLabel).fill('someone@example.com');
      await card(page).getByRole('button', { name: 'Continue' }).click();

      await expect(heading(page)).toHaveText(text.passwordTitle);
      await expect(page.getByTestId('identifier-chip-identifier')).toHaveText('someone@example.com');
      await expect(page).toHaveTitle(`${text.passwordTitle} – ${TENANT}`);
    });

    test('The Password step: the chip, the username and current-password fields, focus on the heading, no deferred control', async ({ page }) => {
      const response = await open(page, 'password');
      expect(response.status()).toBe(200);

      await expect(heading(page)).toHaveText(text.passwordTitle);
      await expect(heading(page)).toBeFocused();
      await expect(page).toHaveTitle(`${text.passwordTitle} – ${TENANT}`);
      await expect(page.getByTestId('identifier-chip-identifier')).toHaveText('known@example.com');
      await expect(chip(page).getByRole('button', { name: text.edit })).toBeVisible();

      // The read-only username field in the same form, for password managers, out of the tab order.
      const username = page.getByTestId('identifier-chip-username');
      await expect(username).toHaveAttribute('name', 'username');
      await expect(username).toHaveAttribute('autocomplete', 'username');
      await expect(username).toHaveAttribute('readonly', '');
      await expect(username).toHaveValue('known@example.com');
      const sameForm = await page.evaluate(() => {
        const user = document.querySelector<HTMLInputElement>('[data-testid="identifier-chip-username"]');
        const secret = document.querySelector<HTMLInputElement>('input[autocomplete="current-password"]');
        return user?.form !== null && user?.form === secret?.form;
      });
      expect(sameForm).toBe(true);

      // Masked by default, with its Show toggle.
      await expect(passwordField(page)).toHaveAttribute('type', 'password');
      await expect(passwordField(page)).toHaveAttribute('autocomplete', 'current-password');
      await page.getByRole('button', { name: text.show }).click();
      await expect(passwordField(page)).toHaveAttribute('type', 'text');

      // Story 4.11's "Forgot password?", but no recovery code and no passkey hint: no deferred control, and no link at all.
      await expect(card(page).getByRole('button')).toHaveText([text.edit, 'Forgot password?', 'Hide', text.logIn]);
      await expect(page.locator('a')).toHaveCount(0);
      await expect(card(page)).not.toContainText(/recovery|passkey/i);
      await expectAxe(page);
    });

    test('The identifier chip wraps a long email at 320px, never truncating it', async ({ page }) => {
      await page.setViewportSize({ width: 320, height: 720 });
      await open(page, 'password_long');

      const identifier = page.getByTestId('identifier-chip-identifier');
      await expect(identifier).toHaveText(LONG_EMAIL);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
      const box = await identifier.evaluate((element) => ({
        height: element.getBoundingClientRect().height,
        line: parseFloat(getComputedStyle(element).lineHeight),
        clipped: element.scrollWidth > element.clientWidth,
        ellipsis: getComputedStyle(element).textOverflow,
      }));
      expect(box.height).toBeGreaterThan(box.line * 1.5);
      expect(box.clipped).toBe(false);
      expect(box.ellipsis).not.toBe('ellipsis');
      await expectAxe(page);
    });

    test('Edit posts the step version with its CSRF token and goes back to Login with the email kept', async ({ page }) => {
      await open(page, 'password');
      const posted = apiPost(page, '/login/api/password/back');
      await chip(page).getByRole('button', { name: text.edit }).click();
      const request = await posted;

      expect(request.headers()['x-gatekeep-csrf']).toBe(PASSWORD_CSRF);
      expect(request.postDataJSON()).toEqual({ stepVersion: 2 });
      await expect(heading(page)).toHaveText(text.loginTitle);
      await expect(page.getByLabel(text.emailLabel)).toHaveValue('known@example.com');
    });

    test('A wrong password shows "Incorrect email or password." under it, focused, with "Error:" in the title, and the field cleared', async ({ page }) => {
      await open(page, 'password');
      await passwordField(page).fill('Wrong-Horse-9battery');
      const posted = apiPost(page, '/login/api/password');
      await card(page).getByRole('button', { name: text.logIn }).click();
      const request = await posted;

      expect(request.headers()['x-gatekeep-csrf']).toBe(PASSWORD_CSRF);
      expect(request.postDataJSON()).toEqual({ stepVersion: 2, password: 'Wrong-Horse-9battery' });
      await expect(card(page)).toContainText(text.incorrect);
      await expect(passwordField(page)).toHaveAttribute('aria-invalid', 'true');
      await expect(passwordField(page)).toBeFocused();
      await expect(passwordField(page)).toHaveValue('');
      await expect(page).toHaveTitle(`Error: ${text.passwordTitle} – ${TENANT}`);
      await expectAxe(page);
    });

    test('The correct password follows the redirect with a top-level GET', async ({ page }) => {
      await open(page, 'password');
      await passwordField(page).fill(CORRECT_PASSWORD);
      await passwordField(page).press('Enter');

      await page.waitForURL('**/login/?fixture=generic_error');
      await expect(heading(page)).toHaveText(text.genericErrorTitle);
    });

    test('The Password step: the expiry warning shows, and Keep going keeps the step and the typed password', async ({ page }) => {
      await page.clock.install();
      await open(page, 'password');
      await passwordField(page).fill(CORRECT_PASSWORD);

      await page.clock.runFor(1800_000 - 120_000);
      const warning = page.getByRole('alertdialog');
      await expect(warning).toBeVisible();
      await expectAxe(page);

      const posted = apiPost(page, '/login/api/transaction/extend');
      await warning.getByRole('button', { name: 'Keep going' }).click();
      expect((await posted).headers()['x-gatekeep-csrf']).toBe(PASSWORD_CSRF);

      await expect(warning).toHaveCount(0);
      await expect(heading(page)).toHaveText(text.passwordTitle);
      await expect(page.getByTestId('identifier-chip-identifier')).toHaveText('known@example.com');
      await expect(passwordField(page)).toHaveValue(CORRECT_PASSWORD);
    });

    test('A password submit answered 429 shows the Generic error screen', async ({ page }) => {
      await open(page, 'password');
      await passwordField(page).fill('rate-limited');
      await card(page).getByRole('button', { name: text.logIn }).click();

      await expect(heading(page)).toHaveText(text.genericErrorTitle);
      await expect(page.getByText('temporarily_unavailable')).toBeVisible();
      await expectAxe(page);
    });
  });
}
