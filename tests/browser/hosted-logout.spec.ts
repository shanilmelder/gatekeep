// Story 4.13: logout's steps on the built Hosted Login bundle served as Host.Hosted serves it (hosted-step-server.mjs),
// its one request stubbed as Host.Hosted answers it: the confirmation "Log out of {Tenant}?" with "Log out" and "Stay
// signed in", "Stay signed in" going back with no request, "Log out" posting the end-session parameters back with the
// Session-bound CSRF token, and the completed logout, "You're logged out." with no action, or a top-level GET back to the
// Application's logout URL. Each in light and dark, with axe; the steps that stay on this origin under the CSP watch.
// Expected text comes from the catalogue's defaults.

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { watchCsp } from './csp-watch';
import { APP_LOGOUT_URL, HOSTILE_LOGOUT_TARGETS, ID_TOKEN_HINT, LOGOUT_CSRF, LOGOUT_STATE } from './hosted-logout-fixture.mjs';

/** The catalogue's defaults (packages/ui/src/messages.tsx) these steps show. */
const text = {
  logoutTitle: 'Log out of Northwind?',
  logoutBody: "You'll be signed out of all Northwind apps on this browser.",
  stay: 'Stay signed in',
  logOut: 'Log out',
  loggedOut: "You're logged out.",
  stillSignedIn: "You're still signed in.",
  canClose: 'You can close this page.',
};

const TENANT = 'Northwind';

const card = (page: Page) => page.locator('[data-hosted-card]');
const heading = (page: Page) => page.getByRole('heading', { level: 1 });

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
  test.describe(`Logout in ${scheme}`, () => {
    watchCsp(test);
    test.use({ colorScheme: scheme });

    test('The confirmation asks "Log out of {Tenant}?" with Log out and Stay signed in, its heading focused', async ({ page }) => {
      const response = await open(page, 'logout');
      expect(response.status()).toBe(200);

      await expect(heading(page)).toHaveText(text.logoutTitle);
      await expect(heading(page)).toBeFocused();
      await expect(card(page)).toContainText(text.logoutBody);
      const logOut = card(page).getByRole('button', { name: text.logOut, exact: true });
      const stay = card(page).getByRole('button', { name: text.stay });
      await expect(logOut).toBeVisible();
      await expect(logOut).toHaveAttribute('data-variant', 'primary');
      await expect(stay).toBeVisible();
      await expect(stay).toHaveAttribute('data-variant', 'secondary');
      await expect(page).toHaveTitle(`${text.logoutTitle} – ${TENANT}`);

      // Side by side, Stay signed in on the left and Log out on the right, on one row.
      const [left, right] = await Promise.all([stay.boundingBox(), logOut.boundingBox()]);
      expect(left!.x + left!.width).toBeLessThanOrEqual(right!.x);
      expect(Math.abs(left!.y - right!.y)).toBeLessThan(2);
      expect(Math.abs(left!.width - right!.width)).toBeLessThan(2);
      await expectAxe(page);
    });

    test('At 320px the two actions stack, Stay signed in above Log out', async ({ page }) => {
      await page.setViewportSize({ width: 320, height: 640 });
      await open(page, 'logout');
      const [stay, logOut] = await Promise.all([
        card(page).getByRole('button', { name: text.stay }).boundingBox(),
        card(page).getByRole('button', { name: text.logOut, exact: true }).boundingBox(),
      ]);
      expect(stay!.y + stay!.height).toBeLessThanOrEqual(logOut!.y);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await expectAxe(page);
    });

    test('Stay signed in with no page to go back to says the User is still signed in, with no request', async ({ page }) => {
      // A tab opened on the logout link has one history entry. Chromium keeps a fresh page's initial about:blank as
      // an entry before the first goto, so the test pins the length the browser reports instead.
      await page.addInitScript(() => {
        Object.defineProperty(History.prototype, 'length', { configurable: true, get: () => 1 });
      });
      await open(page, 'logout');
      expect(await page.evaluate(() => window.history.length)).toBe(1);
      const posts: string[] = [];
      page.on('request', (request) => {
        if (request.method() === 'POST') posts.push(new URL(request.url()).pathname);
      });
      await card(page).getByRole('button', { name: text.stay }).click();

      await expect(heading(page)).toHaveText(text.stillSignedIn);
      await expect(heading(page)).toBeFocused();
      await expect(card(page)).toContainText(text.canClose);
      await expect(card(page).getByRole('button')).toHaveCount(0);
      await expect(page).toHaveTitle(`${text.stillSignedIn} – ${TENANT}`);
      expect(new URL(page.url()).searchParams.get('fixture')).toBe('logout');
      expect(posts).toEqual([]);
      await expectAxe(page);
    });

    test('Stay signed in sends no request and goes back', async ({ page }) => {
      await page.goto('/login/?fixture=generic_error');
      await open(page, 'logout');

      const posts: string[] = [];
      page.on('request', (request) => {
        if (request.method() === 'POST') posts.push(new URL(request.url()).pathname);
      });
      await card(page).getByRole('button', { name: text.stay }).click();
      await page.waitForURL((url) => url.searchParams.get('fixture') === 'generic_error');
      expect(posts).toEqual([]);
    });

    test('Log out posts the parameters back with the logout CSRF token and shows "You\'re logged out." with no action', async ({ page }) => {
      await open(page, 'logout');
      const posted = apiPost(page, '/login/api/logout');
      await card(page).getByRole('button', { name: text.logOut, exact: true }).click();
      const request = await posted;

      expect(request.headers()['x-gatekeep-csrf']).toBe(LOGOUT_CSRF);
      expect(request.postDataJSON()).toEqual({ idTokenHint: null, postLogoutRedirectUri: null, state: null, clientId: null });
      await expect(heading(page)).toHaveText(text.loggedOut);
      await expect(heading(page)).toBeFocused();
      await expect(card(page).getByRole('button')).toHaveCount(0);
      await expect(card(page).getByRole('link')).toHaveCount(0);
      await expect(page).toHaveTitle(`${text.loggedOut} – ${TENANT}`);
      expect(new URL(page.url()).origin).toBe(new URL(request.url()).origin);
      await expectAxe(page);
    });

    test('A completed logout with no redirect shows "You\'re logged out." with its success icon', async ({ page }) => {
      await open(page, 'logged_out');
      await expect(heading(page)).toHaveText(text.loggedOut);
      await expect(card(page).locator('[data-status="success"]')).toBeVisible();
      await expect(card(page).getByRole('button')).toHaveCount(0);
      await expectAxe(page);
    });

    for (const fixture of Object.keys(HOSTILE_LOGOUT_TARGETS)) {
      test(`A completed logout whose redirectTo isn't a safe URL (${fixture}) is never followed`, async ({ page }) => {
        await open(page, fixture);
        await expect(card(page)).toContainText('invalid_step');
        expect(new URL(page.url()).searchParams.get('fixture')).toBe(fixture);
      });
    }
  });

  test.describe(`Logout back to the Application in ${scheme}`, () => {
    test.use({ colorScheme: scheme });

    /** The Application's logout page, answered here: the only other origin these tests reach. */
    async function application(page: Page, baseURL: string | undefined) {
      const elsewhere: string[] = [];
      const own = baseURL ? new URL(baseURL).origin : null;
      page.on('request', (request) => {
        const url = new URL(request.url());
        if (url.protocol.startsWith('http') && url.origin !== own && url.origin !== new URL(APP_LOGOUT_URL).origin) {
          elsewhere.push(request.url());
        }
      });
      await page.route(`${new URL(APP_LOGOUT_URL).origin}/**`, (route) =>
        route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>Signed out</title><p>Application</p>' }),
      );
      return elsewhere;
    }

    test('Log out with a valid hint and a registered URL leaves by a top-level GET to it, with state', async ({ page, baseURL }) => {
      const elsewhere = await application(page, baseURL);
      await open(page, 'logout_redirect');
      await expectAxe(page);

      const posted = apiPost(page, '/login/api/logout');
      const navigation = page.waitForRequest((request) => request.url().startsWith(APP_LOGOUT_URL));
      await card(page).getByRole('button', { name: text.logOut, exact: true }).click();
      const request = await posted;
      expect(request.headers()['x-gatekeep-csrf']).toBe(LOGOUT_CSRF);
      expect(request.postDataJSON()).toEqual({ idTokenHint: ID_TOKEN_HINT, postLogoutRedirectUri: APP_LOGOUT_URL, state: LOGOUT_STATE, clientId: null });

      const leaving = await navigation;
      expect(leaving.method()).toBe('GET');
      expect(leaving.isNavigationRequest()).toBe(true);
      expect(leaving.frame()).toBe(page.mainFrame());
      // The page's Referrer-Policy: no-referrer keeps the confirmation's URL, and any hint in it, from the Application.
      expect(leaving.headers()['referer']).toBeUndefined();
      await page.waitForURL(`${APP_LOGOUT_URL}?state=${LOGOUT_STATE}`);
      expect(elsewhere).toEqual([]);
    });

    test('A completed logout with a redirect goes there at once, with no request of its own', async ({ page, baseURL }) => {
      const elsewhere = await application(page, baseURL);
      const posts: string[] = [];
      page.on('request', (request) => {
        if (request.method() === 'POST') posts.push(request.url());
      });
      // The page leaves while it loads, so only its commit is awaited.
      await page.goto('/login/?fixture=logged_out_redirect', { waitUntil: 'commit' });
      await page.waitForURL(`${APP_LOGOUT_URL}?state=${LOGOUT_STATE}`);
      expect(posts).toEqual([]);
      expect(elsewhere).toEqual([]);
    });
  });
}
