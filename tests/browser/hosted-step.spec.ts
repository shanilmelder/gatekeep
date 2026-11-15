// The Story 4.1 matrix's browser rows, on the built Hosted Login bundle served as Host.Hosted serves
// it (hosted-step-server.mjs): the step page with its embedded JSON and theme link, under the exact
// AD-21 CSP. Rendered, No JS, Hostile name and Bad step JSON, in light and dark, with watchCsp
// failing any violation or request to another origin. Expected values come from the generated
// tokens and the catalogue, never from hex here.

import AxeBuilder from '@axe-core/playwright';
import { tokens } from '@gatekeep/design-tokens';
import { expect, test, type Page, type Request } from '@playwright/test';
import { watchCsp } from './csp-watch';

watchCsp(test);

/** The catalogue's defaults (packages/ui/src/messages.tsx) the page shows. */
const messages = {
  genericErrorTitle: 'Something went wrong',
  genericErrorBody: "We couldn't complete this request. Go back and try again.",
  hostedNoScript: 'Sign-in needs JavaScript. Turn it on in your browser, then reload this page.',
  hostedFallbackTitle: 'Sign in',
};

/** The harness's fixture step (hosted-step-server.mjs). */
const TENANT = 'Northwind';
const CODE = 'invalid_request';
const TRACE = '4bf92f3577b34da6a3ce929d0e0e4736';
const HOSTILE = '</script><b>x';

const card = (page: Page) => page.locator('[data-hosted-card]');
const heading = (page: Page) => page.getByRole('heading', { level: 1 });
const reference = (page: Page, which: 'code' | 'trace') => page.locator(`[data-reference="${which}"]`);

/** Every request the page makes from now on. */
function requests(page: Page) {
  const seen: Request[] = [];
  page.on('request', (request) => seen.push(request));
  return seen;
}

/** A token's #rrggbb as the rgb() form getComputedStyle returns. */
function rgb(hex: string) {
  const n = parseInt(hex.slice(1), 16);
  return `rgb(${n >> 16}, ${(n >> 8) & 255}, ${n & 255})`;
}

async function open(page: Page, fixture?: string) {
  const response = await page.goto(fixture ? `/login/?fixture=${fixture}` : '/login/');
  await expect(card(page)).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  return response!;
}

for (const scheme of ['light', 'dark'] as const) {
  test.describe(`in ${scheme}`, () => {
    test.use({ colorScheme: scheme });

    test('Rendered: Generic error from the embedded step, with no request but the page, its CSS, JS, fonts and theme', async ({ page, baseURL }) => {
      const origin = new URL(baseURL!).origin;
      const seen = requests(page);

      const response = await open(page);
      await page.waitForLoadState('networkidle');

      expect(response.status()).toBe(400);
      expect(response.headers()['cache-control']).toBe('no-store');
      await expect(heading(page)).toHaveText(messages.genericErrorTitle);
      await expect(card(page)).toContainText(messages.genericErrorBody);
      await expect(reference(page, 'code')).toHaveText(CODE);
      await expect(reference(page, 'trace')).toHaveText(TRACE);
      await expect(page).toHaveTitle(`${messages.genericErrorTitle} – ${TENANT}`);
      await expect(card(page).locator('[data-variant="primary"]')).toHaveCount(0);
      await expect(page.locator('a')).toHaveCount(0);

      // Nothing fetched: only the document and what it links.
      const kinds = seen.map((request) => ({ type: request.resourceType(), path: new URL(request.url()).pathname, origin: new URL(request.url()).origin }));
      expect(kinds.every((kind) => kind.origin === origin)).toBe(true);
      expect(kinds.filter((kind) => kind.type === 'fetch' || kind.type === 'xhr')).toEqual([]);
      for (const kind of kinds) {
        expect(kind.path, `${kind.type} ${kind.path}`).toMatch(
          /^\/login\/(?:|assets\/[\w.-]+\.(?:js|css|woff2)|theme\/[0-9a-f]{16}\.css)$/,
        );
      }
      expect(kinds.filter((kind) => kind.type === 'document')).toHaveLength(1);
      expect(kinds.filter((kind) => kind.path.startsWith('/login/theme/'))).toHaveLength(1);

      // The theme stylesheet is linked in head, and its tokens are the ones in force for the scheme.
      expect(await page.locator('head link[rel="stylesheet"][href^="/login/theme/"]').count()).toBe(1);
      const frame = page.locator('main').locator('..');
      expect(await frame.getAttribute('data-gk-theme')).not.toBeNull();
      expect(await frame.evaluate((element) => getComputedStyle(element).backgroundColor)).toBe(rgb(tokens.schemes[scheme].bg));
      expect(await frame.evaluate((element) => getComputedStyle(element).getPropertyValue('--gk-color-ac').trim())).toBe(tokens.schemes[scheme].ac);
    });

    test('Rendered: focus on the heading, one main, lang and the title, reflow at 320px, and axe passes', async ({ page }) => {
      await open(page);

      await expect(heading(page)).toBeFocused();
      await expect(page.locator('main')).toHaveCount(1);
      await expect(page.getByRole('main')).toHaveCount(1);
      expect(await page.evaluate(() => document.documentElement.lang)).toBe('en');
      expect(await page.evaluate(() => document.documentElement.dataset)).toEqual({ gkSurface: 'hosted', gkScheme: 'auto' });

      await page.setViewportSize({ width: 320, height: 640 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
      const box = await card(page).boundingBox();
      expect(box!.x).toBeGreaterThanOrEqual(0);
      expect(box!.x + box!.width).toBeLessThanOrEqual(320);

      await page.evaluate(() => Promise.allSettled(document.getAnimations().map((animation) => animation.finished)));
      const results = await new AxeBuilder({ page }).analyze();
      expect(results.violations.map((violation) => ({ id: violation.id, nodes: violation.nodes.map((node) => node.target) }))).toEqual([]);
    });

    test('Hostile name: the JSON is escaped, and the page shows the literal name with no injected element', async ({ page, request }) => {
      const raw = await (await request.get('/login/?fixture=hostile')).text();
      expect(raw).not.toContain(HOSTILE);
      expect(raw).toContain('\\u003c/script\\u003e\\u003cb\\u003ex');

      await open(page, 'hostile');

      await expect(page).toHaveTitle(`${messages.genericErrorTitle} – ${HOSTILE}`);
      await expect(card(page).getByRole('img', { name: `${HOSTILE} logo` })).toBeVisible();
      await expect(page.locator('b')).toHaveCount(0);
      expect(await page.locator('script').count()).toBe(await page.locator('script[src], script[type="application/json"]').count());
      expect(JSON.parse(await page.locator('#gk-step').textContent() ?? '').data.tenant).toBe(HOSTILE);
    });

    for (const fixture of ['unknown', 'broken', 'missing']) {
      test(`Bad step JSON (${fixture}): Generic error with invalid_step and no trace ID`, async ({ page }) => {
        await open(page, fixture);

        await expect(heading(page)).toHaveText(messages.genericErrorTitle);
        await expect(reference(page, 'code')).toHaveText('invalid_step');
        await expect(reference(page, 'trace')).toHaveCount(0);
        await expect(heading(page)).toBeFocused();
      });
    }
  });
}

test.describe('with JavaScript off', () => {
  test.use({ javaScriptEnabled: false });

  test('No JS: the fixed noscript text shows, and the fallback title names no Tenant and never Gatekeep', async ({ page }) => {
    await page.goto('/login/');

    // Playwright's text engine skips noscript, so the paragraph is found by its place.
    const text = page.locator('noscript > p');
    await expect(text).toBeVisible();
    await expect(text).toHaveText(messages.hostedNoScript);
    await expect(page).toHaveTitle(messages.hostedFallbackTitle);
    await expect(card(page)).toHaveCount(0);
  });
});
