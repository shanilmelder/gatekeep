// The Story 1.18 matrix, row by row, on the Hosted fixture (tests/browser/fixture at
// ?page=hosted): the page frame, the card, the status icon, the social row, the alert dialog
// and the Generic error screen from @gatekeep/hosted-screens, in both schemes, following the
// device, and under a test-only Tenant theme. Driven by keyboard and pointer in Chromium,
// never by snapshot. Expected values come from the generated tokens, never from hex here,
// except the test theme's own overrides, which mirror fixture/src/hosted-theme.css.

import AxeBuilder from '@axe-core/playwright';
import { tokens } from '@gatekeep/design-tokens';
import { expect, test, type Locator, type Page } from '@playwright/test';

type Scheme = 'light' | 'dark';

/** The fixture's error code and trace ID (fixture/src/HostedFixture.tsx). */
const ERROR_CODE = 'invalid_request';
const TRACE_ID = '7f2c9a1e4b3d';
/** The test theme's overrides (fixture/src/hosted-theme.css). */
const THEME = {
  light: { ac: '#6d28d9', onAc: '#ffffff' },
  dark: { ac: '#a78bfa', onAc: '#1e1b4b' },
  controlRadius: '2px',
  cardRadius: '4px',
};
/** The catalogue's defaults (packages/ui/src/messages.tsx) the screen shows. */
const messages = {
  genericErrorTitle: 'Something went wrong',
  genericErrorBody: "We couldn't complete this request. Go back and try again.",
  errorCode: 'Code',
  traceId: 'Trace ID',
  copy: 'Copy',
};

const px = (value: string) => parseFloat(value);

/** A token's #rrggbb as the rgb() form getComputedStyle returns. */
function rgb(hex: string) {
  const n = parseInt(hex.slice(1), 16);
  return `rgb(${n >> 16}, ${(n >> 8) & 255}, ${n & 255})`;
}

async function open(page: Page, query = '') {
  await page.goto(`/?page=hosted${query}`);
  await expect(page.locator('[data-hosted-card]')).toBeVisible();
}

/** Resolves a CSS value, such as a token variable or a shadow, to its computed form inside `scope`. */
async function resolve(scope: Locator, property: 'color' | 'boxShadow', value: string) {
  return scope.evaluate(
    (element, [property, value]) => {
      const probe = document.createElement('span');
      probe.style[property as 'color'] = value!;
      element.append(probe);
      const resolved = getComputedStyle(probe)[property as 'color'];
      probe.remove();
      return resolved;
    },
    [property, value],
  );
}

/** Collects every console.error from now on. */
function errors(page: Page) {
  const seen: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'error') seen.push(message.text());
  });
  return seen;
}

/** Waits for every running animation to finish, so axe and colour reads see final values. */
const still = (page: Page) =>
  // allSettled: an animation cancelled meanwhile (a closing dialog, a re-render) rejects its
  // finished promise with an AbortError, and that animation is done as well.
  page.evaluate(() => Promise.allSettled(document.getAnimations().map((animation) => animation.finished)).then(() => undefined));

const card = (page: Page) => page.locator('[data-hosted-card]');
const hostedPage = (page: Page) => page.getByTestId('hosted-page');
const primary = (page: Page) => card(page).locator('[data-variant="primary"]');
const alert = (page: Page) => page.getByTestId('alert');
const isOpen = (locator: Locator) => locator.evaluate((element) => (element as HTMLDialogElement).open && element.matches(':modal'));
const activeInside = (locator: Locator) => locator.evaluate((element) => element.contains(document.activeElement));

/**
 * Every visible text node under `root`, outside aria-hidden decoration, with its computed
 * colour, and whether it sits on the accent (the primary button or the logo initial).
 */
function texts(root: Locator) {
  return root.evaluate((element) => {
    const found: { text: string; color: string; onAccent: boolean }[] = [];
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = node.textContent?.trim() ?? '';
      const parent = node.parentElement;
      if (!text || !parent || parent.closest('[aria-hidden="true"]')) continue;
      if (!parent.checkVisibility({ visibilityProperty: true, opacityProperty: true })) continue;
      found.push({
        text,
        color: getComputedStyle(parent).color,
        onAccent: !!parent.closest('[data-variant="primary"], [data-logo="initial"]'),
      });
    }
    return found;
  });
}

/** The page's tx, tx2, tx3 and on-ac, resolved in the Hosted scope. */
async function textColours(scope: Locator) {
  const [tx, tx2, tx3, onAc] = await Promise.all(
    ['tx', 'tx2', 'tx3', 'on-ac'].map((name) => resolve(scope, 'color', `var(--gk-color-${name})`)),
  );
  return { tx: tx!, tx2: tx2!, tx3: tx3!, onAc: onAc! };
}

async function expectScheme(page: Page, scheme: Scheme) {
  const values = tokens.schemes[scheme];
  await still(page);
  await expect(hostedPage(page)).toHaveCSS('background-color', rgb(values.bg));
  await expect(card(page)).toHaveCSS('background-color', rgb(values.sf));
  await expect(card(page)).toHaveCSS('border-top-color', rgb(values.bd));
  await expect(card(page)).toHaveCSS('box-shadow', await resolve(hostedPage(page), 'boxShadow', values.sh));
  await expect(primary(page)).toHaveCSS('background-color', rgb(values.ac));
}

// Pinned: the card's width and the focus trap depend on it.
test.use({ permissions: ['clipboard-read', 'clipboard-write'], viewport: { width: 1280, height: 720 } });

test('the Hosted building blocks are shared: the hosted entry exports them, and admin the very same modules', async ({ page }) => {
  await open(page, '&scheme=light');
  const html = page.locator('html');
  await expect(html).toHaveAttribute('data-same-modules', 'true');
  const hosted = (await html.getAttribute('data-hosted-exports'))!.split(' ');
  const adminOnly = (await html.getAttribute('data-admin-only-exports'))!.split(' ');
  for (const name of ['AlertDialog', 'ButtonLink', 'ErrorReference', 'HostedCard', 'HostedPage', 'SOCIAL_MAX', 'SocialButtons', 'StatusIcon']) {
    expect(hosted, name).toContain(name);
    expect(adminOnly, name).not.toContain(name);
  }
});

test.describe('page and card', () => {
  test('Card order: logo tile, status icon, h1, subtitle, code line, primary action, in DOM order', async ({ page }) => {
    await open(page, '&scheme=light');
    const parts = [
      card(page).locator('[data-logo]'),
      card(page).locator('[data-status]'),
      card(page).getByRole('heading', { level: 1 }),
      card(page).getByText(messages.genericErrorBody, { exact: true }),
      card(page).locator('[data-reference="code"]'),
      primary(page),
    ];
    for (const part of parts) await expect(part).toHaveCount(1);
    const handles = await Promise.all(parts.map((part) => part.elementHandle()));
    const ordered = await page.evaluate(
      (elements) => elements.every((element, index) => index === 0 || !!(elements[index - 1]!.compareDocumentPosition(element!) & Node.DOCUMENT_POSITION_FOLLOWING)),
      handles,
    );
    expect(ordered).toBe(true);

    // One main landmark, on the Hosted surface, holding the one card.
    await expect(page.getByRole('main')).toHaveCount(1);
    await expect(hostedPage(page)).toHaveAttribute('data-gk-surface', 'hosted');
    await expect(page.getByRole('main').locator('[data-hosted-card]')).toHaveCount(1);
  });

  test('Generic error shows the fixed text, the code and trace ID in Geist Mono, and Back to the Tenant, nothing else', async ({ page }) => {
    await open(page, '&scheme=light');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(messages.genericErrorTitle);
    const back = page.getByRole('link', { name: 'Back to Northwind' });
    await expect(back).toHaveAttribute('href', '/?page=hosted&back=1');
    await expect(back).toHaveAttribute('data-variant', 'primary');
    for (const reference of ['code', 'trace']) {
      expect(await card(page).locator(`[data-reference="${reference}"]`).evaluate((element) => getComputedStyle(element).fontFamily)).toContain('Geist Mono');
    }
    // The code and trace ID are the only variable detail (FR-33), and it names the Tenant, never Gatekeep.
    expect((await texts(card(page))).map(({ text }) => text)).toEqual([
      'N',
      messages.genericErrorTitle,
      messages.genericErrorBody,
      messages.errorCode,
      ERROR_CODE,
      messages.traceId,
      TRACE_ID,
      messages.copy,
      'Back to Northwind',
    ]);
    expect(await page.locator('body').innerText()).not.toMatch(/gatekeep/i);
  });

  test('never Gatekeep: not in the text, the accessible names, alt, aria-label or title, with either logo', async ({ page }) => {
    for (const query of ['&scheme=light', '&scheme=light&logo=image', '&scheme=light&screen=kit']) {
      await open(page, query);
      expect(await page.locator('body').ariaSnapshot(), query).not.toMatch(/gatekeep/i);
      const named = await page.evaluate(() =>
        [...document.body.querySelectorAll('[alt], [aria-label], [title], [aria-description]')].flatMap((element) =>
          ['alt', 'aria-label', 'title', 'aria-description'].map((name) => element.getAttribute(name) ?? ''),
        ),
      );
      expect(named.filter((value) => /gatekeep/i.test(value)), query).toEqual([]);
    }
  });

  test('without a validated Application to go back to there is no primary action, and nothing redirects', async ({ page }) => {
    await open(page, '&scheme=light&back=none');
    await expect(card(page).getByRole('heading', { level: 1 })).toHaveText(messages.genericErrorTitle);
    await expect(primary(page)).toHaveCount(0);
    await expect(card(page).getByRole('link')).toHaveCount(0);
    await expect(card(page).locator('[data-reference="trace"]')).toHaveText(TRACE_ID);
  });

  test('a primary ButtonLink takes the focus ring tokens on Tab', async ({ page }) => {
    await open(page, '&scheme=light');
    const back = page.getByRole('link', { name: 'Back to Northwind' });
    for (let index = 0; index < 4 && !(await back.evaluate((element) => element === document.activeElement)); index += 1) {
      await page.keyboard.press('Tab');
    }
    await expect(back).toBeFocused();
    expect(await back.evaluate((element) => element.matches(':focus-visible'))).toBe(true);
    const ring = tokens.components['focus-ring'];
    await expect(back).toHaveCSS('outline-style', ring['outline-style']);
    await expect(back).toHaveCSS('outline-width', ring['outline-width']);
    await expect(back).toHaveCSS('outline-offset', ring['outline-offset']);
    await expect(back).toHaveCSS('outline-color', rgb(tokens.schemes.light.ac));
    await expect(back).toHaveCSS('text-decoration-line', 'none');
  });

  test('the card sits on its hosted-card tokens', async ({ page }) => {
    await open(page, '&scheme=light');
    await expect(card(page)).toHaveCSS('border-top-width', '1px');
    await expect(card(page)).toHaveCSS('border-top-left-radius', tokens.rounded.modal);
    await expect(card(page)).toHaveCSS('padding-top', tokens.spacing['hosted-card-padding']);
    await expect(card(page)).toHaveCSS('padding-left', tokens.spacing['hosted-card-padding']);
    await expectScheme(page, 'light');
    const title = card(page).getByRole('heading', { level: 1 });
    await expect(title).toHaveCSS('font-size', tokens.typography['page-title'].fontSize);
    await expect(title).toHaveCSS('font-weight', String(tokens.typography['page-title'].fontWeight));
    expect(await title.evaluate((element) => getComputedStyle(element).fontFamily)).toContain('Geist');
  });

  test('Card sizing: 384px at 1280px, and the width less a 16px gutter at 360px, centred', async ({ page }) => {
    await open(page, '&scheme=light');
    expect((await card(page).boundingBox())!.width).toBe(px(tokens.spacing['hosted-card-w']));
    let box = (await card(page).boundingBox())!;
    expect(box.x + box.width / 2).toBeCloseTo(640, 0);

    // 416px is where the full width less the gutters meets 384px; below it the card shrinks.
    for (const [viewport, width] of [
      [416, 384],
      [400, 368],
      [360, 328],
    ] as const) {
      await page.setViewportSize({ width: viewport, height: 720 });
      box = (await card(page).boundingBox())!;
      expect(box.width, `at ${viewport}px`).toBe(width);
      expect(box.x, `at ${viewport}px`).toBe(16);
    }
  });

  test('the kit card keeps the order: header, content, primary action, quiet link', async ({ page }) => {
    await open(page, '&scheme=light&screen=kit');
    const parts = [
      card(page).getByRole('heading', { level: 1 }),
      page.getByTestId('social'),
      page.getByTestId('email'),
      page.getByTestId('continue'),
      page.getByTestId('help'),
    ];
    const handles = await Promise.all(parts.map((part) => part.elementHandle()));
    const ordered = await page.evaluate(
      (elements) => elements.every((element, index) => index === 0 || !!(elements[index - 1]!.compareDocumentPosition(element!) & Node.DOCUMENT_POSITION_FOLLOWING)),
      handles,
    );
    expect(ordered).toBe(true);
    // The quiet link is plain at rest, in tx2, and the primary action is full width.
    const help = page.getByTestId('help');
    await expect(help).toHaveCSS('text-decoration-line', 'none');
    await expect(help).toHaveCSS('color', rgb(tokens.schemes.light.tx2));
    const content = await card(page).evaluate((element) => element.clientWidth - 2 * parseFloat(getComputedStyle(element).paddingLeft));
    expect((await page.getByTestId('continue').boundingBox())!.width).toBeCloseTo(content, 0);
  });

  test('Control min-height: at 200% text the button and input grow from 44px, nothing clips, and the page scrolls', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 600 });
    await open(page, '&scheme=light&screen=kit');
    const minimum = px(tokens.spacing['control-h-hosted']);
    const button = page.getByTestId('continue');
    const input = page.getByTestId('email');
    expect((await button.boundingBox())!.height).toBe(minimum);
    expect((await input.boundingBox())!.height).toBe(minimum);
    await expect(button).toHaveCSS('min-height', `${minimum}px`);
    await expect(input).toHaveCSS('min-height', `${minimum}px`);
    await expect(button).toHaveCSS('height', `${minimum}px`);

    // The tokens are px, so the root font size alone changes nothing: double every Hosted
    // type token as well, which is what 200% text does to them.
    const double = (name: 'hosted-body' | 'hosted-button' | 'hosted-label' | 'page-title' | 'helper' | 'section') => {
      const style = tokens.typography[name];
      return `--gk-font-${name}: ${style.fontWeight} ${px(style.fontSize) * 2}px/${px(style.lineHeight) * 2}px var(--gk-font-${name}-family);`;
    };
    await page.addStyleTag({
      content: `html { font-size: 200%; }\n:root, html [data-gk-scheme], html [data-gk-theme] { ${(['hosted-body', 'hosted-button', 'hosted-label', 'page-title', 'helper', 'section'] as const).map(double).join(' ')} }`,
    });
    await expect(button).toHaveCSS('font-size', `${px(tokens.typography['hosted-button'].fontSize) * 2}px`);
    await expect(input).toHaveCSS('font-size', `${px(tokens.typography['hosted-body'].fontSize) * 2}px`);
    expect((await button.boundingBox())!.height).toBeGreaterThanOrEqual(minimum);
    // The input holds a whole doubled line: its height is at least its line-height, padding and borders.
    const needed = await input.evaluate((element) => {
      const s = getComputedStyle(element);
      return [s.lineHeight, s.paddingTop, s.paddingBottom, s.borderTopWidth, s.borderBottomWidth].reduce((sum, value) => sum + parseFloat(value), 0);
    });
    expect(needed).toBeGreaterThanOrEqual(px(tokens.typography['hosted-body'].lineHeight) * 2);
    expect((await input.boundingBox())!.height).toBeGreaterThanOrEqual(Math.max(minimum, needed));

    // A long label wraps onto more than one line, inside a button that grows past 44px.
    const long = page.getByTestId('long');
    const lines = await long.evaluate((element) => {
      // The text nodes' own line boxes, not the label element's box around them.
      const tops = new Set<number>();
      const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        const range = document.createRange();
        range.selectNodeContents(node);
        for (const rect of range.getClientRects()) tops.add(Math.round(rect.top));
      }
      return tops.size;
    });
    expect(lines).toBeGreaterThan(1);
    const longBox = (await long.boundingBox())!;
    expect(longBox.height).toBeGreaterThan(minimum);
    const labelBox = await long.evaluate((element) => {
      const range = document.createRange();
      range.selectNodeContents(element);
      const rect = range.getBoundingClientRect();
      return { top: rect.top, bottom: rect.bottom, left: rect.left, right: rect.right };
    });
    expect(labelBox.top).toBeGreaterThanOrEqual(longBox.y);
    expect(labelBox.bottom).toBeLessThanOrEqual(longBox.y + longBox.height + 0.5);
    expect(labelBox.left).toBeGreaterThanOrEqual(longBox.x);
    expect(labelBox.right).toBeLessThanOrEqual(longBox.x + longBox.width + 0.5);

    // Nothing is clipped: every button's and link's content fits inside it.
    for (const control of await card(page).locator('button:visible, a:visible').all()) {
      const fits = await control.evaluate((element) => element.scrollHeight <= element.clientHeight + 1 && element.scrollWidth <= element.clientWidth + 1);
      expect(fits, await control.evaluate((element) => element.outerHTML.slice(0, 80))).toBe(true);
    }
    expect(await card(page).evaluate((element) => element.scrollHeight <= element.clientHeight + 1)).toBe(true);
    // The card is taller than the window: the page scrolls to it rather than clipping its top.
    const box = (await card(page).boundingBox())!;
    expect(box.y).toBeGreaterThanOrEqual(0);
    expect(box.height).toBeGreaterThan(600);
    const scroll = await page.evaluate(() => ({ height: document.scrollingElement!.scrollHeight, view: innerHeight }));
    expect(scroll.height).toBeGreaterThanOrEqual(box.y + box.height);
    expect(scroll.height).toBeGreaterThan(scroll.view);
  });

  test('Logo: the Tenant initial on ac, or the image named "{Tenant} logo"', async ({ page }) => {
    await open(page, '&scheme=light');
    const initial = card(page).getByRole('img', { name: 'Northwind logo' });
    await expect(initial).toHaveAttribute('data-logo', 'initial');
    await expect(initial).toHaveText('N');
    await expect(initial).toHaveCSS('background-color', rgb(tokens.schemes.light.ac));
    await expect(initial).toHaveCSS('color', rgb(tokens.schemes.light['on-ac']));
    let box = (await initial.boundingBox())!;
    expect([box.width, box.height]).toEqual([42, 42]);

    await open(page, '&scheme=light&logo=image');
    const image = card(page).getByRole('img', { name: 'Northwind logo' });
    await expect(image).toHaveAttribute('data-logo', 'image');
    await expect(image).toHaveAttribute('alt', 'Northwind logo');
    expect(await image.evaluate((element) => (element as HTMLImageElement).complete && (element as HTMLImageElement).naturalWidth > 0)).toBe(true);
    box = (await image.boundingBox())!;
    expect([box.width, box.height]).toEqual([42, 42]);
  });

  test('Logo: an image that fails to load falls back to the initial tile', async ({ page }) => {
    await open(page, '&scheme=light&logo=broken');
    const tile = card(page).getByRole('img', { name: 'Northwind logo' });
    await expect(tile).toHaveAttribute('data-logo', 'initial');
    await expect(tile).toHaveText('N');
    await expect(card(page).locator('img')).toHaveCount(0);
  });

  test('Logo: an explicit initial, and one grapheme from a name with format characters or an emoji', async ({ page }) => {
    const tile = () => card(page).locator('[data-logo="initial"]');
    await open(page, '&scheme=light&initial=W');
    await expect(tile()).toHaveText('W');
    // A longer initial is cut to its first grapheme, and a blank one falls back to the name's.
    await open(page, '&scheme=light&initial=wx');
    await expect(tile()).toHaveText('W');
    await open(page, '&scheme=light&initial=%20');
    await expect(tile()).toHaveText('N');
    // A bidi override never starts the initial, nor reorders the tile.
    await open(page, '&scheme=light&tenant=bidi');
    await expect(tile()).toHaveText('A');
    // A joined emoji is one grapheme, kept whole, and the tile clips anything wider.
    await open(page, '&scheme=light&tenant=emoji');
    await expect(tile()).toHaveText('👩‍💻');
    await expect(tile()).toHaveCSS('overflow', 'hidden');
    const box = (await tile().boundingBox())!;
    expect([box.width, box.height]).toEqual([42, 42]);
  });

  test('Logo: a blank Tenant name logs a console.error and renders safely, with no unnamed image', async ({ page }) => {
    const seen = errors(page);
    await open(page, '&scheme=light&tenant=blank&logo=image');
    const tile = card(page).locator('[data-logo]');
    await expect(tile).toHaveAttribute('data-logo', 'initial');
    await expect(tile).toHaveAttribute('aria-hidden', 'true');
    await expect(tile).toHaveText('');
    await expect(card(page).getByRole('img')).toHaveCount(0);
    await expect.poll(() => seen.some((text) => text.includes('HostedCard: the Tenant name is empty'))).toBe(true);
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`StatusIcon: each status's glyph on its -sf surface, decorative, in the ${scheme} scheme`, async ({ page }) => {
      await open(page, `&scheme=${scheme}&screen=status`);
      const values = tokens.schemes[scheme];
      const statuses = [
        ['success', '✓', 'ok-sf', 'ok'],
        ['warning', '@', 'warn-sf', 'warn'],
        ['error', '!', 'bad-sf', 'bad'],
        ['blocked', '⊘', 'bad-sf', 'bad'],
      ] as const;
      const size = px(tokens.components['status-icon'].size);
      for (const [status, glyph, surface, tone] of statuses) {
        const icon = page.getByTestId(`status-${status}`);
        await expect(icon, status).toHaveAttribute('aria-hidden', 'true');
        await expect(icon, status).toHaveAttribute('data-status', status);
        await expect(icon, status).toHaveText(glyph);
        await expect(icon, status).toHaveCSS('background-color', rgb(values[surface]));
        await expect(icon, status).toHaveCSS('color', rgb(values[tone]));
        await expect(icon, status).toHaveCSS('border-top-left-radius', tokens.rounded.full);
        const box = (await icon.boundingBox())!;
        expect([box.width, box.height], status).toEqual([size, size]);
      }
      // An unknown status, even one named after an Object.prototype key, draws the error look.
      await expect(page.getByTestId('status-unknown')).toHaveAttribute('data-status', 'error');
      await expect(page.getByTestId('status-unknown')).toHaveText('!');
    });
  }

  for (const scheme of ['light', 'dark'] as const) {
    for (const screen of ['error', 'kit'] as const) {
      test(`Text contrast: every text node is tx or tx2, never tx3, on ${screen} in the ${scheme} scheme`, async ({ page }) => {
        await open(page, `&scheme=${scheme}&screen=${screen}`);
        await still(page);
        const colours = await textColours(hostedPage(page));
        const check = async (root: Locator) => {
          const found = await texts(root);
          expect(found.length).toBeGreaterThan(0);
          for (const { text, color, onAccent } of found) {
            expect(color, text).not.toBe(colours.tx3);
            expect(onAccent ? [colours.onAc] : [colours.tx, colours.tx2], text).toContain(color);
          }
        };
        await check(hostedPage(page));
        if (screen === 'kit') {
          // Placeholders are text too: tx2 on Hosted Login.
          expect(await page.getByTestId('email').evaluate((element) => getComputedStyle(element, '::placeholder').color)).toBe(colours.tx2);
          await page.getByTestId('open-alert').click();
          await still(page);
          await check(alert(page));
        }
      });
    }
  }
});

test.describe('colour scheme', () => {
  test('Scheme auto: the dark tokens under an emulated dark scheme, the light ones under light, with no script', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await open(page);
    await expect(hostedPage(page)).toHaveAttribute('data-gk-scheme', 'auto');
    await expect(page.locator('html')).toHaveAttribute('data-gk-scheme', 'auto');
    await expectScheme(page, 'dark');
    await expect(hostedPage(page)).toHaveCSS('color-scheme', 'dark');

    // The device changes its mind: the page follows at once, with no reload and no attribute change.
    await page.emulateMedia({ colorScheme: 'light' });
    await expectScheme(page, 'light');
    await expect(hostedPage(page)).toHaveCSS('color-scheme', 'light');
    await expect(hostedPage(page)).toHaveAttribute('data-gk-scheme', 'auto');
  });

  test('Scheme forced: scheme=dark gives the dark tokens under an emulated light scheme, and light the reverse', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await open(page, '&scheme=dark');
    await expect(hostedPage(page)).toHaveAttribute('data-gk-scheme', 'dark');
    await expectScheme(page, 'dark');

    await page.emulateMedia({ colorScheme: 'dark' });
    await open(page, '&scheme=light');
    await expectScheme(page, 'light');
  });

  test("with no scheme given, HostedPage's own default is auto and follows the device", async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/?page=hosted');
    await expect(card(page)).toBeVisible();
    await expect(hostedPage(page)).toHaveAttribute('data-gk-scheme', 'auto');
    await expectScheme(page, 'dark');
    await page.emulateMedia({ colorScheme: 'light' });
    await expectScheme(page, 'light');
  });

  test('a HostedPage under an Admin, light <html> still takes Hosted sizing, and auto follows a dark device', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await open(page, '&root=admin&scheme=auto&screen=kit');
    await expect(page.locator('html')).toHaveAttribute('data-gk-surface', 'admin');
    await expect(page.locator('html')).toHaveAttribute('data-gk-scheme', 'light');
    await expect(hostedPage(page)).toHaveAttribute('data-gk-surface', 'hosted');
    const hosted = tokens.spacing['control-h-hosted'];
    await expect(page.getByTestId('continue')).toHaveCSS('min-height', hosted);
    await expect(page.getByTestId('email')).toHaveCSS('min-height', hosted);
    await expect(page.getByTestId('continue')).toHaveCSS('font-size', tokens.typography['hosted-button'].fontSize);
    const dark = tokens.schemes.dark;
    await still(page);
    await expect(hostedPage(page)).toHaveCSS('background-color', rgb(dark.bg));
    await expect(card(page)).toHaveCSS('background-color', rgb(dark.sf));
    await expect(page.getByTestId('continue')).toHaveCSS('background-color', rgb(dark.ac));
    // The page behind the frame stays the Admin light canvas.
    await expect(page.locator('body')).toHaveCSS('background-color', rgb(tokens.schemes.light.bg));
  });

  test('no script sets the scheme: no inline --gk-* style on <html>, body or the HostedPage, in any scheme', async ({ page }) => {
    for (const [query, emulate] of [
      ['', 'dark'],
      ['&scheme=auto', 'light'],
      ['&scheme=dark', 'light'],
      ['&scheme=light&theme=custom', 'dark'],
    ] as const) {
      await page.emulateMedia({ colorScheme: emulate });
      await open(page, query);
      for (const target of [page.locator('html'), page.locator('body'), hostedPage(page)]) {
        const inline = await target.evaluate((element) => (element as HTMLElement).style.cssText);
        expect(inline, query).not.toMatch(/--gk-/);
      }
    }
  });

  test('a screen renders in an Admin page, inside a forced-scheme preview scope, with Hosted sizing', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await open(page, '&frame=preview&scheme=dark');
    await expect(page.locator('html')).toHaveAttribute('data-gk-surface', 'admin');
    await expect(hostedPage(page)).toHaveCount(0);
    const preview = page.getByTestId('preview');
    await expect(preview).toHaveAttribute('data-gk-scheme', 'dark');
    await expect(preview.locator('[data-hosted-card]')).toHaveCount(1);
    await expect(card(page)).toHaveCSS('background-color', rgb(tokens.schemes.dark.sf));
    await expect(primary(page)).toHaveCSS('background-color', rgb(tokens.schemes.dark.ac));
    await expect(primary(page)).toHaveCSS('min-height', tokens.spacing['control-h-hosted']);
    await expect(primary(page)).toHaveCSS('font-size', tokens.typography['hosted-button'].fontSize);
    // The Admin page holds the one h1, so the card's heading is an h2.
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(['Theme preview']);
    await expect(card(page).getByRole('heading', { level: 2 })).toHaveText(messages.genericErrorTitle);
    // The Admin page around it stays light.
    await expect(page.locator('body')).toHaveCSS('background-color', rgb(tokens.schemes.light.bg));
  });
});

test.describe('theme', () => {
  const variants = [
    { name: 'light', query: '&scheme=light', emulate: 'light', scheme: 'light' },
    { name: 'dark', query: '&scheme=dark', emulate: 'light', scheme: 'dark' },
    { name: 'auto with an emulated dark scheme', query: '&scheme=auto', emulate: 'dark', scheme: 'dark' },
  ] as const;

  for (const theme of ['custom', 'plain'] as const) {
    for (const { name, query, emulate, scheme } of variants) {
      test(`Theme variant (${theme}, ${name}): the override ac on the primary button, the override radii, the same markup`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: emulate });
        await open(page, `${query}&logo=image`);
        const untouched = await card(page).evaluate((element) => element.outerHTML);
        await expect(primary(page)).toHaveCSS('background-color', rgb(tokens.schemes[scheme].ac));

        await open(page, `${query}&logo=image&theme=${theme}`);
        await expect(hostedPage(page)).toHaveAttribute('data-gk-theme', theme);
        expect(await card(page).evaluate((element) => element.outerHTML)).toBe(untouched);
        await expect(primary(page)).toHaveCSS('background-color', rgb(THEME[scheme].ac));
        await expect(primary(page)).toHaveCSS('color', rgb(THEME[scheme].onAc));
        await expect(primary(page)).toHaveCSS('border-top-left-radius', THEME.controlRadius);
        await expect(card(page)).toHaveCSS('border-top-left-radius', THEME.cardRadius);
        await expect(card(page).locator('[data-logo]')).toHaveCSS('border-top-left-radius', THEME.controlRadius);
        // Surfaces aren't themeable: the card keeps the scheme's sf.
        await expect(card(page)).toHaveCSS('background-color', rgb(tokens.schemes[scheme].sf));
        // The font stays the bundled Geist.
        expect(await card(page).getByRole('heading', { level: 1 }).evaluate((element) => getComputedStyle(element).fontFamily)).toMatch(/^"?Geist"?,/);

        // The controls take the theme's radius and primary too.
        await open(page, `${query}&theme=${theme}&screen=kit`);
        await expect(page.getByTestId('email')).toHaveCSS('border-top-left-radius', THEME.controlRadius);
        await expect(page.getByRole('button', { name: 'Continue with Google' })).toHaveCSS('border-top-left-radius', THEME.controlRadius);
        await expect(page.getByTestId('continue')).toHaveCSS('background-color', rgb(THEME[scheme].ac));
      });
    }
  }
});

test.describe('social row', () => {
  const social = (page: Page) => page.getByTestId('social').getByRole('button');
  const ofSocial = (seen: string[]) => seen.filter((text) => text.includes('SocialButtons'));

  test('Social row: two providers give two buttons named "Continue with {provider}"', async ({ page }) => {
    const seen = errors(page);
    await open(page, '&scheme=light&screen=kit&providers=2');
    const buttons = social(page);
    await expect(buttons).toHaveCount(2);
    await expect(page.getByRole('button', { name: 'Continue with Google', exact: true })).toHaveText('Google');
    await expect(page.getByRole('button', { name: 'Continue with GitHub', exact: true })).toHaveText('GitHub');
    // Secondary buttons at the Hosted height, side by side in one row of equal columns.
    const boxes = await Promise.all((await buttons.all()).map((button) => button.boundingBox()));
    expect(boxes[0]!.y).toBe(boxes[1]!.y);
    expect(boxes[0]!.width).toBeCloseTo(boxes[1]!.width, 0);
    expect(boxes[0]!.height).toBe(px(tokens.spacing['control-h-hosted']));
    await expect(buttons.first()).toHaveAttribute('data-variant', 'secondary');
    await expect(buttons.first()).toHaveCSS('border-top-color', rgb(tokens.schemes.light.tx3));

    await page.getByRole('button', { name: 'Continue with GitHub' }).click();
    await expect(page.getByTestId('selected')).toHaveText('github');
    expect(ofSocial(seen)).toEqual([]);
  });

  test('Social row: three providers sit in one row in the card', async ({ page }) => {
    await open(page, '&scheme=light&screen=kit');
    await expect(social(page)).toHaveText(['Google', 'GitHub', 'Microsoft']);
    const boxes = await Promise.all((await social(page).all()).map((button) => button.boundingBox()));
    expect(new Set(boxes.map((box) => box!.y)).size).toBe(1);
  });

  test('Social row: at 320px no provider name breaks mid-word', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 720 });
    await open(page, '&scheme=light&screen=kit');
    await expect(social(page)).toHaveCount(3);
    for (const button of await social(page).all()) {
      const { text, lines, fits } = await button.evaluate((element) => {
        // The text nodes' own line boxes, not the label element's box around them.
        const tops = new Set<number>();
        const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
        for (let node = walker.nextNode(); node; node = walker.nextNode()) {
          const range = document.createRange();
          range.selectNodeContents(node);
          for (const rect of range.getClientRects()) tops.add(Math.round(rect.top));
        }
        return {
          text: element.textContent ?? '',
          lines: tops.size,
          fits: element.scrollWidth <= element.clientWidth + 1,
        };
      });
      // A one-word name stays on one line; a name only wraps at its spaces, so never past its word count.
      expect(lines, text).toBeLessThanOrEqual(text.trim().split(/\s+/).length);
      expect(fits, text).toBe(true);
    }
  });

  test('Social row: one provider gives one full-width button, and none gives no row', async ({ page }) => {
    const seen = errors(page);
    await open(page, '&scheme=light&screen=kit&providers=1');
    await expect(social(page)).toHaveCount(1);
    await expect(social(page)).toHaveAccessibleName('Continue with Google');
    const row = (await page.getByTestId('social').boundingBox())!;
    expect((await social(page).first().boundingBox())!.width).toBeCloseTo(row.width, 0);

    await open(page, '&scheme=light&screen=kit&providers=0');
    await expect(page.getByTestId('social')).toHaveCount(0);
    expect(ofSocial(seen)).toEqual([]);
  });

  test('Social row: four providers render three, with a console.error', async ({ page }) => {
    const seen = errors(page);
    await open(page, '&scheme=light&screen=kit&providers=4');
    await expect(social(page)).toHaveCount(3);
    await expect(social(page)).toHaveText(['Google', 'GitHub', 'Microsoft']);
    await expect(page.getByRole('button', { name: 'Continue with GitLab' })).toHaveCount(0);
    await expect.poll(() => ofSocial(seen).some((text) => text.includes('a row holds 3'))).toBe(true);
  });

  test('Social row: a repeated provider id is dropped, with a console.error', async ({ page }) => {
    const seen = errors(page);
    await open(page, '&scheme=light&screen=kit&providers=dupe');
    await expect(social(page)).toHaveText(['Google', 'GitHub']);
    await expect.poll(() => ofSocial(seen).some((text) => text.includes('provider ids repeat (google)'))).toBe(true);
  });

  test('Social row: pending on press, only the pressed provider, and it ignores a second press', async ({ page }) => {
    await open(page, '&scheme=light&screen=kit');
    const github = page.getByRole('button', { name: 'Continue with GitHub' });
    await github.click();
    await expect(github).toHaveAttribute('aria-busy', 'true');
    await expect(github).toHaveAttribute('aria-disabled', 'true');
    await expect(github).toHaveAccessibleName('Continue with GitHub');
    for (const other of ['Google', 'Microsoft']) {
      await expect(page.getByRole('button', { name: `Continue with ${other}` })).not.toHaveAttribute('aria-busy', 'true');
    }
    // A real click on the busy button: Button cancels it, so onSelect isn't called again.
    await github.dispatchEvent('click');
    await expect(page.getByTestId('selects')).toHaveText('1');
  });
});

test.describe('alert dialog', () => {
  test('Alert dialog open: role alertdialog, named by its title, described by its body, focus on the primary action', async ({ page }) => {
    await open(page, '&scheme=light&screen=kit');
    await expect(alert(page)).toBeHidden();
    await page.getByTestId('open-alert').click();
    const dialog = page.getByRole('alertdialog');
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAttribute('data-testid', 'alert');
    expect(await isOpen(alert(page))).toBe(true);
    await expect(dialog).toHaveAccessibleName('Your session is about to end');
    await expect(dialog).toHaveAccessibleDescription('For your security, this sign-in ends in 2 minutes. Keep going to stay on this step.');
    await expect(page.getByRole('button', { name: 'Keep going' })).toBeFocused();
    // The page behind is inert: focus can't move to it.
    await page.getByTestId('continue').evaluate((element) => (element as HTMLElement).focus());
    await expect(page.getByRole('button', { name: 'Keep going' })).toBeFocused();
  });

  test('Alert dialog trap: Tab and Shift+Tab keep focus inside', async ({ page }) => {
    await open(page, '&scheme=light&screen=kit');
    await page.getByTestId('open-alert').click();
    await expect(page.getByRole('button', { name: 'Keep going' })).toBeFocused();
    for (let index = 0; index < 5; index += 1) {
      await page.keyboard.press('Tab');
      expect(await activeInside(alert(page)), `Tab ${index}`).toBe(true);
    }
    for (let index = 0; index < 5; index += 1) {
      await page.keyboard.press('Shift+Tab');
      expect(await activeInside(alert(page)), `Shift+Tab ${index}`).toBe(true);
    }
    // Both actions take a stop, and the wrap goes from one to the other.
    await page.getByRole('button', { name: 'Keep going' }).focus();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Start over' })).toBeFocused();
  });

  test('Alert dialog close: the primary action closes it, and focus returns to the trigger; so does Esc', async ({ page }) => {
    await open(page, '&scheme=light&screen=kit');
    const trigger = page.getByTestId('open-alert');
    await trigger.click();
    await expect(page.getByRole('button', { name: 'Keep going' })).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(alert(page)).toBeHidden();
    expect(await isOpen(alert(page))).toBe(false);
    await expect(trigger).toBeFocused();
    await expect(page.getByTestId('actions')).toHaveText('1');

    await trigger.press('Enter');
    await expect(page.getByRole('alertdialog')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(alert(page)).toBeHidden();
    await expect(trigger).toBeFocused();
    await expect(page.getByTestId('actions')).toHaveText('1');
  });

  const dialogs = (page: Page) => page.getByTestId('dialogs');

  for (const holder of ['Modal', 'Drawer'] as const) {
    test(`Alert dialog registry: while a ${holder} is open it refuses to open, with its console.error, and its caller falls back to closed`, async ({ page }) => {
      const seen = errors(page);
      await open(page, '&scheme=light&screen=kit');
      await page.evaluate((name) => window.gkHosted![name === 'Modal' ? 'openModal' : 'openDrawer'](), holder);
      const held = page.getByTestId(holder === 'Modal' ? 'registry-modal' : 'registry-drawer');
      await expect(held).toBeVisible();
      await page.evaluate(() => window.gkHosted!.openAlert());
      await expect.poll(() => seen.some((text) => text.startsWith('AlertDialog: a modal or drawer is already open'))).toBe(true);
      await expect(dialogs(page)).toContainText('alert:closed');
      expect(await isOpen(alert(page))).toBe(false);
      expect(await isOpen(held)).toBe(true);
    });

    test(`Alert dialog registry: while it is open a ${holder} refuses to open, and the alert dialog stays`, async ({ page }) => {
      const seen = errors(page);
      await open(page, '&scheme=light&screen=kit');
      await page.getByTestId('open-alert').click();
      expect(await isOpen(alert(page))).toBe(true);
      await page.evaluate((name) => window.gkHosted![name === 'Modal' ? 'openModal' : 'openDrawer'](), holder);
      await expect.poll(() => seen.some((text) => text.startsWith(`${holder}: a modal or drawer is already open`) || text.startsWith(`${holder}: another modal or drawer is already open`))).toBe(true);
      await expect(dialogs(page)).toContainText(holder === 'Modal' ? 'modal:closed' : 'drawer:closed');
      expect(await isOpen(alert(page))).toBe(true);
      await expect(page.getByRole('button', { name: 'Keep going' })).toBeFocused();
    });
  }

  test("Alert dialog initialFocus: focus goes to the caller's element", async ({ page }) => {
    await open(page, '&scheme=light&screen=kit&alertFocus=secondary');
    await page.getByTestId('open-alert').click();
    await expect(page.getByRole('button', { name: 'Start over' })).toBeFocused();
  });

  test('Alert dialog dismissible={false}: Escape leaves it open, and only an action closes it', async ({ page }) => {
    await open(page, '&scheme=light&screen=kit&dismissible=false');
    await page.getByTestId('open-alert').click();
    await expect(page.getByRole('button', { name: 'Keep going' })).toBeFocused();
    await page.keyboard.press('Escape');
    await page.keyboard.press('Escape');
    expect(await isOpen(alert(page))).toBe(true);
    await expect(page.getByRole('alertdialog')).toBeVisible();
    await page.getByRole('button', { name: 'Keep going' }).click();
    await expect(alert(page)).toBeHidden();
  });

  test('Alert dialog close with its trigger gone: focus goes to fallbackFocus, or else the main h1', async ({ page }) => {
    await open(page, '&scheme=light&screen=kit&fallback=email');
    await page.getByTestId('open-alert-once').click();
    await expect(page.getByTestId('open-alert-once')).toHaveCount(0);
    await page.getByRole('button', { name: 'Keep going' }).click();
    await expect(page.getByTestId('email')).toBeFocused();

    await open(page, '&scheme=light&screen=kit');
    await page.getByTestId('open-alert-once').click();
    await page.keyboard.press('Escape');
    await expect(alert(page)).toBeHidden();
    await expect(page.getByRole('main').getByRole('heading', { level: 1 })).toBeFocused();
  });

  test('Alert dialog under reduced motion: no animation runs', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await open(page, '&scheme=light&screen=kit');
    await page.getByTestId('open-alert').click();
    expect(await isOpen(alert(page))).toBe(true);
    expect(await page.evaluate(() => document.getAnimations().filter((animation) => animation.playState === 'running').length)).toBe(0);
    await expect(alert(page)).toHaveCSS('animation-name', 'none');
  });
});

test('Copy trace: Copy on the trace ID puts exactly the trace ID on the clipboard', async ({ page }) => {
  await open(page, '&scheme=light');
  const copy = page.getByRole('button', { name: 'Copy trace ID', exact: true });
  await copy.click();
  await expect(page.getByRole('button', { name: 'Copied trace ID', exact: true })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(TRACE_ID);
});

test('No third party: every request the hosted fixture makes is same-origin', async ({ page, baseURL }) => {
  const requests: string[] = [];
  page.on('request', (request) => requests.push(request.url()));
  await open(page, '&logo=image');
  await page.getByRole('button', { name: 'Copy trace ID' }).click();
  await open(page, '&screen=kit&theme=custom');
  await page.getByTestId('open-alert').click();
  await expect(page.getByRole('alertdialog')).toBeVisible();
  await page.evaluate(() => document.fonts.ready.then(() => undefined));
  expect(requests.length).toBeGreaterThan(0);
  const origin = new URL(baseURL!).origin;
  expect(requests.filter((url) => new URL(url).origin !== origin)).toEqual([]);
});

const accessibility = [
  { name: 'light', query: '&scheme=light', emulate: 'light' },
  { name: 'dark', query: '&scheme=dark', emulate: 'light' },
  { name: 'auto with an emulated dark scheme', query: '&scheme=auto', emulate: 'dark' },
  { name: 'the custom theme', query: '&scheme=light&theme=custom&logo=image', emulate: 'light' },
  { name: 'the custom theme, dark', query: '&scheme=dark&theme=custom&logo=image', emulate: 'light' },
  { name: 'the plain theme with auto and an emulated dark scheme', query: '&scheme=auto&theme=plain', emulate: 'dark' },
  { name: 'the Admin preview frame, forced dark', query: '&frame=preview&scheme=dark', emulate: 'light' },
] as const;

for (const { name, query, emulate } of accessibility) {
  test(`Accessibility: axe finds no violations on Generic error and the alert dialog, in ${name}`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: emulate });
    const violations = async () =>
      (await new AxeBuilder({ page }).analyze()).violations.map((violation) => ({
        id: violation.id,
        targets: violation.nodes.map((node) => node.target.join(' ')),
      }));

    await open(page, query);
    await still(page);
    expect(await violations(), 'Generic error').toEqual([]);

    await open(page, `${query}&screen=kit`);
    await page.getByTestId('open-alert').click();
    expect(await isOpen(alert(page))).toBe(true);
    await still(page);
    expect(await violations(), 'alert dialog open').toEqual([]);
  });
}
