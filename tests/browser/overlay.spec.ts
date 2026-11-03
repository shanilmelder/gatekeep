// The Story 1.16 matrix, row by row, on the overlays and feedback fixture (tests/browser/fixture
// at ?page=overlay). Toast and banner run on both surfaces; the modals run on Admin, the one
// surface that exports them. Driven by keyboard and pointer in Chromium, never by snapshot.
// Expected values come from the generated tokens, never hex.

import AxeBuilder from '@axe-core/playwright';
import { tokens } from '@gatekeep/design-tokens';
import { expect, test, type Locator, type Page } from '@playwright/test';

type Surface = 'admin' | 'hosted';
type Scheme = 'light' | 'dark';

// One animation frame and then some, on the paused clock.
const FRAME = 20;
const MONO = /^"?Geist Mono"?,/;
const seconds = (value: string) => `${parseFloat(value) / 1000}s`;

async function open(page: Page, surface: Surface, scheme: Scheme = 'light', extra = '') {
  await page.goto(`/?page=overlay&surface=${surface}&scheme=${scheme}${extra}`);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(`Overlays on ${surface}`);
}

/** TOAST_MS as @gatekeep/ui exports it, which the fixture puts on <html>. */
const toastMs = async (page: Page) => Number(await page.locator('html').getAttribute('data-toast-ms'));

/** Resolves a CSS colour, such as a token variable, to its computed rgb() form in the page. */
async function colour(page: Page, value: string) {
  return page.evaluate((color) => {
    const probe = document.createElement('span');
    probe.style.color = color;
    document.body.append(probe);
    const resolved = getComputedStyle(probe).color;
    probe.remove();
    return resolved;
  }, value);
}

/** Collects every console.error from now on. */
function errors(page: Page) {
  const seen: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'error') seen.push(message.text());
  });
  return seen;
}

/** Stops the page's clock, so timers and frames fire only when a test advances it. */
async function pauseClock(page: Page) {
  const now = await page.evaluate(() => Date.now());
  await page.clock.pauseAt(now + 1000);
}

/** Records every text a live region takes from now on. */
async function record(region: Locator) {
  await region.evaluate((element) => {
    const texts: string[] = [];
    (element as HTMLElement & { texts?: string[] }).texts = texts;
    new MutationObserver(() => texts.push(element.textContent ?? '')).observe(element, {
      childList: true,
      characterData: true,
      subtree: true,
    });
  });
  return () => region.evaluate((element) => (element as HTMLElement & { texts?: string[] }).texts ?? []);
}

/** The toast region: the one status region ToastProvider renders, in the page or in the open modal. */
const region = (page: Page) => page.getByTestId('toast-region');
const toast = (page: Page) => page.getByTestId('toast');

/** On the paused clock, advances frame by frame until the toast region reads `text`. */
async function settle(page: Page, text: string) {
  await expect
    .poll(async () => {
      await page.clock.runFor(FRAME);
      return region(page).textContent();
    })
    .toBe(text);
}

const dialog = (page: Page, testId: string) => page.getByTestId(testId);
const isOpen = (locator: Locator) => locator.evaluate((element) => (element as HTMLDialogElement).open && element.matches(':modal'));
const activeInside = (locator: Locator) => locator.evaluate((element) => element.contains(document.activeElement));

/** Waits for every running animation, such as a modal's rise, to finish, so axe reads final colours. */
const still = (page: Page) =>
  // allSettled: an animation cancelled meanwhile (a closing dialog, a re-render) rejects its
  // finished promise with an AbortError, and that animation is done as well.
  page.evaluate(() => Promise.allSettled(document.getAnimations().map((animation) => animation.finished)).then(() => undefined));

/** Every element whose computed style still animates or transitions. */
const moving = (page: Page) =>
  page.evaluate(() => {
    const found: string[] = [];
    const check = (label: string, s: CSSStyleDeclaration) => {
      const animated = s.animationName !== 'none';
      const transitions = s.transitionDuration.split(',').some((d) => parseFloat(d) > 0);
      if (animated || transitions) found.push(`${label}: ${s.animationName} ${s.transitionDuration}`);
    };
    for (const element of document.querySelectorAll('*')) {
      // The pending spinner keeps a slowed turn on purpose (controls.spec.ts checks its speed).
      if (element.closest('[data-gk-motion="essential"]')) continue;
      const label = element.getAttribute('data-testid') ?? element.tagName.toLowerCase();
      check(label, getComputedStyle(element));
      check(`${label}::before`, getComputedStyle(element, '::before'));
      check(`${label}::after`, getComputedStyle(element, '::after'));
      if (element instanceof HTMLDialogElement && element.open) check(`${label}::backdrop`, getComputedStyle(element, '::backdrop'));
    }
    return found;
  });

test.use({ permissions: ['clipboard-read', 'clipboard-write'] });

for (const surface of ['admin', 'hosted'] as const) {
  test.describe(`on ${surface}`, () => {
    test('toast and banner are shared with Hosted, and the modals are Admin only', async ({ page }) => {
      await open(page, surface);
      const html = page.locator('html');
      await expect(html).toHaveAttribute('data-same-modules', 'true');
      const hosted = (await html.getAttribute('data-hosted-exports'))!.split(' ');
      const adminOnly = (await html.getAttribute('data-admin-only-exports'))!.split(' ');
      for (const name of ['Banner', 'ToastProvider', 'useToast', 'TOAST_MS']) expect(hosted, name).toContain(name);
      for (const name of ['Modal', 'ModalProvider', 'ConfirmModal', 'OneTimeReveal']) {
        expect(hosted, name).not.toContain(name);
        expect(adminOnly, name).toContain(name);
      }
    });

    test('a toast holds a plain string only: no button, link or Copy, and anything else is refused', async ({ page }) => {
      const seen = errors(page);
      await open(page, surface);
      await page.getByTestId('save-top').click();
      await expect(toast(page)).toHaveText('Saved');
      await expect(toast(page).locator('button, a, input, [role="button"], [role="link"], [tabindex]')).toHaveCount(0);
      await expect(toast(page).getByRole('button')).toHaveCount(0);
      await expect(toast(page).getByRole('link')).toHaveCount(0);
      // The check glyph is decorative: the text is the whole message.
      await expect(region(page)).toHaveText('Saved');

      await page.getByTestId('rich-top').click();
      await expect(page.getByTestId('rich-result-top')).toHaveText('refused');
      expect(seen.some((text) => text.includes('toast: takes one non-empty plain string'))).toBe(true);
      await expect(region(page).locator('a')).toHaveCount(0);
    });

    test('the toast takes its inverted tokens', async ({ page }) => {
      await open(page, surface);
      await page.getByTestId('save-top').click();
      const s = await toast(page).evaluate((element) => {
        const c = getComputedStyle(element);
        return { background: c.backgroundColor, color: c.color, radius: c.borderTopLeftRadius, shadow: c.boxShadow };
      });
      expect(s.background).toBe(await colour(page, 'var(--gk-color-tx)'));
      expect(s.color).toBe(await colour(page, 'var(--gk-color-bg)'));
      expect(s.radius).toBe(tokens.rounded.card);
      expect(s.shadow).not.toBe('none');
      const check = await toast(page).locator('svg').evaluate((element) => getComputedStyle(element).stroke);
      expect(check).toBe(await colour(page, 'var(--gk-color-ac)'));
      await expect(toast(page).locator('svg')).toHaveAttribute('aria-hidden', 'true');
    });

    test('the toast never covers the focused control, whichever edge it is at', async ({ page }) => {
      await open(page, surface);
      const overlap = async (control: Locator) => {
        const a = (await toast(page).boundingBox())!;
        const b = (await control.boundingBox())!;
        return a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;
      };

      // A control at the bottom edge, where the toast sits: it moves to the top.
      const bottom = page.getByTestId('save-bottom');
      await bottom.evaluate((element) => element.scrollIntoView({ block: 'end' }));
      await bottom.focus();
      await page.keyboard.press('Enter');
      await expect(toast(page)).toHaveText('Saved');
      // At the bottom, the toast would have covered it.
      const box = (await bottom.boundingBox())!;
      const viewport = page.viewportSize()!;
      expect(box.y + box.height).toBeGreaterThan(viewport.height - parseFloat(tokens.spacing['24']) - 1);
      expect(box.x).toBeLessThan(viewport.width / 2);
      expect(box.x + box.width).toBeGreaterThan(viewport.width / 2);
      expect(await overlap(bottom)).toBe(false);
      await expect(region(page)).toHaveAttribute('data-placement', 'top');

      // A control at the top edge: the toast goes back to the bottom as focus moves.
      const top = page.getByTestId('update-top');
      await top.evaluate((element) => element.scrollIntoView({ block: 'start' }));
      await top.focus();
      await page.keyboard.press('Enter');
      await expect(toast(page)).toHaveText('Profile updated');
      expect(await overlap(top)).toBe(false);
      await expect(region(page)).toHaveAttribute('data-placement', 'bottom');
    });

    test('banners take their tone tokens, and only warn and bad shown after load are alerts', async ({ page }) => {
      await open(page, surface);
      for (const tone of ['info', 'warn', 'bad'] as const) {
        const banner = page.getByTestId(`banner-load-${tone}`);
        // Part of the page as loaded: plain text, no role.
        expect(await banner.getAttribute('role'), tone).toBeNull();
        const s = await banner.evaluate((element) => {
          const c = getComputedStyle(element);
          return { background: c.backgroundColor, color: c.color, radius: c.borderTopLeftRadius, padding: c.padding };
        });
        expect(s.background, tone).toBe(await colour(page, `var(--gk-color-${tone}-sf)`));
        expect(s.color, tone).toBe(await colour(page, 'var(--gk-color-tx)'));
        expect(s.radius, tone).toBe(tokens.rounded.card);
        expect(s.padding, tone).toBe(tokens.components.banner.padding);
        const glyph = banner.locator('svg');
        await expect(glyph).toHaveAttribute('aria-hidden', 'true');
        expect(await glyph.evaluate((element) => getComputedStyle(element).stroke), tone).toBe(await colour(page, `var(--gk-color-${tone})`));
      }
      await expect(page.getByRole('alert')).toHaveCount(0);

      // The click is the page's first interaction: banners from now on are news.
      await page.getByTestId('show-banners').click();
      await expect(page.getByTestId('banner-later-warn')).toHaveAttribute('role', 'alert');
      await expect(page.getByTestId('banner-later-bad')).toHaveAttribute('role', 'alert');
      // News in the info tone is polite.
      await expect(page.getByTestId('banner-later-info')).toHaveAttribute('role', 'status');
      await expect(page.getByRole('alert')).toHaveCount(2);
    });

    test('a banner has at most its one action, which works', async ({ page }) => {
      await open(page, surface);
      const bad = page.getByTestId('banner-load-bad');
      await expect(bad.getByRole('button')).toHaveCount(1);
      await bad.getByRole('button', { name: 'Retry' }).click();
      await expect(page.getByTestId('retries')).toHaveText('1');
      await expect(page.getByTestId('banner-load-info').getByRole('button')).toHaveCount(0);
    });

    test.describe('with reduced motion', () => {
      test.use({ reducedMotion: 'reduce' });

      test('nothing animates or transitions, with a toast shown and, on Admin, a modal open', async ({ page }) => {
        await open(page, surface);
        await page.getByTestId('save-top').click();
        await expect(toast(page)).toBeVisible();
        expect(await toast(page).evaluate((element) => getComputedStyle(element).animationName)).toBe('none');
        expect(await moving(page)).toEqual([]);
        if (surface === 'admin') {
          await page.getByTestId('open-form').click();
          const modal = dialog(page, 'form-modal');
          expect(await isOpen(modal)).toBe(true);
          expect(await modal.evaluate((element) => getComputedStyle(element).animationName)).toBe('none');
          expect(await modal.evaluate((element) => getComputedStyle(element, '::backdrop').animationName)).toBe('none');
          expect(await moving(page)).toEqual([]);
        }
      });

      test('the controls page stops moving too, all but the slowed pending spinners', async ({ page }) => {
        await page.goto(`/?surface=${surface}`);
        await expect(page.getByRole('heading', { level: 1 })).toHaveText(`Controls on ${surface}`);
        expect(await moving(page)).toEqual([]);
        const spinners = page.locator('[data-gk-motion="essential"]');
        expect(await spinners.count()).toBeGreaterThan(0);
        expect(await spinners.first().evaluate((element) => getComputedStyle(element).animationName)).not.toBe('none');
      });
    });

    test('without reduced motion, the toast rises and fades in on the short motion duration', async ({ page }) => {
      await open(page, surface);
      await page.getByTestId('save-top').click();
      const s = await toast(page).evaluate((element) => {
        const c = getComputedStyle(element);
        return { name: c.animationName, duration: c.animationDuration, easing: c.animationTimingFunction };
      });
      expect(s.name).not.toBe('none');
      expect(s.duration).toBe(seconds(tokens.elevation.motion.durationMin));
      expect(s.easing).toBe(tokens.elevation.motion.easing);
    });

    for (const scheme of ['light', 'dark'] as const) {
      test(`axe finds no violations, in the ${scheme} scheme, with banners and a toast shown${surface === 'admin' ? ' and with modals open' : ''}`, async ({
        page,
      }) => {
        await open(page, surface, scheme);
        const violations = async () =>
          (await new AxeBuilder({ page }).analyze()).violations.map((violation) => ({
            id: violation.id,
            targets: violation.nodes.map((node) => node.target.join(' ')),
          }));
        await page.getByTestId('show-banners').click();
        await page.getByTestId('save-top').click();
        await expect(toast(page)).toHaveText('Saved');
        await still(page);
        expect(await violations(), 'banners and a toast').toEqual([]);

        if (surface === 'admin') {
          await page.getByTestId('open-confirm').click();
          expect(await isOpen(dialog(page, 'confirm-modal'))).toBe(true);
          await still(page);
          expect(await violations(), 'confirm modal open').toEqual([]);
          await page.keyboard.press('Escape');

          await page.getByTestId('open-typed').click();
          expect(await isOpen(dialog(page, 'typed-modal'))).toBe(true);
          await still(page);
          expect(await violations(), 'typed confirmation open').toEqual([]);
          await page.keyboard.press('Escape');

          await page.getByTestId('create-secret').click();
          expect(await isOpen(dialog(page, 'reveal-modal'))).toBe(true);
          await still(page);
          expect(await violations(), 'one-time reveal open').toEqual([]);
        }
      });
    }
  });
}

test.describe('toast timing', () => {
  test('on Admin, a toast is announced politely and leaves after 2.4 seconds', async ({ page }) => {
    await page.clock.install();
    await open(page, 'admin');
    await pauseClock(page);
    const TOAST_MS = await toastMs(page);
    expect(TOAST_MS).toBe(2400);
    await expect(region(page)).toHaveAttribute('role', 'status');
    expect(await region(page).getAttribute('aria-live')).not.toBe('assertive');
    const texts = await record(region(page));

    await page.getByTestId('save-top').click();
    await settle(page, 'Saved');
    await expect(toast(page)).toBeVisible();
    // The poll above may have run a few frames past the moment the toast showed.
    await page.clock.runFor(TOAST_MS - 10 * FRAME);
    await expect(toast(page)).toHaveText('Saved');
    await page.clock.runFor(20 * FRAME);
    await expect(toast(page)).toHaveCount(0);
    await expect(region(page)).toHaveText('');

    // The same text again is announced afresh: the region empties, then fills.
    await page.getByTestId('save-top').click();
    await settle(page, 'Saved');
    await page.getByTestId('save-top').click();
    await settle(page, 'Saved');
    const seen = await texts();
    expect(seen.filter((text) => text === 'Saved').length).toBeGreaterThanOrEqual(3);
    expect(seen.filter((text) => text === '').length).toBeGreaterThanOrEqual(2);
  });

  test('on Hosted, a toast stays until the next toast or action, and is never timed out', async ({ page }) => {
    await page.clock.install();
    await open(page, 'hosted');
    await pauseClock(page);
    const TOAST_MS = await toastMs(page);
    await page.getByTestId('save-top').click();
    await settle(page, 'Saved');
    await page.clock.runFor(TOAST_MS * 5);
    await expect(toast(page)).toHaveText('Saved');

    // The next toast replaces it.
    await page.getByTestId('update-top').click();
    await settle(page, 'Profile updated');
    await page.clock.runFor(TOAST_MS * 2);
    await expect(toast(page)).toHaveText('Profile updated');

    // The next action ends it.
    await page.getByTestId('show-banners').click();
    await page.clock.runFor(FRAME);
    await expect(toast(page)).toHaveCount(0);
    await expect(region(page)).toHaveText('');
  });
});

test.describe('modals on admin', () => {
  test('a modal takes its tokens over the scrim, and rises in on the long motion duration', async ({ page }) => {
    await open(page, 'admin');
    await page.getByTestId('open-form').click();
    const modal = dialog(page, 'form-modal');
    expect(await isOpen(modal)).toBe(true);
    const s = await modal.evaluate((element) => {
      const c = getComputedStyle(element);
      // The last child but the toast region, which renders inside an open modal.
      const footer = [...element.children].filter((child) => !child.matches('[popover]')).at(-1)!;
      return {
        width: element.getBoundingClientRect().width,
        background: c.backgroundColor,
        radius: c.borderTopLeftRadius,
        shadow: c.boxShadow,
        animation: c.animationName,
        duration: c.animationDuration,
        footer: getComputedStyle(footer).backgroundColor,
        footerJustify: getComputedStyle(footer).justifyContent,
        backdrop: getComputedStyle(element, '::backdrop').backgroundColor,
      };
    });
    expect(s.width).toBe(parseFloat(tokens.spacing['modal-w']));
    expect(s.background).toBe(await colour(page, 'var(--gk-color-sf)'));
    expect(s.footer).toBe(await colour(page, 'var(--gk-color-sf2)'));
    expect(s.footerJustify).toBe('flex-end');
    expect(s.radius).toBe(tokens.rounded.modal);
    expect(s.shadow).not.toBe('none');
    expect(s.backdrop).toBe(await colour(page, 'var(--gk-elevation-scrim)'));
    expect(s.animation).not.toBe('none');
    expect(s.duration).toBe(seconds(tokens.elevation.motion.durationMax));
    await expect(modal).toHaveAccessibleName('Rename application');
  });

  test('focus is trapped: Tab and Shift+Tab never leave the modal, and the page behind is inert', async ({ page }) => {
    await open(page, 'admin');
    const trigger = page.getByTestId('open-form');
    await trigger.click();
    const modal = dialog(page, 'form-modal');
    expect(await isOpen(modal)).toBe(true);
    expect(await activeInside(modal)).toBe(true);
    const visited = new Set<string>();
    for (let i = 0; i < 12; i++) {
      await page.keyboard.press('Tab');
      expect(await activeInside(modal), `Tab ${i + 1}`).toBe(true);
      visited.add(await page.evaluate(() => document.activeElement?.outerHTML ?? ''));
    }
    for (let i = 0; i < 12; i++) {
      await page.keyboard.press('Shift+Tab');
      expect(await activeInside(modal), `Shift+Tab ${i + 1}`).toBe(true);
    }
    // Two fields, Cancel and Save: every stop is reached, and wraps.
    expect(visited.size).toBe(4);

    // A pointer on the page behind reaches the dialog's backdrop, not the control.
    const box = (await page.getByTestId('open-confirm').boundingBox())!;
    const hit = await page.evaluate(([x, y]) => document.elementFromPoint(x!, y!)?.getAttribute('data-testid') ?? null, [box.x + box.width / 2, box.y + box.height / 2]);
    expect(hit).not.toBe('open-confirm');
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    expect(await isOpen(dialog(page, 'confirm-modal'))).toBe(false);
    expect(await isOpen(modal)).toBe(true);
  });

  test('Esc and Cancel close the modal without confirming, and focus returns to the trigger', async ({ page }) => {
    await open(page, 'admin');
    const trigger = page.getByTestId('open-confirm');
    const modal = dialog(page, 'confirm-modal');

    await trigger.click();
    expect(await isOpen(modal)).toBe(true);
    await expect(modal.getByTestId('reauth-slot')).toBeVisible();
    await page.keyboard.press('Escape');
    expect(await isOpen(modal)).toBe(false);
    await expect(trigger).toBeFocused();
    await expect(page.getByTestId('confirms')).toHaveText('0');

    // Twice in a row, with no other input between: Esc still only closes.
    await page.keyboard.press('Enter');
    expect(await isOpen(modal)).toBe(true);
    await page.keyboard.press('Escape');
    expect(await isOpen(modal)).toBe(false);
    await expect(trigger).toBeFocused();

    await trigger.click();
    await modal.getByRole('button', { name: 'Cancel' }).click();
    expect(await isOpen(modal)).toBe(false);
    await expect(trigger).toBeFocused();
    await expect(page.getByTestId('confirms')).toHaveText('0');

    // The confirm itself works, and is the only thing that does.
    await trigger.click();
    await modal.getByRole('button', { name: 'Block' }).click();
    expect(await isOpen(modal)).toBe(false);
    await expect(page.getByTestId('confirms')).toHaveText('1');
    await expect(trigger).toBeFocused();
  });

  test('when the action deletes the trigger, focus goes to the next row, or the page heading if none', async ({ page }) => {
    await open(page, 'admin');
    const modal = dialog(page, 'delete-modal');

    await page.getByTestId('delete-Row A').click();
    expect(await isOpen(modal)).toBe(true);
    await expect(modal).toHaveAccessibleName('Delete Row A?');
    await modal.getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByTestId('delete-Row A')).toHaveCount(0);
    await expect(page.getByTestId('delete-Row B')).toBeFocused();

    // The last row has no next row: the page's main heading takes focus.
    await page.getByTestId('delete-Row C').click();
    await modal.getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByTestId('delete-Row C')).toHaveCount(0);
    await expect(page.getByRole('heading', { level: 1 })).toBeFocused();
  });

  test('a destructive confirm uses the outlined destructive button', async ({ page }) => {
    await open(page, 'admin');
    await page.getByTestId('delete-Row A').click();
    const confirm = dialog(page, 'delete-modal').getByRole('button', { name: 'Delete' });
    await expect(confirm).toHaveAttribute('data-variant', 'destructive');
    const s = await confirm.evaluate((element) => {
      const c = getComputedStyle(element);
      return { background: c.backgroundColor, border: c.borderTopColor, color: c.color };
    });
    expect(s.background).toBe(await colour(page, 'var(--gk-color-bad-sf)'));
    expect(s.color).toBe(await colour(page, 'var(--gk-color-bad)'));
    // Outlined: the border is bad, never a fill of it.
    expect(s.border).toBe(await colour(page, 'var(--gk-color-bad)'));
    // The impact describes the dialog.
    await expect(dialog(page, 'delete-modal')).toHaveAccessibleDescription(/Its tokens stop working at once/);
  });

  test('one level deep: a second modal is refused with a console.error, and the first stays open', async ({ page }) => {
    const seen = errors(page);
    await open(page, 'admin');
    const first = dialog(page, 'confirm-modal');
    await page.getByTestId('open-confirm').click();
    await first.getByTestId('open-second').click();
    await expect.poll(() => seen.some((text) => text.includes('Modals are one level deep'))).toBe(true);
    expect(await isOpen(first)).toBe(true);
    expect(await isOpen(dialog(page, 'second-modal'))).toBe(false);
    await expect(dialog(page, 'second-modal')).not.toBeVisible();
    expect(await activeInside(first)).toBe(true);
    expect(await page.evaluate(() => document.querySelectorAll('dialog[open]').length)).toBe(1);

    // And the first still closes normally.
    await page.keyboard.press('Escape');
    expect(await isOpen(first)).toBe(false);
  });

  test('typed confirmation: Confirm stays disabled until the field matches exactly', async ({ page }) => {
    await open(page, 'admin');
    const modal = dialog(page, 'typed-modal');
    await page.getByTestId('open-typed').click();
    const field = modal.getByLabel('Tenant subdomain');
    const confirm = modal.getByRole('button', { name: 'Delete Tenant' });
    await expect(field).toBeFocused();
    expect(await field.evaluate((element) => getComputedStyle(element).fontFamily)).toMatch(MONO);
    await expect(field).toHaveAccessibleDescription('Type northwind to confirm.');
    await expect(confirm).toHaveAttribute('data-variant', 'destructive');

    for (const near of ['', 'Northwind', 'NORTHWIND', 'northwind ', ' northwind', 'northwin', 'north wind']) {
      await field.fill(near);
      await expect(confirm, JSON.stringify(near)).toHaveAttribute('aria-disabled', 'true');
      await expect(confirm).toHaveAccessibleDescription('Type northwind to confirm.');
      // aria-disabled keeps it focusable, so a click still lands, and does nothing.
      await confirm.click({ force: true });
      expect(await isOpen(modal)).toBe(true);
      await expect(page.getByTestId('typed-confirms')).toHaveText('0');
    }

    // Enter in the field confirms only on an exact match.
    await field.fill('Northwind');
    await field.press('Enter');
    expect(await isOpen(modal)).toBe(true);
    await expect(page.getByTestId('typed-confirms')).toHaveText('0');

    await field.fill('northwind');
    await expect(confirm).not.toHaveAttribute('aria-disabled', 'true');
    await confirm.click();
    expect(await isOpen(modal)).toBe(false);
    await expect(page.getByTestId('typed-confirms')).toHaveText('1');

    // Reopened, the field starts empty again.
    await page.getByTestId('open-typed').click();
    await expect(field).toHaveValue('');
    await expect(confirm).toHaveAttribute('aria-disabled', 'true');
  });

  test('one-time reveal: Close and Esc do nothing until "I\'ve copied this" is ticked', async ({ page }) => {
    await open(page, 'admin');
    const modal = dialog(page, 'reveal-modal');
    const trigger = page.getByTestId('create-secret');
    await trigger.click();
    expect(await isOpen(modal)).toBe(true);
    const value = modal.locator('code');
    await expect(value).toHaveText('gks_1_7Hq2xV9pLm4R');
    expect(await value.evaluate((element) => getComputedStyle(element).fontFamily)).toMatch(MONO);
    // The warn banner says it's shown once, as plain text inside the modal.
    await expect(modal.locator('[data-tone="warn"]')).toContainText("only time it's shown");
    // Part of the modal's content, not news of its own: plain text.
    expect(await modal.locator('[data-tone="warn"]').getAttribute('role')).toBeNull();
    await expect(modal.getByRole('button', { name: 'Copy client secret' })).toBeFocused();
    await modal.getByRole('button', { name: 'Copy client secret' }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('gks_1_7Hq2xV9pLm4R');

    const close = modal.getByRole('button', { name: 'Close' });
    const tick = modal.getByLabel("I've copied this");
    await expect(close).toHaveAttribute('aria-disabled', 'true');
    await expect(close).toHaveAccessibleDescription('Tick "I\'ve copied this" to close.');
    await page.keyboard.press('Escape');
    await page.keyboard.press('Escape');
    expect(await isOpen(modal)).toBe(true);
    await close.click({ force: true });
    expect(await isOpen(modal)).toBe(true);

    // Ticked, then unticked: back to disabled.
    await tick.check();
    await expect(close).not.toHaveAttribute('aria-disabled', 'true');
    await tick.uncheck();
    await expect(close).toHaveAttribute('aria-disabled', 'true');
    await page.keyboard.press('Escape');
    expect(await isOpen(modal)).toBe(true);

    await tick.check();
    await close.click();
    expect(await isOpen(modal)).toBe(false);
    await expect(trigger).toBeFocused();
  });

  test('one-time reveal: once closed, the value is gone, even reopened on the same instance', async ({ page }) => {
    await open(page, 'admin');
    const modal = dialog(page, 'reveal-modal');
    const secret = 'gks_1_7Hq2xV9pLm4R';
    const inPage = () => page.evaluate((text) => document.documentElement.outerHTML.includes(text), secret);
    await page.getByTestId('create-secret').click();
    expect(await inPage()).toBe(true);
    await modal.getByLabel("I've copied this").check();
    await page.keyboard.press('Escape');
    expect(await isOpen(modal)).toBe(false);
    expect(await inPage()).toBe(false);

    await page.getByTestId('reopen-reveal').click();
    expect(await isOpen(modal)).toBe(true);
    await expect(modal).toContainText("This value can't be shown again.");
    await expect(modal.locator('code')).toHaveCount(0);
    await expect(modal.getByRole('button', { name: /Copy/ })).toHaveCount(0);
    expect(await inPage()).toBe(false);
    // Nothing to copy, so nothing holds Close back.
    await modal.getByRole('button', { name: 'Close' }).click();
    expect(await isOpen(modal)).toBe(false);
    expect(await inPage()).toBe(false);

    // A new value from the caller shows.
    await page.getByTestId('create-secret').click();
    await expect(modal.locator('code')).toHaveText('gks_2_7Hq2xV9pLm4R');
    expect(await inPage()).toBe(false);
  });
});

test.describe('modals on admin, edge cases', () => {
  test('one registry per document: a sibling provider and a provider-less modal are refused too', async ({ page }) => {
    const seen = errors(page);
    await open(page, 'admin');
    const first = dialog(page, 'confirm-modal');
    await page.getByTestId('open-confirm').click();
    for (const [button, other] of [
      ['open-sibling', 'sibling-modal'],
      ['open-loose', 'loose-modal'],
    ] as const) {
      const before = seen.length;
      await first.getByTestId(button).click();
      await expect.poll(() => seen.slice(before).some((text) => text.includes('Modals are one level deep'))).toBe(true);
      expect(await isOpen(dialog(page, other)), other).toBe(false);
      expect(await isOpen(first)).toBe(true);
    }
    expect(await page.evaluate(() => document.querySelectorAll('dialog[open]').length)).toBe(1);
  });

  test('initialFocus is honoured, and Esc a control inside handles leaves the modal open', async ({ page }) => {
    await open(page, 'admin');
    const modal = dialog(page, 'form-modal');
    await page.getByTestId('open-form').click();
    const description = modal.getByLabel('Description');
    await expect(description).toBeFocused();
    await page.keyboard.press('Escape');
    expect(await isOpen(modal)).toBe(true);
    await modal.getByLabel('Name').focus();
    await page.keyboard.press('Escape');
    expect(await isOpen(modal)).toBe(false);
  });

  test('a native close of a dismissible modal frees the registry, even if its caller keeps it open', async ({ page }) => {
    await open(page, 'admin');
    const sticky = dialog(page, 'sticky-modal');
    await page.getByTestId('open-sticky').click();
    expect(await isOpen(sticky)).toBe(true);
    await sticky.evaluate((element) => (element as HTMLDialogElement).close());
    await expect.poll(() => isOpen(sticky)).toBe(false);
    // Another modal can open now.
    await page.getByTestId('open-confirm').click();
    expect(await isOpen(dialog(page, 'confirm-modal'))).toBe(true);
  });

  test('a native close of an unticked one-time reveal leaves it open', async ({ page }) => {
    await open(page, 'admin');
    const modal = dialog(page, 'reveal-modal');
    await page.getByTestId('create-secret').click();
    await modal.evaluate((element) => (element as HTMLDialogElement).close());
    await expect.poll(() => isOpen(modal)).toBe(true);
    await expect(modal.locator('code')).toHaveText('gks_1_7Hq2xV9pLm4R');
  });

  test('at 360px wide, a long body scrolls while the header and footer stay in view', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 480 });
    await open(page, 'admin');
    await page.getByTestId('open-long').click();
    const modal = dialog(page, 'long-modal');
    expect(await isOpen(modal)).toBe(true);
    await still(page);
    const accept = modal.getByRole('button', { name: 'Accept' });
    const inView = async (locator: Locator) => {
      const box = (await locator.boundingBox())!;
      return box.x >= 0 && box.y >= 0 && box.x + box.width <= 360 && box.y + box.height <= 480;
    };
    const body = modal.locator('p').first().locator('..');
    const scroll = await body.evaluate((element) => ({
      client: element.clientHeight,
      height: element.scrollHeight,
      overflow: getComputedStyle(element).overflowY,
    }));
    expect(scroll.height).toBeGreaterThan(scroll.client);
    expect(scroll.overflow).toBe('auto');
    expect((await modal.boundingBox())!.width).toBeLessThanOrEqual(360 - 2 * parseFloat(tokens.spacing['16']));
    expect(await inView(accept)).toBe(true);
    await body.evaluate((element) => element.scrollTo(0, element.scrollHeight));
    await expect(modal.getByText('Clause 30.')).toBeInViewport();
    expect(await inView(accept)).toBe(true);
    expect(await inView(modal.getByRole('heading', { name: 'Terms of service' }))).toBe(true);
  });

  test('while pending, Cancel, Esc and Confirm do nothing, and Confirm shows its spinner', async ({ page }) => {
    await open(page, 'admin');
    const modal = dialog(page, 'pending-modal');
    await page.getByTestId('open-pending').click();
    const confirm = modal.getByRole('button', { name: 'Revoke' });
    await confirm.click();
    await expect(page.getByTestId('revokes')).toHaveText('1');
    await expect(confirm).toHaveAttribute('aria-busy', 'true');
    await expect(confirm.locator('[data-gk-motion="essential"]')).toBeVisible();

    await confirm.click({ force: true });
    await expect(page.getByTestId('revokes')).toHaveText('1');
    await page.keyboard.press('Escape');
    expect(await isOpen(modal)).toBe(true);
    const cancel = modal.getByRole('button', { name: 'Cancel' });
    await expect(cancel).toHaveAttribute('aria-disabled', 'true');
    await cancel.click({ force: true });
    expect(await isOpen(modal)).toBe(true);

    await modal.getByTestId('finish').click();
    expect(await isOpen(modal)).toBe(false);
  });

  test('the modal rises from a 6px offset and fades in', async ({ page }) => {
    await open(page, 'admin');
    await page.getByTestId('open-form').click();
    const first = await dialog(page, 'form-modal').evaluate((element) => {
      const animation = element.getAnimations().find((a) => a instanceof CSSAnimation);
      const frames = (animation?.effect as KeyframeEffect | undefined)?.getKeyframes() ?? [];
      const from = frames[0];
      return from ? { opacity: String(from.opacity), translate: String(from.translate) } : null;
    });
    expect(first).toEqual({ opacity: '0', translate: `0px ${tokens.elevation.motion.rise}` });
  });

  test('a toast fired with a modal open shows above it, in a live region inside the modal', async ({ page }) => {
    await open(page, 'admin');
    const modal = dialog(page, 'confirm-modal');
    await page.getByTestId('open-confirm').click();
    await modal.getByTestId('notify').click();
    await expect(toast(page)).toHaveText('Saved');
    await still(page);
    // Inside the modal, so not inert, and in the top layer above it.
    expect(await region(page).evaluate((element) => !!element.closest('dialog[open]') && element.matches(':popover-open'))).toBe(true);
    await expect(region(page)).toHaveAttribute('role', 'status');
    const box = (await toast(page).boundingBox())!;
    const hit = await page.evaluate(
      ([x, y]) => !!document.elementFromPoint(x!, y!)?.closest('[data-testid="toast"]'),
      [box.x + box.width / 2, box.y + box.height / 2],
    );
    expect(hit).toBe(true);
    await expect(page.getByRole('status').filter({ hasText: 'Saved' })).toHaveCount(1);
  });
});

for (const surface of ['admin', 'hosted'] as const) {
  test.describe(`edge cases on ${surface}`, () => {
    test('a toast sent from a child mount effect, before the provider mounted, still shows', async ({ page }) => {
      await open(page, surface, 'light', '&mounttoast');
      await expect(toast(page)).toHaveText('Welcome back');
    });

    test('with a control spanning the viewport, the toast stays off it and is still announced', async ({ page }) => {
      await open(page, surface, 'light', '&span');
      const span = page.getByTestId('span');
      await span.evaluate((element) => element.scrollIntoView({ block: 'start' }));
      await span.focus();
      await page.keyboard.press('Control+Enter');
      await expect(region(page)).toHaveText('Saved');
      await expect(region(page)).toHaveAttribute('data-placement', 'aside');
      const box = (await toast(page).boundingBox())!;
      expect(box.width).toBeLessThanOrEqual(1);
      expect(box.height).toBeLessThanOrEqual(1);
      await expect(span).toBeFocused();
    });

    test('a warn banner mounted 1.5 seconds after load, with no interaction, is announced', async ({ page }) => {
      await open(page, surface, 'light', '&timerbanner');
      await expect(page.getByTestId('banner-timed')).toHaveAttribute('role', 'alert', { timeout: 10_000 });
    });
  });
}

test('on Hosted, a toast ends on a keyboard form submit', async ({ page }) => {
  await open(page, 'hosted');
  await page.getByTestId('save-top').click();
  await expect(toast(page)).toHaveText('Saved');
  // The dismissal starts listening a task after the toast shows.
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 50)));
  await page.getByTestId('form-input').focus();
  await page.keyboard.press('Enter');
  await expect(page.getByTestId('submits')).toHaveText('1');
  await expect(toast(page)).toHaveCount(0);
});
