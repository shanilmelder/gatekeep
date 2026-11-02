// The Story 1.17 matrix, row by row, on the drawer and menu fixture (tests/browser/fixture at
// ?page=drawer). Both components are Admin only. Driven by keyboard and pointer in Chromium,
// never by snapshot. Expected values come from the generated tokens, never hex.

import AxeBuilder from '@axe-core/playwright';
import { tokens } from '@gatekeep/design-tokens';
import { expect, test, type Locator, type Page } from '@playwright/test';

type Scheme = 'light' | 'dark';

/** The fixture's canary: a value in the raw event that no Viewer's DOM may ever hold. */
const RAW_CANARY = 'raw-canary-7f3a91';
/** The catalogue's default note in place of raw detail. */
const LIMITED = "Raw detail is limited by role, and yours can't see it.";

async function open(page: Page, scheme: Scheme = 'light', extra = '') {
  await page.goto(`/?page=drawer&scheme=${scheme}${extra}`);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Drawer and menu');
}

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

const isOpen = (locator: Locator) => locator.evaluate((element) => (element as HTMLDialogElement).open && element.matches(':modal'));
const activeInside = (locator: Locator) => locator.evaluate((element) => element.contains(document.activeElement));

/** Waits for every running animation to finish, so axe reads final colours. */
const still = (page: Page) =>
  page.evaluate(() => Promise.all(document.getAnimations().map((animation) => animation.finished)).then(() => undefined));

const eventDrawer = (page: Page) => page.getByTestId('event-drawer');
/** A menu's trigger, inside the wrapper the testid marks. */
const trigger = (page: Page, testId: string) => page.getByTestId(testId).locator('[data-menu-trigger]');
/** A menu's popup, open or not. */
const popup = (page: Page, testId: string) => page.getByTestId(testId).locator('[role="menu"]');
const item = (page: Page, name: string) => page.getByRole('menuitem', { name, exact: true });
const selected = (page: Page) => page.getByTestId('selected');

async function expectMenuOpen(page: Page, testId: string, open: boolean) {
  await expect(trigger(page, testId)).toHaveAttribute('aria-expanded', String(open));
  if (open) await expect(popup(page, testId)).toBeVisible();
  else await expect(popup(page, testId)).toBeHidden();
}

// Pinned: the focus trap, the drawer's width and the menu's placement all depend on it.
test.use({ permissions: ['clipboard-read', 'clipboard-write'], viewport: { width: 1280, height: 720 } });

test('the drawer and menu are Admin only, exported from the admin entry', async ({ page }) => {
  await open(page);
  const html = page.locator('html');
  await expect(html).toHaveAttribute('data-same-modules', 'true');
  const hosted = (await html.getAttribute('data-hosted-exports'))!.split(' ');
  const adminOnly = (await html.getAttribute('data-admin-only-exports'))!.split(' ');
  for (const name of ['Drawer', 'EventDrawer', 'Menu']) {
    expect(hosted, name).not.toContain(name);
    expect(adminOnly, name).toContain(name);
  }
});

test.describe('drawer', () => {
  test('a drawer is a 440px modal panel at the inline end, on its tokens, and slides in', async ({ page }) => {
    await open(page);
    await page.getByTestId('open-event').click();
    const drawer = eventDrawer(page);
    expect(await isOpen(drawer)).toBe(true);
    const viewport = page.viewportSize()!;
    // The slide-in's animation name, read while it runs, then the settled box.
    const animation = await drawer.evaluate((element) => getComputedStyle(element).animationName);
    await still(page);
    const s = await drawer.evaluate((element) => {
      const c = getComputedStyle(element);
      const box = element.getBoundingClientRect();
      return {
        left: box.left,
        right: box.right,
        top: box.top,
        bottom: box.bottom,
        width: box.width,
        background: c.backgroundColor,
        edge: c.borderLeftColor,
        edgeWidth: c.borderLeftWidth,
      };
    });
    expect(s.width).toBeCloseTo(parseFloat(tokens.spacing['drawer-w']), 1);
    expect(s.right).toBeCloseTo(viewport.width, 1);
    expect(s.top).toBe(0);
    expect(s.bottom).toBeCloseTo(viewport.height, 1);
    expect(s.background).toBe(await colour(page, 'var(--gk-drawer-background)'));
    expect(s.edge).toBe(await colour(page, 'var(--gk-drawer-border)'));
    expect(s.edgeWidth).toBe('1px');
    expect(animation).toContain('gkSlide');

    // At most half the window.
    await page.keyboard.press('Escape');
    await page.setViewportSize({ width: 800, height: 600 });
    await page.getByTestId('open-event').click();
    expect(await isOpen(drawer)).toBe(true);
    await still(page);
    expect(await drawer.evaluate((element) => element.getBoundingClientRect().width)).toBeCloseTo(400, 1);
  });

  test('Esc closes the drawer and focus returns to the trigger', async ({ page }) => {
    await open(page);
    const opener = page.getByTestId('open-event');
    await opener.focus();
    await page.keyboard.press('Enter');
    const drawer = eventDrawer(page);
    expect(await isOpen(drawer)).toBe(true);
    // Focus starts inside, on Close.
    await expect(drawer.getByRole('button', { name: 'Close', exact: true })).toBeFocused();
    await page.keyboard.press('Escape');
    expect(await isOpen(drawer)).toBe(false);
    await expect(opener).toBeFocused();

    // Opened by pointer, and closed by Esc from deep inside: the same.
    await opener.click();
    await drawer.getByRole('region', { name: 'Raw event' }).focus();
    await page.keyboard.press('Escape');
    expect(await isOpen(drawer)).toBe(false);
    await expect(opener).toBeFocused();
  });

  test('the Close button does the same as Esc', async ({ page }) => {
    await open(page);
    const opener = page.getByTestId('open-event');
    await opener.click();
    const drawer = eventDrawer(page);
    expect(await isOpen(drawer)).toBe(true);
    await drawer.getByRole('button', { name: 'Close', exact: true }).click();
    expect(await isOpen(drawer)).toBe(false);
    await expect(opener).toBeFocused();
  });

  test('when the trigger is gone, focus goes to the caller fallback, or the page heading if none', async ({ page }) => {
    await open(page);
    const drawer = page.getByTestId('row-drawer');

    await page.getByTestId('view-Event A').click();
    expect(await isOpen(drawer)).toBe(true);
    await expect(drawer).toHaveAccessibleName('Event A');
    await drawer.getByTestId('remove-row').click();
    expect(await isOpen(drawer)).toBe(false);
    await expect(page.getByTestId('view-Event A')).toHaveCount(0);
    await expect(page.getByTestId('view-Event B')).toBeFocused();

    // The last row has no next row: the page heading takes focus.
    await page.getByTestId('view-Event C').click();
    await drawer.getByTestId('remove-row').click();
    expect(await isOpen(drawer)).toBe(false);
    await expect(page.getByRole('heading', { level: 1 })).toBeFocused();
  });

  test('a modal is refused over the drawer, and a drawer over a modal, each with a console.error', async ({ page }) => {
    const seen = errors(page);
    await open(page);

    await page.getByTestId('open-event').click();
    const drawer = eventDrawer(page);
    expect(await isOpen(drawer)).toBe(true);
    await drawer.getByTestId('drawer-open-modal').click();
    await expect.poll(() => seen.some((text) => text.includes('Modal: another modal or drawer is already open'))).toBe(true);
    expect(await isOpen(page.getByTestId('drawer-modal'))).toBe(false);
    expect(await isOpen(drawer)).toBe(true);
    expect(await page.evaluate(() => document.querySelectorAll('dialog:modal').length)).toBe(1);
    await page.keyboard.press('Escape');
    expect(await isOpen(drawer)).toBe(false);

    seen.length = 0;
    await page.getByTestId('open-modal').click();
    const modal = page.getByTestId('page-modal');
    expect(await isOpen(modal)).toBe(true);
    await modal.getByTestId('modal-open-drawer').click();
    await expect.poll(() => seen.some((text) => text.includes('Drawer: a modal or drawer is already open'))).toBe(true);
    expect(await isOpen(page.getByTestId('modal-drawer'))).toBe(false);
    expect(await isOpen(modal)).toBe(true);
    expect(await page.evaluate(() => document.querySelectorAll('dialog:modal').length)).toBe(1);

    // Once the modal closes, the drawer can open again: the registry was released.
    await page.keyboard.press('Escape');
    expect(await isOpen(modal)).toBe(false);
    await page.getByTestId('open-event').click();
    expect(await isOpen(drawer)).toBe(true);
  });

  test('focus is trapped: Tab and Shift+Tab never leave the drawer, and the page behind is inert', async ({ page }) => {
    await open(page);
    await page.getByTestId('open-event').click();
    const drawer = eventDrawer(page);
    expect(await isOpen(drawer)).toBe(true);
    const visited = new Set<string>();
    for (let i = 0; i < 14; i++) {
      await page.keyboard.press('Tab');
      expect(await activeInside(drawer), `Tab ${i + 1}`).toBe(true);
      visited.add(await page.evaluate(() => document.activeElement?.outerHTML ?? ''));
    }
    for (let i = 0; i < 14; i++) {
      await page.keyboard.press('Shift+Tab');
      expect(await activeInside(drawer), `Shift+Tab ${i + 1}`).toBe(true);
    }
    // Close, Copy JSON, the JSON viewer, the More menu, "Open a modal" and Notify: every stop, and wraps.
    expect(visited.size).toBe(6);

    // A pointer on the page behind reaches the backdrop, not the control.
    const box = (await page.getByTestId('open-modal').boundingBox())!;
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    expect(await isOpen(page.getByTestId('page-modal'))).toBe(false);
    expect(await isOpen(drawer)).toBe(true);
  });

  test('event drawer with canSeeRaw: code badge, summary rows, the JSON viewer and Copy JSON', async ({ page }) => {
    await open(page);
    await page.getByTestId('open-event').click();
    const drawer = eventDrawer(page);
    expect(await isOpen(drawer)).toBe(true);
    await expect(drawer).toHaveAccessibleName(/^user\.login\.failed\s*Failed sign-in$/);

    const badge = drawer.getByRole('heading', { level: 2 }).locator('[data-badge="code"]');
    await expect(badge).toHaveText('user.login.failed');
    await expect(badge).toHaveAttribute('data-outcome', 'failure');
    expect(await badge.evaluate((element) => getComputedStyle(element).fontFamily)).toMatch(/^"?Geist Mono"?,/);

    const terms = drawer.locator('dl dt');
    const values = drawer.locator('dl dd');
    await expect(terms).toHaveText(['Time', 'User', 'Application', 'Outcome']);
    await expect(values).toHaveText(['2026-11-03 09:41:07 UTC', 'ada@northwind.test', 'Northwind web', 'Failure']);

    const viewer = drawer.getByRole('region', { name: 'Raw event' });
    await expect(viewer).toContainText('"type": "user.login.failed"');
    await expect(viewer).toContainText(RAW_CANARY);
    await expect(drawer.getByRole('heading', { level: 3, name: 'Raw event' })).toBeVisible();
    await expect(drawer.getByText(LIMITED)).toHaveCount(0);

    await drawer.getByRole('button', { name: 'Copy JSON' }).click();
    await expect(drawer.getByRole('button', { name: 'Copied JSON' })).toBeVisible();
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    expect(JSON.parse(copied)).toMatchObject({ type: 'user.login.failed', trace: RAW_CANARY, attempts: 3 });
  });

  for (const [testId, who] of [
    ['open-viewer', 'a Viewer, passed no raw'],
    ['open-untyped', 'an untyped caller passing raw anyway'],
  ] as const) {
    test(`event drawer without canSeeRaw, for ${who}: badge and summary only, no JSON or Copy in the DOM, and the note`, async ({ page }) => {
      await open(page);
      await page.getByTestId(testId).click();
      const drawer = eventDrawer(page);
      expect(await isOpen(drawer)).toBe(true);
      await expect(drawer.locator('[data-badge="code"]')).toHaveText('user.login.failed');
      await expect(drawer.locator('dl dt')).toHaveCount(4);
      await expect(drawer.getByText(LIMITED)).toBeVisible();

      // Not hidden: absent. Nothing of the raw event reaches the DOM, even when an untyped
      // caller passes it.
      await expect(drawer.getByRole('region', { name: 'Raw event' })).toHaveCount(0);
      await expect(drawer.getByRole('button', { name: /JSON/ })).toHaveCount(0);
      await expect(drawer.locator('[data-event-raw], pre, code')).toHaveCount(0);
      const html = await page.evaluate(() => document.documentElement.outerHTML);
      expect(html).not.toContain(RAW_CANARY);
      expect(html).not.toContain('wrong_password');
      expect(html).not.toContain('Raw event');
    });
  }

  for (const [testId, what] of [
    ['open-broken', 'a value JSON cannot represent'],
    ['open-missing', 'no raw value'],
  ] as const) {
    test(`event drawer with canSeeRaw and ${what}: the viewer's neutral message, and no Copy`, async ({ page }) => {
      await open(page);
      await page.getByTestId(testId).click();
      const drawer = eventDrawer(page);
      expect(await isOpen(drawer)).toBe(true);
      const viewer = drawer.getByRole('region', { name: 'Raw event' });
      await expect(viewer).toHaveText("This value can't be shown as JSON.");
      await expect(drawer.getByRole('button', { name: /JSON/ })).toHaveCount(0);
      await expect(drawer.getByText(LIMITED)).toHaveCount(0);
    });
  }

  test('a long body scrolls on its own, and is a Tab stop, while the header stays in view', async ({ page }) => {
    await open(page);
    await page.getByTestId('open-long').click();
    const drawer = eventDrawer(page);
    expect(await isOpen(drawer)).toBe(true);
    const body = drawer.locator('[data-drawer-body]');
    await expect(body).toHaveAttribute('tabindex', '0');
    // Its own name, not a repeat of the dialog's.
    await expect(body).toHaveRole('region');
    await expect(body).toHaveAccessibleName('Details');
    const close = drawer.getByRole('button', { name: 'Close', exact: true });
    const before = (await close.boundingBox())!;
    expect(await body.evaluate((element) => element.scrollHeight > element.clientHeight)).toBe(true);
    await body.evaluate((element) => element.scrollTo(0, element.scrollHeight));
    expect(await body.evaluate((element) => element.scrollTop)).toBeGreaterThan(0);
    expect(await drawer.evaluate((element) => element.scrollTop)).toBe(0);
    expect((await close.boundingBox())!.y).toBe(before.y);
    await expect(drawer.getByRole('button', { name: 'Open a modal' })).toBeInViewport();
  });

  test.describe('with reduced motion', () => {
    test.use({ reducedMotion: 'reduce' });

    test('the drawer and its backdrop neither animate nor transition', async ({ page }) => {
      await open(page);
      await page.getByTestId('open-event').click();
      const drawer = eventDrawer(page);
      expect(await isOpen(drawer)).toBe(true);
      expect(await drawer.evaluate((element) => getComputedStyle(element).animationName)).toBe('none');
      expect(await drawer.evaluate((element) => getComputedStyle(element, '::backdrop').animationName)).toBe('none');
    });
  });
});

test.describe('menu', () => {
  test('Enter, Space, ArrowDown and a click open it on the first item, and ArrowUp on the last', async ({ page }) => {
    await open(page);
    const button = trigger(page, 'user-menu');
    await expect(button).toHaveAttribute('aria-haspopup', 'menu');
    await expectMenuOpen(page, 'user-menu', false);

    for (const key of ['Enter', 'Space', 'ArrowDown']) {
      await button.focus();
      await page.keyboard.press(key);
      await expectMenuOpen(page, 'user-menu', true);
      await expect(item(page, 'Block user'), key).toBeFocused();
      await page.keyboard.press('Escape');
      await expectMenuOpen(page, 'user-menu', false);
      await expect(button, key).toBeFocused();
    }

    // The last enabled item: Archive is disabled, so Delete user.
    await page.keyboard.press('ArrowUp');
    await expectMenuOpen(page, 'user-menu', true);
    await expect(item(page, 'Delete user')).toBeFocused();
    await page.keyboard.press('Escape');

    await button.click();
    await expectMenuOpen(page, 'user-menu', true);
    await expect(item(page, 'Block user')).toBeFocused();
    // The trigger toggles it closed again.
    await button.click();
    await expectMenuOpen(page, 'user-menu', false);
  });

  test('the popup is a menu of menuitems with a separator, named by its trigger', async ({ page }) => {
    await open(page);
    await trigger(page, 'user-menu').click();
    const menu = page.getByRole('menu', { name: 'Actions' });
    await expect(menu).toBeVisible();
    await expect(menu.getByRole('menuitem')).toHaveCount(8);
    await expect(menu.getByRole('separator')).toHaveCount(1);
    await expect(item(page, 'Reset MFA')).toHaveAttribute('aria-disabled', 'true');
    await expect(item(page, 'Open credentials')).toHaveAttribute('href', '#credentials');
    expect(await item(page, 'Delete user').evaluate((element) => getComputedStyle(element).color)).toBe(await colour(page, 'var(--gk-color-bad)'));
  });

  test('arrows move and wrap, Home and End jump, a typed letter finds the next item, all skipping disabled ones', async ({ page }) => {
    await open(page);
    await trigger(page, 'user-menu').focus();
    await page.keyboard.press('Enter');
    const order = ['Bulk export', 'Rename', 'Open credentials', 'Focus notes', 'Delete user', 'Block user'];
    for (const name of order) {
      await page.keyboard.press('ArrowDown');
      await expect(item(page, name), `ArrowDown to ${name}`).toBeFocused();
    }
    for (const name of ['Delete user', 'Focus notes', 'Open credentials', 'Rename', 'Bulk export', 'Block user']) {
      await page.keyboard.press('ArrowUp');
      await expect(item(page, name), `ArrowUp to ${name}`).toBeFocused();
    }
    await page.keyboard.press('End');
    await expect(item(page, 'Delete user')).toBeFocused();
    await page.keyboard.press('Home');
    await expect(item(page, 'Block user')).toBeFocused();

    // Each search waits out the 500ms typeahead buffer first. "r" skips the disabled Reset
    // MFA; "b" wraps round, and again cycles; an unmatched letter stays put.
    const type = async (text: string) => {
      await page.waitForTimeout(600);
      await page.keyboard.type(text);
    };
    await type('r');
    await expect(item(page, 'Rename')).toBeFocused();
    await type('b');
    await expect(item(page, 'Block user')).toBeFocused();
    await type('B');
    await expect(item(page, 'Bulk export')).toBeFocused();
    await type('z');
    await expect(item(page, 'Bulk export')).toBeFocused();
    await type('a');
    await expect(item(page, 'Bulk export')).toBeFocused();

    // Letters typed together build one search: "bl", "bu", a repeated "bbb" cycles, and "ren"
    // passes the disabled Reset MFA.
    await type('bl');
    await expect(item(page, 'Block user')).toBeFocused();
    await type('bu');
    await expect(item(page, 'Bulk export')).toBeFocused();
    await type('bbb');
    await expect(item(page, 'Block user')).toBeFocused();
    await type('ren');
    await expect(item(page, 'Rename')).toBeFocused();
    await expectMenuOpen(page, 'user-menu', true);
  });

  test('Enter or Space on an item calls onSelect, closes the menu and puts focus on the trigger', async ({ page }) => {
    await open(page);
    const button = trigger(page, 'user-menu');
    await button.focus();
    await page.keyboard.press('Enter');
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');
    await expect(selected(page)).toHaveText('export');
    await expectMenuOpen(page, 'user-menu', false);
    await expect(button).toBeFocused();

    await page.keyboard.press('Enter');
    await page.keyboard.press('Space');
    await expect(selected(page)).toHaveText('export block');
    await expectMenuOpen(page, 'user-menu', false);
    await expect(button).toBeFocused();

    // A pointer click on an item does the same.
    await button.click();
    await item(page, 'Rename').click();
    await expect(selected(page)).toHaveText('export block rename');
    await expectMenuOpen(page, 'user-menu', false);
    await expect(button).toBeFocused();
  });

  test('an action that moves focus keeps it there, and one that opens a modal returns focus to the trigger', async ({ page }) => {
    await open(page);
    const button = trigger(page, 'user-menu');
    await button.focus();
    await page.keyboard.press('Enter');
    await page.keyboard.press('f');
    await expect(item(page, 'Focus notes')).toBeFocused();
    await page.keyboard.press('Enter');
    await expectMenuOpen(page, 'user-menu', false);
    await expect(page.getByTestId('notes')).toBeFocused();

    await button.focus();
    await page.keyboard.press('ArrowUp');
    await expect(item(page, 'Delete user')).toBeFocused();
    await page.keyboard.press('Enter');
    const modal = page.getByTestId('delete-modal');
    expect(await isOpen(modal)).toBe(true);
    await page.keyboard.press('Escape');
    expect(await isOpen(modal)).toBe(false);
    await expect(button).toBeFocused();
  });

  test('a disabled item can be neither reached nor activated', async ({ page }) => {
    await open(page);
    await trigger(page, 'user-menu').click();
    // Forced past Playwright's own enabled check, which already honours aria-disabled.
    await item(page, 'Reset MFA').click({ force: true });
    await item(page, 'Archive').click({ force: true });
    await page.keyboard.press('Enter');
    await expect(selected(page)).toHaveText('');
    await expectMenuOpen(page, 'user-menu', true);

    // From a disabled item a pointer focused, the arrows step to its enabled neighbours.
    await item(page, 'Reset MFA').click({ force: true });
    await page.keyboard.press('ArrowDown');
    await expect(item(page, 'Rename')).toBeFocused();
    await item(page, 'Reset MFA').click({ force: true });
    await page.keyboard.press('ArrowUp');
    await expect(item(page, 'Bulk export')).toBeFocused();
  });

  test('a menu with no enabled item has an aria-disabled trigger and never opens', async ({ page }) => {
    await open(page);
    for (const testId of ['empty-menu', 'disabled-menu']) {
      const button = trigger(page, testId);
      await expect(button, testId).toHaveAttribute('aria-disabled', 'true');
      await button.click({ force: true });
      await button.focus();
      for (const key of ['Enter', 'Space', 'ArrowDown', 'ArrowUp']) await page.keyboard.press(key);
      await expectMenuOpen(page, testId, false);
    }
  });

  test('Esc closes it with focus on the trigger; Tab closes it and moves on; a click outside closes it and still acts', async ({ page }) => {
    await open(page);
    const button = trigger(page, 'user-menu');
    await button.click();
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Escape');
    await expectMenuOpen(page, 'user-menu', false);
    await expect(button).toBeFocused();

    await page.keyboard.press('Enter');
    await page.keyboard.press('Tab');
    await expectMenuOpen(page, 'user-menu', false);
    await expect(page.getByTestId('outside')).toBeFocused();

    await button.click();
    await page.keyboard.press('Shift+Tab');
    await expectMenuOpen(page, 'user-menu', false);
    await expect(page.getByTestId('view-Event C')).toBeFocused();

    // Not modal: the page behind takes the click that closes the menu.
    await button.click();
    await expectMenuOpen(page, 'user-menu', true);
    await page.getByTestId('outside').click();
    await expectMenuOpen(page, 'user-menu', false);
    await expect(page.getByTestId('outside-count')).toHaveText('1');
    await expect(selected(page)).toHaveText('');
  });

  test('a link item navigates, by keyboard and by pointer', async ({ page }) => {
    await open(page);
    const button = trigger(page, 'user-menu');
    await button.focus();
    await page.keyboard.press('Enter');
    await page.keyboard.press('o');
    await expect(item(page, 'Open credentials')).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.getByTestId('hash')).toHaveText('#credentials');
    await expect(page).toHaveURL(/#credentials$/);
    await expectMenuOpen(page, 'user-menu', false);
    await expect(button).toBeFocused();

    await trigger(page, 'avatar-menu').click();
    await item(page, 'Your credentials').click();
    await expect(page.getByTestId('hash')).toHaveText('#own-credentials');
    await expectMenuOpen(page, 'avatar-menu', false);
  });

  test('the popup sits below its trigger, inside the viewport, on the menu tokens', async ({ page }) => {
    await open(page);
    const viewport = page.viewportSize()!;
    const margin = parseFloat(tokens.spacing['8']);
    for (const testId of ['user-menu', 'avatar-menu']) {
      await trigger(page, testId).click();
      await expectMenuOpen(page, testId, true);
      const anchor = (await trigger(page, testId).boundingBox())!;
      const box = (await popup(page, testId).boundingBox())!;
      expect(box.y, testId).toBeGreaterThanOrEqual(anchor.y + anchor.height);
      expect(box.y, testId).toBeLessThanOrEqual(anchor.y + anchor.height + parseFloat(tokens.spacing['8']));
      expect(box.x, testId).toBeGreaterThanOrEqual(margin - 0.5);
      expect(box.x + box.width, testId).toBeLessThanOrEqual(viewport.width - margin + 0.5);
      await page.keyboard.press('Escape');
    }
    // The user menu lines up with its trigger's start; the avatar's moved in from the edge.
    await trigger(page, 'user-menu').click();
    expect((await popup(page, 'user-menu').boundingBox())!.x).toBeCloseTo((await trigger(page, 'user-menu').boundingBox())!.x, 0);

    const s = await popup(page, 'user-menu').evaluate((element) => {
      const c = getComputedStyle(element);
      return { background: c.backgroundColor, border: c.borderTopColor, radius: c.borderTopLeftRadius, shadow: c.boxShadow };
    });
    expect(s.background).toBe(await colour(page, 'var(--gk-menu-background)'));
    expect(s.border).toBe(await colour(page, 'var(--gk-menu-border)'));
    expect(s.radius).toBe(tokens.rounded.card);
    expect(s.shadow).not.toBe('none');
    await item(page, 'Bulk export').hover();
    expect(await item(page, 'Bulk export').evaluate((element) => getComputedStyle(element).backgroundColor)).toBe(
      await colour(page, 'var(--gk-menu-item-hover)'),
    );
  });

  test('inside a drawer, Esc closes only the menu, and Tab out of it stays in the drawer', async ({ page }) => {
    await open(page);
    await page.getByTestId('open-event').click();
    const drawer = eventDrawer(page);
    expect(await isOpen(drawer)).toBe(true);
    const button = trigger(page, 'drawer-menu');
    await button.focus();
    await page.keyboard.press('Enter');
    await expectMenuOpen(page, 'drawer-menu', true);
    await expect(item(page, 'Filter by this user')).toBeFocused();
    await page.keyboard.press('Escape');
    await expectMenuOpen(page, 'drawer-menu', false);
    expect(await isOpen(drawer)).toBe(true);
    await expect(button).toBeFocused();

    await page.keyboard.press('Enter');
    await page.keyboard.press('Tab');
    await expectMenuOpen(page, 'drawer-menu', false);
    await expect(drawer.getByTestId('drawer-open-modal')).toBeFocused();
    await page.keyboard.press('Tab');
    expect(await activeInside(drawer)).toBe(true);

    await button.click();
    await item(page, 'Filter by this user').click();
    await expect(selected(page)).toHaveText('filter');
    expect(await isOpen(drawer)).toBe(true);
    await expect(button).toBeFocused();
  });
});

test.describe('drawer, more cases', () => {
  test('describedBy is set while the drawer is open, and removed when it closes', async ({ page }) => {
    await open(page);
    const drawer = page.getByTestId('row-drawer');
    await expect(drawer).not.toHaveAttribute('aria-describedby');
    await page.getByTestId('view-Event A').click();
    expect(await isOpen(drawer)).toBe(true);
    await expect(drawer).toHaveAttribute('aria-describedby', 'row-drawer-note');
    await expect(drawer).toHaveAccessibleDescription('Removing the row also removes the button that opened this drawer.');
    await page.keyboard.press('Escape');
    expect(await isOpen(drawer)).toBe(false);
    await expect(drawer).not.toHaveAttribute('aria-describedby');
  });

  test('a drawer is refused over another drawer, with a console.error', async ({ page }) => {
    const seen = errors(page);
    await open(page);
    await page.getByTestId('view-Event A').click();
    const drawer = page.getByTestId('row-drawer');
    expect(await isOpen(drawer)).toBe(true);
    await drawer.getByTestId('row-open-drawer').click();
    await expect.poll(() => seen.some((text) => text.includes('Drawer: a modal or drawer is already open'))).toBe(true);
    expect(await isOpen(eventDrawer(page))).toBe(false);
    expect(await isOpen(drawer)).toBe(true);
    expect(await page.evaluate(() => document.querySelectorAll('dialog:modal').length)).toBe(1);
  });

  test('a toast shown while the drawer is open appears whole, above the drawer', async ({ page }) => {
    await open(page);
    await page.getByTestId('open-event').click();
    const drawer = eventDrawer(page);
    expect(await isOpen(drawer)).toBe(true);
    await drawer.getByTestId('drawer-notify').click();
    const toast = page.getByTestId('toast');
    await expect(toast).toHaveText('Filter saved');
    await still(page);
    const viewport = page.viewportSize()!;
    const box = (await toast.boundingBox())!;
    expect(box.x).toBeGreaterThanOrEqual(0);
    expect(box.y).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width).toBeLessThanOrEqual(viewport.width);
    expect(box.y + box.height).toBeLessThanOrEqual(viewport.height);
    // Each corner and the centre hit the toast itself: nothing clips or covers it.
    // Inside the rounded corners.
    const inset = 8;
    const points = [
      [box.x + inset, box.y + inset],
      [box.x + box.width - inset, box.y + inset],
      [box.x + inset, box.y + box.height - inset],
      [box.x + box.width - inset, box.y + box.height - inset],
      [box.x + box.width / 2, box.y + box.height / 2],
    ];
    for (const [x, y] of points) {
      const hit = await page.evaluate(
        ([px, py]) => !!document.elementFromPoint(px!, py!)?.closest('[data-testid="toast"]'),
        [x, y],
      );
      expect(hit, `${x},${y}`).toBe(true);
    }
  });

  test('right to left, the drawer sits at the left edge with its border on the right', async ({ page }) => {
    await open(page, 'light', '&dir=rtl');
    await page.getByTestId('open-event').click();
    const drawer = eventDrawer(page);
    expect(await isOpen(drawer)).toBe(true);
    await still(page);
    const s = await drawer.evaluate((element) => {
      const c = getComputedStyle(element);
      const box = element.getBoundingClientRect();
      return { left: box.left, width: box.width, right: c.borderRightWidth, leftEdge: c.borderLeftWidth, colour: c.borderRightColor };
    });
    expect(s.left).toBeCloseTo(0, 1);
    expect(s.width).toBeCloseTo(parseFloat(tokens.spacing['drawer-w']), 1);
    expect(s.right).toBe('1px');
    expect(s.leftEdge).toBe('0px');
    expect(s.colour).toBe(await colour(page, 'var(--gk-drawer-border)'));
  });

  test('below 767px wide, the drawer keeps a gutter instead of taking half the window', async ({ page }) => {
    await page.setViewportSize({ width: 400, height: 700 });
    await open(page);
    await page.getByTestId('open-event').click();
    const drawer = eventDrawer(page);
    expect(await isOpen(drawer)).toBe(true);
    await still(page);
    const box = await drawer.evaluate((element) => element.getBoundingClientRect().toJSON() as DOMRect);
    expect(box.width).toBeCloseTo(400 - parseFloat(tokens.spacing['16']), 1);
    expect(box.right).toBeCloseTo(400, 1);
  });

  test('a body that grows after opening becomes a Tab stop', async ({ page }) => {
    await open(page);
    await page.getByTestId('open-event').click();
    const drawer = eventDrawer(page);
    expect(await isOpen(drawer)).toBe(true);
    const body = drawer.locator('[data-drawer-body]');
    await expect(body).not.toHaveAttribute('tabindex');
    // Content added later, as an async load would.
    await body.evaluate((element) => {
      const extra = document.createElement('div');
      extra.style.height = '2000px';
      extra.style.flex = 'none';
      element.append(extra);
    });
    await expect(body).toHaveAttribute('tabindex', '0');
    await expect(body).toHaveAccessibleName('Details');
  });
});

test.describe('menu, more cases', () => {
  test('hovering an item focuses it, so only one item is ever highlighted', async ({ page }) => {
    await open(page);
    await trigger(page, 'user-menu').focus();
    await page.keyboard.press('Enter');
    await expect(item(page, 'Block user')).toBeFocused();
    await item(page, 'Rename').hover();
    await expect(item(page, 'Rename')).toBeFocused();
    const hover = await colour(page, 'var(--gk-menu-item-hover)');
    const lit = await popup(page, 'user-menu')
      .locator('[role="menuitem"]')
      .evaluateAll((elements, value) => elements.filter((element) => getComputedStyle(element).backgroundColor === value).map((element) => element.textContent), hover);
    expect(lit).toEqual(['Rename']);
    // Hovering a disabled item leaves focus where it was.
    await item(page, 'Reset MFA').hover();
    await expect(item(page, 'Rename')).toBeFocused();
  });

  test('focus leaving the menu by any route closes it', async ({ page }) => {
    await open(page);
    await trigger(page, 'user-menu').click();
    await expectMenuOpen(page, 'user-menu', true);
    await page.getByTestId('notes').focus();
    await expectMenuOpen(page, 'user-menu', false);
    await expect(page.getByTestId('notes')).toBeFocused();
  });

  test('items that change while open keep focus on the nearest enabled item, or the popup', async ({ page }) => {
    await open(page);
    const live = (change: string) => page.evaluate((value) => window.gkLive!(value as never), change);
    await trigger(page, 'live-menu').click();
    await page.keyboard.press('ArrowDown');
    await expect(item(page, 'Beta')).toBeFocused();
    await live('disable-beta');
    await expect(item(page, 'Gamma')).toBeFocused();
    await page.keyboard.press('ArrowUp');
    await expect(item(page, 'Alpha')).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(item(page, 'Gamma')).toBeFocused();
    await expectMenuOpen(page, 'live-menu', true);

    await page.reload();
    await trigger(page, 'live-menu').click();
    await page.keyboard.press('ArrowDown');
    await expect(item(page, 'Beta')).toBeFocused();
    await live('remove-beta');
    await expect(item(page, 'Gamma')).toBeFocused();
    await expectMenuOpen(page, 'live-menu', true);

    await live('empty');
    await expect(popup(page, 'live-menu')).toBeFocused();
    expect(await page.evaluate(() => document.activeElement === document.body)).toBe(false);
  });

  test('an alignment change while open places the popup again without moving focus', async ({ page }) => {
    await open(page);
    await trigger(page, 'live-menu').click();
    await page.keyboard.press('ArrowDown');
    await expect(item(page, 'Beta')).toBeFocused();
    const anchor = (await trigger(page, 'live-menu').boundingBox())!;
    await page.evaluate(() => window.gkLive!('align'));
    await expect(item(page, 'Beta')).toBeFocused();
    await expect
      .poll(async () => {
        const box = (await popup(page, 'live-menu').boundingBox())!;
        return Math.round(box.x + box.width);
      })
      .toBe(Math.round(anchor.x + anchor.width));
  });

  test('a menu at the bottom edge opens above its trigger, inside the viewport', async ({ page }) => {
    await open(page);
    const viewport = page.viewportSize()!;
    await trigger(page, 'bottom-menu').click();
    await expectMenuOpen(page, 'bottom-menu', true);
    const anchor = (await trigger(page, 'bottom-menu').boundingBox())!;
    const box = (await popup(page, 'bottom-menu').boundingBox())!;
    expect(box.y + box.height).toBeLessThanOrEqual(anchor.y);
    expect(box.y).toBeGreaterThanOrEqual(parseFloat(tokens.spacing['8']) - 0.5);
    expect(box.y + box.height).toBeLessThanOrEqual(viewport.height);
  });

  test('in a short viewport the popup takes a max-height and scrolls, inside the viewport', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 200 });
    await open(page);
    const button = trigger(page, 'user-menu');
    await button.evaluate((element) => element.scrollIntoView({ block: 'center' }));
    await button.click();
    await expectMenuOpen(page, 'user-menu', true);
    const menu = popup(page, 'user-menu');
    const s = await menu.evaluate((element) => ({
      maxHeight: element.style.maxHeight,
      scrolls: element.scrollHeight > element.clientHeight,
      top: element.getBoundingClientRect().top,
      bottom: element.getBoundingClientRect().bottom,
    }));
    expect(s.maxHeight).toMatch(/px$/);
    expect(s.scrolls).toBe(true);
    expect(s.top).toBeGreaterThanOrEqual(0);
    expect(s.bottom).toBeLessThanOrEqual(200);
  });

  test('the popup max-width comes from the viewport without its scrollbar', async ({ page }) => {
    await open(page);
    await trigger(page, 'user-menu').click();
    const s = await popup(page, 'user-menu').evaluate((element) => ({
      maxWidth: element.style.maxWidth,
      client: document.documentElement.clientWidth,
      full: window.innerWidth,
    }));
    // The page scrolls, so the scrollbar takes width that 100vw would still count.
    expect(s.client).toBeLessThanOrEqual(s.full);
    expect(s.maxWidth).toBe(`${s.client - 2 * parseFloat(tokens.spacing['8'])}px`);
  });

  test('the popup stays anchored as the page scrolls and the window resizes', async ({ page }) => {
    await open(page);
    const button = trigger(page, 'avatar-menu');
    const menu = popup(page, 'avatar-menu');
    const gap = parseFloat(tokens.spacing['4']);
    const anchored = async () => {
      const anchor = (await button.boundingBox())!;
      const box = (await menu.boundingBox())!;
      return Math.round(box.y - (anchor.y + anchor.height) - gap);
    };
    await button.click();
    await expectMenuOpen(page, 'avatar-menu', true);
    expect(await anchored()).toBe(0);
    await page.evaluate(() => window.scrollBy(0, 20));
    await expect.poll(anchored).toBe(0);
    await page.setViewportSize({ width: 1000, height: 720 });
    await expect.poll(anchored).toBe(0);
    await expect
      .poll(async () => {
        const box = (await menu.boundingBox())!;
        return box.x + box.width <= 1000 - parseFloat(tokens.spacing['8']) + 0.5;
      })
      .toBe(true);
    await expectMenuOpen(page, 'avatar-menu', true);
  });

  test('the menu closes, without taking focus back, when its trigger scrolls out of view', async ({ page }) => {
    await open(page);
    const button = trigger(page, 'user-menu');
    await button.click();
    await expectMenuOpen(page, 'user-menu', true);
    await button.evaluate((element) => window.scrollTo(0, element.getBoundingClientRect().bottom + window.scrollY + 50));
    await expect(button).not.toBeInViewport();
    await expectMenuOpen(page, 'user-menu', false);
    await expect(button).not.toBeFocused();
    expect(await page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
  });

  test('right to left, a start-aligned popup lines up with its trigger right edge', async ({ page }) => {
    await open(page, 'light', '&dir=rtl');
    const button = trigger(page, 'user-menu');
    await button.click();
    await expectMenuOpen(page, 'user-menu', true);
    const anchor = (await button.boundingBox())!;
    const box = (await popup(page, 'user-menu').boundingBox())!;
    expect(box.x + box.width).toBeCloseTo(anchor.x + anchor.width, 0);
    expect(box.y).toBeGreaterThanOrEqual(anchor.y + anchor.height);
  });
});

for (const scheme of ['light', 'dark'] as const) {
  test(`axe finds no violations, in the ${scheme} scheme, with the drawer open and with the menu open`, async ({ page }) => {
    await open(page, scheme);
    const violations = async () =>
      (await new AxeBuilder({ page }).analyze()).violations.map((violation) => ({
        id: violation.id,
        targets: violation.nodes.map((node) => node.target.join(' ')),
      }));

    await page.getByTestId('open-event').click();
    expect(await isOpen(eventDrawer(page))).toBe(true);
    await still(page);
    expect(await violations(), 'event drawer open').toEqual([]);

    await trigger(page, 'drawer-menu').click();
    await expectMenuOpen(page, 'drawer-menu', true);
    await still(page);
    expect(await violations(), 'menu open in the drawer').toEqual([]);
    await page.keyboard.press('Escape');
    await page.keyboard.press('Escape');

    await page.getByTestId('open-viewer').click();
    expect(await isOpen(eventDrawer(page))).toBe(true);
    await still(page);
    expect(await violations(), 'viewer drawer open').toEqual([]);
    await page.keyboard.press('Escape');

    await page.getByTestId('open-long').click();
    await still(page);
    expect(await violations(), 'long drawer open').toEqual([]);
    await page.keyboard.press('Escape');

    await trigger(page, 'user-menu').click();
    await item(page, 'Bulk export').hover();
    await expectMenuOpen(page, 'user-menu', true);
    await still(page);
    expect(await violations(), 'menu open').toEqual([]);
    await page.keyboard.press('Escape');

    await trigger(page, 'avatar-menu').click();
    await expectMenuOpen(page, 'avatar-menu', true);
    await still(page);
    expect(await violations(), 'avatar menu open').toEqual([]);
  });
}
