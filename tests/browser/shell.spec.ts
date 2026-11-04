// Story 1.25: the Admin shell's presentational parts on the fixture (tests/browser/fixture at
// ?page=shell): AdminShell, TopBar, Sidebar with sample items in every group, ThemeToggle and
// SectionPage, all from @gatekeep/ui/admin. The dashboard's own wiring is admin-shell.spec.ts's.
// Driven by keyboard and pointer in Chromium, never by snapshot.

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { watchCsp } from './csp-watch';

// The fixture has no CSP of its own, so this guards the parts' own markup only.
watchCsp(test);

type Scheme = 'light' | 'dark';

/** The nine v1 groups, in EXPERIENCE order, written out here rather than read from the package. */
const GROUPS = [
  'Applications',
  'Authentication',
  'User management',
  'Authorization',
  'Security',
  'Branding',
  'Monitoring',
  'Settings',
  'Deployment',
];

/** Each group's first sample item, as the fixture lists them. */
const FIRST: Record<string, string> = {
  Applications: '/tenants/ten_a/applications',
  Authentication: '/tenants/ten_a/connections/database',
  'User management': '/tenants/ten_a/users',
  Authorization: '/tenants/ten_a/roles',
  Security: '/tenants/ten_a/mfa',
  Branding: '/tenants/ten_a/branding',
  Monitoring: '/tenants/ten_a/logs',
  Settings: '/tenants/ten_a/settings',
  Deployment: '/deployment/tenants',
};

async function open(page: Page, { width = 1280, scheme = 'light' as Scheme, extra = '' } = {}) {
  await page.setViewportSize({ width, height: 720 });
  await page.goto(`/?page=shell&scheme=${scheme}${extra}`);
  await expect(page.getByTestId('shell')).toBeVisible();
}

const nav = (page: Page) => page.getByRole('navigation', { name: 'Main' });
const banner = (page: Page) => page.getByRole('banner');
const groupButton = (page: Page, name: string) => nav(page).getByRole('button', { name, exact: true });
const recorded = (page: Page) => page.evaluate(() => window.gkShell!);

/** Waits for every running animation to finish, so axe reads final colours. */
const still = (page: Page) =>
  page.evaluate(() => Promise.allSettled(document.getAnimations().map((animation) => animation.finished)).then(() => undefined));

async function axe(page: Page) {
  await still(page);
  return (await new AxeBuilder({ page }).analyze()).violations.map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
}

/**
 * From now on, whether each click reached the window with its default still to run: false is a
 * click left to the browser, such as a modified one. The default is then cancelled here, so the
 * test opens no tab or window.
 */
async function browserDefaults(page: Page) {
  await page.evaluate(() => {
    const seen: boolean[] = [];
    (window as unknown as { __gkDefaults: boolean[] }).__gkDefaults = seen;
    window.addEventListener('click', (event) => {
      seen.push(event.defaultPrevented);
      event.preventDefault();
    });
  });
  return () => page.evaluate(() => (window as unknown as { __gkDefaults: boolean[] }).__gkDefaults);
}

test('the shell parts are Admin only, exported from the admin entry', async ({ page }) => {
  await open(page);
  const html = page.locator('html');
  await expect(html).toHaveAttribute('data-same-modules', 'true');
  const hosted = (await html.getAttribute('data-hosted-exports'))!.split(' ');
  const adminOnly = (await html.getAttribute('data-admin-only-exports'))!.split(' ');
  for (const name of ['ADMIN_NAV_GROUPS', 'AdminShell', 'SectionPage', 'Sidebar', 'ThemeToggle', 'TopBar', 'useMediaQuery']) {
    expect(hosted, name).not.toContain(name);
    expect(adminOnly, name).toContain(name);
  }
});

for (const width of [1280, 1100, 1099, 768, 767]) {
  const wide = width >= 1100;
  test(`at ${width}px: the ${wide ? 'full 236px sidebar' : '52px icon rail'}, the wordmark ${wide ? 'shown' : 'visually hidden'}, and only main scrolls`, async ({
    page,
  }) => {
    await open(page, { width });

    expect((await nav(page).boundingBox())!.width).toBe(wide ? 236 : 52);
    expect((await banner(page).boundingBox())!.height).toBe(48);

    // The brand link keeps its name either way; below 1100px its wordmark is a 1px clip.
    const brand = banner(page).getByRole('link', { name: 'gatekeep', exact: true });
    await expect(brand).toHaveAttribute('href', '/');
    // At 1100px and wider the brand is 208px, so its end lines up with the sidebar's.
    if (wide) expect((await brand.boundingBox())!.width).toBe(208);
    const wordmark = (await brand.locator('[data-part="wordmark"]').boundingBox())!;
    if (wide) expect(wordmark.width).toBeGreaterThan(20);
    else expect(wordmark.width).toBeLessThanOrEqual(1);

    const sizes = await page.evaluate(() => {
      const root = document.scrollingElement!;
      const main = document.querySelector('main')!;
      return {
        rootHeight: root.scrollHeight,
        rootWidth: root.scrollWidth,
        innerHeight,
        innerWidth: document.documentElement.clientWidth,
        mainScroll: main.scrollHeight,
        mainClient: main.clientHeight,
        overflow: getComputedStyle(main).overflowY,
      };
    });
    expect(sizes.rootHeight).toBe(sizes.innerHeight);
    expect(sizes.rootWidth).toBe(sizes.innerWidth);
    expect(sizes.overflow).toBe('auto');
    expect(sizes.mainScroll).toBeGreaterThan(sizes.mainClient);

    // Scrolling main moves the page, never the window.
    await page.locator('main').evaluate((main) => main.scrollTo(0, 400));
    expect(await page.evaluate(() => [scrollY, document.querySelector('main')!.scrollTop > 0])).toEqual([0, true]);
  });
}

test.describe('wide sidebar', () => {
  test('lists the nine groups in EXPERIENCE order as disclosures, the current group open', async ({ page }) => {
    await open(page);

    const buttons = nav(page).getByRole('button');
    await expect(buttons).toHaveText(GROUPS);
    for (const name of GROUPS) {
      const button = groupButton(page, name);
      await expect(button).toHaveAttribute('aria-expanded', name === 'User management' ? 'true' : 'false');
      const list = page.locator(`[id="${await button.getAttribute('aria-controls')}"]`);
      if (name === 'User management') await expect(list).toBeVisible();
      else await expect(list).toBeHidden();
    }

    const current = nav(page).getByRole('link', { name: 'Users', exact: true });
    await expect(current).toHaveAttribute('aria-current', 'page');
    // DESIGN's active item: a 2px jade rule on the left, on sf2, at weight 500.
    const style = await current.evaluate((link) => {
      const probe = document.createElement('span');
      probe.style.color = 'var(--gk-color-ac)';
      probe.style.backgroundColor = 'var(--gk-color-sf2)';
      document.body.append(probe);
      const expected = getComputedStyle(probe);
      const computed = getComputedStyle(link);
      const result = {
        width: computed.borderLeftWidth,
        rule: computed.borderLeftColor === expected.color,
        surface: computed.backgroundColor === expected.backgroundColor,
        weight: computed.fontWeight,
      };
      probe.remove();
      return result;
    });
    expect(style).toEqual({ width: '2px', rule: true, surface: true, weight: '500' });
    await expect(current).toHaveAttribute('href', '/tenants/ten_a/users');
    await expect(nav(page).locator('[aria-current]')).toHaveCount(1);
  });

  test('a group with no item is not rendered, and nothing is drawn for an item not given', async ({ page }) => {
    await open(page, { extra: '&omit=branding' });

    await expect(nav(page).getByRole('button')).toHaveText(GROUPS.filter((name) => name !== 'Branding'));
    await expect(nav(page).getByText('Branding')).toHaveCount(0);
    await expect(nav(page).getByText('Universal Login')).toHaveCount(0);
  });

  test('Enter and Space open and close a group, in Tab order after the top bar', async ({ page }) => {
    await open(page);

    await banner(page).getByRole('link', { name: 'gatekeep' }).focus();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Dark theme' })).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: 'Account' })).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(groupButton(page, 'Applications')).toBeFocused();

    await page.keyboard.press('Enter');
    await expect(groupButton(page, 'Applications')).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('Tab');
    await expect(nav(page).getByRole('link', { name: 'Applications', exact: true })).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(nav(page).getByRole('link', { name: 'APIs', exact: true })).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(groupButton(page, 'Authentication')).toBeFocused();

    await page.keyboard.press(' ');
    await expect(groupButton(page, 'Authentication')).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press(' ');
    await expect(groupButton(page, 'Authentication')).toHaveAttribute('aria-expanded', 'false');

    // The current group closes by hand too, and stays closed.
    await groupButton(page, 'User management').click();
    await expect(groupButton(page, 'User management')).toHaveAttribute('aria-expanded', 'false');
  });

  test('a plain click navigates in the page and moves focus to the new h1; a modified click is the browser’s', async ({ page }) => {
    await open(page);
    // First load: focus stays on the document.
    expect(await page.evaluate(() => document.activeElement === document.body)).toBe(true);

    await groupButton(page, 'Security').click();
    await nav(page).getByRole('link', { name: 'Multi-factor auth' }).click();
    expect((await recorded(page)).navigated).toEqual(['/tenants/ten_a/mfa']);
    await expect(page).toHaveURL(/\?page=shell/);
    const heading = page.getByRole('heading', { level: 1 });
    await expect(heading).toHaveText('Multi-factor auth');
    await expect(heading).toBeFocused();
    await expect(nav(page).getByRole('link', { name: 'Multi-factor auth' })).toHaveAttribute('aria-current', 'page');

    const defaults = await browserDefaults(page);
    await nav(page).getByRole('link', { name: 'Multi-factor auth' }).click({ modifiers: ['ControlOrMeta'] });
    expect((await recorded(page)).navigated).toEqual(['/tenants/ten_a/mfa']);
    expect(await defaults()).toEqual([false]);

    await banner(page).getByRole('link', { name: 'gatekeep' }).click();
    expect((await recorded(page)).navigated).toEqual(['/tenants/ten_a/mfa', '/']);
  });
});

test.describe('icon rail', () => {
  for (const width of [1099, 768]) {
    test(`at ${width}px each group is one link to its first item, named by its label`, async ({ page }) => {
      await open(page, { width });

      await expect(nav(page).getByRole('button')).toHaveCount(0);
      const links = nav(page).getByRole('link');
      await expect(links).toHaveCount(GROUPS.length);
      for (const [index, name] of GROUPS.entries()) {
        const link = links.nth(index);
        await expect(link).toHaveAccessibleName(name);
        await expect(link).toHaveAttribute('title', name);
        await expect(link).toHaveAttribute('href', FIRST[name]!);
        if (name === 'User management') await expect(link).toHaveAttribute('aria-current', 'true');
        else expect(await link.getAttribute('aria-current')).toBeNull();
      }
      // No item list is drawn: only the group links.
      await expect(nav(page).getByRole('link', { name: 'APIs' })).toHaveCount(0);

      await nav(page).getByRole('link', { name: 'Deployment' }).click();
      expect((await recorded(page)).navigated).toEqual(['/deployment/tenants']);
      await expect(nav(page).getByRole('link', { name: 'Deployment' })).toHaveAttribute('aria-current', 'true');

      const defaults = await browserDefaults(page);
      await nav(page).getByRole('link', { name: 'Security' }).click({ modifiers: ['Shift'] });
      expect((await recorded(page)).navigated).toEqual(['/deployment/tenants']);
      expect(await defaults()).toEqual([false]);
    });
  }
});

test('the top bar holds the brand, the theme toggle and the avatar menu, and nothing deferred', async ({ page }) => {
  await open(page);

  const header = banner(page);
  await expect(header).toHaveCount(1);
  await expect(header.getByRole('link')).toHaveCount(1);
  await expect(header.getByRole('link', { name: 'gatekeep' })).toBeVisible();
  await expect(header.getByRole('button')).toHaveCount(2);
  await expect(header.getByRole('button', { name: 'Dark theme' })).toBeVisible();
  await expect(header.getByRole('button', { name: 'Account' })).toHaveAttribute('aria-haspopup', 'menu');
  await expect(page.getByRole('searchbox')).toHaveCount(0);
  await expect(header.getByRole('textbox')).toHaveCount(0);
  await expect(header.getByRole('searchbox')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /alerts|help/i })).toHaveCount(0);
  await expect(page.getByRole('link', { name: /alerts|help/i })).toHaveCount(0);
  await expect(page.getByText('⌘K')).toHaveCount(0);

  // The avatar menu holds its items, and selecting one calls back.
  await header.getByRole('button', { name: 'Account' }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  expect((await recorded(page)).signOuts).toBe(1);
});

test('the theme toggle is pressed while dark and calls back on each activation', async ({ page }) => {
  await open(page);
  const toggle = page.getByRole('button', { name: 'Dark theme' });
  await expect(toggle).toHaveAttribute('aria-pressed', 'false');

  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-pressed', 'true');
  expect((await recorded(page)).toggles).toBe(1);
  await toggle.press('Enter');
  await expect(toggle).toHaveAttribute('aria-pressed', 'false');
  expect((await recorded(page)).toggles).toBe(2);

  await open(page, { scheme: 'dark' });
  await expect(page.getByRole('button', { name: 'Dark theme' })).toHaveAttribute('aria-pressed', 'true');
});

test('a Section page has one h1, its eyebrow, description and actions', async ({ page }) => {
  await open(page);
  const section = page.getByTestId('section');
  await expect(page.getByRole('heading', { level: 1 })).toHaveCount(1);
  await expect(section.getByRole('heading', { level: 1 })).toHaveText('Users');
  await expect(section.getByRole('heading', { level: 1 })).toHaveAttribute('tabindex', '-1');
  await expect(section.getByText('User management', { exact: true })).toBeVisible();
  await expect(section.getByText("Everyone who can sign in to this Tenant's Applications.")).toBeVisible();
  await expect(section.getByRole('button', { name: 'Create user' })).toHaveAttribute('data-variant', 'primary');
});

test('setting and clearing the banner keeps the page: the same input node, its value and its focus', async ({ page }) => {
  await open(page);
  const input = page.getByTestId('unsaved');
  await input.click();
  await page.keyboard.type('half-typed value');
  await input.evaluate((element) => ((element as unknown as { gkMarker: string }).gkMarker = 'same-node'));

  await page.evaluate(() => window.gkShellBanner!(true));
  await expect(page.getByTestId('fixture-banner')).toHaveAttribute('role', 'alert');
  // The banner sits at the top of main, above the page.
  const [bannerBox, pageBox] = [await page.getByTestId('fixture-banner').boundingBox(), await page.getByTestId('section').boundingBox()];
  expect(bannerBox!.y).toBeLessThan(pageBox!.y);
  expect(await page.locator('main').getByTestId('fixture-banner').count()).toBe(1);

  await page.evaluate(() => window.gkShellBanner!(false));
  await expect(page.getByTestId('fixture-banner')).toHaveCount(0);

  await expect(input).toHaveValue('half-typed value');
  await expect(input).toBeFocused();
  expect(await input.evaluate((element) => (element as unknown as { gkMarker?: string }).gkMarker)).toBe('same-node');
});

for (const scheme of ['light', 'dark'] as const) {
  for (const width of [1100, 768]) {
    test(`axe finds no violations at ${width}px, ${scheme}: at rest, with a group open, with the banner and with the avatar menu open`, async ({ page }) => {
      await open(page, { width, scheme });
      expect(await axe(page), 'at rest').toEqual([]);

      if (width >= 1100) {
        await groupButton(page, 'Applications').click();
        await expect(groupButton(page, 'Applications')).toHaveAttribute('aria-expanded', 'true');
        expect(await axe(page), 'group open').toEqual([]);
      }

      await page.evaluate(() => window.gkShellBanner!(true));
      await expect(page.getByTestId('fixture-banner')).toBeVisible();
      expect(await axe(page), 'banner').toEqual([]);

      await page.getByRole('button', { name: 'Account' }).click();
      await expect(page.getByRole('menu')).toBeVisible();
      expect(await axe(page), 'menu open').toEqual([]);
    });
  }
}
