// The Story 1.15 matrix, row by row, on the data display fixture (tests/browser/fixture at
// ?page=data). The shared pieces (badges, Copy, code block) run on both surfaces; the rest
// runs on Admin, the one surface that exports it. Driven by keyboard and pointer in
// Chromium, never by snapshot. Expected values come from the generated tokens, never hex.

import AxeBuilder from '@axe-core/playwright';
import { tokens } from '@gatekeep/design-tokens';
import { expect, test, type Locator, type Page } from '@playwright/test';

type Surface = 'admin' | 'hosted';
type Scheme = 'light' | 'dark';

const px = (value: string) => parseFloat(value);
const ROW = px(tokens.spacing['table-row-h']);
const HEAD = px(tokens.spacing['table-head-h']);
const COPIED_MS = 2000;
// One animation frame and then some, on the paused clock.
const FRAME = 20;
const MONO = /^"?Geist Mono"?,/;
const TRANSPARENT = 'rgba(0, 0, 0, 0)';

const RAW_EVENT = {
  type: 'login.failure',
  user_id: 'user_007',
  attempts: 3,
  success: false,
  ip: null,
  scopes: ['openid', 'profile'],
};

async function open(page: Page, surface: Surface, scheme: Scheme = 'light', extra = '') {
  await page.goto(`/?page=data&surface=${surface}&scheme=${scheme}${extra}`);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(`Data display on ${surface}`);
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

async function style(locator: Locator) {
  return locator.evaluate((element) => {
    const s = getComputedStyle(element);
    return {
      height: element.getBoundingClientRect().height,
      width: element.getBoundingClientRect().width,
      fontFamily: s.fontFamily,
      fontSize: s.fontSize,
      textAlign: s.textAlign,
      background: s.backgroundColor,
      color: s.color,
      borderColor: s.borderTopColor,
      borderStyle: s.borderTopStyle,
      borderRadius: s.borderTopLeftRadius,
      textDecoration: s.textDecorationLine,
    };
  });
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

/** The status region beside a Copy control, found by the control's test id so it never re-resolves by name. */
const statusOf = (page: Page, testId: string) => page.getByTestId(testId).locator('xpath=following-sibling::*[@role="status"][1]');
const clipboard = (page: Page) => page.evaluate(() => navigator.clipboard.readText());

/** On the paused clock, advances frame by frame until a Copy control's status reads `text`. */
async function settleCopy(page: Page, status: Locator, text: string) {
  await expect
    .poll(async () => {
      await page.clock.runFor(FRAME);
      return status.textContent();
    })
    .toBe(text);
}

test.use({ permissions: ['clipboard-read', 'clipboard-write'] });

for (const surface of ['admin', 'hosted'] as const) {
  test.describe(`on ${surface}`, () => {
    test('the hosted entry exports the shared pieces only, and admin exactly those modules plus its own', async ({ page }) => {
      await open(page, surface);
      const html = page.locator('html');
      // main.tsx checks the admin entry against the hosted exports plus its named own list.
      await expect(html).toHaveAttribute('data-same-modules', 'true');
      const hosted = (await html.getAttribute('data-hosted-exports'))!.split(' ');
      const adminOnly = (await html.getAttribute('data-admin-only-exports'))!.split(' ');
      for (const name of ['StatusBadge', 'ProtocolBadge', 'DraftBadge', 'EnvironmentBadge', 'CodeBadge', 'CopyButton', 'CodeBlock']) {
        expect(hosted, name).toContain(name);
      }
      expect(adminOnly).toEqual(
        [
          'ConfirmModal',
          'DataTable',
          'EmptyState',
          'JsonViewer',
          'Modal',
          'ModalProvider',
          'OneTimeReveal',
          'PAGE_SIZE',
          'RbacMatrix',
          'SKELETON_DELAY_MS',
          'SettingsRow',
          'SkeletonRows',
          'StatTile',
          'Tabs',
          'UsageBar',
          'useUrlTab',
        ].sort(),
      );
    });

    test('badges take their token colours and sizes, and the text, not the dot, carries the meaning', async ({ page }) => {
      await open(page, surface);
      const mono = ['badge-prod', 'badge-staging', 'badge-dev', 'badge-success', 'badge-failure'];
      const cases = [
        ['badge-active', 'Active', 'ok'],
        ['badge-pending', 'Pending', 'warn'],
        ['badge-blocked', 'Blocked', 'bad'],
        ['badge-protocol', 'OIDC', 'info'],
        ['badge-prod', 'Prod', 'bad'],
        ['badge-staging', 'Staging', 'warn'],
        ['badge-dev', 'Dev', 'info'],
        ['badge-failure', 'fp', 'bad'],
      ] as const;
      for (const [id, text, tone] of cases) {
        const badge = page.getByTestId(id);
        await expect(badge, id).toHaveText(text);
        const s = await style(badge);
        expect(s.color, id).toBe(await colour(page, `var(--gk-color-${tone})`));
        expect(s.background, id).toBe(await colour(page, `var(--gk-color-${tone}-sf)`));
      }

      // Status badges carry a 6px dot, hidden from assistive technology; the others have none.
      for (const id of ['badge-active', 'badge-pending', 'badge-blocked']) {
        const dot = page.getByTestId(id).locator('[aria-hidden="true"]');
        await expect(dot).toHaveCount(1);
        const box = (await dot.boundingBox())!;
        expect(box.width).toBe(6);
        expect(box.height).toBe(6);
        expect((await style(dot)).background).toBe((await style(page.getByTestId(id))).color);
      }
      for (const id of ['badge-protocol', 'badge-draft', 'badge-prod', 'badge-success']) {
        await expect(page.getByTestId(id).locator('[aria-hidden="true"]'), id).toHaveCount(0);
      }

      // Status, protocol and Draft badges on badge-status; Draft outlined.
      for (const id of ['badge-active', 'badge-pending', 'badge-blocked', 'badge-protocol', 'badge-draft']) {
        const s = await style(page.getByTestId(id));
        expect(s.height, id).toBe(px(tokens.components['badge-status'].height));
        expect(s.borderRadius, id).toBe(tokens.rounded.tag);
        expect(s.fontFamily, id).not.toMatch(MONO);
      }
      const draft = await style(page.getByTestId('badge-draft'));
      await expect(page.getByTestId('badge-draft')).toHaveText('Draft');
      expect(draft.background).toBe(TRANSPARENT);
      expect(draft.borderColor).toBe(await colour(page, 'var(--gk-color-bd2)'));
      expect(draft.borderStyle).toBe('solid');

      // Environment and Log codes on badge-mono; a success code is tx2 on sf2.
      for (const id of mono) {
        const s = await style(page.getByTestId(id));
        expect(s.fontFamily, id).toMatch(MONO);
        expect(s.fontSize, id).toBe(tokens.components['badge-mono']['font-size']);
        expect(s.height, id).toBe(px(tokens.components['badge-mono'].height));
        expect(s.borderRadius, id).toBe(tokens.rounded.tag);
      }
      const success = await style(page.getByTestId('badge-success'));
      expect(success.background).toBe(await colour(page, 'var(--gk-color-sf2)'));
      expect(success.color).toBe(await colour(page, 'var(--gk-color-tx2)'));
    });

    test('Copy writes the clipboard, shows and announces "Copied" for 2 seconds, and keeps its width', async ({ page }) => {
      await page.clock.install();
      await open(page, surface);
      await pauseClock(page);
      const button = page.getByTestId('copy-client-id');
      const status = statusOf(page, 'copy-client-id');
      await expect(button).toHaveAccessibleName('Copy client ID');
      await expect(status).toHaveText('');
      const before = (await button.boundingBox())!;

      await button.click();
      expect(await clipboard(page)).toBe('app_8f2k3m9q');
      await settleCopy(page, status, 'Copied');
      await expect(button).toHaveAccessibleName('Copied client ID');
      await expect(status).toHaveText('Copied');
      expect((await button.boundingBox())!.width).toBeCloseTo(before.width, 1);

      await page.clock.runFor(COPIED_MS - 2 * FRAME);
      await expect(status).toHaveText('Copied');
      await page.clock.runFor(2 * FRAME);
      await expect(status).toHaveText('');
      await expect(button).toHaveAccessibleName('Copy client ID');

      // A function value is read at the click.
      await page.getByTestId('copy-setup-key').click();
      expect(await clipboard(page)).toBe('computed-at-click');

      // The catalogue supplies the texts and the name's word order.
      const german = page.getByTestId('copy-german');
      await expect(german).toHaveAccessibleName('Schlüssel kopieren');
      await german.click();
      await settleCopy(page, statusOf(page, 'copy-german'), 'Kopiert');
      await expect(german).toHaveAccessibleName('Schlüssel kopiert');
    });

    test('two copies in a row are announced twice, and the 2 seconds restart from the second', async ({ page }) => {
      await page.clock.install();
      await open(page, surface);
      await pauseClock(page);
      const button = page.getByTestId('copy-client-id');
      const status = statusOf(page, 'copy-client-id');
      const texts = await record(status);

      await button.click();
      await settleCopy(page, status, 'Copied');
      await page.clock.runFor(1000);
      await button.click();
      await settleCopy(page, status, 'Copied');
      expect(await texts()).toEqual(['Copied', '', 'Copied']);

      // 1.5 seconds after the second copy, 2.5 after the first: still shown.
      await page.clock.runFor(1500);
      await expect(status).toHaveText('Copied');
      await page.clock.runFor(COPIED_MS - 1500);
      await expect(status).toHaveText('');
    });

    test('a failed copy is announced in neutral words, without the value, every time', async ({ page }) => {
      await open(page, surface);
      await page.evaluate(() => {
        Object.defineProperty(navigator.clipboard, 'writeText', { value: () => Promise.reject(new Error('denied')) });
      });
      const button = page.getByTestId('copy-client-id');
      const status = statusOf(page, 'copy-client-id');
      const texts = await record(status);
      const message = "Couldn't copy. Select the text and copy it instead.";
      await button.click();
      await expect(status).toHaveText(message);
      await button.click();
      await expect.poll(texts).toEqual([message, '', message]);
      await expect(status).not.toContainText('app_8f2k3m9q');
      await expect(button).toHaveAccessibleName('Copy client ID');
    });

    test('a ghost Copy hovers on sf2; on the code block strip it stays clear and underlines', async ({ page }) => {
      await open(page, surface);
      const plain = page.getByTestId('copy-client-id');
      await plain.hover();
      expect((await style(plain)).background).toBe(await colour(page, 'var(--gk-color-sf2)'));

      const strip = page.getByRole('figure', { name: 'auth.ts' }).getByRole('button', { name: 'Copy auth.ts' });
      expect((await style(strip)).color).toBe(await colour(page, 'var(--gk-color-code-tx)'));
      await strip.hover();
      const hovered = await style(strip);
      expect(hovered.background).toBe(TRANSPARENT);
      expect(hovered.textDecoration).toBe('underline');
    });

    test('the code block has a filename header with Copy, and copies the whole code', async ({ page }) => {
      await open(page, surface);
      const figure = page.getByRole('figure', { name: 'auth.ts' });
      await expect(figure).toBeVisible();
      // The code is a named group, not a second landmark.
      await expect(figure.getByRole('region')).toHaveCount(0);
      const code = figure.getByRole('group', { name: 'auth.ts' });
      const text = await code.textContent();
      expect(text).toContain("const issuer = await Issuer.discover('https://northwind.example');");
      expect((await style(figure)).background).toBe(await colour(page, 'var(--gk-color-code-bg)'));
      expect((await style(code)).fontFamily).toMatch(MONO);

      // It's focusable, so a keyboard can scroll it.
      await code.focus();
      await expect(code).toBeFocused();

      await figure.getByRole('button', { name: 'Copy auth.ts' }).click();
      expect(await clipboard(page)).toBe(text);
      await expect(figure.getByRole('status')).toHaveText('Copied');
    });

    for (const scheme of ['light', 'dark'] as const) {
      test(`axe finds no violations, in the ${scheme} scheme, at rest and after a copy`, async ({ page }) => {
        await open(page, surface, scheme);
        const violations = async () => {
          // tx3 on sf2 in table heads is DESIGN.md's one recorded exception (Contrast table:
          // "Known exception: Admin table heads only"), so only contrast skips those cells.
          const everything = await new AxeBuilder({ page }).disableRules(['color-contrast']).analyze();
          const contrast = await new AxeBuilder({ page }).withRules(['color-contrast']).exclude('thead th').analyze();
          return [...everything.violations, ...contrast.violations].map((violation) => ({
            id: violation.id,
            targets: violation.nodes.map((node) => node.target.join(' ')),
          }));
        };
        expect(await violations(), 'at rest').toEqual([]);
        await page.getByTestId('copy-client-id').click();
        await expect(page.getByTestId('copy-client-id')).toHaveAccessibleName('Copied client ID');
        expect(await violations(), 'after a copy').toEqual([]);

        if (surface === 'admin') {
          await page.getByRole('tab', { name: 'Credentials' }).click();
          await page.getByTestId('loading').check();
          await expect(page.getByTestId('loading-area').getByRole('status')).toHaveText('Loading');
          await page.getByRole('button', { name: 'Next' }).first().click();
          expect(await violations(), 'on another tab and page, loading').toEqual([]);
        }
      });
    }
  });
}

test.describe('on admin', () => {
  const table = (page: Page) => page.getByRole('table', { name: 'Users', exact: true });
  const card = (page: Page) => table(page).locator('xpath=..');
  const bodyRows = (page: Page) => table(page).locator('tbody tr');
  const range = (page: Page) => card(page).getByRole('navigation', { name: 'Pagination' }).getByRole('status');
  const applicationTabs = (page: Page) => page.getByRole('tablist', { name: 'Application' });
  const shownPanel = (list: Locator) => list.locator('xpath=following-sibling::*[@role="tabpanel" and not(@hidden)]');

  test('the table uses real table semantics, 38px rows under a 32px head, and right-aligned mono numbers', async ({ page }) => {
    await open(page, 'admin');
    const users = table(page);
    await expect(users).toBeVisible();
    const heads = users.locator('thead th');
    await expect(heads).toHaveCount(3);
    for (const head of await heads.all()) await expect(head).toHaveAttribute('scope', 'col');
    await expect(users.getByRole('columnheader')).toHaveText(['Name', 'Client ID', 'Logins']);
    await expect(users.getByRole('rowheader').first()).toHaveText('User 001');
    await expect(users.locator('tbody th').first()).toHaveAttribute('scope', 'row');

    expect((await style(users.locator('thead tr'))).height).toBe(HEAD);
    for (const row of (await bodyRows(page).all()).slice(0, 5)) expect((await style(row)).height).toBe(ROW);

    const head = await style(heads.first());
    expect(head.background).toBe(await colour(page, 'var(--gk-color-sf2)'));
    expect(head.color).toBe(await colour(page, 'var(--gk-color-tx3)'));

    const logins = await style(bodyRows(page).first().locator('td').last());
    expect(logins.textAlign).toBe('end');
    expect(logins.fontFamily).toMatch(MONO);
    expect((await style(heads.last())).textAlign).toBe('end');
    const name = await style(bodyRows(page).first().locator('th'));
    expect(name.textAlign).toBe('start');
    expect(name.fontFamily).not.toMatch(MONO);
  });

  test('pages at 50 rows, with Previous and Next and a "from–to of total" status', async ({ page }) => {
    await open(page, 'admin');
    const previous = card(page).getByRole('button', { name: 'Previous' });
    const next = card(page).getByRole('button', { name: 'Next' });

    await expect(bodyRows(page)).toHaveCount(50);
    await expect(bodyRows(page).first().locator('th')).toHaveText('User 001');
    await expect(bodyRows(page).last().locator('th')).toHaveText('User 050');
    await expect(range(page)).toHaveText('1–50 of 120');
    await expect(previous).toHaveAttribute('aria-disabled', 'true');
    await expect(next).not.toHaveAttribute('aria-disabled', 'true');

    // At the start, Previous does nothing, and stays focusable.
    await previous.click({ force: true });
    await expect(range(page)).toHaveText('1–50 of 120');

    await next.click();
    await expect(bodyRows(page)).toHaveCount(50);
    await expect(bodyRows(page).first().locator('th')).toHaveText('User 051');
    await expect(bodyRows(page).last().locator('th')).toHaveText('User 100');
    await expect(range(page)).toHaveText('51–100 of 120');
    await expect(previous).not.toHaveAttribute('aria-disabled', 'true');

    await next.press('Enter');
    await expect(bodyRows(page)).toHaveCount(20);
    await expect(range(page)).toHaveText('101–120 of 120');
    await expect(next).toHaveAttribute('aria-disabled', 'true');
    await expect(next).toBeFocused();
    await next.click({ force: true });
    await expect(range(page)).toHaveText('101–120 of 120');

    await previous.click();
    await expect(range(page)).toHaveText('51–100 of 120');
  });

  test('a controlled page waits for the caller, and a page past the end shows the last one', async ({ page }) => {
    await open(page, 'admin');
    const controlled = page.getByRole('table', { name: 'Controlled users' });
    const pager = controlled.locator('xpath=..').getByRole('navigation', { name: 'Pagination' });
    const requests = page.getByTestId('page-requests');
    await expect(pager.getByRole('status')).toHaveText('1–50 of 120');

    await pager.getByRole('button', { name: 'Next' }).click();
    await expect(requests).toHaveText('1');
    // Next only asked: the caller hasn't moved the page.
    await expect(pager.getByRole('status')).toHaveText('1–50 of 120');

    await page.getByTestId('page-past-end').click();
    await expect(pager.getByRole('status')).toHaveText('101–120 of 120');
    await expect(controlled.locator('tbody tr')).toHaveCount(20);
  });

  test('hideCaption keeps the name for assistive technology only, and selectedKey marks one row current', async ({ page }) => {
    await open(page, 'admin');
    const controlled = page.getByRole('table', { name: 'Controlled users' });
    await expect(controlled).toBeVisible();
    const caption = (await controlled.locator('caption').boundingBox())!;
    expect(caption.width).toBeLessThanOrEqual(1);
    expect(caption.height).toBeLessThanOrEqual(1);

    const current = controlled.locator('tbody tr[aria-current="true"]');
    await expect(current).toHaveCount(1);
    await expect(current.locator('th')).toHaveText('User 002');
    expect((await style(current.locator('th'))).background).toBe(await colour(page, 'var(--gk-color-ac-sf)'));
    await expect(bodyRows(page).locator('[aria-current]')).toHaveCount(0);
  });

  test('an empty table shows its empty slot in place of the body', async ({ page }) => {
    await open(page, 'admin');
    const empty = page.getByRole('table', { name: 'No users' });
    await expect(empty.getByRole('columnheader')).toHaveText(['Name']);
    await expect(empty.locator('tbody')).toHaveText('No users yet');
    await expect(empty.locator('tbody td')).toHaveAttribute('colspan', '1');
  });

  test('a click on a row, or Enter on its link, activates it once', async ({ page }) => {
    await open(page, 'admin');
    const activated = page.getByTestId('activated');
    await bodyRows(page).nth(2).locator('td').last().click();
    await expect(activated).toHaveText('user_003');

    const link = bodyRows(page).nth(4).getByRole('button', { name: 'User 005', exact: true });
    await link.focus();
    await page.keyboard.press('Enter');
    await expect(activated).toHaveText('user_003 user_005');

    // A pointer click on the link is still one activation.
    await bodyRows(page).nth(6).getByRole('button', { name: 'User 007', exact: true }).click();
    await expect(activated).toHaveText('user_003 user_005 user_007');
  });

  test('dragging to select text in a row selects it, and does not activate the row', async ({ page }) => {
    await open(page, 'admin');
    const code = bodyRows(page).nth(3).locator('code');
    const box = (await code.boundingBox())!;
    await page.mouse.move(box.x + 1, box.y + box.height / 2);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width - 1, box.y + box.height / 2, { steps: 5 });
    await page.mouse.up();
    expect(await page.evaluate(() => window.getSelection()?.toString())).not.toBe('');
    await expect(page.getByTestId('activated')).toHaveText('');
  });

  test('Copy inside a row copies and announces, and does not open the row', async ({ page }) => {
    await open(page, 'admin');
    const copy = bodyRows(page).nth(1).getByRole('button', { name: /client ID of User 002$/ });
    await copy.click();
    expect(await clipboard(page)).toBe('app_002k3m9q');
    await expect(bodyRows(page).nth(1).getByRole('status')).toHaveText('Copied');
    await copy.press('Enter');
    await expect(page.getByTestId('activated')).toHaveText('');
  });

  test('tabs are one tab stop; arrows, Home and End move focus, and only Enter or Space selects', async ({ page }) => {
    await open(page, 'admin');
    const list = applicationTabs(page);
    const tab = (name: string) => list.getByRole('tab', { name });
    const panel = shownPanel(list);
    await expect(list.locator('[tabindex="0"]')).toHaveCount(1);
    await expect(tab('Settings')).toHaveAttribute('aria-selected', 'true');
    await expect(panel).toHaveText('Settings panel');
    await expect(panel).toHaveAccessibleName('Settings');

    await page.getByTestId('async-guard').focus();
    await page.keyboard.press('Tab');
    await expect(tab('Settings')).toBeFocused();

    await page.keyboard.press('ArrowRight');
    await expect(tab('Credentials')).toBeFocused();
    // Moving focus doesn't navigate.
    await expect(tab('Settings')).toHaveAttribute('aria-selected', 'true');
    await expect(panel).toHaveText('Settings panel');
    expect(new URL(page.url()).searchParams.get('tab')).toBeNull();

    await page.keyboard.press('End');
    await expect(tab('Quickstart')).toBeFocused();
    await page.keyboard.press('ArrowRight');
    await expect(tab('Settings')).toBeFocused();
    await page.keyboard.press('ArrowLeft');
    await expect(tab('Quickstart')).toBeFocused();
    await page.keyboard.press('Home');
    await expect(tab('Settings')).toBeFocused();
    await page.keyboard.press('ArrowRight');
    await page.keyboard.press('ArrowRight');
    await expect(tab('Connections')).toBeFocused();

    await page.keyboard.press('Enter');
    await expect(tab('Connections')).toHaveAttribute('aria-selected', 'true');
    await expect(tab('Settings')).toHaveAttribute('aria-selected', 'false');
    await expect(panel).toHaveText('Connections panel');
    await expect(list.locator('[tabindex="0"]')).toHaveText('Connections');

    await page.keyboard.press('ArrowLeft');
    await page.keyboard.press('Space');
    await expect(tab('Credentials')).toHaveAttribute('aria-selected', 'true');

    // Tab leaves the list for the panel, which holds nothing focusable.
    await page.keyboard.press('Tab');
    await expect(panel).toBeFocused();
    await expect(panel).toHaveText('Credentials panel');

    // The selected tab carries the 2px tx underline; the others none.
    const underline = await tab('Credentials').evaluate((element) => {
      const s = getComputedStyle(element);
      return { width: s.borderBottomWidth, color: s.borderBottomColor, style: s.borderBottomStyle };
    });
    expect(underline).toEqual({ width: '2px', color: await colour(page, 'var(--gk-color-tx)'), style: 'solid' });
    const other = await tab('Settings').evaluate((element) => getComputedStyle(element).borderBottomColor);
    expect(other).toBe(TRANSPARENT);
  });

  test('right to left, the arrow keys follow the reading direction', async ({ page }) => {
    await open(page, 'admin');
    const list = page.getByRole('tablist', { name: 'Right to left' });
    const tab = (name: string) => list.getByRole('tab', { name });
    await tab('Alpha').focus();
    await page.keyboard.press('ArrowLeft');
    await expect(tab('Beta')).toBeFocused();
    await page.keyboard.press('ArrowRight');
    await expect(tab('Alpha')).toBeFocused();
    await page.keyboard.press('ArrowRight');
    await expect(tab('Gamma')).toBeFocused();
  });

  test('controlled tabs without a URL wait for the caller; ids with spaces still link their panels', async ({ page }) => {
    await open(page, 'admin');
    const list = page.getByRole('tablist', { name: 'Controlled' });
    const tab = (name: string) => list.getByRole('tab', { name, exact: true });
    const panel = shownPanel(list);

    await tab('Two').click();
    await expect(page.getByTestId('requested-tab')).toHaveText('two words');
    await expect(tab('One')).toHaveAttribute('aria-selected', 'true');
    await expect(panel).toHaveText('One panel');

    await page.getByTestId('apply-tab').click();
    await expect(tab('Two')).toHaveAttribute('aria-selected', 'true');
    await expect(panel).toHaveAccessibleName('Two');
    const controls = (await tab('Two').getAttribute('aria-controls'))!;
    await expect(page.locator(`[id="${controls}"]`)).toHaveRole('tabpanel');
    // A panel holding a focusable element is no tab stop itself.
    await expect(panel.getByRole('button', { name: 'Inside two' })).toBeVisible();
    await expect(panel).not.toHaveAttribute('tabindex');
  });

  test('the selected tab is in the URL, and Back and Forward restore it', async ({ page }) => {
    await open(page, 'admin');
    const list = applicationTabs(page);
    const tab = (name: string) => list.getByRole('tab', { name });
    const param = () => new URL(page.url()).searchParams.get('tab');

    await tab('Credentials').click();
    await expect(tab('Credentials')).toHaveAttribute('aria-selected', 'true');
    expect(param()).toBe('credentials');
    // Other query parameters stay.
    expect(new URL(page.url()).searchParams.get('page')).toBe('data');

    await tab('Connections').click();
    await expect(tab('Connections')).toHaveAttribute('aria-selected', 'true');
    expect(param()).toBe('connections');

    await page.goBack();
    await expect(tab('Credentials')).toHaveAttribute('aria-selected', 'true');
    await expect(shownPanel(list)).toHaveText('Credentials panel');
    await page.goBack();
    await expect(tab('Settings')).toHaveAttribute('aria-selected', 'true');
    expect(param()).toBeNull();
    await page.goForward();
    await expect(tab('Credentials')).toHaveAttribute('aria-selected', 'true');

    // A shared URL opens on its tab, and an unknown id opens the first.
    await open(page, 'admin', 'light', '&tab=quickstart');
    await expect(tab('Quickstart')).toHaveAttribute('aria-selected', 'true');
    await open(page, 'admin', 'light', '&tab=nope');
    await expect(tab('Settings')).toHaveAttribute('aria-selected', 'true');
  });

  test('Back with unsaved changes is refused, and the URL is put back to match the tab', async ({ page }) => {
    await open(page, 'admin');
    const tab = (name: string) => applicationTabs(page).getByRole('tab', { name });
    const param = () => new URL(page.url()).searchParams.get('tab');
    const calls = page.getByTestId('guard-calls');

    await tab('Credentials').click();
    await expect(tab('Credentials')).toHaveAttribute('aria-selected', 'true');
    await page.getByTestId('dirty').check();

    await page.goBack();
    await expect(calls).toHaveText('2');
    await expect(tab('Credentials')).toHaveAttribute('aria-selected', 'true');
    await expect.poll(param).toBe('credentials');
  });

  test('when canLeave says no, synchronously or later, the tab and the URL stay', async ({ page }) => {
    await page.clock.install();
    await open(page, 'admin');
    await pauseClock(page);
    const tab = (name: string) => applicationTabs(page).getByRole('tab', { name });
    const calls = page.getByTestId('guard-calls');
    const param = () => new URL(page.url()).searchParams.get('tab');

    await page.getByTestId('dirty').check();
    await tab('Credentials').click();
    await expect(calls).toHaveText('1');
    await expect(tab('Settings')).toHaveAttribute('aria-selected', 'true');
    expect(param()).toBeNull();

    // The guard answers 50ms later, on the paused clock.
    await page.getByTestId('async-guard').check();
    await tab('Credentials').click();
    await expect(calls).toHaveText('2');
    await page.clock.runFor(100);
    await expect(tab('Settings')).toHaveAttribute('aria-selected', 'true');
    expect(param()).toBeNull();

    // A second click while the guard is out doesn't ask again.
    await page.getByTestId('dirty').uncheck();
    await tab('Credentials').click();
    await expect(calls).toHaveText('3');
    await tab('Connections').click();
    await expect(calls).toHaveText('3');
    await page.clock.runFor(100);
    await expect(tab('Credentials')).toHaveAttribute('aria-selected', 'true');
    expect(param()).toBe('credentials');

    // Selecting the tab already selected asks nothing.
    await tab('Credentials').click();
    await expect(calls).toHaveText('3');
  });

  test('the JSON viewer shows line numbers that assistive technology skips, and reads the JSON in order', async ({ page }) => {
    await open(page, 'admin');
    const region = page.getByRole('region', { name: 'Raw event' });
    const json = JSON.stringify(RAW_EVENT, null, 2);
    const lines = json.split('\n');

    const gutter = region.locator('[data-gutter]');
    await expect(gutter).toHaveAttribute('aria-hidden', 'true');
    await expect(gutter.locator('span')).toHaveText(lines.map((_, index) => String(index + 1)));
    await expect(gutter).toBeVisible();
    expect(await region.locator('pre').textContent()).toBe(json);

    // What assistive technology gets is the JSON alone, with no number column in it.
    const snapshot = await region.ariaSnapshot();
    expect(snapshot).toContain('login.failure');
    // The code's text starts at the brace: no line number comes before it.
    expect(snapshot).toMatch(/- code: "\{ /);
    expect(snapshot).not.toMatch(/\b1\s+2\s+3\b/);

    expect((await style(region.getByText('"type"'))).color).toBe(await colour(page, 'var(--gk-color-info)'));
    expect((await style(region.getByText('"login.failure"'))).color).toBe(await colour(page, 'var(--gk-color-ac-tx)'));
    expect((await style(region.getByText('3', { exact: true }).last())).color).toBe(await colour(page, 'var(--gk-color-warn)'));
    expect((await style(gutter)).background).toBe(await colour(page, 'var(--gk-color-sf2)'));
    expect(await region.evaluate((element) => getComputedStyle(element).maxHeight)).not.toBe('none');
    await region.focus();
    await expect(region).toBeFocused();

    // A value JSON can't represent shows the neutral message, and the page stays up.
    await expect(page.getByRole('region', { name: 'Big number' })).toHaveText("This value can't be shown as JSON.");
  });

  test('an empty state shows one line and at most one action, and none without one', async ({ page }) => {
    await open(page, 'admin');
    const withAction = page.getByTestId('empty-with-action');
    await expect(withAction.locator('p')).toHaveCount(1);
    await expect(withAction.locator('p')).toHaveText('No applications yet');
    await expect(withAction.getByRole('button')).toHaveCount(1);
    await withAction.getByRole('button', { name: 'Create application' }).click();
    await expect(page.getByTestId('created')).toHaveText('1');
    await expect(withAction.locator('[aria-hidden="true"]')).toHaveText('+');

    const withoutAction = page.getByTestId('empty-without-action');
    await expect(withoutAction.locator('p')).toHaveText('No applications yet');
    await expect(withoutAction.getByRole('button')).toHaveCount(0);
    await expect(withoutAction.locator('[aria-hidden="true"]')).toHaveCount(0);
    const box = await style(withoutAction.locator(':scope > div'));
    expect(box.borderStyle).toBe('dashed');
    expect(box.borderColor).toBe(await colour(page, 'var(--gk-color-bd2)'));
  });

  test('skeleton rows wait 300ms, then match the table they replace, hidden, with one polite status', async ({ page }) => {
    await page.clock.install();
    await open(page, 'admin');
    await pauseClock(page);
    const area = page.getByTestId('loading-area');
    await page.getByTestId('loading').check();

    const skeleton = area.locator(':scope > div');
    const status = area.getByRole('status');
    const bars = skeleton.locator('[aria-hidden="true"]');
    // The Users table it stands in for: the same 50 rows, caption and paging footer.
    const height = (await card(page).boundingBox())!.height;

    await page.clock.runFor(200);
    await expect(skeleton).toHaveAttribute('data-shown', 'false');
    await expect(bars).toBeHidden();
    await expect(status).toHaveText('');
    expect((await style(skeleton)).height).toBe(height);

    await page.clock.runFor(200);
    await expect(skeleton).toHaveAttribute('data-shown', 'true');
    await expect(bars).toBeVisible();
    await expect(status).toHaveText('Loading');
    await expect(area.getByRole('status')).toHaveCount(1);
    expect((await style(skeleton)).height).toBe(height);
    await expect(skeleton.locator('[data-part="row"]')).toHaveCount(50);
    expect((await style(skeleton.locator('[data-part="head"]'))).height).toBe(HEAD);
    const row = skeleton.locator('[data-part="row"]').first();
    expect((await style(row)).height).toBe(ROW);
    expect((await style(row.locator('span').first())).background).toBe(await colour(page, 'var(--gk-color-sf2)'));
    // Nothing in the skeleton reaches assistive technology but the status.
    expect(await area.ariaSnapshot()).toBe('- status: Loading');
  });

  test('the usage bar is a meter with its range and value, and visible text', async ({ page }) => {
    await open(page, 'admin');
    const meter = page.getByRole('meter', { name: 'Sign-ins this minute' });
    await expect(meter).toHaveAttribute('aria-valuemin', '0');
    await expect(meter).toHaveAttribute('aria-valuemax', '100');
    await expect(meter).toHaveAttribute('aria-valuenow', '30');
    await expect(meter).toHaveAttribute('aria-valuetext', '30 of 100');
    await expect(page.getByText('30 of 100', { exact: true })).toBeVisible();
    const track = (await meter.boundingBox())!;
    const fill = (await meter.locator('div').boundingBox())!;
    expect(fill.width).toBeCloseTo(track.width * 0.3, 0);
    expect(track.height).toBe(px(tokens.components['usage-bar'].height));
    expect((await style(meter.locator('div'))).background).toBe(await colour(page, 'var(--gk-color-ac)'));
  });

  test('a usage bar over its limit keeps aria-valuenow in range, and says the real value', async ({ page }) => {
    await open(page, 'admin');
    const meter = page.getByRole('meter', { name: 'Emails this hour' });
    await expect(meter).toHaveAttribute('aria-valuenow', '100');
    await expect(meter).toHaveAttribute('aria-valuetext', '150 of 100');
    await expect(page.getByText('150 of 100', { exact: true })).toBeVisible();
    const track = (await meter.boundingBox())!;
    expect((await meter.locator('div').boundingBox())!.width).toBeCloseTo(track.width, 0);
  });

  test('the RBAC matrix is a real table, and each tick says "Allowed"', async ({ page }) => {
    await open(page, 'admin');
    const matrix = page.getByRole('table', { name: 'Permissions by role' });
    await expect(matrix.getByRole('columnheader')).toHaveText(['Permission', 'Viewer', 'Editor', 'Owner']);
    await expect(matrix.getByRole('rowheader')).toHaveText(['read:users', 'write:users', 'delete:users']);
    await expect(matrix.getByRole('cell', { name: 'Allowed', exact: true })).toHaveCount(6);
    await expect(matrix.getByRole('cell', { name: 'Not allowed', exact: true })).toHaveCount(3);

    const viewerWrite = matrix.getByRole('row', { name: /write:users/ }).getByRole('cell').first();
    await expect(viewerWrite).toHaveAccessibleName('Not allowed');
    const ownerDelete = matrix.getByRole('row', { name: /delete:users/ }).getByRole('cell').last();
    await expect(ownerDelete).toHaveAccessibleName('Allowed');
    const tick = ownerDelete.locator('[aria-hidden="true"]');
    await expect(tick).toBeVisible();
    expect((await style(tick)).color).toBe(await colour(page, 'var(--gk-color-ok)'));
    for (const row of await matrix.locator('tbody tr').all()) expect((await style(row)).height).toBe(ROW);
  });

  test('the stat tile pairs a label with its value, and the settings row groups its control', async ({ page }) => {
    await open(page, 'admin');
    const tile = page.locator('dl').filter({ hasText: 'Logins today' });
    await expect(tile.locator('dt')).toHaveText('Logins today');
    await expect(tile.locator('dd')).toHaveText('318');
    expect((await style(tile)).borderColor).toBe(await colour(page, 'var(--gk-color-bd)'));

    const group = page.getByRole('group', { name: 'Allow sign-up' });
    await expect(group).toHaveAccessibleDescription('New Users can create an account on Hosted Login.');
    const toggle = group.getByRole('switch', { name: 'Allow sign-up' });
    await expect(toggle).toHaveAttribute('aria-checked', 'true');
    await toggle.press('Space');
    await expect(toggle).toHaveAttribute('aria-checked', 'false');
    // The control sits on the right of its label.
    const label = (await group.getByText('Allow sign-up', { exact: true }).first().boundingBox())!;
    expect((await toggle.boundingBox())!.x).toBeGreaterThan(label.x + label.width);
  });
});
