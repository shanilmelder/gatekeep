// The Story 1.14 matrix, row by row, on the controls fixture (tests/browser/fixture), once
// per surface: buttons, pending, validation, password, toggle, checkbox and radio,
// segmented, accessibility. Driven by keyboard and pointer in Chromium, never by snapshot.
// Expected values come from the generated tokens, never from hex here.

import AxeBuilder from '@axe-core/playwright';
import { tokens } from '@gatekeep/design-tokens';
import { expect, test, type Locator, type Page } from '@playwright/test';

type Surface = 'admin' | 'hosted';
type Scheme = 'light' | 'dark';

const px = (value: string) => parseFloat(value);

const sizes = {
  admin: {
    control: px(tokens.spacing['control-h']),
    controlFont: tokens.typography.body.fontSize,
    buttonFont: tokens.typography.button.fontSize,
    edge: 'var(--gk-input-border)',
  },
  hosted: {
    control: px(tokens.spacing['control-h-hosted']),
    controlFont: tokens.typography['hosted-body'].fontSize,
    buttonFont: tokens.typography['hosted-button'].fontSize,
    edge: 'var(--gk-hosted-input-border)',
  },
} as const;

const other = (surface: Surface): Surface => (surface === 'admin' ? 'hosted' : 'admin');

async function open(page: Page, surface: Surface, scheme: Scheme = 'light') {
  await page.goto(`/?surface=${surface}&scheme=${scheme}`);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(`Controls on ${surface}`);
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

async function style(locator: Locator, pseudo?: string) {
  return locator.evaluate((element, pseudo) => {
    const s = getComputedStyle(element, pseudo);
    return {
      height: element.getBoundingClientRect().height,
      width: s.width,
      fontSize: s.fontSize,
      fontFamily: s.fontFamily,
      background: s.backgroundColor,
      color: s.color,
      borderColor: s.borderTopColor,
      borderStyle: s.borderTopStyle,
      borderWidth: s.borderTopWidth,
    };
  }, pseudo);
}

/** The Show/Hide button beside a password input. */
const reveal = (input: Locator) => input.locator('xpath=following-sibling::button[1]');

async function helperOf(page: Page, control: Locator) {
  const id = await control.getAttribute('aria-describedby');
  expect(id, 'the control names its helper').toBeTruthy();
  return page.locator(`[id="${id!.split(' ')[0]}"]`);
}

for (const surface of ['admin', 'hosted'] as const) {
  test.describe(`on ${surface}`, () => {
    test('one component serves both surfaces', async ({ page }) => {
      await open(page, surface);
      await expect(page.locator('html')).toHaveAttribute('data-same-modules', 'true');
    });

    test('renders every button variant, sized for the surface, with no filled warn or destructive', async ({ page }) => {
      await open(page, surface);
      const variants = await page.locator('[data-variant]').evaluateAll((elements) =>
        [...new Set(elements.map((element) => element.getAttribute('data-variant')))].sort(),
      );
      expect(variants).toEqual(['destructive', 'ghost', 'primary', 'secondary']);

      for (const id of ['primary', 'secondary', 'ghost', 'destructive', 'disabled']) {
        const button = await style(page.getByTestId(id));
        expect(button.height, id).toBe(sizes[surface].control);
        expect(button.fontSize, id).toBe(sizes[surface].buttonFont);
      }
      expect((await style(page.getByTestId('small'))).height).toBe(px(tokens.spacing['control-h-sm']));
      expect((await style(page.getByTestId('small'))).fontSize).toBe(tokens.typography['button-sm'].fontSize);
      // data-gk-surface on the component itself overrides the page's surface.
      expect((await style(page.getByTestId('other-surface'))).height).toBe(sizes[other(surface)].control);
      // So does a nested surface that carries its own scheme scope.
      expect((await style(page.getByTestId('island'))).height).toBe(sizes[other(surface)].control);

      const primary = await style(page.getByTestId('primary'));
      expect(primary.background).toBe(await colour(page, 'var(--gk-color-ac)'));
      expect(primary.color).toBe(await colour(page, 'var(--gk-color-on-ac)'));

      const secondary = await style(page.getByTestId('secondary'));
      expect(secondary.borderColor).toBe(await colour(page, surface === 'hosted' ? 'var(--gk-color-tx3)' : 'var(--gk-color-bd2)'));

      // Destructive is outlined on bad-sf, never filled with bad.
      const destructive = await style(page.getByTestId('destructive'));
      expect(destructive.background).toBe(await colour(page, 'var(--gk-color-bad-sf)'));
      expect(destructive.color).toBe(await colour(page, 'var(--gk-color-bad)'));
      expect(destructive.borderColor).toBe(await colour(page, 'var(--gk-color-bad)'));
      expect(destructive.borderStyle).toBe('solid');

      const disabled = page.getByTestId('disabled');
      await expect(disabled).toBeDisabled();
      expect((await style(disabled)).background).toBe(await colour(page, 'var(--gk-color-sf2)'));

      const filled = [await colour(page, 'var(--gk-color-bad)'), await colour(page, 'var(--gk-color-warn)')];
      const backgrounds = await page.locator('button').evaluateAll((buttons) => buttons.map((b) => getComputedStyle(b).backgroundColor));
      for (const background of backgrounds) expect(filled).not.toContain(background);
    });

    test('a pending button ignores clicks and Enter, and keeps its width and name', async ({ page }) => {
      await open(page, surface);
      const button = page.getByTestId('pending');
      const saves = page.getByTestId('saves');
      const before = (await button.boundingBox())!;

      await button.click();
      await expect(saves).toHaveText('1');
      await expect(button).toHaveAttribute('aria-busy', 'true');
      await expect(button).toHaveAttribute('aria-disabled', 'true');
      await expect(button).not.toHaveAttribute('disabled');
      await expect(button).toBeFocused();
      await expect(button).toHaveAccessibleName('Save changes');
      await expect(button).toHaveAccessibleDescription('Loading');
      await expect(button.locator('[aria-hidden="true"]').first()).toBeVisible();

      // Playwright counts aria-disabled as disabled, so force the real pointer click.
      await button.click({ force: true });
      await page.keyboard.press('Enter');
      await page.keyboard.press('Space');
      // Enter in the form's field submits through the same button.
      await page.getByTestId('display-name').press('Enter');
      await expect(saves).toHaveText('1');

      const after = (await button.boundingBox())!;
      expect(after.width).toBeCloseTo(before.width, 1);
      expect(after.height).toBeCloseTo(before.height, 1);

      // Still focusable while pending.
      await page.getByTestId('display-name').focus();
      await page.keyboard.press('Tab');
      await expect(button).toBeFocused();

      await page.getByTestId('reset-pending').click();
      await expect(button).not.toHaveAttribute('aria-busy');
      await expect(button).not.toHaveAttribute('aria-disabled');
      await expect(button).toHaveAccessibleDescription('');
    });

    test('sizes inputs for the surface, with identifiers in the code type', async ({ page }) => {
      await open(page, surface);
      for (const id of ['email', 'select', 'password']) {
        const control = await style(page.getByTestId(id));
        expect(control.height, id).toBe(sizes[surface].control);
        expect(control.fontSize, id).toBe(sizes[surface].controlFont);
        expect(control.borderColor, id).toBe(await colour(page, sizes[surface].edge));
      }
      const clientId = await style(page.getByTestId('client-id'));
      expect(clientId.fontFamily).toMatch(/^"?Geist Mono"?,/);
      expect(clientId.fontSize).toBe(tokens.typography.code.fontSize);
      await expect(page.getByLabel('Email', { exact: true })).toHaveAttribute('data-testid', 'email');
      await expect(page.getByLabel('Callback URLs')).toHaveAttribute('data-testid', 'callbacks');
    });

    test('shows an invalid value on blur, without moving focus, and revalidates on change', async ({ page }) => {
      await open(page, surface);
      const email = page.getByTestId('email');
      const helper = await helperOf(page, email);
      const helperId = await helper.getAttribute('id');
      await expect(helper).toHaveText('The address you signed up with.');

      await email.fill('nope');
      // No check before the first blur.
      await expect(email).not.toHaveAttribute('aria-invalid');
      await email.press('Tab');

      await expect(page.getByTestId('client-id')).toBeFocused();
      await expect(email).toHaveAttribute('aria-invalid', 'true');
      await expect(helper).toHaveText('Enter a valid email address.');
      await expect(email).toHaveAccessibleDescription('Enter a valid email address.');
      expect(await (await helperOf(page, email)).getAttribute('id'), 'the helper keeps its id').toBe(helperId);
      expect((await style(email)).borderColor).toBe(await colour(page, 'var(--gk-color-bad)'));
      expect((await style(helper)).color).toBe(await colour(page, 'var(--gk-color-bad)'));
      await expect(page.getByTestId('client-id')).toBeFocused();

      // In error, every change checks again, with no blur.
      await email.click();
      await email.fill('ada@example');
      await expect(email).toHaveAttribute('aria-invalid', 'true');
      await email.pressSequentially('.com');
      await expect(email).not.toHaveAttribute('aria-invalid');
      await expect(helper).toHaveText('The address you signed up with.');
      await expect(email).toBeFocused();
      expect(await helper.getAttribute('id')).toBe(helperId);

      // A textarea works the same way.
      const callbacks = page.getByTestId('callbacks');
      await callbacks.fill('https://app.example/callback\nnot a url');
      await callbacks.press('Tab');
      await expect(callbacks).toHaveAttribute('aria-invalid', 'true');
      await expect(callbacks).toHaveAccessibleDescription('Must be an absolute URL.');
    });

    test('a valid value passes its first blur with no error', async ({ page }) => {
      await open(page, surface);
      const email = page.getByTestId('email');
      await email.fill('ada@example.com');
      await email.press('Tab');
      await expect(page.getByTestId('client-id')).toBeFocused();
      await expect(email).not.toHaveAttribute('aria-invalid');
      await expect(await helperOf(page, email)).toHaveText('The address you signed up with.');
    });

    test('the password toggle flips Show and Hide, and the password masks again on submit', async ({ page }) => {
      await open(page, surface);
      const password = page.getByTestId('password');
      await expect(page.getByLabel('Password', { exact: true })).toHaveAttribute('data-testid', 'password');
      await expect(password).toHaveAttribute('type', 'password');
      await expect(password).toHaveAttribute('autocomplete', 'current-password');

      // Paste is never blocked.
      const pasteBlocked = await password.evaluate((input) => {
        const event = new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: new DataTransfer() });
        input.dispatchEvent(event);
        return event.defaultPrevented;
      });
      expect(pasteBlocked).toBe(false);
      await password.fill('correct horse battery');

      const show = reveal(password);
      await expect(show).toHaveAccessibleName('Show password');
      await expect(show).toHaveAttribute('type', 'button');
      await expect(show).toHaveText('Show');
      const hit = (await show.boundingBox())!;
      expect(hit.height).toBeGreaterThanOrEqual(px(tokens.components.checkbox['hit-area']));
      expect(hit.width).toBeGreaterThanOrEqual(px(tokens.components.checkbox['hit-area']));

      await show.click();
      await expect(password).toHaveAttribute('type', 'text');
      const hide = reveal(password);
      await expect(hide).toHaveAccessibleName('Hide password');
      await expect(hide).toHaveText('Hide');
      await expect(page.getByTestId('sign-ins'), 'the toggle never submits').toHaveText('0');

      // By keyboard too.
      await hide.focus();
      await page.keyboard.press('Enter');
      await expect(password).toHaveAttribute('type', 'password');
      await page.keyboard.press('Space');
      await expect(password).toHaveAttribute('type', 'text');

      await page.getByTestId('sign-in').click();
      await expect(page.getByTestId('sign-ins')).toHaveText('1');
      await expect(password).toHaveAttribute('type', 'password');
      await expect(password).toHaveValue('correct horse battery');
      await expect(reveal(password)).toHaveAccessibleName('Show password');
    });

    test('built-in strings come from the message catalogue, which callers override', async ({ page }) => {
      await open(page, surface);
      const toggle = page.getByRole('button', { name: 'Passwort anzeigen' });
      await expect(toggle).toHaveText('Anzeigen');
      await toggle.click();
      await expect(page.getByRole('button', { name: 'Passwort verbergen' })).toHaveText('Verbergen');
      await expect(page.getByTestId('passwort')).toHaveAttribute('type', 'text');
    });

    test('Space and Enter flip a toggle, and nothing is saved', async ({ page }) => {
      await open(page, surface);
      const requests: string[] = [];
      page.on('request', (request) => requests.push(request.url()));
      const toggle = page.getByRole('switch', { name: 'Allow sign-up' });
      await expect(toggle).toHaveAttribute('data-testid', 'toggle');
      await expect(toggle).toHaveAttribute('type', 'button');
      await expect(toggle).toHaveAttribute('aria-checked', 'false');

      await toggle.focus();
      await page.keyboard.press('Space');
      await expect(toggle).toHaveAttribute('aria-checked', 'true');
      await page.keyboard.press('Enter');
      await expect(toggle).toHaveAttribute('aria-checked', 'false');
      await page.getByText('Allow sign-up').click();
      await expect(toggle).toHaveAttribute('aria-checked', 'true');
      await expect(page.locator('input[type="hidden"][name="signup"]')).toHaveValue('on');
      await toggle.click();
      await expect(toggle).toHaveAttribute('aria-checked', 'false');
      await expect(page.locator('input[name="signup"]')).toHaveCount(0);

      expect((await toggle.boundingBox())!.height).toBeGreaterThanOrEqual(px(tokens.components.checkbox['hit-area']));
      expect(requests).toEqual([]);
      await expect(page.getByTestId('saves')).toHaveText('0');
      await expect(page.getByTestId('sign-ins')).toHaveText('0');
    });

    test('checkboxes and radios change state as native controls do', async ({ page }) => {
      await open(page, surface);
      const hitArea = px(tokens.components.checkbox['hit-area']);
      const checkbox = page.getByTestId('checkbox');
      await expect(checkbox).toHaveAttribute('type', 'checkbox');
      await expect(page.getByRole('checkbox', { name: "I've copied this" })).toBeVisible();
      const box = (await checkbox.boundingBox())!;
      expect(box.width).toBe(hitArea);
      expect(box.height).toBe(hitArea);
      const drawn = await style(checkbox, '::before');
      expect(drawn.width).toBe(tokens.components.checkbox.size);
      expect(drawn.borderColor).toBe(await colour(page, surface === 'hosted' ? 'var(--gk-color-tx3)' : 'var(--gk-color-bd2)'));

      await checkbox.focus();
      await page.keyboard.press('Space');
      await expect(checkbox).toBeChecked();
      expect((await style(checkbox, '::before')).background).toBe(await colour(page, 'var(--gk-color-ac)'));
      await page.keyboard.press('Space');
      await expect(checkbox).not.toBeChecked();
      await page.getByText("I've copied this").click();
      await expect(checkbox).toBeChecked();

      const group = page.getByRole('group', { name: 'Multi-factor policy' });
      await expect(group).toBeVisible();
      expect(await group.evaluate((element) => element.tagName)).toBe('FIELDSET');
      const never = page.getByTestId('radio-never');
      const always = page.getByTestId('radio-always');
      const optional = page.getByTestId('radio-optional');
      expect((await style(never, '::before')).width).toBe(tokens.components.radio.size);
      expect((await never.boundingBox())!.height).toBe(px(tokens.components.radio['hit-area']));
      await expect(never).toBeChecked();

      await never.focus();
      await page.keyboard.press('ArrowDown');
      await expect(always).toBeChecked();
      await expect(always).toBeFocused();
      await page.keyboard.press('ArrowDown');
      await expect(optional).toBeChecked();
      await page.keyboard.press('ArrowUp');
      await expect(always).toBeChecked();
      await expect(never).not.toBeChecked();
      await page.getByText('Never', { exact: true }).click();
      await expect(never).toBeChecked();

      // A radio group is one tab stop: Tab leaves it for the segmented control.
      await never.focus();
      await page.keyboard.press('Tab');
      await expect(page.getByRole('radio', { name: 'Dark' })).toBeFocused();
    });

    test('segmented is one tab stop; arrows select at once, and Home and End reach the ends', async ({ page }) => {
      await open(page, surface);
      const group = page.getByRole('radiogroup', { name: 'Theme' });
      const segment = (name: string) => group.getByRole('radio', { name });
      const value = page.locator('input[type="hidden"][name="theme"]');
      const expectSelected = async (name: string) => {
        await expect(segment(name)).toBeFocused();
        await expect(segment(name)).toHaveAttribute('aria-checked', 'true');
        await expect(group.locator('[aria-checked="true"]')).toHaveCount(1);
        await expect(group.locator('[tabindex="0"]')).toHaveCount(1);
        await expect(segment(name)).toHaveAttribute('tabindex', '0');
        await expect(value).toHaveValue(name.toLowerCase());
      };

      expect((await style(group)).height).toBe(sizes[surface].control);
      await expect(group.getByRole('radio')).toHaveCount(3);

      // Tab in from the radio group before it lands on the selected segment.
      await page.getByTestId('radio-never').focus();
      await page.keyboard.press('Tab');
      await expectSelected('Dark');

      await page.keyboard.press('ArrowRight');
      await expectSelected('System');
      await page.keyboard.press('ArrowLeft');
      await expectSelected('Dark');
      await page.keyboard.press('End');
      await expectSelected('System');
      await page.keyboard.press('Home');
      await expectSelected('Light');
      await page.keyboard.press('ArrowLeft');
      await expectSelected('System');
      await page.keyboard.press('ArrowRight');
      await expectSelected('Light');

      await page.keyboard.press('Tab');
      await expect(page.getByTestId('after-selection')).toBeFocused();
      await page.keyboard.press('Shift+Tab');
      await expectSelected('Light');

      await segment('Dark').click();
      await expectSelected('Dark');
    });

    test('every control shows the focus ring', async ({ page }) => {
      await open(page, surface);
      await page.evaluate(() => {
        document.body.tabIndex = -1;
        document.body.focus({ preventScroll: true });
      });
      const accent = await colour(page, 'var(--gk-color-ac)');
      const seen: string[] = [];
      for (let step = 0; step < 80; step++) {
        await page.keyboard.press('Tab');
        // Each element is marked on its first visit, so the walk ends when it comes round
        // again, and two controls with the same text still count as two.
        const ring = await page.evaluate((step) => {
          const element = document.activeElement as HTMLElement;
          const revisit = element === document.body || element.dataset.walk !== undefined;
          element.dataset.walk = String(step);
          const s = getComputedStyle(element);
          return {
            revisit,
            name: `${element.getAttribute('data-testid') ?? element.getAttribute('aria-label') ?? element.textContent}#${step}`,
            testid: element.getAttribute('data-testid'),
            focusVisible: element.matches(':focus-visible'),
            style: s.outlineStyle,
            width: s.outlineWidth,
            offset: s.outlineOffset,
            color: s.outlineColor,
          };
        }, step);
        if (ring.revisit) break;
        seen.push(ring.testid ?? ring.name);
        expect(ring.focusVisible, ring.name).toBe(true);
        expect(ring.style, ring.name).toBe(tokens.components['focus-ring']['outline-style']);
        expect(ring.width, ring.name).toBe(tokens.components['focus-ring']['outline-width']);
        expect(ring.offset, ring.name).toBe(tokens.components['focus-ring']['outline-offset']);
        expect(ring.color, ring.name).toBe(accent);
      }
      expect(seen).toEqual(
        expect.arrayContaining(['primary', 'pending', 'aria-disabled', 'email', 'client-id', 'select', 'callbacks', 'password', 'toggle', 'checkbox', 'radio-never', 'after-selection', 'toggle-mfa', 'save-settings']),
      );
      // The three enabled Show password buttons are each reached, though they share a name.
      expect(seen.filter((name) => name.startsWith('Show password#')).length).toBeGreaterThanOrEqual(3);
      for (const disabled of ['disabled', 'select-disabled', 'disabled-password', 'toggle-disabled', 'checkbox-disabled', 'radio-disabled']) {
        expect(seen, `${disabled} takes no focus`).not.toContain(disabled);
      }
    });

    test('an inert button: aria-disabled blocks clicks and submit, and looks disabled', async ({ page }) => {
      await open(page, surface);
      const button = page.getByTestId('aria-disabled');
      await button.click({ force: true });
      await button.focus();
      await page.keyboard.press('Enter');
      await page.keyboard.press('Space');
      await expect(page.getByTestId('aria-submits')).toHaveText('0');
      await expect(button).toBeFocused();
      const drawn = await style(button);
      expect(drawn.background).toBe(await colour(page, 'var(--gk-color-sf2)'));
      expect(drawn.color).toBe(await colour(page, 'var(--gk-color-tx3)'));
    });

    test('a pending small button keeps its spinner inside its border, drawn in the label colour', async ({ page }) => {
      await open(page, surface);
      const button = page.getByTestId('pending-small');
      const spinner = button.locator('[aria-hidden="true"]').first();
      // Measured at rest: a turning square's box grows by its diagonal.
      await spinner.evaluate((element) => {
        element.style.animation = 'none';
      });
      const box = (await button.boundingBox())!;
      const spin = (await spinner.boundingBox())!;
      const label = (await button.locator('span').first().boundingBox())!;
      const border = px((await style(button)).borderWidth);
      expect(spin.x).toBeGreaterThanOrEqual(box.x + border - 0.5);
      expect(label.x + label.width).toBeLessThanOrEqual(box.x + box.width - border + 0.5);
      expect(box.height).toBe(px(tokens.spacing['control-h-sm']));
      const colours = await spinner.evaluate((element) => ({
        stroke: getComputedStyle(element).borderTopColor,
        label: getComputedStyle(element.closest('button')!).color,
      }));
      expect(colours.stroke).toBe(colours.label);
    });

    test('the pending message comes from the catalogue, and an undefined override keeps the default', async ({ page }) => {
      await open(page, surface);
      await expect(page.getByTestId('pending-german')).toHaveAccessibleDescription('Wird geladen');
      await expect(page.getByTestId('pending-german')).toHaveAccessibleName('Speichern');
      await expect(page.getByTestId('pending-kept')).toHaveAccessibleDescription('Loading');
    });

    test('tabbing through an untouched field shows no error', async ({ page }) => {
      await open(page, surface);
      const email = page.getByTestId('email');
      await email.focus();
      await page.keyboard.press('Tab');
      await expect(page.getByTestId('client-id')).toBeFocused();
      await expect(email).not.toHaveAttribute('aria-invalid');
      await expect(await helperOf(page, email)).toHaveText('The address you signed up with.');
    });

    test('the focus ring stays on a field in error', async ({ page }) => {
      await open(page, surface);
      const email = page.getByTestId('email');
      await email.fill('nope');
      await email.press('Tab');
      await page.keyboard.press('Shift+Tab');
      await expect(email).toBeFocused();
      await expect(email).toHaveAttribute('aria-invalid', 'true');
      const ring = await email.evaluate((element) => {
        const s = getComputedStyle(element);
        return { visible: element.matches(':focus-visible'), style: s.outlineStyle, width: s.outlineWidth, color: s.outlineColor };
      });
      expect(ring).toEqual({
        visible: true,
        style: tokens.components['focus-ring']['outline-style'],
        width: tokens.components['focus-ring']['outline-width'],
        color: await colour(page, 'var(--gk-color-ac)'),
      });
    });

    test('a select validates on blur and again on change', async ({ page }) => {
      await open(page, surface);
      const select = page.getByTestId('select');
      await select.selectOption('status');
      await expect(select).not.toHaveAttribute('aria-invalid');
      await select.press('Tab');
      await expect(select).toHaveAttribute('aria-invalid', 'true');
      await expect(select).toHaveAccessibleDescription('Status search is not available yet.');
      await select.selectOption('email');
      await expect(select).not.toHaveAttribute('aria-invalid');
    });

    test('an external error shows until the caller clears it, whatever validate says', async ({ page }) => {
      await open(page, surface);
      const subdomain = page.getByTestId('subdomain');
      const helper = await helperOf(page, subdomain);
      await expect(subdomain).toHaveAttribute('aria-invalid', 'true');
      await expect(helper).toHaveText('That subdomain is not available.');
      await expect(subdomain).toHaveAccessibleDescription('That subdomain is not available.');
      await subdomain.fill('acme-two');
      await subdomain.press('Tab');
      await expect(subdomain).toHaveAttribute('aria-invalid', 'true');
      await expect(helper).toHaveText('That subdomain is not available.');
      await page.getByTestId('clear-subdomain').click();
      await expect(subdomain).not.toHaveAttribute('aria-invalid');
      await expect(helper).toHaveText('Lowercase letters, numbers and hyphens.');

      const password = page.getByTestId('server-password');
      await expect(password).toHaveAttribute('aria-invalid', 'true');
      await expect(password).toHaveAccessibleDescription('Incorrect email or password.');
      await expect(page.getByLabel('Current password', { exact: true })).toHaveAttribute('data-testid', 'server-password');
    });

    test('a control with its own id keeps its label, and a caller aria-invalid passes through', async ({ page }) => {
      await open(page, surface);
      await expect(page.getByLabel('Own id', { exact: true })).toHaveAttribute('data-testid', 'own-id');
      await expect(page.getByTestId('own-id')).toHaveAttribute('id', 'own-id-input');
      await expect(page.getByTestId('spelling')).toHaveAttribute('aria-invalid', 'spelling');
    });

    test('the password masks again when native validation blocks the submit', async ({ page }) => {
      await open(page, surface);
      const password = page.getByTestId('native-password');
      await password.fill('a new passphrase');
      await reveal(password).click();
      await expect(password).toHaveAttribute('type', 'text');
      await page.getByTestId('native-submit').click();
      await expect(page.getByTestId('native-submits')).toHaveText('0');
      await expect(password).toHaveAttribute('type', 'password');
    });

    test('disabled controls show their state, take no input and submit nothing', async ({ page }) => {
      await open(page, surface);
      const tx3 = await colour(page, 'var(--gk-color-tx3)');

      const checkbox = page.getByTestId('checkbox-disabled');
      await expect(checkbox).toBeDisabled();
      await expect(checkbox).toBeChecked();
      expect((await style(checkbox, '::before')).background, 'disabled and checked still looks checked').toBe(tx3);

      const radio = page.getByTestId('radio-disabled');
      await expect(radio).toBeDisabled();
      await expect(radio).toBeChecked();
      const ring = await style(radio, '::before');
      expect(ring.borderColor).toBe(tx3);
      // The same ring as an enabled checked radio (Chromium snaps 4.5px to the device pixel).
      expect(ring.borderWidth).toBe((await style(page.getByTestId('radio-never'), '::before')).borderWidth);
      expect(px(ring.borderWidth)).toBeGreaterThan(1);
      expect((await style(page.getByTestId('radio-disabled-us'), '::before')).borderWidth).toBe('1px');

      const toggle = page.getByTestId('toggle-disabled');
      await expect(toggle).toBeDisabled();
      await expect(toggle).toHaveAttribute('aria-checked', 'true');
      expect((await style(toggle.locator('span').first())).background, 'disabled and on still looks on').toBe(tx3);

      await expect(page.getByTestId('select-disabled')).toBeDisabled();
      const density = page.getByRole('radiogroup', { name: 'Density' }).getByRole('radio');
      await expect(density).toHaveCount(2);
      for (const segment of await density.all()) await expect(segment).toBeDisabled();

      const password = page.getByTestId('disabled-password');
      await expect(password).toBeDisabled();
      await expect(reveal(password)).toBeDisabled();

      await page.getByTestId('save-settings').click();
      // Only the enabled toggles submit: mfa inside the form, alerts through form="settings-form".
      expect(JSON.parse((await page.getByTestId('settings').textContent()) ?? '')).toEqual({ mfa: 'on', alerts: 'on' });
    });

    test('a named toggle in a form submits its value only while on', async ({ page }) => {
      await open(page, surface);
      const settings = page.getByTestId('settings');
      await page.getByTestId('toggle-mfa').click();
      await page.getByTestId('save-settings').click();
      await expect(settings).not.toBeEmpty();
      expect(JSON.parse((await settings.textContent()) ?? '')).toEqual({ alerts: 'on' });
      await page.getByTestId('toggle-mfa').click();
      await page.getByTestId('save-settings').click();
      await expect(settings).toContainText('mfa');
      expect(JSON.parse((await settings.textContent()) ?? '')).toEqual({ mfa: 'on', alerts: 'on' });
    });

    test('segmented falls back to the first option, follows RTL, and keeps focus on a refused change', async ({ page }) => {
      await open(page, surface);
      const fallback = page.getByRole('radiogroup', { name: 'Fallback' });
      await expect(fallback.getByRole('radio', { name: 'First' })).toHaveAttribute('aria-checked', 'true');
      await expect(fallback.getByRole('radio', { name: 'First' })).toHaveAttribute('tabindex', '0');
      await expect(page.locator('input[type="hidden"][name="fallback"]')).toHaveValue('first');

      const rtl = page.getByRole('radiogroup', { name: 'Direction' });
      await rtl.getByRole('radio', { name: 'One' }).focus();
      await page.keyboard.press('ArrowLeft');
      await expect(rtl.getByRole('radio', { name: 'Two' })).toBeFocused();
      await expect(rtl.getByRole('radio', { name: 'Two' })).toHaveAttribute('aria-checked', 'true');
      await page.keyboard.press('ArrowRight');
      await expect(rtl.getByRole('radio', { name: 'One' })).toHaveAttribute('aria-checked', 'true');

      const refused = page.getByRole('radiogroup', { name: 'Refused', exact: true });
      const kept = refused.getByRole('radio', { name: 'Kept' });
      await kept.focus();
      await page.keyboard.press('ArrowRight');
      await expect(kept).toBeFocused();
      await expect(kept).toHaveAttribute('aria-checked', 'true');
      await refused.getByRole('radio', { name: 'Refused option' }).click();
      await expect(kept).toBeFocused();
      await expect(kept).toHaveAttribute('aria-checked', 'true');
    });

    test('the dark scheme draws the controls on the dark tokens', async ({ page }) => {
      await open(page, surface, 'dark');
      const dark = tokens.schemes.dark;
      const primary = await style(page.getByTestId('primary'));
      expect(primary.background).toBe(await colour(page, dark.ac));
      expect(primary.color).toBe(await colour(page, dark['on-ac']));
      expect((await style(page.locator('body'))).background).toBe(await colour(page, dark.bg));
      const email = await style(page.getByTestId('email'));
      expect(email.borderColor).toBe(await colour(page, surface === 'hosted' ? dark.tx3 : dark.bd2));
      expect(email.background).toBe(await colour(page, dark.sf));
      const destructive = await style(page.getByTestId('destructive'));
      expect(destructive.background).toBe(await colour(page, dark['bad-sf']));
      expect(destructive.color).toBe(await colour(page, dark.bad));
      // The nested island declares its own scheme scope and keeps the dark values.
      expect((await style(page.getByTestId('island'))).background).toBe(await colour(page, dark.sf));
      await page.getByTestId('email').fill('nope');
      await page.getByTestId('email').press('Tab');
      expect((await style(await helperOf(page, page.getByTestId('email')))).color).toBe(await colour(page, dark.bad));
    });

    test.describe('in forced colours', () => {
      test.use({ forcedColors: 'active' });

      test('checked, on and selected states take the system highlight', async ({ page }) => {
        await open(page, surface);
        const highlight = await page.evaluate(() => {
          const probe = document.createElement('span');
          probe.style.setProperty('forced-color-adjust', 'none');
          probe.style.color = 'Highlight';
          document.body.append(probe);
          const resolved = getComputedStyle(probe).color;
          probe.remove();
          return resolved;
        });
        await page.getByTestId('checkbox').check();
        expect((await style(page.getByTestId('checkbox'), '::before')).background).toBe(highlight);
        await page.getByTestId('toggle').click();
        expect((await style(page.getByTestId('toggle').locator('span span'))).background).toBe(highlight);
        const selected = page.getByRole('radiogroup', { name: 'Theme' }).getByRole('radio', { name: 'Dark' });
        expect((await style(selected)).borderColor).toBe(highlight);
        // From the keyboard, so the focus is :focus-visible.
        await page.getByTestId('radio-never').focus();
        await page.keyboard.press('Tab');
        await expect(selected).toBeFocused();
        expect(await selected.evaluate((element) => getComputedStyle(element).outlineColor)).toBe(highlight);
      });
    });

    test.describe('with reduced motion', () => {
      test.use({ reducedMotion: 'reduce' });

      test('the toggle stops moving and the spinner slows', async ({ page }) => {
        await open(page, surface);
        const track = page.getByTestId('toggle').locator('span').first();
        const spinner = page.getByTestId('pending-small').locator('[aria-hidden="true"]').first();
        expect(await track.evaluate((element) => getComputedStyle(element).transitionDuration)).toBe('0s');
        expect(await spinner.evaluate((element) => getComputedStyle(element).animationDuration)).toBe(`${(px(tokens.elevation.motion.durationMax) * 12) / 1000}s`);
      });
    });

    test('without reduced motion, the toggle eases and the spinner turns at full speed', async ({ page }) => {
      await open(page, surface);
      const track = page.getByTestId('toggle').locator('span').first();
      const spinner = page.getByTestId('pending-small').locator('[aria-hidden="true"]').first();
      expect(await track.evaluate((element) => getComputedStyle(element).transitionDuration)).toBe(`${px(tokens.elevation.motion.durationMin) / 1000}s`);
      expect(await spinner.evaluate((element) => getComputedStyle(element).animationDuration)).toBe(`${(px(tokens.elevation.motion.durationMax) * 4) / 1000}s`);
    });

    for (const scheme of ['light', 'dark'] as const) {
      test(`axe finds no violations, in the ${scheme} scheme, at rest and in every state`, async ({ page }) => {
        await open(page, surface, scheme);
        const violations = async () =>
          (await new AxeBuilder({ page }).analyze()).violations.map((violation) => ({
            id: violation.id,
            targets: violation.nodes.map((node) => node.target.join(' ')),
          }));
        expect(await violations(), 'at rest').toEqual([]);

        await page.getByTestId('email').fill('nope');
        await page.getByTestId('email').press('Tab');
        await page.getByTestId('callbacks').fill('nope');
        await page.getByTestId('callbacks').press('Tab');
        await reveal(page.getByTestId('password')).click();
        await page.getByRole('switch', { name: 'Allow sign-up' }).click();
        await page.getByTestId('checkbox').check();
        await page.getByTestId('pending').click();
        await expect(page.getByTestId('pending')).toHaveAttribute('aria-busy', 'true');
        expect(await violations(), 'in error, pending, shown and checked').toEqual([]);
      });
    }
  });
}
