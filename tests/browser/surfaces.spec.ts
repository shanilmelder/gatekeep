// The Fonts local, No third party, Focus and Scope rows of the Story 1.13 matrix, on each
// built surface. Expected values come from the generated tokens, never from hex here.

import { tokens } from '@gatekeep/design-tokens';
import { expect, test, type Page } from '@playwright/test';

const body = tokens.typography.body;

test('loads everything, the fonts included, from its own origin', async ({ page, baseURL }) => {
  const origin = new URL(baseURL!).origin;
  const requests: string[] = [];
  const fonts: { url: string; status: number }[] = [];
  page.on('request', (request) => requests.push(request.url()));
  page.on('response', (response) => {
    if (response.request().resourceType() === 'font') fonts.push({ url: response.url(), status: response.status() });
  });

  await page.goto('/');
  // The page's own text, styled by the body rule, must bring Geist in by itself.
  await page.evaluate(() => document.fonts.ready);
  const rendered = await page.evaluate(() => {
    const style = getComputedStyle(document.body);
    return {
      fontFamily: style.fontFamily,
      fontSize: style.fontSize,
      lineHeight: style.lineHeight,
      letterSpacing: style.letterSpacing,
      backgroundColor: style.backgroundColor,
      color: style.color,
      geistLoaded: [...document.fonts].some((face) => face.family.replace(/["']/g, '') === 'Geist' && face.status === 'loaded'),
    };
  });
  expect(rendered.fontFamily).toMatch(/^"?Geist"?,/);
  expect(rendered.fontSize).toBe(body.fontSize);
  expect(rendered.lineHeight).toBe(body.lineHeight);
  expect(rendered.letterSpacing).toBe('letterSpacing' in body ? body.letterSpacing : 'normal');
  expect(rendered.backgroundColor).toBe(await resolvedColor(page, tokens.schemes.light.bg));
  expect(rendered.color).toBe(await resolvedColor(page, tokens.schemes.light.tx));
  expect(rendered.geistLoaded, 'Geist loaded from the body rule alone').toBe(true);

  // No v1 screen sets Geist Mono yet, so ask for it to prove the face loads from here.
  const loaded = await page.evaluate(async () => {
    await document.fonts.load('16px "Geist Mono"');
    await document.fonts.ready;
    return [...document.fonts].filter((face) => face.status === 'loaded').map((face) => face.family.replace(/["']/g, ''));
  });
  await page.waitForLoadState('networkidle');

  expect(loaded).toEqual(expect.arrayContaining(['Geist', 'Geist Mono']));
  expect(fonts).toHaveLength(2);
  for (const font of fonts) {
    expect(new URL(font.url).origin).toBe(origin);
    expect(font.url).toMatch(/\.woff2$/);
    expect(font.status).toBe(200);
  }
  expect(requests.length).toBeGreaterThan(0);
  expect(requests.filter((url) => new URL(url).origin !== origin)).toEqual([]);
});

test('draws the focus ring outside every interactive element', async ({ page }) => {
  await page.goto('/');
  const controls = await addControls(page);
  const accent = await resolvedColor(page, 'var(--gk-color-ac)');

  for (const ring of await tabThrough(page, controls)) {
    expect(ring.focusVisible, ring.element).toBe(true);
    expect(ring.style, ring.element).toBe(tokens.components['focus-ring']['outline-style']);
    expect(ring.width, ring.element).toBe(parseFloat(tokens.components['focus-ring']['outline-width']));
    // A positive offset puts the whole outline outside the element's border box.
    expect(ring.offset, ring.element).toBe(parseFloat(tokens.components['focus-ring']['outline-offset']));
    expect(ring.offset, ring.element).toBeGreaterThan(0);
    expect(ring.color, ring.element).toBe(accent);
  }
});

test.describe('in forced colours', () => {
  test.use({ forcedColors: 'active' });

  test('draws the focus ring in the system highlight', async ({ page }) => {
    await page.goto('/');
    const controls = await addControls(page);
    const highlight = await resolvedColor(page, 'Highlight');

    for (const ring of await tabThrough(page, controls)) {
      expect(ring.focusVisible, ring.element).toBe(true);
      expect(ring.style, ring.element).not.toBe('none');
      expect(ring.offset, ring.element).toBeGreaterThan(0);
      expect(ring.color, ring.element).toBe(highlight);
    }
  });
});

test('a dark scope themes its subtree only', async ({ page }) => {
  await page.goto('/');
  const values = await page.evaluate(() => {
    const fixture = document.createElement('div');
    fixture.innerHTML = [
      '<div data-gk-scheme="dark"><span id="inside"></span></div><span id="outside"></span>',
      '<div data-gk-scheme="dark"><div data-gk-theme><span id="nested"></span></div></div>',
      '<div data-gk-theme data-gk-scheme="dark"><span id="both"></span></div>',
      '<div data-gk-scheme="dark"><div data-gk-scheme="light"><span id="light-in-dark"></span></div></div>',
    ].join('');
    document.body.append(fixture);
    const read = (id: string) => {
      const element = document.getElementById(id)!;
      // The build minifies the shadow's colours, so compare it as a resolved box-shadow.
      element.style.boxShadow = 'var(--gk-elevation-sh)';
      const style = getComputedStyle(element);
      return {
        bg: style.getPropertyValue('--gk-color-bg').trim(),
        sh: style.boxShadow,
        ring: style.getPropertyValue('--gk-focus-ring-outline-color').trim(),
      };
    };
    return Object.fromEntries(['inside', 'outside', 'nested', 'both', 'light-in-dark'].map((id) => [id, read(id)]));
  });

  const shadows = await page.evaluate((values) => values.map((value) => {
    const probe = document.createElement('span');
    probe.style.boxShadow = value;
    document.body.append(probe);
    const resolved = getComputedStyle(probe).boxShadow;
    probe.remove();
    return resolved;
  }), [tokens.schemes.light.sh, tokens.schemes.dark.sh]);
  const scheme = (name: 'light' | 'dark') => ({
    bg: tokens.schemes[name].bg,
    sh: shadows[name === 'light' ? 0 : 1],
    ring: tokens.schemes[name].ac,
  });
  expect(values).toEqual({
    inside: scheme('dark'),
    outside: scheme('light'),
    nested: scheme('light'),
    both: scheme('dark'),
    'light-in-dark': scheme('light'),
  });
});

/** Puts one of each kind of interactive element first in the page. Returns how many. */
async function addControls(page: Page) {
  return page.evaluate(() => {
    const fixture = document.createElement('div');
    fixture.innerHTML = [
      '<button type="button">Button</button>',
      '<a href="/">Link</a>',
      '<input aria-label="Input">',
      '<select aria-label="Select"><option>One</option></select>',
      '<textarea aria-label="Textarea"></textarea>',
      '<input type="checkbox" aria-label="Checkbox">',
      '<details><summary>Summary</summary></details>',
      '<div tabindex="0" role="button">Custom</div>',
    ].join('');
    document.body.prepend(fixture);
    return fixture.querySelectorAll('button, a, input, select, textarea, summary, [tabindex]').length;
  });
}

/** Tabs from the start of the document through `count` elements, reading each one's ring. */
async function tabThrough(page: Page, count: number) {
  // Start from the document, not from whatever an app autofocused: the body is focused
  // (and is first in tree order), so the next Tab lands on the first control.
  await page.evaluate(() => {
    (document.activeElement as HTMLElement | null)?.blur();
    document.body.tabIndex = -1;
    document.body.focus({ preventScroll: true });
  });
  const rings = [];
  for (let index = 0; index < count; index++) {
    await page.keyboard.press('Tab');
    rings.push(await page.evaluate(() => {
      const element = document.activeElement as HTMLElement;
      const style = getComputedStyle(element);
      return {
        element: element.outerHTML.slice(0, 40),
        focusVisible: element.matches(':focus-visible'),
        style: style.outlineStyle,
        width: parseFloat(style.outlineWidth),
        offset: parseFloat(style.outlineOffset),
        color: style.outlineColor,
      };
    }));
  }
  expect(new Set(rings.map((ring) => ring.element)).size, 'each Tab reached a new control').toBe(count);
  return rings;
}

/** Resolves a CSS colour to its computed rgb() form, unaffected by forced colours. */
async function resolvedColor(page: Page, value: string) {
  return page.evaluate((color) => {
    const probe = document.createElement('span');
    probe.style.setProperty('forced-color-adjust', 'none');
    probe.style.color = color;
    document.body.append(probe);
    const resolved = getComputedStyle(probe).color;
    probe.remove();
    return resolved;
  }, value);
}
