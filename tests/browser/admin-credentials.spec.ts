// Story 1.26: Your credentials and the re-authentication gate (UX-DR17) in the built Admin
// Dashboard, served by the built Host.Admin (admin-host.mjs) under its real CSP, from localhost,
// since WebAuthn takes no IP address as an RP ID. The Admin API is answered by route interception;
// the browser's own sheets are answered by a Chromium virtual authenticator over CDP. The server's
// rules are the Isolation tests' (tests/Isolation/Admins/FreshAssertionTests.cs); the helper's,
// apps/admin-dashboard/test/freshAssertion.test.mjs's.

import AxeBuilder from '@axe-core/playwright';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, test, type CDPSession, type Page, type Request, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const CREDENTIALS = '/api/v1/deployment/credentials';
const ASSERTIONS = '/api/v1/deployment/assertions';
const REGISTRATION = '/api/v1/deployment/credentials/registration';
const CSRF = 'K'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000126';
const PATH = '/account/credentials';

const json = (route: Route, status: number, body: unknown, headers?: Record<string, string>) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body), headers });
const problem = (route: Route, status: number, code: string, headers?: Record<string, string>) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: 'f'.repeat(32) }), headers });

type Answer = (route: Route) => Promise<void>;

interface Row {
  id: string;
  kind: 'passkey' | 'securityKey';
  backedUp: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

const acr = (n: number) => `acr_${String.fromCharCode(97 + n).repeat(25)}a`;

const row = (n: number, extra: Partial<Row> = {}): Row => ({
  id: acr(n),
  kind: n % 2 === 0 ? 'passkey' : 'securityKey',
  backedUp: n === 0,
  createdAt: `2026-11-0${n + 1}T10:00:00Z`,
  lastUsedAt: n === 0 ? '2026-11-04T09:30:00Z' : null,
  ...extra,
});

interface State {
  rows: Row[];
  recoveryCode: boolean;
  /** A grant the server holds, as the action and target it confirms. */
  grant: string | null;
  /** The action and target of the last begin. */
  pending: string | null;
  completeAnswer: Answer | null;
  beginAnswer: Answer | null;
  deleteAnswer: ((route: Route, id: string) => Promise<void>) | null;
  registrationAnswer: Answer | null;
  /** Overrides the floor rule for `removable`. */
  removable: boolean | null;
}

/**
 * The Admin API as the server answers a full Session's Your credentials: the list with the floor
 * rule, removal that needs a grant for its target, the fresh-assertion ceremony that makes one,
 * and an add whose registration begin needs a grant for self.credentials.add.
 */
async function answerApi(page: Page, baseURL: string, initial: Partial<State> = {}) {
  const log: string[] = [];
  const requests: Request[] = [];
  const state: State = {
    rows: [row(0), row(1), row(2)],
    recoveryCode: false,
    grant: null,
    pending: null,
    completeAnswer: null,
    beginAnswer: null,
    deleteAnswer: null,
    registrationAnswer: null,
    removable: null,
    ...initial,
  };

  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      const method = request.method();
      log.push(`${method} ${pathname}`);
      requests.push(request);

      if (pathname === SESSION) {
        return json(route, 200, { adminId: ADMIN_ID, kind: 'full', deploymentOwner: true, setupComplete: true, credentials: state.rows.length, recoveryCodeAllowed: false, csrfToken: CSRF });
      }
      if (pathname === CAPABILITIES) return json(route, 200, { capabilities: [] });
      if (pathname === CREDENTIALS && method === 'GET') {
        const removable = state.removable ?? state.rows.length > 2;
        return json(route, 200, { credentials: state.rows.map((r) => ({ ...r, removable })), recoveryCode: state.recoveryCode });
      }
      if (pathname.startsWith(`${CREDENTIALS}/acr_`) && method === 'DELETE') {
        const id = decodeURIComponent(pathname.slice(CREDENTIALS.length + 1));
        if (state.deleteAnswer) return state.deleteAnswer(route, id);
        if (state.grant !== `self.credentials.remove ${id}`) return problem(route, 403, 'fresh_assertion_required');
        state.grant = null;
        state.rows = state.rows.filter((r) => r.id !== id);
        return route.fulfill({ status: 204 });
      }
      if (pathname === ASSERTIONS) {
        if (state.beginAnswer) return state.beginAnswer(route);
        const body = request.postDataJSON() as { action: string; target: string | null };
        state.pending = `${body.action} ${body.target ?? ''}`.trim();
        return json(route, 200, {
          challenge: randomBytes(32).toString('base64url'),
          rpId: new URL(baseURL).hostname,
          timeout: 300000,
          userVerification: 'required',
          allowCredentials: [],
        });
      }
      if (pathname === `${ASSERTIONS}/complete`) {
        if (state.completeAnswer) return state.completeAnswer(route);
        state.grant = state.pending;
        state.pending = null;
        return route.fulfill({ status: 204 });
      }
      if (pathname === REGISTRATION) {
        if (state.registrationAnswer) return state.registrationAnswer(route);
        if (state.grant !== 'self.credentials.add') return problem(route, 403, 'fresh_assertion_required');
        state.grant = null;
        return json(route, 200, {
          rp: { id: new URL(baseURL).hostname, name: 'Gatekeep' },
          user: { id: randomBytes(64).toString('base64url'), name: 'Deployment Owner', displayName: 'Deployment Owner' },
          challenge: randomBytes(32).toString('base64url'),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          timeout: 300000,
          attestation: 'none',
          authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
          excludeCredentials: [],
        });
      }
      if (pathname === `${REGISTRATION}/complete`) {
        state.rows = [...state.rows, row(state.rows.length + 3, { kind: 'securityKey', backedUp: false, createdAt: '2026-11-04T11:00:00Z' })];
        return json(route, 200, { credentials: state.rows.length, setupComplete: true });
      }
      return route.fulfill({ status: 404 });
    },
  );

  return { log, requests, state, count: (entry: string) => log.filter((line) => line === entry).length };
}

/** A virtual CTAP2 authenticator holding the Admin's resident credential, verifying and presenting by itself. */
async function authenticator(page: Page, rpId: string) {
  const cdp: CDPSession = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'usb',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const id = randomBytes(32);
  await cdp.send('WebAuthn.addCredential', {
    authenticatorId,
    credential: {
      credentialId: id.toString('base64'),
      isResidentCredential: true,
      rpId,
      privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
      userHandle: randomBytes(64).toString('base64'),
      signCount: 0,
    },
  });
  /** An authenticator that can't verify the user ends the ceremony with NotAllowedError, as a cancel does. */
  const cancelling = (on: boolean) => cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: !on });
  return { cancelling, credentialId: id.toString('base64url') };
}

async function axe(page: Page) {
  // Finite animations only: a pending button's spinner runs until its action settles.
  await page.evaluate(() =>
    Promise.allSettled(
      document
        .getAnimations()
        .filter((animation) => animation.effect?.getComputedTiming().iterations !== Infinity)
        .map((animation) => animation.finished),
    ).then(() => undefined),
  );
  // tx3 on sf2 in table heads is DESIGN.md's one recorded contrast exception, as data.spec.ts has it.
  const everything = await new AxeBuilder({ page }).disableRules(['color-contrast']).analyze();
  const contrast = await new AxeBuilder({ page }).withRules(['color-contrast']).exclude('thead th').analyze();
  return [...everything.violations, ...contrast.violations].map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
}

/** axe in light and dark, at 1100 and 768px wide, on what the page shows now. */
async function axeEverywhere(page: Page) {
  for (const width of [1100, 768]) {
    for (const colorScheme of ['light', 'dark'] as const) {
      await page.setViewportSize({ width, height: 800 });
      await page.emulateMedia({ colorScheme });
      expect(await axe(page), `${colorScheme} at ${width}px`).toEqual([]);
    }
  }
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.emulateMedia({ colorScheme: 'light' });
}

const heading = (page: Page) => page.getByRole('heading', { level: 1, name: 'Your credentials' });
const removeModal = (page: Page) => page.getByTestId('remove-credential');
const addModal = (page: Page) => page.getByTestId('add-credential');
const removeButtons = (page: Page) => page.getByRole('button', { name: /^Remove (Passkey|Security key) added/ });

test.use({ viewport: { width: 1280, height: 800 } });
watchCsp(test);

test.describe('Your credentials', () => {
  test('the avatar menu leads to the page: its credentials, oldest first, with Remove where the floor allows', async ({ page, baseURL }) => {
    const api = await answerApi(page, baseURL!);

    await page.goto('/');
    await page.getByRole('button', { name: 'Account' }).click();
    await expect(page.getByRole('menuitem')).toHaveText(['Your credentials', 'Sign out']);
    await page.getByRole('menuitem', { name: 'Your credentials' }).click();

    await expect(page).toHaveURL(new RegExp(`${PATH}$`));
    await expect(heading(page)).toBeVisible();
    await expect(heading(page)).toBeFocused();
    await expect(page.getByText('Account', { exact: true }).first()).toBeVisible();
    await expect(page.getByText("The passkeys and security keys you sign in with. Keep at least two, so losing one device can't lock you out.")).toBeVisible();
    await expect(page.getByRole('button', { name: 'Add credential' })).toBeVisible();

    const table = page.getByRole('table', { name: 'Your credentials' });
    await expect(table.getByRole('columnheader')).toHaveText(['Credential', 'Added', 'Last used', 'Remove']);
    await expect(table.getByRole('rowheader')).toHaveText(['Passkey Synced', 'Security key', 'Passkey']);
    await expect(table.getByRole('row').nth(2)).toContainText('Never');
    await expect(removeButtons(page)).toHaveCount(3);
    await expect(page.getByTestId('credentials-floor')).toHaveCount(0);
    expect(api.count(`GET ${CREDENTIALS}`)).toBe(1);

    await axeEverywhere(page);
  });

  test('at the floor no row has Remove, a note says why, and a Recovery Code is mentioned', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { rows: [row(0), row(1)], recoveryCode: true });

    await page.goto(PATH);

    await expect(heading(page)).toBeVisible();
    await expect(removeButtons(page)).toHaveCount(0);
    await expect(page.getByRole('columnheader')).toHaveText(['Credential', 'Added', 'Last used']);
    await expect(page.getByTestId('credentials-floor')).toHaveText('You need at least two credentials. Add another before removing one.');
    await expect(page.getByTestId('credentials-recovery-code')).toHaveText('You also hold an offline recovery code.');
    await axeEverywhere(page);
  });

  test('Remove: the server asks for a fresh assertion, the sheet opens inside the one modal, and the row goes', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);

    await page.goto(PATH);
    await removeButtons(page).nth(1).click();
    await expect(removeModal(page)).toBeVisible();
    await expect(removeModal(page).getByRole('heading', { name: 'Remove this credential?' })).toBeVisible();
    await expect(removeModal(page)).toContainText("You won't be able to sign in with it again. Your other Admin sessions will end.");
    await axeEverywhere(page);

    await removeModal(page).getByRole('button', { name: 'Remove credential' }).click();

    await expect(page.getByTestId('toast')).toHaveText('Credential removed.');
    await expect(removeModal(page)).toBeHidden();
    // The DELETE first, refused; the ceremony for exactly that target; the DELETE once more.
    expect(api.log.filter((line) => !line.startsWith('GET'))).toEqual([
      `DELETE ${CREDENTIALS}/${acr(1)}`,
      `POST ${ASSERTIONS}`,
      `POST ${ASSERTIONS}/complete`,
      `DELETE ${CREDENTIALS}/${acr(1)}`,
    ]);
    const begin = api.requests.find((r) => new URL(r.url()).pathname === ASSERTIONS)!;
    expect(begin.postDataJSON()).toEqual({ action: 'self.credentials.remove', target: acr(1) });
    expect(await begin.headerValue('x-gatekeep-csrf')).toBe(CSRF);
    // The list is read again; at the floor now, focus goes to the heading.
    await expect(page.getByRole('rowheader')).toHaveText(['Passkey Synced', 'Passkey']);
    await expect(heading(page)).toBeFocused();
    // Nothing about the grant reached the page.
    expect(await page.evaluate(() => [Object.keys(localStorage), Object.keys(sessionStorage), document.cookie])).toEqual([[], [], '']);
  });

  test('Remove with a row after it moves focus to that row', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    await answerApi(page, baseURL!, { rows: [row(0), row(1), row(2), row(3)] });

    await page.goto(PATH);
    await removeButtons(page).nth(1).click();
    await removeModal(page).getByRole('button', { name: 'Remove credential' }).click();

    await expect(page.getByTestId('toast')).toHaveText('Credential removed.');
    await expect(removeButtons(page)).toHaveCount(3);
    await expect(page.locator(`[data-credential="${acr(2)}"]`)).toBeFocused();
  });

  const failures: { name: string; text: string; setup: (api: Awaited<ReturnType<typeof answerApi>>, auth: Awaited<ReturnType<typeof authenticator>>) => Promise<void> }[] = [
    {
      name: 'a refused assertion',
      text: "That credential wasn't recognised.",
      setup: async (api) => {
        api.state.completeAnswer = (route) => problem(route, 400, 'assertion_refused');
      },
    },
    {
      name: 'a cancelled sheet',
      text: 'Confirmation cancelled. Nothing was changed.',
      setup: async (_api, auth) => {
        await auth.cancelling(true);
      },
    },
    {
      name: 'a rate limit',
      text: 'Too many attempts. Try again in 30 seconds.',
      setup: async (api) => {
        api.state.beginAnswer = (route) => problem(route, 429, 'rate_limited', { 'Retry-After': '30' });
      },
    },
    {
      name: 'an outage',
      text: "We couldn't confirm it's you. Try again.",
      setup: async (api) => {
        api.state.completeAnswer = (route) => route.fulfill({ status: 503 });
      },
    },
  ];

  for (const failure of failures) {
    test(`after ${failure.name} the modal stays with the reason, nothing is removed, and Confirm retries`, async ({ page, baseURL }) => {
      const auth = await authenticator(page, new URL(baseURL!).hostname);
      const api = await answerApi(page, baseURL!);
      await failure.setup(api, auth);

      await page.goto(PATH);
      await removeButtons(page).first().click();
      const confirm = removeModal(page).getByRole('button', { name: 'Remove credential' });
      await confirm.click();

      await expect(removeModal(page).getByTestId('fresh-assertion-failed')).toHaveText(failure.text);
      await expect(removeModal(page)).toBeVisible();
      await expect(page.getByRole('dialog')).toHaveCount(1);
      expect(api.state.rows).toHaveLength(3);
      expect(api.count(`DELETE ${CREDENTIALS}/${acr(0)}`)).toBe(1);
      await axeEverywhere(page);

      // Confirm runs the whole flow again, and this time it passes.
      api.state.completeAnswer = null;
      api.state.beginAnswer = null;
      await auth.cancelling(false);
      await confirm.click();
      await expect(page.getByTestId('toast')).toHaveText('Credential removed.');
      expect(api.state.rows).toHaveLength(2);
    });
  }

  test('while the sheet is open the slot says so, and Cancel is held', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    api.state.completeAnswer = async (route) => {
      await held;
      api.state.grant = api.state.pending;
      await route.fulfill({ status: 204 });
    };

    await page.goto(PATH);
    await removeButtons(page).first().click();
    await removeModal(page).getByRole('button', { name: 'Remove credential' }).click();

    await expect(removeModal(page).getByTestId('fresh-assertion-prompt')).toHaveText("Confirm it's you with your security key or passkey.");
    await expect(removeModal(page).getByRole('button', { name: 'Cancel' })).toHaveAttribute('aria-disabled', 'true');
    await page.keyboard.press('Escape');
    await expect(removeModal(page)).toBeVisible();
    await axeEverywhere(page);

    release();
    await expect(page.getByTestId('toast')).toHaveText('Credential removed.');
  });

  test('a removal the server refuses for the floor says so in the modal', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    api.state.deleteAnswer = async (route, id) => {
      if (api.state.grant !== `self.credentials.remove ${id}`) return problem(route, 403, 'fresh_assertion_required');
      api.state.grant = null;
      return problem(route, 409, 'credentials_minimum');
    };

    await page.goto(PATH);
    await removeButtons(page).first().click();
    await removeModal(page).getByRole('button', { name: 'Remove credential' }).click();

    await expect(removeModal(page).getByTestId('fresh-assertion-failed')).toHaveText("You can't remove this credential: you need at least two.");
    expect(api.state.rows).toHaveLength(3);
  });

  test('Add: Continue confirms, then the new credential registers from its own button', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);

    await page.goto(PATH);
    await page.getByRole('button', { name: 'Add credential' }).click();
    await expect(addModal(page).getByRole('heading', { name: 'Add a credential' })).toBeVisible();
    await expect(addModal(page)).toContainText(
      "Confirm it's you with a credential you already have, then register the new passkey or security key.",
    );
    await axeEverywhere(page);

    await addModal(page).getByRole('button', { name: 'Continue' }).click();
    await expect(addModal(page).getByTestId('add-credential-register')).toHaveText('Now register the new passkey or security key.');
    // Confirmed first: the add's own begin hasn't been sent.
    expect(api.log.filter((line) => line.startsWith('POST'))).toEqual([`POST ${ASSERTIONS}`, `POST ${ASSERTIONS}/complete`]);
    const begin = api.requests.find((r) => new URL(r.url()).pathname === ASSERTIONS)!;
    expect(begin.postDataJSON()).toEqual({ action: 'self.credentials.add', target: null });
    await axeEverywhere(page);

    await addModal(page).getByTestId('add-credential-register-button').click();

    await expect(page.getByTestId('toast')).toHaveText('Credential added.');
    await expect(addModal(page)).toBeHidden();
    await expect(page.getByRole('rowheader')).toHaveCount(4);
    expect(api.log.filter((line) => line.startsWith('POST'))).toEqual([
      `POST ${ASSERTIONS}`,
      `POST ${ASSERTIONS}/complete`,
      `POST ${REGISTRATION}`,
      `POST ${REGISTRATION}/complete`,
    ]);
  });

  test('Add at the maximum says so, and a used-up confirmation goes back to the first step', async ({ page, baseURL }) => {
    const auth = await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    api.state.registrationAnswer = (route) => problem(route, 409, 'credentials_maximum');

    await page.goto(PATH);
    await page.getByRole('button', { name: 'Add credential' }).click();
    await addModal(page).getByRole('button', { name: 'Continue' }).click();
    await addModal(page).getByTestId('add-credential-register-button').click();
    await expect(addModal(page).getByTestId('fresh-assertion-failed')).toHaveText(
      'You already have 10 credentials. Remove one before adding another.',
    );

    api.state.registrationAnswer = (route) => problem(route, 403, 'fresh_assertion_required');
    await addModal(page).getByTestId('add-credential-register-button').click();
    await expect(addModal(page).getByTestId('fresh-assertion-failed')).toHaveText('Confirmation cancelled. Nothing was changed.');
    await expect(addModal(page).getByTestId('add-credential-register')).toHaveCount(0);

    // A cancelled first sheet keeps the first step, with its reason.
    await auth.cancelling(true);
    await addModal(page).getByRole('button', { name: 'Continue' }).click();
    await expect(addModal(page).getByTestId('fresh-assertion-failed')).toHaveText('Confirmation cancelled. Nothing was changed.');
    await axeEverywhere(page);
  });

  test('a 404 on the removal re-reads the list and closes the modal, with no toast', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    api.state.deleteAnswer = async (route) => {
      api.state.rows = api.state.rows.slice(0, 2).concat(api.state.rows.slice(3));
      return route.fulfill({ status: 404 });
    };

    await page.goto(PATH);
    await expect(removeButtons(page)).toHaveCount(3);
    const reads = api.count(`GET ${CREDENTIALS}`);
    await removeButtons(page).first().click();
    await removeModal(page).getByRole('button', { name: 'Remove credential' }).click();

    await expect(removeModal(page)).toBeHidden();
    await expect.poll(() => api.count(`GET ${CREDENTIALS}`)).toBe(reads + 1);
    await expect(page.getByTestId('toast')).toHaveCount(0);
  });

  test('removing the credential that confirmed it ends the Session, and goes to sign in', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    api.state.deleteAnswer = async (route, id) => {
      if (api.state.grant !== `self.credentials.remove ${id}`) return problem(route, 403, 'fresh_assertion_required');
      return json(route, 200, { sessionEnded: true });
    };

    await page.goto(PATH);
    await removeButtons(page).first().click();
    await removeModal(page).getByRole('button', { name: 'Remove credential' }).click();

    await expect(page).toHaveURL(/\/signin$/);
  });

  test('a removal the server refuses outright says so in the modal', async ({ page, baseURL }) => {
    await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    api.state.deleteAnswer = (route) => route.fulfill({ status: 403 });

    await page.goto(PATH);
    await removeButtons(page).first().click();
    await removeModal(page).getByRole('button', { name: 'Remove credential' }).click();

    await expect(removeModal(page).getByTestId('fresh-assertion-failed')).toHaveText("You can't do this in this session.");
    expect(api.state.rows).toHaveLength(3);
  });

  test('Add: a cancelled second sheet goes back to confirming, as its confirmation was used', async ({ page, baseURL }) => {
    const auth = await authenticator(page, new URL(baseURL!).hostname);
    await answerApi(page, baseURL!);

    await page.goto(PATH);
    await page.getByRole('button', { name: 'Add credential' }).click();
    await addModal(page).getByRole('button', { name: 'Continue' }).click();
    await expect(addModal(page).getByTestId('add-credential-register')).toBeVisible();

    await auth.cancelling(true);
    await addModal(page).getByTestId('add-credential-register-button').click();

    await expect(addModal(page).getByTestId('fresh-assertion-failed')).toHaveText('Confirmation cancelled. Nothing was changed.');
    await expect(addModal(page).getByTestId('add-credential-register')).toHaveCount(0);
    await expect(addModal(page).getByRole('button', { name: 'Continue' })).toBeVisible();
  });

  test('Add: an authenticator that already holds one of the credentials says so', async ({ page, baseURL }) => {
    const auth = await authenticator(page, new URL(baseURL!).hostname);
    const api = await answerApi(page, baseURL!);
    api.state.registrationAnswer = (route) =>
      json(route, 200, {
        rp: { id: new URL(baseURL!).hostname, name: 'Gatekeep' },
        user: { id: randomBytes(64).toString('base64url'), name: 'Deployment Owner', displayName: 'Deployment Owner' },
        challenge: randomBytes(32).toString('base64url'),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        timeout: 300000,
        attestation: 'none',
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        excludeCredentials: [{ type: 'public-key', id: auth.credentialId, transports: ['usb'] }],
      });

    await page.goto(PATH);
    await page.getByRole('button', { name: 'Add credential' }).click();
    await addModal(page).getByRole('button', { name: 'Continue' }).click();
    await addModal(page).getByTestId('add-credential-register-button').click();

    await expect(addModal(page).getByTestId('fresh-assertion-failed')).toHaveText(
      'This passkey or security key is already registered. Use a different security key or device.',
    );
  });

  test('Add is disabled once the list holds the maximum of 10', async ({ page, baseURL }) => {
    await answerApi(page, baseURL!, { rows: Array.from({ length: 10 }, (_, n) => row(n)) });

    await page.goto(PATH);

    await expect(page.getByRole('rowheader')).toHaveCount(10);
    await expect(page.getByRole('button', { name: 'Add credential' })).toBeDisabled();
    await axeEverywhere(page);
  });
});
