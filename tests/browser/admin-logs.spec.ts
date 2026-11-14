// Story 7.4: a Tenant's Logs in the built Admin Dashboard served by the built Host.Admin
// (admin-host.mjs) under its real CSP, from localhost. The Admin API is answered by route
// interception: the field search, its URL, Load more, the empty state, a refused search and the
// sidebar item. The URL-to-query mapping is apps/admin-dashboard/test/logs.test.mjs's; the
// server's search and its Tenant isolation are tests/Isolation/Audit/TenantLogSearchTests.cs's.
//
// Story 7.5: a row opens the event drawer, read from the event endpoint: an Editor's answer
// carries raw, shown as JSON with Copy JSON; a Viewer's raw is null, so only the limited note
// shows. Esc closes it, a failed read offers Retry, and the keyboard opens a row. The server's
// raw-detail decision is tests/Isolation/Audit/TenantLogEventTests.cs's.
//
// Story 7.7: the Deployment Log, the same page at /deployment/logs, is the last describe.

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Route } from '@playwright/test';
import { watchCsp } from './csp-watch';

const SESSION = '/api/v1/deployment/session';
const CAPABILITIES = '/api/v1/deployment/capabilities';
const MY_TENANTS = '/api/v1/deployment/my-tenants';
const CSRF = 'W'.repeat(43);
const ADMIN_ID = '01900000-0000-7000-8000-000000000704';
const ZONE = 'gatekeep.test';

const TENANT = `ten_${'a'.repeat(25)}a`;
const LOGS = `/tenants/${TENANT}/logs`;
const VIEWER = ['tenant.configuration.read', 'tenant.users.read', 'tenant.logs.read'];
const USER = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const CLIENT = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';
const REJECTED = 'admin.cross_tenant.rejected';
const EMPTY = 'No events in this range';
const LIMITED = "Raw detail is limited by role, and yours can't see it.";
const DETAIL = { ipAddress: '198.51.100.23', userAgent: 'DetailAgent/7.5', email: 'detail-u1@example.test' };
const HASH = 'b2'.repeat(32);
const PREV_HASH = 'a1'.repeat(32);

interface LogEvent {
  id: string;
  occurredAt: string;
  type: string;
  outcome: 'success' | 'failure';
  summary: string;
  actor: { kind: string; id: string | null };
  target: { kind: string; id: string | null } | null;
}

/** A distinct, well-formed evt_ ID for each `n`: its base-26 digits as letters. */
function evt(n: number): string {
  let digits = '';
  let rest = n;
  do {
    digits = String.fromCharCode(97 + (rest % 26)) + digits;
    rest = Math.floor(rest / 26);
  } while (rest > 0);
  return `evt_${digits.padStart(25, 'a')}a`;
}

/** `count` events, newest first, every fifth a cross-Tenant rejection and the rest a User's sign-in Session. */
function events(count: number): LogEvent[] {
  return Array.from({ length: count }, (_, i) => {
    const n = count - i;
    const rejected = n % 5 === 0;
    return {
      id: evt(n),
      occurredAt: new Date(Date.UTC(2026, 10, 6, 9, 0, n)).toISOString(),
      type: rejected ? REJECTED : 'sessions.session.started',
      outcome: rejected ? 'failure' : 'success',
      summary: rejected ? 'An Admin holding no Tenant Role in this Tenant was refused a request in it.' : "A User's Session started.",
      actor: rejected ? { kind: 'admin', id: ADMIN_ID } : { kind: 'user', id: USER },
      target: rejected ? { kind: 'tenant', id: TENANT } : { kind: 'client', id: CLIENT },
    };
  });
}

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const problem = (route: Route, status: number, code: string) =>
  route.fulfill({ status, contentType: 'application/problem+json', body: JSON.stringify({ code, traceId: 'c'.repeat(32) }) });

interface State {
  tenantCapabilities: string[];
  events: LogEvent[];
  /** Answers a Log read before the default, such as a 400. */
  logsAnswer: ((route: Route, query: URLSearchParams) => Promise<void>) | null;
  /** Whether an opened event's answer carries raw, as the server sends it to an Editor or Owner. */
  raw: boolean;
  /** Answers an event read before the default, such as a 503. */
  eventAnswer: ((route: Route) => Promise<void>) | null;
}

interface Api {
  /** Each Log read's query string, as sent. */
  logReads: URLSearchParams[];
  /** Each event read's evt_ ID, as sent. */
  eventReads: string[];
  state: State;
}

/** An opened event as the server answers it: the row's fields, and raw only when `withRaw`. */
function opened(event: LogEvent, withRaw: boolean) {
  const { id, occurredAt, type, actor, target } = event;
  const seal = { seq: 2, prevHash: PREV_HASH, hash: HASH };
  return { ...event, raw: withRaw ? { id, occurredAt, type, actor, target, seal, detail: DETAIL } : null };
}

/** The Admin API for a Viewer of TENANT: the Log holds `state.events`, 50 a page, filtered as the server filters. */
async function answerApi(page: Page, initial: Partial<State> = {}): Promise<Api> {
  const logReads: URLSearchParams[] = [];
  const eventReads: string[] = [];
  const state: State = { tenantCapabilities: VIEWER, events: events(12), logsAnswer: null, raw: false, eventAnswer: null, ...initial };

  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const url = new URL(route.request().url());
      const { pathname } = url;
      if (pathname === SESSION) {
        return json(route, 200, {
          adminId: ADMIN_ID,
          kind: 'full',
          deploymentOwner: false,
          setupComplete: true,
          credentials: 2,
          recoveryCodeAllowed: false,
          csrfToken: CSRF,
        });
      }
      if (pathname === CAPABILITIES) return json(route, 200, { capabilities: [] });
      if (pathname === MY_TENANTS) return json(route, 200, { tenants: [{ id: TENANT, name: 'Alpha', host: `alpha.${ZONE}`, label: 'dev' }] });
      if (pathname === `/api/v1/tenants/${TENANT}/capabilities`) return json(route, 200, { capabilities: state.tenantCapabilities });
      if (pathname === `/api/v1/tenants/${TENANT}/label`) return json(route, 200, { label: 'dev', status: 'active' });
      if (pathname === `/api/v1/tenants/${TENANT}/logs`) {
        const query = url.searchParams;
        logReads.push(query);
        if (state.logsAnswer) return state.logsAnswer(route, query);
        let list = state.events;
        const type = query.get('type');
        const outcome = query.get('outcome');
        const user = query.get('user');
        const from = query.get('from');
        if (type) list = list.filter((e) => e.type === type);
        if (outcome) list = list.filter((e) => e.outcome === outcome);
        if (user) list = list.filter((e) => e.actor.id === user || e.target?.id === user);
        if (from) list = list.filter((e) => e.occurredAt >= from);
        const cursor = query.get('cursor');
        const start = cursor ? list.findIndex((e) => e.id === cursor) + 1 : 0;
        const slice = list.slice(start, start + 50);
        const next = start + 50 < list.length ? slice[slice.length - 1]!.id : null;
        return json(route, 200, { events: slice, nextCursor: next });
      }
      const eventPrefix = `/api/v1/tenants/${TENANT}/logs/`;
      if (pathname.startsWith(eventPrefix)) {
        const id = decodeURIComponent(pathname.slice(eventPrefix.length));
        eventReads.push(id);
        if (state.eventAnswer) return state.eventAnswer(route);
        const event = state.events.find((e) => e.id === id);
        if (!event) return problem(route, 404, 'not_found');
        return json(route, 200, opened(event, state.raw));
      }
      return route.fulfill({ status: 404 });
    },
  );

  return { logReads, eventReads, state };
}

/** Axe on the page, with DESIGN.md's one contrast exception, table heads, as admin-tenants.spec.ts runs it. */
async function axe(page: Page) {
  const everything = await new AxeBuilder({ page }).disableRules(['color-contrast']).analyze();
  const contrast = await new AxeBuilder({ page }).withRules(['color-contrast']).exclude('thead th').analyze();
  return [...everything.violations, ...contrast.violations].map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target.join(' ')),
  }));
}

const heading = (page: Page) => page.getByRole('heading', { level: 1 });
const nav = (page: Page) => page.getByRole('navigation', { name: 'Main' });
const table = (page: Page) => page.getByTestId('logs').getByRole('table');
const rows = (page: Page) => table(page).locator('tbody tr');
const field = (page: Page) => page.getByLabel('Search by');
const value = (page: Page) => page.getByTestId('logs-value');
const searchButton = (page: Page) => page.getByRole('button', { name: 'Search' });

async function openLogs(page: Page, path = LOGS) {
  await page.goto(path);
  await expect(heading(page)).toHaveText('Logs');
}

const drawer = (page: Page) => page.getByTestId('log-event');
const isOpen = (page: Page) => drawer(page).evaluate((element) => (element as HTMLDialogElement).open);

test.use({ viewport: { width: 1280, height: 720 } });
watchCsp(test);

test.describe('Logs', () => {
  test('lists the Log newest first with its five columns, then an Event type search keeps field and value in the URL', async ({ page }) => {
    const api = await answerApi(page);
    await openLogs(page);

    await expect(table(page).locator('thead th')).toHaveText(['Time (UTC)', 'Type', 'Description', 'User', 'Application']);
    await expect(rows(page)).toHaveCount(12);
    const first = rows(page).first();
    await expect(first).toContainText('2026-11-06 09:00:12');
    await expect(first.locator('[data-badge="code"]')).toHaveText('sessions.session.started');
    await expect(first.locator('[data-badge="code"]')).toHaveAttribute('data-outcome', 'success');
    await expect(first).toContainText(USER);
    await expect(first).toContainText(CLIENT);
    expect(api.logReads[0]!.toString()).toBe('');
    // No Live view, Log streams, query bar or Location column.
    await expect(page.getByRole('button', { name: /live|log streams/i })).toHaveCount(0);
    await expect(table(page)).not.toContainText('Location');

    await expect(field(page)).toHaveValue('type');
    await value(page).fill(REJECTED);
    await searchButton(page).click();

    await expect(page).toHaveURL(new RegExp(`${LOGS}\\?field=type&value=${REJECTED.replace(/\./g, '\\.')}$`));
    await expect(rows(page)).toHaveCount(2);
    for (const badge of await rows(page).locator('[data-badge="code"]').all()) {
      await expect(badge).toHaveText(REJECTED);
      await expect(badge).toHaveAttribute('data-outcome', 'failure');
    }
    await expect(rows(page).first()).toContainText('2026-11-06 09:00:10');
    expect(api.logReads.at(-1)!.get('type')).toBe(REJECTED);

    expect(await axe(page)).toEqual([]);
  });

  test('a reload and Back restore the search the URL holds', async ({ page }) => {
    const api = await answerApi(page);
    await openLogs(page, `${LOGS}?field=outcome&value=failure`);

    await expect(field(page)).toHaveValue('outcome');
    await expect(value(page)).toHaveValue('failure');
    await expect(rows(page)).toHaveCount(2);
    expect(api.logReads.at(-1)!.get('outcome')).toBe('failure');

    await page.reload();
    await expect(heading(page)).toHaveText('Logs');
    await expect(field(page)).toHaveValue('outcome');
    await expect(value(page)).toHaveValue('failure');
    await expect(rows(page)).toHaveCount(2);

    // A second search, then Back to the first.
    await field(page).selectOption('user');
    await expect(value(page)).toHaveValue('');
    await value(page).fill(USER);
    await searchButton(page).click();
    await expect(page).toHaveURL(new RegExp(`\\?field=user&value=${USER}$`));
    await expect(rows(page)).toHaveCount(10);
    expect(api.logReads.at(-1)!.get('user')).toBe(USER);

    await page.goBack();
    await expect(page).toHaveURL(/\?field=outcome&value=failure$/);
    await expect(field(page)).toHaveValue('outcome');
    await expect(value(page)).toHaveValue('failure');
    await expect(rows(page)).toHaveCount(2);
    expect(api.logReads.at(-1)!.get('outcome')).toBe('failure');
  });

  test('a time range searches from that long ago, and an email is sent as the User', async ({ page }) => {
    const api = await answerApi(page);
    await openLogs(page);

    await field(page).selectOption('range');
    await value(page).selectOption({ label: 'Last 24 hours' });
    const before = Date.now();
    await searchButton(page).click();
    await expect(page).toHaveURL(/\?field=range&value=24h$/);
    await expect.poll(() => api.logReads.at(-1)?.get('from') ?? null).not.toBeNull();
    const from = Date.parse(api.logReads.at(-1)!.get('from')!);
    expect(Math.abs(before - 24 * 60 * 60 * 1000 - from)).toBeLessThan(60_000);

    await field(page).selectOption('user');
    await value(page).fill('a+b@example.test');
    await searchButton(page).click();
    await expect(page).toHaveURL(/\?field=user&value=a%2Bb%40example\.test$/);
    await expect.poll(() => api.logReads.at(-1)?.get('user') ?? null).toBe('a+b@example.test');
  });

  test('Load more reads the next 50 with the cursor until the last page', async ({ page }) => {
    const api = await answerApi(page, { events: events(60) });
    await openLogs(page);

    await expect(rows(page)).toHaveCount(50);
    const more = page.getByTestId('logs-load-more');
    await expect(more).toHaveText('Load more');
    await more.click();

    await expect(rows(page)).toHaveCount(60);
    await expect(more).toHaveCount(0);
    expect(api.logReads.at(-1)!.get('cursor')).toBe(evt(11));
    await expect(rows(page).last()).toContainText('2026-11-06 09:00:01');
  });

  test('a failed Load more keeps the rows and offers Retry, which reads the same cursor and filters', async ({ page }) => {
    const api = await answerApi(page, { events: events(60) });
    await openLogs(page);
    await expect(rows(page)).toHaveCount(50);
    const first = api.logReads.at(-1)!;

    api.state.logsAnswer = (route) => route.fulfill({ status: 503 });
    await page.getByTestId('logs-load-more').click();
    const failed = page.getByTestId('logs-more-failed');
    await expect(failed).toBeVisible();
    await expect(rows(page)).toHaveCount(50);
    await expect(page.getByTestId('logs-load-more')).toHaveCount(0);

    api.state.logsAnswer = null;
    await failed.getByRole('button', { name: 'Retry' }).click();
    await expect(rows(page)).toHaveCount(60);
    await expect(failed).toHaveCount(0);
    const last = api.logReads.at(-1)!;
    expect(last.get('cursor')).toBe(evt(11));
    // The same filters as the first page's read, plus the cursor.
    last.delete('cursor');
    expect(last.toString()).toBe(first.toString());
  });

  test('Search with nothing changed reads the Log again with the same query', async ({ page }) => {
    const api = await answerApi(page);
    await openLogs(page);
    await value(page).fill(REJECTED);
    await searchButton(page).click();
    await expect(rows(page)).toHaveCount(2);
    await expect.poll(() => api.logReads.at(-1)?.get('type') ?? null).toBe(REJECTED);
    const reads = api.logReads.length;

    await searchButton(page).click();
    await expect.poll(() => api.logReads.length).toBe(reads + 1);
    expect(api.logReads.at(-1)!.toString()).toBe(api.logReads.at(-2)!.toString());
    await expect(page).toHaveURL(new RegExp(`${LOGS}\\?field=type&value=${REJECTED.replace(/\./g, '\\.')}$`));
    await expect(rows(page)).toHaveCount(2);
  });

  test('a search that matches nothing shows the empty state', async ({ page }) => {
    await answerApi(page);
    await openLogs(page);

    await value(page).fill('tests.never.written');
    await searchButton(page).click();

    await expect(page.getByText(EMPTY, { exact: true })).toBeVisible();
    await expect(rows(page).locator('[data-badge="code"]')).toHaveCount(0);
    await expect(page.getByTestId('logs-load-more')).toHaveCount(0);
  });

  test('a refused search shows its banner, and a failed read offers Retry', async ({ page }) => {
    const api = await answerApi(page);
    api.state.logsAnswer = (route) => problem(route, 400, 'invalid_request');
    await openLogs(page, `${LOGS}?field=user&value=nope`);

    const invalid = page.getByTestId('logs-invalid');
    await expect(invalid).toContainText("That search isn't valid.");
    await expect(invalid).toContainText('invalid_request');
    await expect(invalid.getByRole('button', { name: 'Retry' })).toHaveCount(0);

    api.state.logsAnswer = (route) => route.fulfill({ status: 503 });
    await value(page).fill(USER);
    await searchButton(page).click();
    const failed = page.getByTestId('logs-load-failed');
    await expect(failed).toBeVisible();

    api.state.logsAnswer = null;
    await failed.getByRole('button', { name: 'Retry' }).click();
    await expect(rows(page)).toHaveCount(10);
  });

  test('the sidebar lists Monitoring, Logs only with tenant.logs.read', async ({ page }) => {
    const api = await answerApi(page);
    await page.goto(`/tenants/${TENANT}/settings`);
    await expect(heading(page)).toHaveText('Tenant settings');
    // The Monitoring group holds it: the sidebar opens only the current page's group.
    await nav(page).getByRole('button', { name: 'Monitoring' }).click();
    const link = nav(page).getByRole('link', { name: 'Logs' });
    await expect(link).toHaveAttribute('href', LOGS);

    api.state.tenantCapabilities = ['tenant.configuration.read'];
    await page.reload();
    await expect(heading(page)).toHaveText('Tenant settings');
    await expect(nav(page).getByRole('link', { name: 'Tenant' })).toBeVisible();
    await expect(nav(page).getByRole('button', { name: 'Monitoring' })).toHaveCount(0);
    await expect(nav(page).getByRole('link', { name: 'Logs' })).toHaveCount(0);

    // Typed in, the page is forbidden and reads nothing.
    const reads = api.logReads.length;
    await page.goto(LOGS);
    await expect(page.getByTestId('forbidden')).toBeVisible();
    expect(api.logReads.length).toBe(reads);
  });

  test("an Editor's row opens the drawer: code badge, summary rows, the raw JSON and a Copy JSON that copies it", async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const api = await answerApi(page, { raw: true });
    await openLogs(page);
    const event = api.state.events[0]!;

    // A click anywhere on the row opens it.
    await rows(page).first().locator('td').first().click();
    await expect.poll(() => isOpen(page)).toBe(true);
    expect(api.eventReads).toEqual([event.id]);
    await expect(rows(page).first()).toHaveAttribute('aria-current', 'true');

    const badge = drawer(page).getByRole('heading', { level: 2 }).locator('[data-badge="code"]');
    await expect(badge).toHaveText(event.type);
    await expect(badge).toHaveAttribute('data-outcome', 'success');
    await expect(drawer(page).getByRole('heading', { level: 2 })).toContainText(event.summary);
    await expect(drawer(page).locator('dl dt')).toHaveText(['Time (UTC)', 'Actor', 'Target', 'User', 'Application', 'IP address', 'User-Agent', 'Email']);
    await expect(drawer(page).locator('dl dd')).toHaveText([
      '2026-11-06 09:00:12',
      `user ${USER}`,
      `client ${CLIENT}`,
      USER,
      CLIENT,
      DETAIL.ipAddress,
      DETAIL.userAgent,
      DETAIL.email,
    ]);

    const viewer = drawer(page).getByRole('region', { name: 'Raw event' });
    await expect(viewer).toContainText(HASH);
    await expect(viewer).toContainText(DETAIL.email);
    await expect(drawer(page).getByText(LIMITED)).toHaveCount(0);

    await drawer(page).getByRole('button', { name: 'Copy JSON' }).click();
    await expect(drawer(page).getByRole('button', { name: 'Copied JSON' })).toBeVisible();
    const copied = JSON.parse(await page.evaluate(() => navigator.clipboard.readText()));
    expect(copied).toEqual(opened(event, true).raw);

    // The drawer isn't kept in the URL.
    await expect(page).toHaveURL(new RegExp(`${LOGS}$`));
    expect(await axe(page)).toEqual([]);
  });

  test('a Viewer sees the badge, the summary rows and the limited note, and no raw section', async ({ page }) => {
    const api = await answerApi(page, { raw: false });
    await openLogs(page);

    await rows(page).first().locator('td').first().click();
    await expect.poll(() => isOpen(page)).toBe(true);
    await expect(drawer(page).getByText(LIMITED)).toBeVisible();
    await expect(drawer(page).locator('[data-badge="code"]')).toHaveText(api.state.events[0]!.type);
    await expect(drawer(page).locator('dl dt')).toHaveText(['Time (UTC)', 'Actor', 'Target', 'User', 'Application']);
    await expect(drawer(page).locator('[data-event-raw]')).toHaveCount(0);
    await expect(drawer(page).getByRole('button', { name: /JSON/ })).toHaveCount(0);
    const html = await page.evaluate(() => document.documentElement.outerHTML);
    expect(html).not.toContain(HASH);
    expect(html).not.toContain(DETAIL.ipAddress);
  });

  test('Esc closes the drawer, and Close does too', async ({ page }) => {
    await answerApi(page, { raw: true });
    await openLogs(page);

    await rows(page).first().locator('td').first().click();
    await expect.poll(() => isOpen(page)).toBe(true);
    await expect(drawer(page).locator('[data-event-raw]')).toHaveCount(1);
    await page.keyboard.press('Escape');
    await expect.poll(() => isOpen(page)).toBe(false);
    await expect(rows(page).first()).not.toHaveAttribute('aria-current', 'true');

    await rows(page).nth(1).locator('td').first().click();
    await expect.poll(() => isOpen(page)).toBe(true);
    await drawer(page).getByRole('button', { name: 'Close' }).click();
    await expect.poll(() => isOpen(page)).toBe(false);
  });

  test('a failed read shows a banner with Retry, which reads again; a missing event offers no Retry', async ({ page }) => {
    const api = await answerApi(page, { raw: true });
    api.state.eventAnswer = (route) => route.fulfill({ status: 503 });
    await openLogs(page);

    await rows(page).first().locator('td').first().click();
    const failed = drawer(page).getByTestId('log-event-failed');
    await expect(failed).toContainText("We couldn't load this event.");
    await expect(drawer(page).locator('[data-event-raw]')).toHaveCount(0);
    await expect(drawer(page).getByText(LIMITED)).toHaveCount(0);
    expect(api.eventReads).toHaveLength(1);

    api.state.eventAnswer = null;
    await failed.getByRole('button', { name: 'Retry' }).click();
    await expect(drawer(page).locator('[data-event-raw]')).toHaveCount(1);
    await expect(failed).toHaveCount(0);
    expect(api.eventReads).toEqual([api.state.events[0]!.id, api.state.events[0]!.id]);

    await page.keyboard.press('Escape');
    await expect.poll(() => isOpen(page)).toBe(false);
    api.state.eventAnswer = (route) => problem(route, 404, 'not_found');
    await rows(page).nth(1).locator('td').first().click();
    const missing = drawer(page).getByTestId('log-event-not-found');
    await expect(missing).toContainText('not_found');
    await expect(missing.getByRole('button', { name: 'Retry' })).toHaveCount(0);
  });

  test("the keyboard opens a row from its Description link", async ({ page }) => {
    const api = await answerApi(page, { raw: false });
    await openLogs(page);
    const event = api.state.events[2]!;

    const link = rows(page).nth(2).locator('[data-gk-row-link]');
    await expect(link).toHaveText(event.summary);
    await link.focus();
    await page.keyboard.press('Enter');
    await expect.poll(() => isOpen(page)).toBe(true);
    expect(api.eventReads).toEqual([event.id]);
    await expect(drawer(page).getByText(LIMITED)).toBeVisible();

    // Closed, focus goes back to the row's link.
    await page.keyboard.press('Escape');
    await expect.poll(() => isOpen(page)).toBe(false);
    await expect(link).toBeFocused();
  });
});

// Story 7.7: the Deployment Log, the same page for the Deployment Owner at /deployment/logs. Its
// search is by Admin and Tenant in place of User and Application, and its drawer always has the
// raw JSON. The server's search and its refusals are tests/Isolation/Audit/DeploymentLogTests.cs's.
const DEPLOYMENT_LOGS = '/deployment/logs';
const DEPLOYMENT_LOG_API = '/api/v1/deployment/logs';
const OWNER_ID = '01900000-0000-7000-8000-000000000777';
const OTHER_TENANT = `ten_${'b'.repeat(25)}a`;

/** The Deployment Log as bootstrap leaves it, newest first, after two Tenants were created. */
function deploymentEvents(): LogEvent[] {
  const at = (n: number) => new Date(Date.UTC(2026, 10, 14, 8, 0, n)).toISOString();
  const owner = { kind: 'admin', id: OWNER_ID };
  const created = 'A Deployment Owner created a Tenant.';
  return [
    { id: evt(7), occurredAt: at(7), type: 'tenancy.tenant.created', outcome: 'success', summary: created, actor: owner, target: { kind: 'tenant', id: OTHER_TENANT } },
    { id: evt(6), occurredAt: at(6), type: 'tenancy.tenant.created', outcome: 'success', summary: created, actor: owner, target: { kind: 'tenant', id: TENANT } },
    { id: evt(5), occurredAt: at(5), type: 'admin.signin.succeeded', outcome: 'success', summary: 'An Admin signed in.', actor: owner, target: owner },
    { id: evt(4), occurredAt: at(4), type: 'admin.setup.completed', outcome: 'success', summary: 'An Admin completed setup.', actor: owner, target: owner },
    { id: evt(3), occurredAt: at(3), type: 'admin.credential.registered', outcome: 'success', summary: 'An Admin registered a credential.', actor: owner, target: owner },
    { id: evt(2), occurredAt: at(2), type: 'bootstrap.admin.created', outcome: 'success', summary: 'The bootstrap token was claimed.', actor: owner, target: owner },
    { id: evt(1), occurredAt: at(1), type: 'bootstrap.token.issued', outcome: 'success', summary: 'The first bootstrap token was issued.', actor: { kind: 'system', id: null }, target: null },
  ];
}

/** The Admin API for an Admin holding `capabilities`, the Deployment Owner's unless said: the Deployment Log holds `deploymentEvents()`. */
async function answerDeploymentApi(page: Page, capabilities: string[] = ['deployment.tenants.read', 'deployment.log.read']) {
  const logReads: URLSearchParams[] = [];
  const eventReads: string[] = [];
  const list = deploymentEvents();

  await page.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const url = new URL(route.request().url());
      const { pathname } = url;
      if (pathname === SESSION) {
        return json(route, 200, {
          adminId: OWNER_ID,
          kind: 'full',
          deploymentOwner: capabilities.includes('deployment.log.read'),
          setupComplete: true,
          credentials: 2,
          recoveryCodeAllowed: false,
          csrfToken: CSRF,
        });
      }
      if (pathname === CAPABILITIES) return json(route, 200, { capabilities });
      if (pathname === MY_TENANTS) return json(route, 200, { tenants: [] });
      if (pathname === '/api/v1/deployment/tenants') return json(route, 200, { tenantZone: ZONE, tenants: [], nextCursor: null });
      if (pathname === DEPLOYMENT_LOG_API) {
        const query = url.searchParams;
        logReads.push(query);
        let found = list;
        const type = query.get('type');
        const admin = query.get('admin');
        const tenant = query.get('tenant');
        if (type) found = found.filter((e) => e.type === type);
        if (admin) found = found.filter((e) => e.actor.id === admin || e.target?.id === admin);
        if (tenant) found = found.filter((e) => e.target?.kind === 'tenant' && e.target.id === tenant);
        return json(route, 200, { events: found, nextCursor: null });
      }
      if (pathname.startsWith(`${DEPLOYMENT_LOG_API}/`)) {
        const id = decodeURIComponent(pathname.slice(DEPLOYMENT_LOG_API.length + 1));
        eventReads.push(id);
        const event = list.find((e) => e.id === id);
        if (!event) return problem(route, 404, 'not_found');
        return json(route, 200, opened(event, true));
      }
      return route.fulfill({ status: 404 });
    },
  );

  return { logReads, eventReads, list };
}

test.describe('Deployment Log', () => {
  test('lists the bootstrap events newest first with its own columns, and a Tenant search keeps field and value in the URL', async ({ page }) => {
    const api = await answerDeploymentApi(page);
    await page.goto(DEPLOYMENT_LOGS);
    await expect(heading(page)).toHaveText('Log');
    await expect(page.getByTestId('deployment-logs-page')).toBeVisible();

    await expect(table(page).locator('thead th')).toHaveText(['Time (UTC)', 'Type', 'Description', 'Admin', 'Tenant']);
    await expect(rows(page)).toHaveCount(7);
    await expect(rows(page).first()).toContainText('2026-11-14 08:00:07');
    await expect(rows(page).first()).toContainText(OWNER_ID);
    await expect(rows(page).first()).toContainText(OTHER_TENANT);
    await expect(rows(page).last().locator('[data-badge="code"]')).toHaveText('bootstrap.token.issued');
    expect(api.logReads[0]!.toString()).toBe('');

    // Its fields: Admin and Tenant in place of User and Application.
    await expect(field(page).locator('option')).toHaveText(['Event type', 'Admin', 'Tenant', 'Outcome', 'Time range']);
    await field(page).selectOption('tenant');
    await value(page).fill(TENANT);
    await searchButton(page).click();

    await expect(page).toHaveURL(new RegExp(`${DEPLOYMENT_LOGS}\\?field=tenant&value=${TENANT}$`));
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page).first()).toContainText(TENANT);
    expect(api.logReads.at(-1)!.get('tenant')).toBe(TENANT);
    expect(api.logReads.at(-1)!.has('user')).toBe(false);

    // A reload restores it.
    await page.reload();
    await expect(field(page)).toHaveValue('tenant');
    await expect(value(page)).toHaveValue(TENANT);
    await expect(rows(page)).toHaveCount(1);

    // An Admin search goes out as admin.
    await field(page).selectOption('admin');
    await value(page).fill(OWNER_ID);
    await searchButton(page).click();
    await expect(rows(page)).toHaveCount(6);
    expect(api.logReads.at(-1)!.get('admin')).toBe(OWNER_ID);

    expect(await axe(page)).toEqual([]);
  });

  test('a row opens the drawer with its summary rows and the raw JSON', async ({ page }) => {
    const api = await answerDeploymentApi(page);
    await page.goto(DEPLOYMENT_LOGS);
    await expect(rows(page)).toHaveCount(7);
    const event = api.list[1]!;

    await rows(page).nth(1).locator('td').first().click();
    await expect.poll(() => isOpen(page)).toBe(true);
    expect(api.eventReads).toEqual([event.id]);
    await expect(drawer(page).getByRole('heading', { level: 2 }).locator('[data-badge="code"]')).toHaveText(event.type);
    await expect(drawer(page).locator('dl dt')).toHaveText(['Time (UTC)', 'Actor', 'Target', 'IP address', 'User-Agent', 'Email']);
    await expect(drawer(page).locator('dl dd')).toHaveText([
      '2026-11-14 08:00:06',
      `admin ${OWNER_ID}`,
      `tenant ${TENANT}`,
      DETAIL.ipAddress,
      DETAIL.userAgent,
      DETAIL.email,
    ]);
    const viewer = drawer(page).getByRole('region', { name: 'Raw event' });
    await expect(viewer).toContainText(HASH);
    await expect(drawer(page).getByRole('button', { name: 'Copy JSON' })).toBeVisible();
    await expect(drawer(page).getByText(LIMITED)).toHaveCount(0);

    await page.keyboard.press('Escape');
    await expect.poll(() => isOpen(page)).toBe(false);
    await expect(page).toHaveURL(new RegExp(`${DEPLOYMENT_LOGS}$`));
  });

  test('the Deployment group lists Log only with deployment.log.read, and the page is otherwise forbidden', async ({ page }) => {
    const api = await answerDeploymentApi(page);
    await page.goto(DEPLOYMENT_LOGS);
    await expect(heading(page)).toHaveText('Log');
    const link = nav(page).getByRole('link', { name: 'Log', exact: true });
    await expect(link).toHaveAttribute('href', DEPLOYMENT_LOGS);
    await expect(link).toHaveAttribute('aria-current', 'page');

    await page.unrouteAll({ behavior: 'wait' });
    const without = await answerDeploymentApi(page, ['deployment.tenants.read']);
    await page.goto('/deployment/tenants');
    await expect(heading(page)).toHaveText('Tenants');
    await expect(nav(page).getByRole('link', { name: 'Tenants', exact: true })).toBeVisible();
    await expect(nav(page).getByRole('link', { name: 'Log', exact: true })).toHaveCount(0);

    // Typed in, the page is forbidden and reads nothing.
    await page.goto(DEPLOYMENT_LOGS);
    await expect(page.getByTestId('forbidden')).toBeVisible();
    expect(without.logReads).toHaveLength(0);
    expect(api.logReads.length).toBeGreaterThan(0);
  });
});
