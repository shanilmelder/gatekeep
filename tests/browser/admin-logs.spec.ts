// Story 7.4: a Tenant's Logs in the built Admin Dashboard served by the built Host.Admin
// (admin-host.mjs) under its real CSP, from localhost. The Admin API is answered by route
// interception: the field search, its URL, Load more, the empty state, a refused search and the
// sidebar item. The URL-to-query mapping is apps/admin-dashboard/test/logs.test.mjs's; the
// server's search and its Tenant isolation are tests/Isolation/Audit/TenantLogSearchTests.cs's.

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
}

interface Api {
  /** Each Log read's query string, as sent. */
  logReads: URLSearchParams[];
  state: State;
}

/** The Admin API for a Viewer of TENANT: the Log holds `state.events`, 50 a page, filtered as the server filters. */
async function answerApi(page: Page, initial: Partial<State> = {}): Promise<Api> {
  const logReads: URLSearchParams[] = [];
  const state: State = { tenantCapabilities: VIEWER, events: events(12), logsAnswer: null, ...initial };

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
      return route.fulfill({ status: 404 });
    },
  );

  return { logReads, state };
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
});
