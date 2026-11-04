// Story 1.25: one CSP watch for every test in a spec. Called at the top of a spec, it reports,
// from document creation on and across every navigation, each securitypolicyviolation, each
// console CSP message and each request to another origin, and fails the test after it runs if
// there was any. Not a spec itself, so no project runs it on its own.

import { expect, test as base, type Page } from '@playwright/test';

interface Seen {
  violations: string[];
  console: string[];
  elsewhere: string[];
}

const seen = new WeakMap<Page, Seen>();

export function watchCsp(test: typeof base): void {
  test.beforeEach(async ({ page, baseURL }) => {
    const record: Seen = { violations: [], console: [], elsewhere: [] };
    seen.set(page, record);
    const origin = baseURL ? new URL(baseURL).origin : null;
    page.on('console', (message) => {
      if (/content security policy|refused to/i.test(message.text())) record.console.push(message.text());
    });
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (origin && url.protocol.startsWith('http') && url.origin !== origin) record.elsewhere.push(request.url());
    });
    // A binding outlives every navigation, so a violation in a document since replaced counts too.
    await page.exposeBinding('__gkReportViolation', (_source, text: string) => {
      record.violations.push(text);
    });
    await page.addInitScript(() => {
      document.addEventListener('securitypolicyviolation', (event) => {
        void (window as unknown as { __gkReportViolation: (text: string) => Promise<void> }).__gkReportViolation(
          `${event.effectiveDirective} ${event.blockedURI}`,
        );
      });
    });
  });

  test.afterEach(async ({ page }) => {
    const record = seen.get(page);
    if (!record) return;
    expect(record.violations, 'CSP violations').toEqual([]);
    expect(record.console, 'console CSP messages').toEqual([]);
    expect(record.elsewhere, 'requests to another origin').toEqual([]);
  });
}
