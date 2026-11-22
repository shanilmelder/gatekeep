// Hosted Login's only navigation (Story 4.2): a top-level GET, never a form post, to a path on this
// origin. A redirect step's location goes back to the authorization endpoint; an expired sign-in goes
// to /login, which restarts it with the email kept.

import { isSameOriginPath } from './step';

/** Where an expired sign-in goes. */
export const LOGIN_PATH = '/login';

/**
 * Opens `path` with a top-level GET, when it is a path on this origin: it passes the step reader's check and,
 * resolved against the page, keeps the page's origin. Anything else is ignored.
 */
export function go(path: string): void {
  if (!isSameOriginPath(path)) return;
  const origin = window.location.origin;
  let target: URL;
  try {
    target = new URL(path, origin);
  } catch {
    return;
  }
  if (target.origin === origin) window.location.assign(target.href);
}

/**
 * The page's one non-empty `token` query value, or null (Story 4.11): a reset link's page keeps it in memory for Reset
 * password, read before `forgetQuery` drops it from the address bar. It is never stored.
 */
export function queryToken(): string | null {
  const values = new URLSearchParams(window.location.search).getAll('token');
  return values.length === 1 && values[0] !== '' ? values[0]! : null;
}

/**
 * Drops the page's query from the address bar and its history entry, without a request (Story 4.7): a verification link's
 * token is in its URL, and once its page is shown the token has no further use there.
 */
export function forgetQuery(): void {
  if (window.location.search === '') return;
  window.history.replaceState(null, '', window.location.pathname);
}
