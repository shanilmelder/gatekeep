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
 * Drops the page's query from the address bar and its history entry, without a request (Story 4.7): a verification link's
 * token is in its URL, and once its page is shown the token has no further use there.
 */
export function forgetQuery(): void {
  if (window.location.search === '') return;
  window.history.replaceState(null, '', window.location.pathname);
}
