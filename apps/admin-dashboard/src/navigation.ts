// The dashboard's own paths, without a router library: the History API and one event. A
// navigation in the page keeps what is in memory, such as the CSRF token.

import { useEffect, useState } from 'react';

const EVENT = 'gk:navigate';

/** Whether the navigation being dispatched replaces the current entry: read while it is dispatched. */
let replacing = false;

/** An in-page navigation to `path`. With `replace`, it takes the current entry's place in the history, as a redirect does. */
export function navigate(path: string, { replace = false }: { replace?: boolean } = {}): void {
  if (replace) window.history.replaceState(null, '', path);
  else window.history.pushState(null, '', path);
  replacing = replace;
  try {
    window.dispatchEvent(new Event(EVENT));
  } finally {
    replacing = false;
  }
}

/**
 * Where the page is, and a key that changes on every navigation, to the same path or not, and
 * whether that navigation replaced the entry, as a redirect does (Story 1.29), rather than being
 * the Admin's own: a link, the brand, a sidebar item, back or forward.
 */
export interface Location {
  path: string;
  key: number;
  replaced: boolean;
}

/**
 * The current path and a navigation key. The key changes on every in-page navigation (a link,
 * the brand, a sidebar item, the browser's back or forward), even one to the path already shown,
 * so the shell reads its capabilities again each time.
 */
export function useLocation(): Location {
  const [location, setLocation] = useState<Location>(() => ({ path: current(), key: 0, replaced: false }));
  useEffect(() => {
    const update = (replaced: boolean) => () => setLocation((previous) => ({ path: current(), key: previous.key + 1, replaced }));
    const onPop = update(false);
    const onNavigate = () => update(replacing)();
    window.addEventListener('popstate', onPop);
    window.addEventListener(EVENT, onNavigate);
    return () => {
      window.removeEventListener('popstate', onPop);
      window.removeEventListener(EVENT, onNavigate);
    };
  }, []);
  return location;
}

/** The current path, without a trailing slash but for the root. */
export function usePath(): string {
  return useLocation().path;
}

function current(): string {
  const path = window.location.pathname;
  return path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
}
