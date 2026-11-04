// The dashboard's own paths, without a router library: the History API and one event. A
// navigation in the page keeps what is in memory, such as the CSRF token.

import { useEffect, useState } from 'react';

const EVENT = 'gk:navigate';

/** An in-page navigation to `path`. With `replace`, it takes the current entry's place in the history, as a redirect does. */
export function navigate(path: string, { replace = false }: { replace?: boolean } = {}): void {
  if (replace) window.history.replaceState(null, '', path);
  else window.history.pushState(null, '', path);
  window.dispatchEvent(new Event(EVENT));
}

/** Where the page is, and a key that changes on every navigation, to the same path or not. */
export interface Location {
  path: string;
  key: number;
}

/**
 * The current path and a navigation key. The key changes on every in-page navigation (a link,
 * the brand, a sidebar item, the browser's back or forward), even one to the path already shown,
 * so the shell reads its capabilities again each time.
 */
export function useLocation(): Location {
  const [location, setLocation] = useState<Location>(() => ({ path: current(), key: 0 }));
  useEffect(() => {
    const update = () => setLocation((previous) => ({ path: current(), key: previous.key + 1 }));
    window.addEventListener('popstate', update);
    window.addEventListener(EVENT, update);
    return () => {
      window.removeEventListener('popstate', update);
      window.removeEventListener(EVENT, update);
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
