// The dashboard's own paths, without a router library: the History API and one event. A
// navigation in the page keeps what is in memory, such as the CSRF token.

import { useEffect, useState } from 'react';

const EVENT = 'gk:navigate';

export function navigate(path: string): void {
  window.history.pushState(null, '', path);
  window.dispatchEvent(new Event(EVENT));
}

/** The current path, without a trailing slash but for the root. */
export function usePath(): string {
  const [path, setPath] = useState(current);
  useEffect(() => {
    const update = () => setPath(current());
    window.addEventListener('popstate', update);
    window.addEventListener(EVENT, update);
    return () => {
      window.removeEventListener('popstate', update);
      window.removeEventListener(EVENT, update);
    };
  }, []);
  return path;
}

function current(): string {
  const path = window.location.pathname;
  return path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
}
