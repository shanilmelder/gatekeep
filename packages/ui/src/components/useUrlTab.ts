import { useCallback, useEffect, useRef, useState } from 'react';

// pushState fires no event, so the hook announces its own changes to every other instance.
const CHANGE = 'gk-url-tab';

export interface UrlTabOptions {
  /**
   * Asked before Back or Forward changes the value, with the value the URL now holds. When
   * it returns or resolves to false, or throws, the value stays and the URL is put back to
   * it with a new history entry, so the tab and the URL never disagree.
   */
  canChange?: (to: string | null) => boolean | Promise<boolean>;
}

function read(param: string | null): string | null {
  if (param === null || typeof window === 'undefined') return null;
  return new URLSearchParams(window.location.search).get(param);
}

function urlWith(param: string, value: string | null): URL {
  const url = new URL(window.location.href);
  if (value === null) url.searchParams.delete(param);
  else url.searchParams.set(param, value);
  return url;
}

/** Runs a guard, treating a throw or a rejection as a refusal. */
export async function allowed(guard: (() => boolean | Promise<boolean>) | undefined): Promise<boolean> {
  if (!guard) return true;
  try {
    return (await guard()) !== false;
  } catch {
    return false;
  }
}

/**
 * A tab selection kept in the URL's query string under `param`, with the History API only:
 * no router. Selecting pushes a history entry, so Back and Forward restore the tab, and a
 * shared or reloaded URL opens on it. Other query parameters and the hash are kept.
 *
 * Returns the selected id (null when the URL has none) and the function that selects one.
 * Pass `param: null` to keep nothing in the URL: the value is then always null.
 */
export function useUrlTab(param: string | null, options: UrlTabOptions = {}): [string | null, (id: string) => void] {
  const [value, setValue] = useState(() => read(param));
  const valueRef = useRef(value);
  valueRef.current = value;
  const guardRef = useRef(options.canChange);
  guardRef.current = options.canChange;

  useEffect(() => {
    if (param === null) return;
    setValue(read(param));
    let live = true;

    async function onPopState() {
      const to = read(param);
      if (to === valueRef.current) return;
      const href = window.location.href;
      const guard = guardRef.current;
      const ok = await allowed(guard && (() => guard(to)));
      // Another navigation since then decides instead.
      if (!live || window.location.href !== href) return;
      if (ok) setValue(to);
      else window.history.pushState(window.history.state, '', urlWith(param!, valueRef.current));
    }
    const onChange = () => setValue(read(param));

    window.addEventListener('popstate', onPopState);
    window.addEventListener(CHANGE, onChange);
    return () => {
      live = false;
      window.removeEventListener('popstate', onPopState);
      window.removeEventListener(CHANGE, onChange);
    };
  }, [param]);

  const select = useCallback(
    (id: string) => {
      if (param === null) return;
      if (read(param) !== id) window.history.pushState(window.history.state, '', urlWith(param, id));
      setValue(id);
      window.dispatchEvent(new Event(CHANGE));
    },
    [param],
  );

  return [value, select];
}
