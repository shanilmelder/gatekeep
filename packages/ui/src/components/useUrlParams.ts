import { useCallback, useEffect, useRef, useState } from 'react';

// pushState fires no event, so the hook announces its own changes to every other instance.
const CHANGE = 'gk-url-params';

export type UrlParams<N extends string> = Readonly<Record<N, string | null>>;

function read<N extends string>(names: readonly N[]): UrlParams<N> {
  const search = typeof window === 'undefined' ? new URLSearchParams() : new URLSearchParams(window.location.search);
  return Object.fromEntries(names.map((name) => [name, search.get(name)])) as Record<N, string | null>;
}

function same<N extends string>(names: readonly N[], a: UrlParams<N>, b: UrlParams<N>): boolean {
  return names.every((name) => a[name] === b[name]);
}

/**
 * Several values kept together in the URL's query string, such as a field search's field and
 * value (Story 7.4), with the History API only: no router. Setting them pushes one history entry
 * for all of them, so Back and Forward restore them together, and a shared or reloaded URL opens
 * on them. A null value removes its parameter; other query parameters and the hash are kept.
 * The sibling of `useUrlTab`, which keeps one.
 *
 * Returns the values (null for each the URL lacks) and the function that sets them.
 */
export function useUrlParams<N extends string>(names: readonly N[]): [UrlParams<N>, (values: Partial<Record<N, string | null>>) => void] {
  const key = names.join('\u0000');
  const namesRef = useRef(names);
  namesRef.current = names;
  const [values, setValues] = useState<UrlParams<N>>(() => read(names));

  useEffect(() => {
    const update = () =>
      setValues((current) => {
        const next = read(namesRef.current);
        return same(namesRef.current, current, next) ? current : next;
      });
    update();
    window.addEventListener('popstate', update);
    window.addEventListener(CHANGE, update);
    return () => {
      window.removeEventListener('popstate', update);
      window.removeEventListener(CHANGE, update);
    };
  }, [key]);

  const set = useCallback(
    (changes: Partial<Record<N, string | null>>) => {
      const url = new URL(window.location.href);
      for (const name of namesRef.current) {
        if (!(name in changes)) continue;
        const value = changes[name];
        if (value === null || value === undefined) url.searchParams.delete(name);
        else url.searchParams.set(name, value);
      }
      if (url.href !== window.location.href) window.history.pushState(window.history.state, '', url);
      // The other instances, and this one, read the URL again.
      window.dispatchEvent(new Event(CHANGE));
    },
    [key],
  );

  return [values, set];
}
