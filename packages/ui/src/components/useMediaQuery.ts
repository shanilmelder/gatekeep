import { useCallback, useSyncExternalStore } from 'react';

/** The Admin shell's one breakpoint: the full sidebar at this width and wider, the icon rail below. */
export const ADMIN_WIDE_QUERY = '(min-width: 1100px)';

/**
 * Whether `query` matches now, re-rendering when that changes. It reads `matchMedia` during
 * render through `useSyncExternalStore`, so the first render is already right, with no frame
 * where a CSS media query and this disagree. Without `matchMedia` it is false.
 */
export function useMediaQuery(query: string): boolean {
  const subscribe = useCallback(
    (onChange: () => void) => {
      if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return () => {};
      const list = window.matchMedia(query);
      list.addEventListener('change', onChange);
      return () => list.removeEventListener('change', onChange);
    },
    [query],
  );
  const snapshot = () => typeof window !== 'undefined' && typeof window.matchMedia === 'function' && window.matchMedia(query).matches;
  return useSyncExternalStore(subscribe, snapshot, () => false);
}
