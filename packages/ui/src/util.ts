import type { Ref, RefCallback } from 'react';

/** `data-gk-surface` values: Admin Dashboard or Hosted Login sizing (AD-22). */
export type Surface = 'admin' | 'hosted';

/** Joins class names, skipping the empty ones. */
export function cx(...names: (string | false | null | undefined)[]): string {
  return names.filter(Boolean).join(' ');
}

/** Joins space-separated id lists such as aria-describedby, or undefined when empty. */
export function joinIds(...ids: (string | false | null | undefined)[]): string | undefined {
  const joined = ids.filter(Boolean).join(' ');
  return joined === '' ? undefined : joined;
}

/**
 * One ref callback that sets every ref given. It returns React 19's cleanup: each callback
 * ref's own cleanup when it returns one, or a call with null when it doesn't, and object
 * refs reset to null. Memoise the result, or React detaches and reattaches every render.
 */
export function mergeRefs<T>(...refs: (Ref<T> | undefined)[]): RefCallback<T> {
  return (value) => {
    const cleanups: (() => void)[] = [];
    for (const ref of refs) {
      if (typeof ref === 'function') {
        const cleanup = ref(value);
        cleanups.push(typeof cleanup === 'function' ? cleanup : () => ref(null));
      } else if (ref) {
        ref.current = value;
        cleanups.push(() => {
          ref.current = null;
        });
      }
    }
    return () => cleanups.forEach((cleanup) => cleanup());
  };
}
