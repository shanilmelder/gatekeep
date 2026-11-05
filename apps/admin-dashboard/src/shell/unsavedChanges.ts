// Unsaved changes (Story 1.28): a page says it holds some, and the Tenant switcher asks before a
// switch would discard them. Only the shell reads it; nothing is stored.

import { createContext, createElement, useContext, useEffect, useRef, type MutableRefObject, type ReactNode } from 'react';

type Registry = MutableRefObject<Set<symbol>>;

const UnsavedContext = createContext<Registry | null>(null);

/** The shell's registry of pages holding unsaved changes, and whether any does now. */
export function useUnsavedRegistry(): { registry: Registry; any: () => boolean } {
  const registry = useRef(new Set<symbol>());
  return { registry, any: () => registry.current.size > 0 };
}

export function UnsavedChangesProvider({ registry, children }: { registry: Registry; children?: ReactNode }) {
  return createElement(UnsavedContext.Provider, { value: registry }, children);
}

/** Registers the calling page as holding unsaved changes while `dirty` is true, and until it unmounts. */
export function useUnsavedChanges(dirty: boolean): void {
  const registry = useContext(UnsavedContext);
  const id = useRef(Symbol('unsaved'));
  useEffect(() => {
    if (!registry || !dirty) return;
    const key = id.current;
    registry.current.add(key);
    return () => {
      registry.current.delete(key);
    };
  }, [registry, dirty]);
}
