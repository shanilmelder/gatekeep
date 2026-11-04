// The Admin Dashboard's colour scheme (DESIGN.md: a manual toggle on the Admin Dashboard, the
// device's scheme on Hosted Login). index.html starts <html> on `auto`, so CSS follows the
// device before any script runs. Shell routes then take the Admin's stored choice, `light` or
// `dark`, or stay `auto`; the pre-Session cards always follow the device, as HostedPage's own
// `auto` scope does, so the canvas and the card agree.
//
// The choice is the only thing the dashboard ever writes to web storage. Storage that throws
// (a private window, blocked site data) leaves the choice in memory for this page.

import { useMediaQuery } from '@gatekeep/ui/admin';
import { useCallback, useState } from 'react';

export type SchemeChoice = 'light' | 'dark';

export const SCHEME_KEY = 'gatekeep.admin.scheme';

// The choice made on this page, once there is one: it wins over storage that may refuse it.
let remembered: SchemeChoice | null = null;

export function storedScheme(): SchemeChoice | null {
  if (remembered) return remembered;
  try {
    const value = window.localStorage.getItem(SCHEME_KEY);
    return value === 'light' || value === 'dark' ? value : null;
  } catch {
    return null;
  }
}

function store(choice: SchemeChoice) {
  remembered = choice;
  try {
    window.localStorage.setItem(SCHEME_KEY, choice);
  } catch {
    // In memory only: the toggle still switches this page.
  }
}

/** `<html>` for a shell route: the stored choice, or the device's. */
export function applyShellScheme(): void {
  document.documentElement.dataset.gkScheme = storedScheme() ?? 'auto';
}

/** `<html>` for a pre-Session card: always the device's. */
export function applyPreSessionScheme(): void {
  document.documentElement.dataset.gkScheme = 'auto';
}

/** Whether the shell is dark now, chosen or from the device, and the toggle that flips it. */
export function useScheme(): { dark: boolean; toggle: () => void } {
  const deviceDark = useMediaQuery('(prefers-color-scheme: dark)');
  const [choice, setChoice] = useState<SchemeChoice | null>(storedScheme);
  const dark = choice ? choice === 'dark' : deviceDark;
  const toggle = useCallback(() => {
    const next: SchemeChoice = dark ? 'light' : 'dark';
    store(next);
    setChoice(next);
    document.documentElement.dataset.gkScheme = next;
  }, [dark]);
  return { dark, toggle };
}
