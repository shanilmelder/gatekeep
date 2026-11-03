import type { ReactNode } from 'react';
import { cx } from '../util';
import styles from './HostedPage.module.css';

/** `data-gk-scheme` values: `auto` follows the device (prefers-color-scheme), with no script. */
export type HostedScheme = 'auto' | 'light' | 'dark';

export interface HostedPageProps {
  /**
   * The colour scheme. Hosted Login follows the device, so `auto` is the default and there is
   * no toggle (DESIGN.md, Tenant theme contract). A caller such as the theme preview forces
   * `light` or `dark`.
   */
  scheme?: HostedScheme;
  /**
   * The theme scope, set as `data-gk-theme`: a Tenant theme is a stylesheet that overrides
   * tokens under it (Story 15.1). The default theme otherwise.
   */
  theme?: string;
  /** One screen: a HostedCard. */
  children?: ReactNode;
  className?: string;
  'data-testid'?: string;
}

/**
 * The Hosted Login page frame: the Hosted surface and scheme, and a `main` landmark centring
 * one card on `bg`. The page is at least the window's height, so a tall card, or text at
 * 200%, makes the page scroll and nothing is clipped. Screens don't include it, so a preview
 * can place a screen in a frame of its own.
 *
 * The app's `<html>` must carry `data-gk-surface="hosted"` and the same `data-gk-scheme`
 * (Hosted Login's index.html, served by Story 4.1). This frame sets them for its own subtree,
 * but the canvas behind it, overscroll and the scrollbars take `<html>`'s scheme and surface.
 */
export function HostedPage({ scheme = 'auto', theme, children, className, 'data-testid': testId }: HostedPageProps) {
  return (
    <div
      className={cx(styles.page, className)}
      data-gk-surface="hosted"
      data-gk-scheme={scheme}
      data-gk-theme={theme}
      data-testid={testId}
    >
      <main className={styles.main}>{children}</main>
    </div>
  );
}
