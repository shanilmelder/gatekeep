import { useState, type HTMLAttributes, type ReactNode } from 'react';
import { cx, type Surface } from '../util';
import { Button } from './Button';
import styles from './Banner.module.css';

export type BannerTone = 'info' | 'warn' | 'bad';

/** A banner's one action, such as Retry or Reload. */
export interface BannerAction {
  label: ReactNode;
  onClick: () => void;
}

export interface BannerProps extends Omit<HTMLAttributes<HTMLDivElement>, 'role' | 'children'> {
  tone?: BannerTone;
  /** The state, in words: the text carries the meaning, the glyph only repeats it. */
  children: ReactNode;
  /** At most one action. */
  action?: BannerAction;
  /**
   * Whether the banner is news, announced as role="alert" when its tone is warn or bad, and
   * as a polite role="status" when it's info. By default it is when the banner first
   * appears after the page has loaded (after the first interaction, or a second after the
   * load event), such as a Save failure, and isn't when it's part of the page as loaded,
   * such as a view-only notice. A single-page app sets it to false for the banners a newly
   * rendered page starts with.
   */
  live?: boolean;
  surface?: Surface;
}

// A banner is news when it first appears once the page has settled: after the user's first
// interaction with the page, or a second after the window's load event, whichever comes first.
// One mounting before then is part of the page as loaded, however late its first render ran.
const SETTLE_MS = 1000;
let settled = false;
if (typeof window !== 'undefined') {
  const settle = () => setTimeout(() => (settled = true), SETTLE_MS);
  if (document.readyState === 'complete') settle();
  else window.addEventListener('load', settle, { once: true });
}

function pageSettled() {
  return settled || (typeof navigator !== 'undefined' && navigator.userActivation?.hasBeenActive === true);
}

const GLYPHS: Record<BannerTone, ReactNode> = {
  info: (
    <>
      <circle cx="8" cy="8" r="6.5" />
      <path d="M8 7.25v4M8 4.75v.01" />
    </>
  ),
  warn: (
    <>
      <path d="M8 1.75 14.75 13.75H1.25Z" />
      <path d="M8 6.25v3.5M8 11.75v.01" />
    </>
  ),
  bad: (
    <>
      <circle cx="8" cy="8" r="6.5" />
      <path d="m5.75 5.75 4.5 4.5m0-4.5-4.5 4.5" />
    </>
  ),
};

/**
 * A persistent page-level state on its status -sf surface, with a leading glyph in the
 * status colour and at most one action (DESIGN.md, Toast and banner). It stays until the
 * page removes it. When it's news (see `live`), warn and bad use role="alert" and info a
 * polite role="status"; otherwise the banner is plain text.
 */
export function Banner({ tone = 'info', children, action, live, surface, className, ...rest }: BannerProps) {
  // Decided once, when the banner first mounts.
  const [afterLoad] = useState(pageSettled);
  const news = live ?? afterLoad;
  const role = !news ? undefined : tone === 'info' ? 'status' : 'alert';
  return (
    <div
      {...rest}
      // Keyed by tone, so a tone change mounts a fresh live region, which is announced, rather
      // than turning existing content into an alert, which often isn't.
      key={tone}
      role={role}
      className={cx(styles.banner, styles[tone], className)}
      data-tone={tone}
      data-gk-surface={surface}
    >
      <svg className={styles.glyph} viewBox="0 0 16 16" aria-hidden="true" focusable="false">
        {GLYPHS[tone]}
      </svg>
      <div className={styles.text}>{children}</div>
      {action && (
        <Button size="sm" className={styles.action} onClick={action.onClick}>
          {action.label}
        </Button>
      )}
    </div>
  );
}
