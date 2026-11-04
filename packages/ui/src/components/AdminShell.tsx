import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { useMessages } from '../messages';
import { cx } from '../util';
import a11y from './a11y.module.css';
import styles from './AdminShell.module.css';
import { SKELETON_DELAY_MS } from './SkeletonRows';

export interface AdminShellProps {
  /** The TopBar. */
  topBar: ReactNode;
  /** The Sidebar. */
  sidebar: ReactNode;
  /**
   * Banners at the top of `main`, above the page, such as Session expiry. Setting or clearing
   * them never unmounts or re-keys the page, so what the Admin typed stays. When one goes away
   * with focus inside it (its action was the last thing used), focus moves to the page's `h1`.
   */
  banner?: ReactNode;
  /**
   * Changes on every in-shell navigation, when its page is shown. Focus then moves to the new
   * page's `h1` once it renders. It doesn't move for the first key given, the first load: until
   * then it may be undefined.
   */
  pageKey?: string | number;
  /**
   * The next page is loading while this one stays in place: `main` is aria-busy at once, and
   * after 300ms a thin bar shows under the top bar and a polite status says "Loading". Nothing
   * is blocked.
   */
  busy?: boolean;
  /** A polite announcement, such as "You're signed in again." It is read when it changes. */
  announcement?: string;
  /** The page. */
  children?: ReactNode;
  className?: string;
  'data-testid'?: string;
}

/**
 * The Admin shell (EXPERIENCE.md, Admin shell; DESIGN.md, Admin shell): the top bar over a
 * sidebar and a main area, as a grid exactly the window's height. The window never scrolls:
 * only `main` does.
 */
export function AdminShell({
  topBar,
  sidebar,
  banner,
  pageKey,
  busy = false,
  announcement,
  children,
  className,
  'data-testid': testId,
}: AdminShellProps) {
  const messages = useMessages();
  const main = useRef<HTMLElement>(null);
  const bannerSlot = useRef<HTMLDivElement>(null);
  const shownKey = useRef(pageKey);
  const focusPending = useRef(false);
  // Whether focus was last inside the banner slot.
  const focusInBanner = useRef(false);
  const [showBusy, setShowBusy] = useState(false);

  const focusHeading = () => {
    const heading = main.current?.querySelector<HTMLElement>('h1');
    if (!heading) return false;
    heading.focus({ preventScroll: true });
    return true;
  };

  // A new page: back to the top, and focus to its h1 as soon as there is one. Compared with the
  // key last shown rather than run on mount, so Strict Mode's second mount moves nothing; and the
  // first key given, the first page shown, is the first load.
  useLayoutEffect(() => {
    if (shownKey.current === pageKey) return;
    const first = shownKey.current === undefined;
    shownKey.current = pageKey;
    if (first) return;
    focusPending.current = true;
    if (main.current) main.current.scrollTop = 0;
  }, [pageKey]);

  // Every render: the page may render its h1 only after its reads, a render or more later; and a
  // banner that took focus with it when it went leaves focus on the document.
  useLayoutEffect(() => {
    if (focusPending.current && focusHeading()) focusPending.current = false;
    const active = document.activeElement;
    if (focusInBanner.current && !bannerSlot.current?.contains(active) && (active === null || active === document.body)) {
      focusInBanner.current = false;
      focusHeading();
    }
  });

  useEffect(() => {
    if (!busy) {
      setShowBusy(false);
      return;
    }
    const timer = setTimeout(() => setShowBusy(true), SKELETON_DELAY_MS);
    return () => clearTimeout(timer);
  }, [busy]);

  return (
    <div
      className={cx(styles.shell, className)}
      data-gk-surface="admin"
      data-testid={testId}
      onFocus={(event) => {
        focusInBanner.current = bannerSlot.current?.contains(event.target) ?? false;
      }}
    >
      {topBar}
      <div className={styles.body}>
        {sidebar}
        <main ref={main} className={styles.main} aria-busy={busy || undefined}>
          <div ref={bannerSlot} className={styles.banner} data-part="banner">
            {banner}
          </div>
          {children}
        </main>
      </div>
      {showBusy && <div className={styles.progress} aria-hidden="true" data-part="progress" />}
      {/* Outside main, so its aria-busy doesn't hold these back. Always present, so new text is read. */}
      <span role="status" className={a11y.visuallyHidden} data-part="status">
        {showBusy ? messages.loading : (announcement ?? '')}
      </span>
    </div>
  );
}
