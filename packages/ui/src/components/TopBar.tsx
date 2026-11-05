import type { MouseEvent, ReactNode } from 'react';
import { useMessages } from '../messages';
import { cx } from '../util';
import { Menu, type MenuItem } from './Menu';
import { inPageClick } from './navigate';
import { ThemeToggle } from './ThemeToggle';
import styles from './TopBar.module.css';
import { ADMIN_WIDE_QUERY, useMediaQuery } from './useMediaQuery';

export interface TopBarProps {
  /** Where the brand goes. The Admin Dashboard's root by default. */
  brandHref?: string;
  /** A plain click on the brand. Modified clicks (a new tab or window) stay the browser's. */
  onBrandNavigate: (href: string) => void;
  /** Whether the scheme in force is dark, for the theme toggle. */
  dark: boolean;
  onToggleTheme: () => void;
  /** The avatar menu's items, such as Sign out. */
  accountItems: readonly MenuItem[];
  /** The Tenant switcher (Story 1.28), after the brand and a `/` separator. */
  tenantSwitcher?: ReactNode;
  className?: string;
  'data-testid'?: string;
}

/** A generic person: the Session carries no name or email to show initials from. */
function PersonGlyph() {
  return (
    <svg className={styles.person} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4.5 20a7.5 7.5 0 0 1 15 0" />
    </svg>
  );
}

/**
 * The Admin top bar (EXPERIENCE.md, Admin shell; DESIGN.md, components.top-bar): a 48px
 * `header` on sf with a bd bottom border. The brand links to the root: the mark and the
 * "gatekeep" wordmark, which is visually hidden below 1100px but stays the link's name. After the
 * brand, a `/` separator and the Tenant switcher, when the page gives one (Story 1.28). On the
 * right, the theme toggle and then the avatar menu. No global search, alerts or Help until the
 * stories that build them.
 */
export function TopBar({
  brandHref = '/',
  onBrandNavigate,
  dark,
  onToggleTheme,
  accountItems,
  tenantSwitcher,
  className,
  'data-testid': testId,
}: TopBarProps) {
  const messages = useMessages();
  const wide = useMediaQuery(ADMIN_WIDE_QUERY);

  function onBrandClick(event: MouseEvent<HTMLAnchorElement>) {
    if (!inPageClick(event)) return;
    event.preventDefault();
    onBrandNavigate(brandHref);
  }

  return (
    <header className={cx(styles.topBar, className)} data-rail={wide ? undefined : ''} data-testid={testId}>
      <a href={brandHref} className={styles.brand} onClick={onBrandClick} data-part="brand">
        <span className={styles.mark} aria-hidden="true" />
        <span className={styles.wordmark} data-part="wordmark">
          {messages.brandWordmark}
        </span>
      </a>
      {tenantSwitcher !== undefined && tenantSwitcher !== null && (
        <>
          <span className={styles.separator} aria-hidden="true">
            /
          </span>
          <div className={styles.tenant}>{tenantSwitcher}</div>
        </>
      )}
      <div className={styles.end}>
        <ThemeToggle dark={dark} onToggle={onToggleTheme} />
        <Menu
          className={styles.account}
          label={
            <span className={styles.avatar}>
              <PersonGlyph />
            </span>
          }
          aria-label={messages.account}
          items={accountItems}
          align="end"
          data-testid="account-menu"
        />
      </div>
    </header>
  );
}
