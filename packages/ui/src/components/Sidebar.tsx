import { useId, useState, type MouseEvent } from 'react';
import { useMessages } from '../messages';
import { cx } from '../util';
import a11y from './a11y.module.css';
import { ADMIN_NAV_GROUPS, type AdminNavGroupId, type AdminNavItem } from './adminNav';
import { inPageClick } from './navigate';
import styles from './Sidebar.module.css';
import { ADMIN_WIDE_QUERY, useMediaQuery } from './useMediaQuery';

export interface SidebarProps {
  /** The links to list. A group with none isn't rendered, and nothing is drawn for a link not given. */
  items: readonly AdminNavItem[];
  /** The current page's href, marked as current. */
  currentHref?: string;
  /** A plain click on a link. Modified clicks (a new tab or window) stay the browser's. */
  onNavigate: (href: string) => void;
  className?: string;
  'data-testid'?: string;
}

function Chevron() {
  return (
    <svg className={styles.chevron} viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path d="M6 4l4 4-4 4" />
    </svg>
  );
}

/**
 * The Admin sidebar (EXPERIENCE.md, Admin shell): one `nav` named "Main" holding the nine v1
 * groups in order, leaving out any group with no link. At 1100px and wider it is 236px, each
 * group a disclosure over its links, the one holding the current page open to start with; the
 * open state lives in memory only. Below, it is a 52px icon rail where each group is one link to
 * its first item, named by the group label. With no links it is still drawn, empty, at its width.
 */
export function Sidebar({ items, currentHref, onNavigate, className, 'data-testid': testId }: SidebarProps) {
  const messages = useMessages();
  const id = useId();
  const wide = useMediaQuery(ADMIN_WIDE_QUERY);
  // Only the groups the Admin opened or closed by hand: the rest follow the current page.
  const [toggled, setToggled] = useState<Partial<Record<AdminNavGroupId, boolean>>>({});

  const groups = ADMIN_NAV_GROUPS.map((group) => ({ ...group, items: items.filter((item) => item.group === group.id) })).filter(
    (group) => group.items.length > 0,
  );

  const follow = (href: string) => (event: MouseEvent<HTMLAnchorElement>) => {
    if (!inPageClick(event)) return;
    event.preventDefault();
    onNavigate(href);
  };

  return (
    <nav aria-label={messages.navMain} className={cx(styles.nav, className)} data-rail={wide ? undefined : ''} data-testid={testId}>
      {groups.length > 0 && (
        <ul className={styles.groups}>
          {groups.map((group) => {
            const label = messages[group.label];
            const holdsCurrent = group.items.some((item) => item.href === currentHref);
            if (!wide) {
              const first = group.items[0]!;
              return (
                <li key={group.id}>
                  <a
                    href={first.href}
                    title={label}
                    className={styles.railLink}
                    aria-current={holdsCurrent ? 'true' : undefined}
                    data-group={group.id}
                    onClick={follow(first.href)}
                  >
                    <span className={styles.icon}>{group.icon}</span>
                    <span className={a11y.visuallyHidden}>{label}</span>
                  </a>
                </li>
              );
            }
            const open = toggled[group.id] ?? holdsCurrent;
            const listId = `${id}-${group.id}`;
            return (
              <li key={group.id} className={styles.group}>
                <button
                  type="button"
                  className={styles.groupButton}
                  aria-expanded={open}
                  aria-controls={listId}
                  data-group={group.id}
                  data-current={holdsCurrent ? '' : undefined}
                  onClick={() => setToggled((state) => ({ ...state, [group.id]: !open }))}
                >
                  <span className={styles.icon}>{group.icon}</span>
                  <span className={styles.groupLabel}>{label}</span>
                  <Chevron />
                </button>
                <ul id={listId} className={styles.items} hidden={!open}>
                  {group.items.map((item) => (
                    <li key={item.href}>
                      <a
                        href={item.href}
                        className={styles.item}
                        aria-current={item.href === currentHref ? 'page' : undefined}
                        onClick={follow(item.href)}
                      >
                        {item.label}
                      </a>
                    </li>
                  ))}
                </ul>
              </li>
            );
          })}
        </ul>
      )}
    </nav>
  );
}
