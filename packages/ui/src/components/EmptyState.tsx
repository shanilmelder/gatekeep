import type { ReactNode } from 'react';
import { cx, type Surface } from '../util';
import { Button } from './Button';
import styles from './EmptyState.module.css';
import { present } from './present';

export interface EmptyStateAction {
  label: ReactNode;
  onClick: () => void;
}

export interface EmptyStateProps {
  /** The one line of explanation, such as "No applications yet". */
  message: ReactNode;
  /**
   * The one action, such as Create application. Leave it out where the Admin's role can't
   * take it: then no button shows (EXPERIENCE.md, empty-state).
   */
  action?: EmptyStateAction;
  /** A decorative glyph for the 32px icon tile. Hidden from assistive technology. */
  icon?: ReactNode;
  surface?: Surface;
  className?: string;
}

/**
 * An empty list (UX-DR14): a dashed card with exactly one line and at most one small
 * action. The line is plain text: the page's own heading already names the list.
 */
export function EmptyState({ message, action, icon, surface, className }: EmptyStateProps) {
  return (
    <div className={cx(styles.empty, className)} data-gk-surface={surface}>
      {present(icon) && (
        <span className={styles.icon} aria-hidden="true">
          {icon}
        </span>
      )}
      <p className={styles.message}>{message}</p>
      {action && (
        <Button size="sm" onClick={action.onClick}>
          {action.label}
        </Button>
      )}
    </div>
  );
}
