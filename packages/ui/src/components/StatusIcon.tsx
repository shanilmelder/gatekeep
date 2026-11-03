import { cx } from '../util';
import styles from './StatusIcon.module.css';

export type StatusIconStatus = 'success' | 'warning' | 'error' | 'blocked';

export interface StatusIconProps {
  status: StatusIconStatus;
  className?: string;
  'data-testid'?: string;
}

/** Each status's glyph (DESIGN.md, Hosted Login components). */
const GLYPHS: Record<StatusIconStatus, string> = { success: '✓', warning: '@', error: '!', blocked: '⊘' };

/**
 * A Hosted card's status icon (components.status-icon): a circle on the status's -sf surface
 * with its glyph in the status colour. It's decorative and hidden from assistive technology,
 * because the card's heading carries the meaning.
 */
export function StatusIcon({ status, className, 'data-testid': testId }: StatusIconProps) {
  // An unknown status from an untyped caller draws the error look rather than nothing.
  const known: StatusIconStatus = Object.hasOwn(GLYPHS, status) ? status : 'error';
  return (
    <span className={cx(styles.icon, styles[known], className)} aria-hidden="true" data-status={known} data-testid={testId}>
      {GLYPHS[known]}
    </span>
  );
}
