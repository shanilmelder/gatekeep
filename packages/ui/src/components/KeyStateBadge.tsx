import type { HTMLAttributes } from 'react';
import { useMessages } from '../messages';
import { cx } from '../util';
import styles from './KeyStateBadge.module.css';

/*
 * A Signing Key's state (Story 9.1, UX-DR44), as the badge DESIGN.md's status badge draws it:
 * Next on info, Current on ok, Previous and Retired muted, Revoked on bad. The text always carries
 * the state: colour and the dot only repeat it, and the dot is hidden from assistive technology.
 */

export type KeyState = 'next' | 'current' | 'previous' | 'retired' | 'revoked';

export interface KeyStateBadgeProps extends Omit<HTMLAttributes<HTMLSpanElement>, 'children'> {
  state: KeyState;
}

export function KeyStateBadge({ state, className, ...rest }: KeyStateBadgeProps) {
  const messages = useMessages();
  // An unknown state from an untyped caller falls back to itself as the text, muted.
  const known = (
    {
      next: messages.keyStateNext,
      current: messages.keyStateCurrent,
      previous: messages.keyStatePrevious,
      retired: messages.keyStateRetired,
      revoked: messages.keyStateRevoked,
    } as Record<string, string | undefined>
  )[state];
  const tone = ({ next: 'info', current: 'ok', revoked: 'bad' } as Record<string, string | undefined>)[state] ?? 'muted';
  return (
    <span {...rest} className={cx(styles.badge, styles[tone], className)} data-badge="key-state" data-state={state}>
      <span className={styles.dot} aria-hidden="true" />
      {known ?? String(state)}
    </span>
  );
}
