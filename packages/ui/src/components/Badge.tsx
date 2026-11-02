import type { HTMLAttributes, ReactNode } from 'react';
import { useMessages } from '../messages';
import { cx } from '../util';
import styles from './Badge.module.css';

/*
 * The badges DESIGN.md keeps (UX-DR9). The text always carries the meaning: colour and the
 * status dot only repeat it, and the dot is hidden from assistive technology.
 */

type SpanProps = Omit<HTMLAttributes<HTMLSpanElement>, 'children'>;

export type BadgeStatus = 'active' | 'pending' | 'blocked';

export interface StatusBadgeProps extends SpanProps {
  status: BadgeStatus;
  /** Replaces the catalogue's text for the status. */
  children?: ReactNode;
}

/** A status with a 6px dot: Active on ok, Pending on warn, Blocked on bad. */
export function StatusBadge({ status, children, className, ...rest }: StatusBadgeProps) {
  const messages = useMessages();
  // An unknown status from an untyped caller falls back to itself as the text.
  const text = ({ active: messages.statusActive, pending: messages.statusPending, blocked: messages.statusBlocked } as Record<string, string | undefined>)[status];
  return (
    <span {...rest} className={cx(styles.badge, styles[status], className)} data-badge="status" data-status={status}>
      <span className={styles.dot} aria-hidden="true" />
      {children ?? text ?? String(status)}
    </span>
  );
}

export interface ProtocolBadgeProps extends SpanProps {
  /** The protocol, such as "OIDC". */
  children: ReactNode;
}

/** A protocol on info, with no dot. */
export function ProtocolBadge({ children, className, ...rest }: ProtocolBadgeProps) {
  return (
    <span {...rest} className={cx(styles.badge, styles.protocol, className)} data-badge="protocol">
      {children}
    </span>
  );
}

export interface DraftBadgeProps extends SpanProps {
  /** Replaces the catalogue's "Draft". */
  children?: ReactNode;
}

/** The outlined Draft badge. */
export function DraftBadge({ children, className, ...rest }: DraftBadgeProps) {
  const messages = useMessages();
  return (
    <span {...rest} className={cx(styles.badge, styles.draft, className)} data-badge="draft">
      {children ?? messages.draft}
    </span>
  );
}

export type Environment = 'prod' | 'staging' | 'dev';

export interface EnvironmentBadgeProps extends SpanProps {
  environment: Environment;
  /** Replaces the catalogue's text for the environment. */
  children?: ReactNode;
}

/**
 * A Tenant's environment in mono: Prod on bad, Staging on warn, Dev on info. The colour
 * marks risk, so Prod looks distinct (DESIGN.md, Prod treatment).
 */
export function EnvironmentBadge({ environment, children, className, ...rest }: EnvironmentBadgeProps) {
  const messages = useMessages();
  const text = ({ prod: messages.environmentProd, staging: messages.environmentStaging, dev: messages.environmentDev } as Record<string, string | undefined>)[environment];
  return (
    <span
      {...rest}
      className={cx(styles.badge, styles.mono, styles[environment], className)}
      data-badge="environment"
      data-environment={environment}
    >
      {children ?? text ?? String(environment)}
    </span>
  );
}

export interface CodeBadgeProps extends SpanProps {
  /** A failure code sits on bad-sf, a success code on sf2. */
  outcome?: 'success' | 'failure';
  /** The code, such as a Log event type. */
  children: ReactNode;
}

/** A Log event code in mono. */
export function CodeBadge({ outcome = 'success', children, className, ...rest }: CodeBadgeProps) {
  return (
    <span
      {...rest}
      className={cx(styles.badge, styles.mono, outcome === 'failure' ? styles.failure : styles.success, className)}
      data-badge="code"
      data-outcome={outcome}
    >
      {children}
    </span>
  );
}
