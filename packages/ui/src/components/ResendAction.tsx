import { useEffect, useState } from 'react';
import { formatMessage, useMessages } from '../messages';
import { cx } from '../util';
import a11y from './a11y.module.css';
import { LinkButton } from './LinkButton';
import styles from './ResendAction.module.css';

/** How long "Resend email" waits after a send before it can be used again: 30 seconds (EXPERIENCE.md, Resend). */
export const RESEND_COOLDOWN_SECONDS = 30;

export interface ResendActionProps {
  /** The action's text, such as "Resend email". */
  label: string;
  /** Resend: the caller sends the request. It's ignored while the countdown runs or a send is under way. */
  onResend: () => void;
  /**
   * Changes each time a send is shown, so the countdown starts again from the full wait: the page's step counter, for
   * example. The first wait starts when the action first renders.
   */
  restartKey?: number | string;
  /** The email was just sent again: "Email sent" is announced once, through a polite status region. */
  sent?: boolean;
  /** A send is under way. */
  pending?: boolean;
  /** The wait, in seconds. */
  cooldownSeconds?: number;
  className?: string;
  'data-testid'?: string;
}

/**
 * "Resend email" (Story 4.7, EXPERIENCE.md, Resend): an inline link-styled action, `aria-disabled` while a 30-second
 * countdown runs, so focus stays on it. The countdown is visible beside it, outside any live region, so it is never
 * announced each second. After a send, "Email sent" is announced once by a polite status region.
 */
export function ResendAction({
  label,
  onResend,
  restartKey,
  sent = false,
  pending = false,
  cooldownSeconds = RESEND_COOLDOWN_SECONDS,
  className,
  'data-testid': testId,
}: ResendActionProps) {
  const messages = useMessages();
  const [left, setLeft] = useState(cooldownSeconds);

  useEffect(() => {
    setLeft(cooldownSeconds);
    const started = Date.now();
    const timer = setInterval(() => {
      const remaining = Math.max(0, cooldownSeconds - Math.floor((Date.now() - started) / 1000));
      setLeft(remaining);
      if (remaining === 0) clearInterval(timer);
    }, 1000);
    return () => clearInterval(timer);
  }, [restartKey, cooldownSeconds]);

  // Emptied, then filled, so each send is announced even when the words are the same as the last.
  const [status, setStatus] = useState('');
  useEffect(() => {
    setStatus('');
    if (!sent) return;
    const timer = setTimeout(() => setStatus(messages.emailSent), 100);
    return () => clearTimeout(timer);
  }, [restartKey, sent, messages]);

  const waiting = left > 0;
  return (
    <span className={cx(styles.resend, className)} data-testid={testId}>
      <LinkButton aria-disabled={waiting || pending} onClick={onResend} data-testid={testId === undefined ? undefined : `${testId}-button`}>
        {label}
      </LinkButton>
      {waiting && (
        <span className={styles.countdown} data-testid={testId === undefined ? undefined : `${testId}-countdown`}>
          {formatMessage(messages.resendAvailableIn, { seconds: left })}
        </span>
      )}
      <span role="status" className={a11y.visuallyHidden}>
        {status}
      </span>
    </span>
  );
}
