import { useMessages } from '../messages';
import { cx } from '../util';
import { CopyButton } from './CopyButton';
import styles from './ErrorReference.module.css';

export interface ErrorReferenceProps {
  /** The error code, such as "invalid_request". Its row is left out when it's empty. */
  code: string;
  /** The trace ID support asks for, with a Copy control. Its row and Copy are left out when it's empty. */
  traceId: string;
  className?: string;
  'data-testid'?: string;
}

/**
 * An error's code and trace ID, the only variable detail an error page shows (FR-33): each
 * labelled, the values in Geist Mono, and Copy on the trace ID, named "Copy trace ID". Labels
 * are tx2 and values tx, never tx3, so they pass AA on Hosted Login in both schemes. An empty
 * value's row is left out, and with neither there is nothing to show.
 */
export function ErrorReference({ code, traceId, className, 'data-testid': testId }: ErrorReferenceProps) {
  const messages = useMessages();
  const hasCode = code.trim() !== '';
  const hasTrace = traceId.trim() !== '';
  if (!hasCode && !hasTrace) return null;
  return (
    <dl className={cx(styles.reference, className)} data-testid={testId}>
      {hasCode && (
        <div className={styles.row}>
          <dt className={styles.label}>{messages.errorCode}</dt>
          <dd className={styles.value}>
            <code className={styles.code} data-reference="code">
              {code}
            </code>
          </dd>
        </div>
      )}
      {hasTrace && (
        <div className={styles.row}>
          <dt className={styles.label}>{messages.traceId}</dt>
          <dd className={styles.value}>
            <code className={styles.code} data-reference="trace">
              {traceId}
            </code>
            <CopyButton value={traceId} what={messages.traceIdCopy} />
          </dd>
        </div>
      )}
    </dl>
  );
}
