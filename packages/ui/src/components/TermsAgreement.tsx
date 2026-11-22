import { useId, type ReactNode, type Ref } from 'react';
import { cx } from '../util';
import { Checkbox } from './Choice';
import styles from './TermsAgreement.module.css';

export interface TermsAgreementProps {
  /** The checkbox's label, such as "I agree to the". */
  label: ReactNode;
  /** The link's text, such as "Terms of Service". */
  linkLabel: ReactNode;
  /** The terms to agree to: opened in a new tab, with no opener or referrer. */
  href: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  /** The error under the checkbox, such as "Accept the terms to continue.". It marks the checkbox invalid. */
  error?: ReactNode;
  ref?: Ref<HTMLInputElement>;
  className?: string;
  'data-testid'?: string;
}

/**
 * A terms agreement row (Story 4.8): a Checkbox, its label, then the terms link outside the label, so following the link
 * never ticks the box. The link opens in a new tab with `rel="noopener noreferrer"` and is underlined, so it doesn't rely
 * on colour. The box is named by the label and the link text together (`aria-labelledby`). The box keeps the Checkbox's 24px hit area and token edge. An error is written under it, linked by
 * `aria-describedby`, with the box marked `aria-invalid`, so focus can move to it after a refused submit.
 */
export function TermsAgreement({
  label,
  linkLabel,
  href,
  checked,
  onChange,
  error,
  ref,
  className,
  'data-testid': testId,
}: TermsAgreementProps) {
  const id = useId();
  const errorId = `${id}-error`;
  const labelId = `${id}-label`;
  const linkId = `${id}-link`;
  const invalid = Boolean(error);
  return (
    <div className={cx(styles.terms, className)} data-testid={testId}>
      <div className={styles.row}>
        <Checkbox
          ref={ref}
          label={<span id={labelId}>{label}</span>}
          checked={checked}
          onChange={(event) => onChange(event.currentTarget.checked)}
          // Named by the label and the link together, though the link stays outside the label.
          aria-labelledby={`${labelId} ${linkId}`}
          aria-invalid={invalid ? true : undefined}
          aria-describedby={invalid ? errorId : undefined}
          data-testid={testId === undefined ? undefined : `${testId}-checkbox`}
        />{' '}
        <a
          id={linkId}
          className={styles.link}
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          data-testid={testId === undefined ? undefined : `${testId}-link`}
        >
          {linkLabel}
        </a>
      </div>
      <div id={errorId} className={cx(styles.helper, invalid && styles.error)}>
        {error}
      </div>
    </div>
  );
}
