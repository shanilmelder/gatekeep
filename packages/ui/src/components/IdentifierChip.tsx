import { cx } from '../util';
import a11y from './a11y.module.css';
import styles from './IdentifierChip.module.css';
import { LinkButton } from './LinkButton';

export interface IdentifierChipProps {
  /** The identifier entered at Login, such as an email address, shown whole. */
  identifier: string;
  /** The edit action's text, such as "Edit", from the catalogue. */
  editLabel: string;
  /** Edit: the caller goes back to Login with the identifier kept. */
  onEdit: () => void;
  /** An edit is under way: the action is inert but keeps focus. */
  pending?: boolean;
  /**
   * The accessible name of the chip's read-only `username` field, such as "Email address", which lets password managers
   * pair the identifier with the password in the same form. It is visually hidden and out of the tab order. With none, no
   * field is rendered.
   */
  usernameLabel?: string;
  className?: string;
  'data-testid'?: string;
}

/**
 * The identifier chip (Story 4.9, UX-DR32): the identifier the step is for, then an "Edit" action back to Login, and with
 * `usernameLabel` a visually hidden read-only `username` field holding it, for password managers. The
 * identifier wraps at any character and is never truncated, so a long address stays readable at 320px and 200% zoom. The
 * action is a `type="button"` LinkButton, so it never submits the form it sits beside, with a 24px inline hit area.
 */
export function IdentifierChip({
  identifier,
  editLabel,
  onEdit,
  pending = false,
  usernameLabel,
  className,
  'data-testid': testId,
}: IdentifierChipProps) {
  return (
    <div className={cx(styles.chip, className)} data-testid={testId}>
      {usernameLabel !== undefined && (
        <input
          className={a11y.visuallyHidden}
          type="email"
          name="username"
          autoComplete="username"
          value={identifier}
          readOnly
          tabIndex={-1}
          aria-label={usernameLabel}
          data-testid={testId === undefined ? undefined : `${testId}-username`}
        />
      )}
      <span className={styles.identifier} data-testid={testId === undefined ? undefined : `${testId}-identifier`}>
        {identifier}
      </span>
      <LinkButton
        className={styles.edit}
        onClick={onEdit}
        aria-disabled={pending ? true : undefined}
        data-testid={testId === undefined ? undefined : `${testId}-edit`}
      >
        {editLabel}
      </LinkButton>
    </div>
  );
}
