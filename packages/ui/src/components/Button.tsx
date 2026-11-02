import { useId, type ButtonHTMLAttributes, type MouseEvent, type Ref } from 'react';
import { useMessages } from '../messages';
import { cx, joinIds, type Surface } from '../util';
import a11y from './a11y.module.css';
import styles from './Button.module.css';

/**
 * The button variants DESIGN.md keeps. Destructive is outlined, and there is no filled warn
 * or filled destructive variant. A destructive button never acts on its own: it opens the
 * confirming modal (EXPERIENCE.md, Component Patterns).
 */
export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'destructive';

/**
 * `aria-disabled` makes a button inert but focusable: it's drawn as disabled and ignores
 * clicks, Enter and its form's submission. The `disabled` attribute also removes it from
 * the tab order.
 */
export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: 'md' | 'sm';
  /**
   * The button's action is under way. It keeps its width and name, shows a spinner, sets
   * aria-busy and aria-disabled, stays focusable, and ignores clicks and Enter, which also
   * stops it submitting its form again.
   */
  pending?: boolean;
  surface?: Surface;
  ref?: Ref<HTMLButtonElement>;
}

export function Button({
  variant = 'secondary',
  size = 'md',
  pending = false,
  surface,
  type = 'button',
  className,
  onClick,
  children,
  'aria-describedby': describedBy,
  'aria-disabled': ariaDisabled,
  ref,
  ...rest
}: ButtonProps) {
  const messages = useMessages();
  const statusId = useId();
  // A caller's aria-disabled blocks the action just as pending does, and stays focusable.
  const inert = pending || ariaDisabled === true || ariaDisabled === 'true';

  function handleClick(event: MouseEvent<HTMLButtonElement>) {
    // Enter and Space reach a button as a click, and so does a form's implicit submission,
    // so cancelling the click stops all of them, including a second submit.
    if (inert) {
      event.preventDefault();
      return;
    }
    onClick?.(event);
  }

  return (
    <button
      {...rest}
      ref={ref}
      type={type}
      className={cx(styles.button, styles[variant], size === 'sm' && styles.sm, pending && styles.pending, className)}
      data-variant={variant}
      data-size={size}
      data-gk-surface={surface}
      aria-busy={pending || undefined}
      aria-disabled={pending ? true : ariaDisabled}
      aria-describedby={joinIds(describedBy, pending && statusId)}
      onClick={handleClick}
    >
      <span className={styles.label}>
        {pending && (
          // The spinner is hidden from the name, so the name stays the label. Its text is
          // the button's description while pending.
          <span className={styles.spinner} aria-hidden="true">
            <span id={statusId} className={a11y.visuallyHidden}>
              {messages.pending}
            </span>
          </span>
        )}
        {children}
      </span>
    </button>
  );
}
