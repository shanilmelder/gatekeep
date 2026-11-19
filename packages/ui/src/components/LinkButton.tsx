import type { ButtonHTMLAttributes, MouseEvent, Ref } from 'react';
import { cx } from '../util';
import styles from './LinkButton.module.css';

export interface LinkButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'type'> {
  ref?: Ref<HTMLButtonElement>;
}

/**
 * An action drawn as an inline text link (Story 4.7), such as "Sign up", "Log in" or "Resend email": a
 * `type="button"`, since what it does is a request, not a navigation. It's underlined, so it doesn't rely on colour, and
 * its hit area is at least 24px tall (WCAG 2.2 target size, inline). `aria-disabled` makes it inert but focusable: it's
 * drawn as disabled and ignores clicks, Enter and Space, so focus stays on it.
 */
export function LinkButton({ className, onClick, 'aria-disabled': ariaDisabled, ref, ...rest }: LinkButtonProps) {
  const inert = ariaDisabled === true || ariaDisabled === 'true';

  function handleClick(event: MouseEvent<HTMLButtonElement>) {
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
      type="button"
      className={cx(styles.link, className)}
      aria-disabled={ariaDisabled}
      onClick={handleClick}
    />
  );
}
