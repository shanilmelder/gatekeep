import { useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useMessages } from '../messages';
import { mergeRefs } from '../util';
import a11y from './a11y.module.css';
import styles from './controls.module.css';
import { Field, type Validate } from './Field';
import { Input, type InputProps } from './Input';

export interface PasswordFieldProps extends Omit<InputProps, 'type' | 'code'> {
  label: ReactNode;
  /** An action on the right of the label's row (Story 4.11), such as "Forgot password?". */
  labelAction?: ReactNode;
  /**
   * The account's username (Story 4.11), such as Reset password's email, held in a visually hidden read-only
   * `autocomplete="username"` field beside the password, out of the tab order, so password managers save the new
   * password for it. `usernameLabel` is that field's accessible name. With none, there is no such field.
   */
  username?: string;
  usernameLabel?: string;
  helper?: ReactNode;
  validate?: Validate;
  error?: ReactNode;
}

/**
 * A masked password in a Field, with a `type="button"` toggle named "Show password" or
 * "Hide password". It masks again when its form submits, and when the browser's own
 * validation stops that submit. The toggle is disabled with the field. Paste and password
 * managers are never blocked: there's no autocomplete="off", and no paste handler.
 */
export function PasswordField({
  label,
  labelAction,
  username,
  usernameLabel,
  helper,
  validate,
  error,
  id,
  surface,
  className,
  autoComplete = 'current-password',
  ref,
  ...rest
}: PasswordFieldProps) {
  const messages = useMessages();
  const [shown, setShown] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const inputRef = useMemo(() => mergeRefs(input, ref), [ref]);
  // The form the input belongs to now: its `form` attribute or its place can change.
  const [form, setForm] = useState<HTMLFormElement | null>(null);

  useLayoutEffect(() => {
    const current = input.current?.form ?? null;
    if (current !== form) setForm(current);
  });

  useEffect(() => {
    if (!form) return;
    const mask = () => setShown(false);
    // A blocked submit fires `invalid` on each invalid control, which doesn't bubble.
    form.addEventListener('submit', mask);
    form.addEventListener('invalid', mask, true);
    return () => {
      form.removeEventListener('submit', mask);
      form.removeEventListener('invalid', mask, true);
    };
  }, [form]);

  return (
    <Field label={label} labelAction={labelAction} helper={helper} validate={validate} error={error} id={id} surface={surface} className={className}>
      {username !== undefined && (
        <input
          className={a11y.visuallyHidden}
          type="text"
          name="username"
          autoComplete="username"
          value={username}
          readOnly
          tabIndex={-1}
          aria-label={usernameLabel}
          data-testid="password-field-username"
        />
      )}
      <span className={styles.passwordWrap}>
        <Input
          {...rest}
          ref={inputRef}
          type={shown ? 'text' : 'password'}
          autoComplete={autoComplete}
          className={styles.passwordInput}
        />
        <button
          type="button"
          className={styles.reveal}
          disabled={rest.disabled}
          aria-label={shown ? messages.hidePassword : messages.showPassword}
          onClick={() => setShown((value) => !value)}
        >
          {shown ? messages.hide : messages.show}
        </button>
      </span>
    </Field>
  );
}
