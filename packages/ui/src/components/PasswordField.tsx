import { useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useMessages } from '../messages';
import { mergeRefs } from '../util';
import styles from './controls.module.css';
import { Field, type Validate } from './Field';
import { Input, type InputProps } from './Input';

export interface PasswordFieldProps extends Omit<InputProps, 'type' | 'code'> {
  label: ReactNode;
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
    <Field label={label} helper={helper} validate={validate} error={error} id={id} surface={surface} className={className}>
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
