import {
  createContext,
  useContext,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type ChangeEvent,
  type FocusEvent,
  type ReactNode,
} from 'react';
import { cx, joinIds, type Surface } from '../util';
import styles from './Field.module.css';

/**
 * Checks a value and returns the error to show, or nothing when it's valid. Browser checks
 * are feedback only: the server runs every rule again (EXPERIENCE.md, Validation Rules).
 */
export type Validate = (value: string) => string | null | undefined | false;

export interface FieldProps {
  /** The visible label, tied to the control. */
  label: ReactNode;
  /** Text under the control. An error replaces it, in the same element. */
  helper?: ReactNode;
  /**
   * Runs on blur once the value has changed at least once, so tabbing through an untouched
   * field shows nothing, then on every change while the field is in error.
   */
  validate?: Validate;
  /**
   * An error from outside, such as the server's. Shown ahead of `validate`'s, whatever
   * `validate` says, until the caller clears it: the Field never clears it itself.
   */
  error?: ReactNode;
  /** The control's id. Generated when absent. An id set on the control itself wins. */
  id?: string;
  surface?: Surface;
  className?: string;
  /** One Input, Select or Textarea. */
  children: ReactNode;
}

interface FieldState {
  id: string;
  helperId: string;
  invalid: boolean;
  claimId(id: string | undefined): void;
  onBlur(value: string): void;
  onChange(value: string): void;
}

const FieldContext = createContext<FieldState | null>(null);

/**
 * A label above a control and a helper below it. The helper keeps its id, linked by
 * aria-describedby, whether or not it holds an error, and the error is written into it
 * silently. Focus never moves on validation: only a submit moves it.
 */
export function Field({ label, helper, validate, error, id, surface, className, children }: FieldProps) {
  const generated = useId();
  const controlId = id ?? generated;
  const helperId = `${controlId}-helper`;
  // A control given its own id claims it, so the label always points at the control.
  const [claimedId, claimId] = useState<string | undefined>(undefined);
  const [validationError, setValidationError] = useState<string | null>(null);
  const changed = useRef(false);

  const check = (value: string) => (validate ? validate(value) || null : null);
  const shown = error || validationError;

  const state: FieldState = {
    id: controlId,
    helperId,
    invalid: Boolean(shown),
    claimId,
    onBlur: (value) => {
      if (changed.current) setValidationError(check(value));
    },
    onChange: (value) => {
      changed.current = true;
      if (validationError !== null) setValidationError(check(value));
    },
  };

  return (
    <div className={cx(styles.field, className)} data-gk-surface={surface}>
      <label className={styles.label} htmlFor={claimedId ?? controlId}>
        {label}
      </label>
      <FieldContext.Provider value={state}>{children}</FieldContext.Provider>
      <div id={helperId} className={cx(styles.helper, Boolean(shown) && styles.error)}>
        {shown || helper}
      </div>
    </div>
  );
}

interface ControlProps<E extends HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement> {
  id?: string;
  'aria-describedby'?: string;
  'aria-invalid'?: boolean | 'true' | 'false' | 'grammar' | 'spelling';
  onBlur?: (event: FocusEvent<E>) => void;
  onChange?: (event: ChangeEvent<E>) => void;
}

/** Wires a control to the Field around it, if any: id, helper link, invalid state, checks. */
export function useFieldControl<E extends HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement, P extends ControlProps<E>>(
  props: P,
): P {
  const field = useContext(FieldContext);
  const claimId = field?.claimId;
  useLayoutEffect(() => {
    if (!claimId || props.id === undefined) return;
    claimId(props.id);
    return () => claimId(undefined);
  }, [claimId, props.id]);
  if (!field) return props;
  return {
    ...props,
    id: props.id ?? field.id,
    'aria-describedby': joinIds(field.helperId, props['aria-describedby']),
    // The Field's error wins; otherwise the caller's value, such as "spelling", passes through.
    'aria-invalid': field.invalid ? true : props['aria-invalid'],
    onBlur: (event: FocusEvent<E>) => {
      field.onBlur(event.currentTarget.value);
      props.onBlur?.(event);
    },
    onChange: (event: ChangeEvent<E>) => {
      field.onChange(event.currentTarget.value);
      props.onChange?.(event);
    },
  } as P;
}
