import { useId, useState, type ButtonHTMLAttributes, type ReactNode, type Ref } from 'react';
import { cx, type Surface } from '../util';
import a11y from './a11y.module.css';
import styles from './choices.module.css';

export interface ToggleProps
  extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'type' | 'role' | 'onChange' | 'value' | 'defaultValue'> {
  label: ReactNode;
  /** Keeps the label for assistive technology only, such as in a settings row that shows its own. */
  hideLabel?: boolean;
  checked?: boolean;
  defaultChecked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
  /** Submits `value` under this name while on and enabled, as a checkbox would, to `form` if given. */
  name?: string;
  value?: string;
  surface?: Surface;
  ref?: Ref<HTMLButtonElement>;
}

/**
 * A switch: a button with role="switch" and aria-checked. It changes form state only; the
 * page's Save commits it (EXPERIENCE.md, Component Patterns).
 */
export function Toggle({
  label,
  hideLabel = false,
  checked,
  defaultChecked = false,
  onCheckedChange,
  name,
  value = 'on',
  surface,
  id,
  className,
  disabled,
  form,
  onClick,
  ref,
  ...rest
}: ToggleProps) {
  const generated = useId();
  const buttonId = id ?? generated;
  const labelId = `${buttonId}-label`;
  const [own, setOwn] = useState(defaultChecked);
  const on = checked ?? own;

  return (
    <span className={cx(styles.toggle, className)} data-gk-surface={surface}>
      <button
        {...rest}
        ref={ref}
        id={buttonId}
        disabled={disabled}
        form={form}
        type="button"
        role="switch"
        aria-checked={on}
        aria-labelledby={labelId}
        className={styles.switch}
        onClick={(event) => {
          onClick?.(event);
          if (event.defaultPrevented) return;
          if (checked === undefined) setOwn(!on);
          onCheckedChange?.(!on);
        }}
      >
        <span className={styles.track} aria-hidden="true">
          <span className={styles.knob} />
        </span>
      </button>
      <label id={labelId} htmlFor={buttonId} className={hideLabel ? a11y.visuallyHidden : styles.text}>
        {label}
      </label>
      {name !== undefined && on && !disabled && <input type="hidden" name={name} value={value} form={form} />}
    </span>
  );
}
