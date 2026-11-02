import { createContext, useContext, useId, type InputHTMLAttributes, type ReactNode, type Ref } from 'react';
import { cx, type Surface } from '../util';
import styles from './choices.module.css';

type NativeInput = Omit<InputHTMLAttributes<HTMLInputElement>, 'type'>;

export interface CheckboxProps extends NativeInput {
  label: ReactNode;
  surface?: Surface;
  ref?: Ref<HTMLInputElement>;
}

/** A native checkbox, drawn at 15px in a 24px hit area, inside its label. */
export function Checkbox({ label, surface, className, ref, ...rest }: CheckboxProps) {
  return (
    <label className={cx(styles.choice, className)} data-gk-surface={surface}>
      <input {...rest} ref={ref} type="checkbox" className={cx(styles.box, styles.checkbox)} />
      <span className={styles.text}>{label}</span>
    </label>
  );
}

interface RadioGroupState {
  name: string;
  value: string | undefined;
  defaultValue: string | undefined;
  onChange: ((value: string) => void) | undefined;
}

const RadioGroupContext = createContext<RadioGroupState | null>(null);

export interface RadioGroupProps {
  /** The group's visible name, as the fieldset's legend. */
  legend: ReactNode;
  /** Shared by every radio. Generated when absent. */
  name?: string;
  /** The checked value, when the caller controls it. */
  value?: string;
  defaultValue?: string;
  onChange?: (value: string) => void;
  surface?: Surface;
  className?: string;
  children: ReactNode;
}

/**
 * Native radios in a fieldset and legend. Arrow keys move and check within the group, as
 * the browser does for radios sharing a name.
 */
export function RadioGroup({ legend, name, value, defaultValue, onChange, surface, className, children }: RadioGroupProps) {
  const generated = useId();
  const state: RadioGroupState = { name: name ?? generated, value, defaultValue, onChange };
  return (
    <fieldset className={cx(styles.group, className)} data-gk-surface={surface}>
      <legend className={styles.legend}>{legend}</legend>
      <div className={styles.options}>
        <RadioGroupContext.Provider value={state}>{children}</RadioGroupContext.Provider>
      </div>
    </fieldset>
  );
}

export interface RadioProps extends Omit<NativeInput, 'value'> {
  label: ReactNode;
  value: string;
  surface?: Surface;
  ref?: Ref<HTMLInputElement>;
}

/** A native radio, drawn at 15px in a 24px hit area. Takes its name and state from its RadioGroup. */
export function Radio({ label, value, surface, className, onChange, ref, ...rest }: RadioProps) {
  const group = useContext(RadioGroupContext);
  const checked =
    group?.value !== undefined
      ? { checked: group.value === value }
      : group?.defaultValue !== undefined && rest.defaultChecked === undefined && rest.checked === undefined
        ? { defaultChecked: group.defaultValue === value }
        : {};
  return (
    <label className={cx(styles.choice, className)} data-gk-surface={surface}>
      <input
        name={group?.name}
        {...rest}
        {...checked}
        ref={ref}
        type="radio"
        value={value}
        className={cx(styles.box, styles.radio)}
        onChange={(event) => {
          onChange?.(event);
          if (event.currentTarget.checked) group?.onChange?.(value);
        }}
      />
      <span className={styles.text}>{label}</span>
    </label>
  );
}
