import type { InputHTMLAttributes, Ref, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react';
import { cx, type Surface } from '../util';
import styles from './controls.module.css';
import { useFieldControl } from './Field';

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  /** An identifier field: set in the code type, Geist Mono. */
  code?: boolean;
  surface?: Surface;
  ref?: Ref<HTMLInputElement>;
}

/** A text input. Inside a Field it takes the Field's label, helper and validation. */
export function Input({ code = false, surface, className, ref, ...rest }: InputProps) {
  const props = useFieldControl<HTMLInputElement, typeof rest>(rest);
  return (
    <input
      type="text"
      {...props}
      ref={ref}
      className={cx(styles.control, code && styles.code, className)}
      data-gk-surface={surface}
    />
  );
}

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  surface?: Surface;
  ref?: Ref<HTMLSelectElement>;
}

/** A native select with the ▼ glyph. Inside a Field it takes the Field's label and helper. */
export function Select({ surface, className, ref, children, ...rest }: SelectProps) {
  const props = useFieldControl<HTMLSelectElement, typeof rest>(rest);
  return (
    <span className={styles.selectWrap} data-gk-surface={surface}>
      <select {...props} ref={ref} className={cx(styles.control, styles.select, className)}>
        {children}
      </select>
      <span className={styles.chevron} aria-hidden="true">
        ▼
      </span>
    </span>
  );
}

export interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  surface?: Surface;
  ref?: Ref<HTMLTextAreaElement>;
}

/** A textarea in the code type, such as one URL per line. Inside a Field it takes the Field's label and helper. */
export function Textarea({ surface, className, rows = 4, ref, ...rest }: TextareaProps) {
  const props = useFieldControl<HTMLTextAreaElement, typeof rest>(rest);
  return (
    <textarea
      rows={rows}
      {...props}
      ref={ref}
      className={cx(styles.control, styles.textarea, className)}
      data-gk-surface={surface}
    />
  );
}
