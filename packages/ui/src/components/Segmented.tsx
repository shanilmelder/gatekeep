import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { cx, type Surface } from '../util';
import a11y from './a11y.module.css';
import styles from './Segmented.module.css';

export interface SegmentedOption {
  value: string;
  label: ReactNode;
}

export interface SegmentedProps {
  /** The group's visible name. */
  label: ReactNode;
  hideLabel?: boolean;
  /** Two to four mutually exclusive options (DESIGN.md, Selection), each with a unique value. */
  options: readonly SegmentedOption[];
  /** The selected value, when the caller controls it. One matching no option selects the first. */
  value?: string;
  /** The first selection when uncontrolled. The first option when absent or matching none. */
  defaultValue?: string;
  onChange?: (value: string) => void;
  /** Submits the selected value under this name, unless disabled. */
  name?: string;
  disabled?: boolean;
  surface?: Surface;
  className?: string;
}

type Move = (index: number, count: number) => number;
const next: Move = (index, count) => (index + 1) % count;
const previous: Move = (index, count) => (index - 1 + count) % count;
const KEYS: Record<string, Move> = {
  ArrowRight: next,
  ArrowDown: next,
  ArrowLeft: previous,
  ArrowUp: previous,
  Home: () => 0,
  End: (_, count) => count - 1,
};
// Right to left, the arrows follow the reading direction.
const RTL_KEYS: Record<string, Move> = { ...KEYS, ArrowRight: previous, ArrowLeft: next };

/**
 * A radio group drawn as segments. It's one tab stop, on the selected option. Arrow keys
 * move and select at once, wrapping at the ends, and Home and End go to the first and last.
 * Selecting changes form state only (EXPERIENCE.md, Component Patterns).
 */
export function Segmented({
  label,
  hideLabel = false,
  options,
  value,
  defaultValue,
  onChange,
  name,
  disabled = false,
  surface,
  className,
}: SegmentedProps) {
  if (import.meta.env?.DEV) {
    const values = options.map((option) => option.value);
    if (new Set(values).size !== values.length) {
      throw new Error(`Segmented options need unique values: ${values.join(', ')}.`);
    }
  }

  const labelId = useId();
  const [own, setOwn] = useState(defaultValue);
  const wanted = value ?? own;
  const matched = options.findIndex((option) => option.value === wanted);
  // A value matching no option falls back to the first, so what's submitted is what's shown.
  const selectedIndex = matched === -1 ? 0 : matched;
  const selected = options[selectedIndex]?.value;
  const buttons = useRef<(HTMLButtonElement | null)[]>([]);
  const refocus = useRef(false);
  const [, rerender] = useState(0);

  // Focus follows the selection once it renders, so a controlled change the caller refuses
  // leaves focus on the segment that is still selected, the group's one tab stop.
  useEffect(() => {
    if (!refocus.current) return;
    refocus.current = false;
    buttons.current[selectedIndex]?.focus();
  });

  function select(index: number) {
    const option = options[index];
    if (!option) return;
    if (value === undefined) setOwn(option.value);
    if (option.value !== selected) onChange?.(option.value);
    refocus.current = true;
    // Re-render even when nothing changed, so the effect puts focus back.
    rerender((count) => count + 1);
  }

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const keys = getComputedStyle(event.currentTarget).direction === 'rtl' ? RTL_KEYS : KEYS;
    const move = keys[event.key];
    if (!move || event.altKey || event.ctrlKey || event.metaKey) return;
    event.preventDefault();
    select(move(index, options.length));
  }

  return (
    <div className={cx(styles.segmented, className)} data-gk-surface={surface}>
      <span id={labelId} className={hideLabel ? a11y.visuallyHidden : styles.label}>
        {label}
      </span>
      <div role="radiogroup" aria-labelledby={labelId} aria-disabled={disabled || undefined} className={styles.track}>
        {options.map((option, index) => (
          <button
            key={option.value}
            ref={(element) => {
              buttons.current[index] = element;
            }}
            type="button"
            role="radio"
            aria-checked={index === selectedIndex}
            tabIndex={index === selectedIndex ? 0 : -1}
            disabled={disabled}
            className={styles.segment}
            onClick={() => select(index)}
            onKeyDown={(event) => handleKeyDown(event, index)}
          >
            {option.label}
          </button>
        ))}
      </div>
      {name !== undefined && selected !== undefined && !disabled && <input type="hidden" name={name} value={selected} />}
    </div>
  );
}
