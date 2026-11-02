import { useId, type CSSProperties, type ReactNode } from 'react';
import { formatMessage, useMessages } from '../messages';
import { cx, type Surface } from '../util';
import styles from './Section.module.css';
import { present } from './present';

/*
 * The Section template's blocks (UX-DR21): StatTile, SettingsRow and UsageBar. The RBAC
 * matrix, also a Section block, is RbacMatrix.
 */

export interface StatTileProps {
  label: ReactNode;
  value: ReactNode;
  surface?: Surface;
  className?: string;
}

/** A label over a value, on an sf card. The label is the value's term, as in a description list. */
export function StatTile({ label, value, surface, className }: StatTileProps) {
  return (
    <dl className={cx(styles.tile, className)} data-gk-surface={surface}>
      <dt className={styles.tileLabel}>{label}</dt>
      <dd className={styles.tileValue}>{value}</dd>
    </dl>
  );
}

export interface SettingsRowProps {
  label: ReactNode;
  description?: ReactNode;
  /**
   * The control, such as a Toggle with `hideLabel`. The row groups it under the label and
   * description, so the control is read with them.
   */
  children: ReactNode;
  surface?: Surface;
  className?: string;
}

/** A setting: label and description on the left, its control on the right, over a bd divider. */
export function SettingsRow({ label, description, children, surface, className }: SettingsRowProps) {
  const id = useId();
  const labelId = `${id}-label`;
  const descriptionId = `${id}-description`;
  return (
    <div
      role="group"
      aria-labelledby={labelId}
      aria-describedby={present(description) ? descriptionId : undefined}
      className={cx(styles.settingsRow, className)}
      data-gk-surface={surface}
    >
      <div className={styles.settingsText}>
        <div id={labelId} className={styles.settingsLabel}>
          {label}
        </div>
        {present(description) && (
          <div id={descriptionId} className={styles.settingsDescription}>
            {description}
          </div>
        )}
      </div>
      <div className={styles.settingsControl}>{children}</div>
    </div>
  );
}

export interface UsageBarProps {
  label: ReactNode;
  value: number;
  max: number;
  min?: number;
  /** The visible and spoken text. "{value} of {max}" from the catalogue by default. */
  valueText?: string;
  surface?: Surface;
  className?: string;
}

/**
 * Usage against a limit: a role="meter" with its minimum, maximum and value, a visible
 * label and visible text, and an ac fill on an sf2 track. Outside the range, the fill and
 * aria-valuenow clamp, while the text and aria-valuetext keep the real value, such as "120 of 100".
 */
export function UsageBar({ label, value, max, min = 0, valueText, surface, className }: UsageBarProps) {
  const messages = useMessages();
  const id = useId();
  const labelId = `${id}-label`;
  // The bounds are made valid: non-finite ones fall back, and inverted ones swap.
  const low = Number.isFinite(min) ? min : 0;
  const high = Number.isFinite(max) ? max : low;
  const [lo, hi] = low <= high ? [low, high] : [high, low];
  const real = Number.isFinite(value) ? value : lo;
  // aria-valuenow stays in range, while the text says the real value, so overage shows.
  const clamped = Math.min(Math.max(real, lo), hi);
  const fraction = hi > lo ? (clamped - lo) / (hi - lo) : 0;
  const text = valueText ?? formatMessage(messages.usage, { value: real, max: hi });
  return (
    <div className={cx(styles.usage, className)} data-gk-surface={surface}>
      <div className={styles.usageText}>
        <span id={labelId}>{label}</span>
        <span className={styles.usageValue}>{text}</span>
      </div>
      <div
        role="meter"
        aria-labelledby={labelId}
        aria-valuemin={lo}
        aria-valuemax={hi}
        aria-valuenow={clamped}
        aria-valuetext={text}
        className={styles.track}
        style={{ '--gk-ui-usage': fraction } as CSSProperties}
      >
        <div className={styles.fill} />
      </div>
    </div>
  );
}
