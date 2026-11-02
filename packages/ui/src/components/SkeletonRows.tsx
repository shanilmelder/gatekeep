import { useEffect, useState } from 'react';
import { useMessages } from '../messages';
import { cx, type Surface } from '../util';
import a11y from './a11y.module.css';
import styles from './Table.module.css';
import skeleton from './SkeletonRows.module.css';

/** Loading shows nothing until this long has passed (EXPERIENCE.md, Global states). */
export const SKELETON_DELAY_MS = 300;

export interface SkeletonRowsProps {
  /** The rows the table will hold, such as its page size: the skeleton keeps their height. */
  rows: number;
  /** Bars per row. 4 by default. */
  columns?: number;
  /** Reserves the DataTable's visible caption. On by default, as on DataTable; off for `hideCaption`. */
  caption?: boolean;
  /** Reserves the DataTable's paging footer, shown when its rows fill more than one page. */
  footer?: boolean;
  /** Before the skeleton shows. 300ms by default; 0 or less shows it at once. */
  delay?: number;
  surface?: Surface;
  className?: string;
}

const count = (value: number, fallback: number, least: number) =>
  Number.isFinite(value) ? Math.max(least, Math.floor(value)) : fallback;

/**
 * Stands in for a loading DataTable with the same rows, caption and footer, and measures
 * what it will. It holds that height from the start, so nothing jumps, but draws the
 * skeleton only after 300ms, so a fast load never flashes it. The bars are hidden from
 * assistive technology; one polite status says "Loading" with them.
 */
export function SkeletonRows({
  rows,
  columns = 4,
  caption = true,
  footer = false,
  delay = SKELETON_DELAY_MS,
  surface,
  className,
}: SkeletonRowsProps) {
  const messages = useMessages();
  const [elapsed, setElapsed] = useState(false);
  const immediate = !(delay > 0);
  const shown = immediate || elapsed;

  useEffect(() => {
    if (immediate) return;
    const timer = setTimeout(() => setElapsed(true), delay);
    return () => clearTimeout(timer);
  }, [delay, immediate]);

  const lines = count(rows, 0, 0);
  const bars = count(columns, 4, 1);
  const barsOf = (prefix: string) => Array.from({ length: bars }, (_, bar) => <span key={`${prefix}${bar}`} className={skeleton.bar} />);
  return (
    <div className={cx(styles.card, className)} data-gk-surface={surface} data-shown={shown}>
      {/* The status exists from the start, so the text arriving in it is announced. */}
      <span role="status" className={a11y.visuallyHidden}>
        {shown ? messages.loading : ''}
      </span>
      <div aria-hidden="true" className={cx(!shown && skeleton.waiting)}>
        {caption && (
          <div className={styles.caption} data-part="caption">
            <span className={cx(skeleton.bar, skeleton.captionBar)} />
          </div>
        )}
        <div className={cx(skeleton.row, skeleton.headRow)} data-part="head">
          {barsOf('h')}
        </div>
        {Array.from({ length: lines }, (_, row) => (
          <div key={row} className={skeleton.row} data-part="row">
            {barsOf('r')}
          </div>
        ))}
        {footer && (
          <div className={styles.footer} data-part="footer">
            <span className={cx(skeleton.bar, skeleton.button)} />
          </div>
        )}
      </div>
    </div>
  );
}
