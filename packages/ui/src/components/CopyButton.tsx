import { useEffect, useRef, useState, type MouseEvent } from 'react';
import { formatMessage, useMessages } from '../messages';
import { cx, type Surface } from '../util';
import a11y from './a11y.module.css';
import { Button, type ButtonProps } from './Button';
import styles from './CopyButton.module.css';

/** How long "Copied" shows, and its announcement stays, after a copy (EXPERIENCE.md, Copy control). */
export const COPIED_MS = 2000;

export interface CopyButtonProps extends Omit<ButtonProps, 'children' | 'value' | 'variant' | 'pending'> {
  /** What to copy, or a function returning it at the moment of the click. */
  value: string | (() => string);
  /**
   * What is copied, such as "client ID". The name becomes the catalogue's `copyNamed`, such
   * as "Copy client ID", and `copiedNamed` after a copy, so repeated Copy controls stay unique.
   */
  what?: string;
  /** Ghost beside a value (the default), or secondary in a toolbar. */
  variant?: 'ghost' | 'secondary';
  surface?: Surface;
}

type Outcome = 'idle' | 'copied' | 'failed';

/**
 * The Copy control. It writes `value` to the clipboard and shows "Copied" for 2 seconds,
 * announced through its own role="status" region. A failure is announced in neutral words
 * and never repeats the value. Every copy empties the region first and fills it a frame
 * later, so a second copy in a row is announced again. It's a button, so a table row it
 * sits in doesn't open.
 */
export function CopyButton({ value, what, variant = 'ghost', size = 'sm', className, onClick, ...rest }: CopyButtonProps) {
  const messages = useMessages();
  const [outcome, setOutcome] = useState<Outcome>('idle');
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const frame = useRef<number | undefined>(undefined);
  const attempt = useRef(0);
  const mounted = useRef(false);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      clearTimeout(timer.current);
      if (frame.current !== undefined) cancelAnimationFrame(frame.current);
    };
  }, []);

  function settle(next: Outcome, id: number) {
    // A later click wins over an earlier copy that settles after it, and an unmounted
    // control settles nothing.
    if (id !== attempt.current || !mounted.current) return;
    frame.current = requestAnimationFrame(() => {
      frame.current = undefined;
      if (id !== attempt.current || !mounted.current) return;
      setOutcome(next);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setOutcome('idle'), COPIED_MS);
    });
  }

  async function handleClick(event: MouseEvent<HTMLButtonElement>) {
    onClick?.(event);
    if (event.defaultPrevented) return;
    const id = ++attempt.current;
    clearTimeout(timer.current);
    if (frame.current !== undefined) cancelAnimationFrame(frame.current);
    // Empty the region now. This click's render flushes it before the outcome's frame comes,
    // so the outcome arriving later is a change.
    setOutcome('idle');
    try {
      const text = typeof value === 'function' ? value() : value;
      if (!navigator.clipboard?.writeText) throw new Error('No clipboard');
      await navigator.clipboard.writeText(text);
      settle('copied', id);
    } catch {
      settle('failed', id);
    }
  }

  const copied = outcome === 'copied';
  const name = what === undefined ? undefined : formatMessage(copied ? messages.copiedNamed : messages.copyNamed, { what });
  return (
    <span className={cx(styles.copy, className)}>
      <Button {...rest} variant={variant} size={size} onClick={handleClick} aria-label={name} data-copied={copied || undefined}>
        {/*
          Both texts share one grid cell, so the button keeps its width when it flips. The
          hidden one is visibility: hidden, which also leaves it out of the name.
        */}
        <span className={styles.texts}>
          <span className={copied ? styles.hidden : undefined}>{messages.copy}</span>
          <span className={copied ? undefined : styles.hidden}>{messages.copied}</span>
        </span>
      </Button>
      <span role="status" className={a11y.visuallyHidden}>
        {copied ? messages.copied : outcome === 'failed' ? messages.copyFailed : ''}
      </span>
    </span>
  );
}
