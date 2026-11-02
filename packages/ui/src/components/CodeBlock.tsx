import { useId } from 'react';
import { cx, type Surface } from '../util';
import styles from './CodeBlock.module.css';
import { CopyButton } from './CopyButton';

export interface CodeBlockProps {
  /** The code, shown read-only and copied whole. Never a secret (FR-43). */
  code: string;
  /** The header's filename, such as "app.ts". It also names the block. */
  filename: string;
  surface?: Surface;
  className?: string;
}

/**
 * Read-only code on code-bg, dark in both themes, under a header strip that holds the
 * filename and Copy (DESIGN.md, Code block). The code scrolls inside its own box, which is
 * focusable so a keyboard can scroll it.
 */
export function CodeBlock({ code, filename, surface, className }: CodeBlockProps) {
  const nameId = useId();
  return (
    <figure className={cx(styles.block, className)} data-gk-surface={surface} aria-labelledby={nameId}>
      <figcaption className={styles.header}>
        <span id={nameId} className={styles.filename}>
          {filename}
        </span>
        <CopyButton value={code} what={filename} className={styles.copy} />
      </figcaption>
      {/* A named group, not a landmark: focusable so a keyboard can scroll it. */}
      <pre className={styles.code} tabIndex={0} role="group" aria-labelledby={nameId}>
        <code>{code}</code>
      </pre>
    </figure>
  );
}
