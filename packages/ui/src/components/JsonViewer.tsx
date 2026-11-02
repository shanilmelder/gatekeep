import type { ReactNode } from 'react';
import { useMessages } from '../messages';
import { cx, type Surface } from '../util';
import styles from './JsonViewer.module.css';

export interface JsonViewerProps {
  /** Any JSON-serialisable value, shown indented by two spaces. */
  value: unknown;
  /** Names the region, such as "Raw event". Unique on the page. */
  label: string;
  surface?: Surface;
  className?: string;
}

// One token at a time: a string (a key when a colon follows), a number or a literal. Punctuation stays plain.
const TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b/g;

function highlight(line: string): ReactNode[] {
  const parts: ReactNode[] = [];
  let last = 0;
  for (const match of line.matchAll(TOKEN)) {
    const index = match.index ?? 0;
    if (index > last) parts.push(line.slice(last, index));
    const [whole, string, colon, number, literal] = match;
    if (string !== undefined) {
      parts.push(
        <span key={index} className={colon ? styles.key : styles.string}>
          {string}
        </span>,
      );
      if (colon) parts.push(colon);
    } else if (number !== undefined) {
      parts.push(
        <span key={index} className={styles.number}>
          {number}
        </span>,
      );
    } else if (literal !== undefined) {
      parts.push(
        <span key={index} className={styles.literal}>
          {literal}
        </span>,
      );
    }
    last = index + whole.length;
  }
  if (last < line.length) parts.push(line.slice(last));
  return parts;
}

/** The value as indented JSON, or null when JSON can't represent it: BigInt, a cycle, undefined, a function. */
function toJson(value: unknown): string | null {
  try {
    return JSON.stringify(value, null, 2) ?? null;
  } catch {
    return null;
  }
}

/**
 * Read-only, line-numbered JSON on DESIGN.md's json-viewer tokens. The line numbers are a
 * separate column hidden from assistive technology, so the JSON reads in order without
 * them. The region scrolls past a fixed height and is focusable so a keyboard can scroll
 * it. A value JSON can't represent shows the catalogue's neutral message, never the value.
 */
export function JsonViewer({ value, label, surface, className }: JsonViewerProps) {
  const messages = useMessages();
  const text = toJson(value);
  if (text === null) {
    return (
      <div className={cx(styles.viewer, styles.unavailable, className)} data-gk-surface={surface} role="region" aria-label={label}>
        <p className={styles.message}>{messages.jsonUnavailable}</p>
      </div>
    );
  }
  const lines = text.split('\n');
  return (
    <div className={cx(styles.viewer, className)} data-gk-surface={surface} role="region" aria-label={label} tabIndex={0}>
      <div className={styles.gutter} aria-hidden="true" data-gutter="">
        {lines.map((_, index) => (
          <span key={index}>{index + 1}</span>
        ))}
      </div>
      <pre className={styles.code}>
        <code>
          {lines.map((line, index) => (
            <span key={index}>
              {highlight(line)}
              {index < lines.length - 1 ? '\n' : null}
            </span>
          ))}
        </code>
      </pre>
    </div>
  );
}
