import type { ReactNode } from 'react';
import { useMessages } from '../messages';
import { CodeBadge } from './Badge';
import { CopyButton } from './CopyButton';
import { Drawer, type DrawerProps } from './Drawer';
import styles from './EventDrawer.module.css';
import { JsonViewer } from './JsonViewer';

/** One summary row: a label and its value, such as "User" and an email. */
export interface EventSummaryRow {
  label: ReactNode;
  value: ReactNode;
  /** A stable React key. The row's index otherwise. */
  key?: string;
}

interface EventDrawerBaseProps extends Omit<DrawerProps, 'title' | 'children' | 'bodyClassName'> {
  /** The event type code, such as "user.login.failed", in the mono Log code badge. */
  code: string;
  /** A failure code sits on bad-sf, a success code on sf2. */
  outcome?: 'success' | 'failure';
  /** The event's title, beside its code. */
  title: ReactNode;
  /** The summary, as label and value pairs in a description list. */
  summary: readonly EventSummaryRow[];
}

/**
 * Whether the caller's role may see raw detail (FR-39), which the server decides. With
 * `canSeeRaw`, `raw` is shown as JSON with Copy JSON; a value JSON can't represent shows the
 * viewer's neutral message and no Copy. Without it, `raw` can't be passed at all, the raw
 * section isn't rendered, and a note says why.
 */
export type EventDrawerProps = EventDrawerBaseProps &
  ({ canSeeRaw: true; raw: unknown } | { canSeeRaw: false; raw?: never });

/** The value as indented JSON, or null when JSON can't represent it. */
function toJson(value: unknown): string | null {
  try {
    return JSON.stringify(value, null, 2) ?? null;
  } catch {
    return null;
  }
}

/**
 * The drawer for one Log event (EXPERIENCE.md, Logs · Event drawer): its code badge beside
 * its title, the summary rows, and, for a role that can see it, the raw JSON with Copy JSON.
 * Without `canSeeRaw`, the raw section is never rendered, so nothing of it reaches the DOM.
 */
export function EventDrawer({ code, outcome = 'success', title, summary, canSeeRaw, raw, ...rest }: EventDrawerProps) {
  const messages = useMessages();
  // Read only for a role that may see it, whatever an untyped caller passes, so the JSON is
  // never even serialised otherwise.
  const json = canSeeRaw ? toJson(raw) : null;
  return (
    <Drawer
      {...rest}
      title={
        <>
          <CodeBadge outcome={outcome}>{code}</CodeBadge> <span>{title}</span>
        </>
      }
    >
      {summary.length > 0 && (
        <dl className={styles.summary}>
          {summary.map((row, index) => (
            <div key={row.key ?? index} className={styles.row}>
              <dt className={styles.label}>{row.label}</dt>
              <dd className={styles.value}>{row.value}</dd>
            </div>
          ))}
        </dl>
      )}
      {canSeeRaw ? (
        // A plain group: the JSON viewer is already the region named "Raw event".
        <div className={styles.raw} data-event-raw="">
          <div className={styles.rawHeader}>
            <h3 className={styles.rawTitle}>
              {messages.rawEvent}
            </h3>
            {json !== null && <CopyButton value={json} what={messages.rawEventCopy} />}
          </div>
          <JsonViewer value={raw} label={messages.rawEvent} />
        </div>
      ) : (
        <p className={styles.limited} data-event-limited="">
          {messages.rawEventLimited}
        </p>
      )}
    </Drawer>
  );
}
