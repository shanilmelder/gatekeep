import type { ReactNode } from 'react';
import { useMessages } from '../messages';
import { cx, type Surface } from '../util';
import a11y from './a11y.module.css';
import styles from './Table.module.css';
import matrix from './RbacMatrix.module.css';

export interface RbacAxis {
  /** Unique along its axis. */
  id: string;
  label: ReactNode;
}

export interface RbacMatrixProps {
  /** Names the table. */
  caption: ReactNode;
  hideCaption?: boolean;
  /** The row headers, such as Permissions, in mono. */
  rows: readonly RbacAxis[];
  /** The column headers, such as Roles. */
  columns: readonly RbacAxis[];
  /** Whether a row is allowed for a column. */
  allowed: (rowId: string, columnId: string) => boolean;
  surface?: Surface;
  className?: string;
}

/**
 * The RBAC matrix (UX-DR21): a real table with an ok tick where a row is allowed for a
 * column. The tick is decorative; each cell carries "Allowed" or "Not allowed" as text.
 */
export function RbacMatrix({ caption, hideCaption = false, rows, columns, allowed, surface, className }: RbacMatrixProps) {
  const messages = useMessages();
  return (
    <div className={cx(styles.card, className)} data-gk-surface={surface}>
      <table className={styles.table}>
        <caption className={hideCaption ? a11y.visuallyHidden : styles.caption}>{caption}</caption>
        <thead>
          <tr className={styles.headRow}>
            <th scope="col" className={styles.head}>
              <span className={a11y.visuallyHidden}>{messages.permission}</span>
            </th>
            {columns.map((column) => (
              <th key={column.id} scope="col" className={cx(styles.head, matrix.center)}>
                {column.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className={styles.row}>
              <th scope="row" className={cx(styles.cell, matrix.permission)}>
                {row.label}
              </th>
              {columns.map((column) => {
                const ok = allowed(row.id, column.id);
                return (
                  <td key={column.id} className={cx(styles.cell, matrix.center)} data-allowed={ok}>
                    {ok && (
                      <span className={matrix.tick} aria-hidden="true">
                        ✓
                      </span>
                    )}
                    <span className={a11y.visuallyHidden}>{ok ? messages.allowed : messages.notAllowed}</span>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
