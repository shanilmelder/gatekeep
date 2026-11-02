import { useEffect, useId, useLayoutEffect, useRef, useState, type MouseEvent, type ReactNode } from 'react';
import { formatMessage, useMessages } from '../messages';
import { cx, type Surface } from '../util';
import a11y from './a11y.module.css';
import { Button } from './Button';
import { present } from './present';
import styles from './Table.module.css';

/** Rows per page (EXPERIENCE.md, Component Patterns: table). */
export const PAGE_SIZE = 50;

export interface DataTableColumn<Row> {
  /** Unique among the columns. */
  key: string;
  header: ReactNode;
  cell: (row: Row) => ReactNode;
  /** Right-aligned mono, such as counts and durations. */
  numeric?: boolean;
  /** The cell is the row's header: a `th scope="row"` naming the row. */
  rowHeader?: boolean;
  /**
   * The cell's content becomes the row's link: a button that opens the row, so Enter on it
   * activates the row as a click on the row does. Give it to one column, with `onRowActivate`.
   */
  rowLink?: boolean;
}

export interface DataTableProps<Row> {
  /** Names the table. Visually hidden with `hideCaption`, where a heading above already says it. */
  caption: ReactNode;
  hideCaption?: boolean;
  columns: readonly DataTableColumn<Row>[];
  rows: readonly Row[];
  /** A stable, unique key per row. */
  rowKey: (row: Row) => string;
  /**
   * Opens a row's detail. A pointer click anywhere on the row calls it, and so does Enter or
   * a click on the row's link. A click on any other control in the row, such as Copy, doesn't.
   */
  onRowActivate?: (row: Row) => void;
  /** The key of a row drawn selected, such as the one whose detail is open. */
  selectedKey?: string;
  /** Rows per page. 50 by default. */
  pageSize?: number;
  /** The page shown, from 0, when the caller controls it. */
  page?: number;
  onPageChange?: (page: number) => void;
  /**
   * Shown in place of the body when there are no rows: an EmptyState, with its one action
   * only where the role can take it. Without it, an empty table shows its head alone.
   */
  empty?: ReactNode;
  surface?: Surface;
  className?: string;
}

// A click on one of these belongs to the control, never to the row.
const INTERACTIVE =
  'a[href], button, input, select, textarea, label, summary, [contenteditable], [tabindex], [role="button"], [role="link"], [role="checkbox"], [role="switch"], [role="menuitem"], [role="tab"]';

/**
 * A real table (UX-DR11): `th scope` headers, 38px rows under a 32px head, numeric columns
 * right-aligned mono. It pages at 50 rows with Previous and Next and a "{from}–{to} of
 * {total}" status. Previous and Next stay focusable at the ends, marked aria-disabled.
 */
export function DataTable<Row>({
  caption,
  hideCaption = false,
  columns,
  rows,
  rowKey,
  onRowActivate,
  selectedKey,
  pageSize = PAGE_SIZE,
  page,
  onPageChange,
  empty,
  surface,
  className,
}: DataTableProps<Row>) {
  const messages = useMessages();
  const [own, setOwn] = useState(0);
  const tableRef = useRef<HTMLTableElement>(null);
  const pagerFocused = useRef(false);
  const captionId = useId();
  const pagerId = useId();
  // A size or page that isn't a finite number falls back, so the body never empties.
  const size = Number.isFinite(pageSize) && pageSize >= 1 ? Math.floor(pageSize) : PAGE_SIZE;
  const total = rows.length;
  const pages = Math.max(1, Math.ceil(total / size));
  const wanted = page !== undefined && Number.isFinite(page) ? Math.floor(page) : own;
  // A page past the end, after rows were removed, shows the last one.
  const current = Math.min(Math.max(0, wanted), pages - 1);
  const from = current * size;
  const shown = rows.slice(from, from + size);
  const paged = pages > 1;

  // Misuse is reported in every build, not only in development.
  const links = columns.filter((column) => column.rowLink).length;
  useEffect(() => {
    if (onRowActivate && links === 0) console.error('DataTable: onRowActivate needs a rowLink column, or the keyboard cannot open rows.');
    if (links > 1) console.error(`DataTable: ${links} columns set rowLink; give it to one.`);
  }, [Boolean(onRowActivate), links]);
  useEffect(() => {
    const keys = rows.map(rowKey);
    const duplicates = keys.filter((key, index) => keys.indexOf(key) !== index);
    if (duplicates.length > 0) console.error(`DataTable: rowKey values must be unique: ${[...new Set(duplicates)].join(', ')}.`);
  }, [rows, rowKey]);

  // An uncontrolled table keeps its stored page in range, so rows that shrink then grow
  // don't jump back to a stale page.
  useEffect(() => {
    if (page === undefined && own > pages - 1) setOwn(pages - 1);
  }, [page, own, pages]);

  // When the pager goes away while it holds focus, focus moves to the table, not to body.
  useLayoutEffect(() => {
    if (paged || !pagerFocused.current) return;
    pagerFocused.current = false;
    if (document.activeElement === null || document.activeElement === document.body) tableRef.current?.focus();
  }, [paged]);

  function go(to: number) {
    if (to < 0 || to >= pages || to === current) return;
    if (page === undefined) setOwn(to);
    onPageChange?.(to);
  }

  function handleRowClick(event: MouseEvent<HTMLTableRowElement>, row: Row) {
    if (!onRowActivate) return;
    const tr = event.currentTarget;
    // Only a control inside the row counts: one around the table is not the row's business.
    let control: Element | null = null;
    for (let element = event.target as Element | null; element && element !== tr; element = element.parentElement) {
      if (element.matches(INTERACTIVE)) {
        control = element;
        break;
      }
    }
    // A control inside the row acts on its own, unless it is the row's link.
    if (control && !control.hasAttribute('data-gk-row-link')) return;
    // A drag that selected text in the row is a selection, not a click.
    const selection = window.getSelection();
    if (!control && selection && !selection.isCollapsed && tr.contains(selection.anchorNode)) return;
    onRowActivate(row);
  }

  return (
    <div className={cx(styles.card, className)} data-gk-surface={surface}>
      <table ref={tableRef} tabIndex={-1} className={styles.table}>
        <caption id={captionId} className={hideCaption ? a11y.visuallyHidden : styles.caption}>
          {caption}
        </caption>
        <thead>
          <tr className={styles.headRow}>
            {columns.map((column) => (
              <th key={column.key} scope="col" className={cx(styles.head, column.numeric && styles.numeric)}>
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {total === 0 && present(empty) && (
            <tr>
              <td colSpan={columns.length} className={styles.emptyCell}>
                {empty}
              </td>
            </tr>
          )}
          {shown.map((row) => {
            const key = rowKey(row);
            return (
              <tr
                key={key}
                className={cx(styles.row, onRowActivate && styles.activatable, key === selectedKey && styles.selected)}
                aria-current={key === selectedKey || undefined}
                onClick={(event) => handleRowClick(event, row)}
              >
                {columns.map((column) => {
                  const Cell = column.rowHeader ? 'th' : 'td';
                  const content = column.cell(row);
                  return (
                    <Cell
                      key={column.key}
                      scope={column.rowHeader ? 'row' : undefined}
                      className={cx(styles.cell, column.numeric && styles.numeric)}
                    >
                      {column.rowLink && onRowActivate ? (
                        <button type="button" className={styles.rowLink} data-gk-row-link="">
                          {content}
                        </button>
                      ) : (
                        content
                      )}
                    </Cell>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
      {paged && (
        <nav
          className={styles.footer}
          // Named with the caption too, so two tables' pagers stay distinct landmarks.
          aria-labelledby={`${pagerId} ${captionId}`}
          onFocus={() => {
            pagerFocused.current = true;
          }}
          onBlur={(event) => {
            // Removal blurs with no next target; that case is the layout effect's.
            if (event.relatedTarget !== null) pagerFocused.current = false;
          }}
        >
          <span id={pagerId} className={a11y.visuallyHidden}>
            {messages.pagination}
          </span>
          <span role="status" className={styles.range}>
            {formatMessage(messages.pageRange, { from: from + 1, to: from + shown.length, total })}
          </span>
          <Button size="sm" aria-disabled={current === 0} onClick={() => go(current - 1)}>
            {messages.previousPage}
          </Button>
          <Button size="sm" aria-disabled={current === pages - 1} onClick={() => go(current + 1)}>
            {messages.nextPage}
          </Button>
        </nav>
      )}
    </div>
  );
}
