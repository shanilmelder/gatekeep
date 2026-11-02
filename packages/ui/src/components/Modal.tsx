import type { ReactNode } from 'react';
import { cx, type Surface } from '../util';
import motion from './motion.module.css';
import styles from './Modal.module.css';
import { useModalDialog } from './useModalDialog';

export interface ModalProviderProps {
  children?: ReactNode;
}

/**
 * Marks the tree its modals live in. The one-at-a-time rule is per document, not per
 * provider: every Modal, under any provider or none, shares one registry, so sibling
 * providers can't stack modals either. Opening a second while one is open is refused, with
 * a console.error in every build, and the first stays open.
 */
export function ModalProvider({ children }: ModalProviderProps) {
  return <>{children}</>;
}

export interface ModalProps {
  /** Whether the modal is open. The caller owns it, and closes the modal from `onClose`. */
  open: boolean;
  /**
   * Esc, Cancel, a native close, or a refused open asked to close. Never a confirmation: a
   * confirming action is the caller's own button in `footer`.
   */
  onClose: () => void;
  /** The heading, which also names the dialog. */
  title: ReactNode;
  /** The body: what the action does, or the form it needs. It scrolls when it's tall. */
  children?: ReactNode;
  /** The footer's actions, right-aligned on sf2, always in view. */
  footer?: ReactNode;
  /**
   * Whether Esc closes the modal. On by default; a one-time reveal turns it off until the
   * value is copied, and a pending confirmation while it runs. Off, Esc does nothing at all.
   */
  dismissible?: boolean;
  /**
   * Where focus goes on close when the element that opened the modal is gone or hidden, such
   * as the next row after a deletion, or its section heading. With none, or none returned,
   * focus goes to the page's main heading.
   */
  fallbackFocus?: () => HTMLElement | null | undefined;
  /** The element to focus on open. The first focusable one in the body or footer otherwise. */
  initialFocus?: () => HTMLElement | null | undefined;
  /** Ids of what describes the dialog, such as the body's statement of impact. */
  describedBy?: string;
  surface?: Surface;
  className?: string;
  'data-testid'?: string;
}

/**
 * A modal on the native `<dialog>`, opened with showModal(), so the page behind is inert and
 * the browser keeps focus in the top layer; Tab and Shift+Tab also wrap inside it. Esc and the
 * caller's Cancel close it and confirm nothing. On close, focus returns to the element that
 * opened it, or, if that's gone, to `fallbackFocus`, or else to the page's main heading.
 *
 * One level deep: while a modal is open, any other in the document refuses to open, with a
 * console.error in every build, and calls its own `onClose`, so its caller's state falls back
 * to closed. The header and footer stay put and the body scrolls, so the actions never do.
 */
export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  dismissible = true,
  fallbackFocus,
  initialFocus,
  describedBy,
  surface,
  className,
  'data-testid': testId,
}: ModalProps) {
  const { ref, titleId, onKeyDown, onCancel } = useModalDialog({
    open,
    onClose,
    dismissible,
    fallbackFocus,
    initialFocus,
    refusal: 'Modal: another modal or drawer is already open. Modals are one level deep, so this one stays closed.',
  });

  return (
    <dialog
      ref={ref}
      className={cx(styles.modal, motion.rise, className)}
      // The title and body render only while open, so the references do too.
      aria-labelledby={open ? titleId : undefined}
      aria-describedby={open ? describedBy : undefined}
      data-gk-surface={surface}
      data-testid={testId}
      tabIndex={-1}
      onKeyDown={onKeyDown}
      onCancel={onCancel}
    >
      {open && (
        <>
          <div className={styles.header}>
            <h2 id={titleId} className={styles.title}>
              {title}
            </h2>
          </div>
          {children !== undefined && <div className={styles.body}>{children}</div>}
          {footer !== undefined && <div className={styles.footer}>{footer}</div>}
        </>
      )}
    </dialog>
  );
}
