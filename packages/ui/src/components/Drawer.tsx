import { useEffect, useRef, useState, type ReactNode, type RefObject } from 'react';
import { useMessages } from '../messages';
import { cx, type Surface } from '../util';
import { Button } from './Button';
import motion from './motion.module.css';
import styles from './Drawer.module.css';
import { useModalDialog } from './useModalDialog';

export interface DrawerProps {
  /** Whether the drawer is open. The caller owns it, and closes the drawer from `onClose`. */
  open: boolean;
  /** Esc, the Close button, a native close, or a refused open asked to close. */
  onClose: () => void;
  /** The heading, which also names the dialog. */
  title: ReactNode;
  /** The body, which scrolls on its own between the pinned header and footer. */
  children?: ReactNode;
  /** Optional actions, pinned under the body. */
  footer?: ReactNode;
  /**
   * Where focus goes on close when the element that opened the drawer is gone or hidden, such
   * as the next row. With none, or none returned, focus goes to the page's main heading.
   */
  fallbackFocus?: () => HTMLElement | null | undefined;
  /** The element to focus on open. The Close button otherwise. */
  initialFocus?: () => HTMLElement | null | undefined;
  /** Ids of what describes the dialog. */
  describedBy?: string;
  surface?: Surface;
  className?: string;
  /** Extra classes for the scrolling body. */
  bodyClassName?: string;
  'data-testid'?: string;
}

/**
 * A side panel from the inline end, 440px wide and never more than half the window
 * (DESIGN.md, components.drawer), for detail such as a Log event. It is a native `<dialog>`
 * opened with showModal(), sharing Modal's behaviour: the page behind is inert, focus stays
 * inside, Esc and Close close it, and focus returns to the trigger, or to `fallbackFocus` if
 * that's gone. It takes the same one-per-document registry, so while a modal is open a drawer
 * refuses to open, with a console.error, and the reverse.
 */
export function Drawer({
  open,
  onClose,
  title,
  children,
  footer,
  fallbackFocus,
  initialFocus,
  describedBy,
  surface,
  className,
  bodyClassName,
  'data-testid': testId,
}: DrawerProps) {
  const messages = useMessages();
  const close = useRef<HTMLButtonElement>(null);
  const { ref, titleId, onKeyDown, onCancel } = useModalDialog({
    open,
    onClose,
    dismissible: true,
    fallbackFocus,
    // Close by default, whatever the title or body holds.
    initialFocus: initialFocus ?? (() => close.current),
    refusal: 'Drawer: a modal or drawer is already open. Modals are one level deep, so this drawer stays closed.',
  });
  const body = useRef<HTMLDivElement>(null);
  const scrolls = useScrolls(body, open);

  return (
    <dialog
      ref={ref}
      className={cx(styles.drawer, motion.slide, className)}
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
            <Button ref={close} variant="ghost" size="sm" className={styles.close} onClick={onClose}>
              {messages.closeDrawer}
            </Button>
          </div>
          <div
            ref={body}
            className={cx(styles.body, bodyClassName)}
            // A body that overflows is a Tab stop, so a keyboard can scroll it.
            tabIndex={scrolls ? 0 : undefined}
            role={scrolls ? 'region' : undefined}
            aria-label={scrolls ? messages.drawerBody : undefined}
            data-drawer-body=""
          >
            {children}
          </div>
          {footer !== undefined && <div className={styles.footer}>{footer}</div>}
        </>
      )}
    </dialog>
  );
}

/**
 * Whether the element overflows vertically, kept up to date as it resizes and as its content
 * changes: a ResizeObserver on it and each child, re-observed whenever children come or go,
 * or the window's resize where there's no ResizeObserver.
 */
function useScrolls(element: RefObject<HTMLElement | null>, active: boolean): boolean {
  const [scrolls, setScrolls] = useState(false);
  useEffect(() => {
    const target = element.current;
    if (!active || !target) {
      setScrolls(false);
      return;
    }
    const measure = () => setScrolls(target.scrollHeight > target.clientHeight + 1);
    const resize = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure);
    const observe = () => {
      if (!resize) return;
      resize.disconnect();
      resize.observe(target);
      for (const child of target.children) resize.observe(child);
    };
    const mutations = new MutationObserver(() => {
      observe();
      measure();
    });
    mutations.observe(target, { childList: true, subtree: true, characterData: true });
    observe();
    measure();
    if (!resize) window.addEventListener('resize', measure);
    return () => {
      mutations.disconnect();
      resize?.disconnect();
      window.removeEventListener('resize', measure);
    };
  }, [element, active]);
  return scrolls;
}
