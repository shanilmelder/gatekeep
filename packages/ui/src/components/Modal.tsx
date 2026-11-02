import { useEffect, useId, useLayoutEffect, useRef, type KeyboardEvent, type ReactNode, type SyntheticEvent } from 'react';
import { cx, type Surface } from '../util';
import { claimModal, releaseModal } from './modalRegistry';
import motion from './motion.module.css';
import styles from './Modal.module.css';

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

const TABBABLE =
  'a[href], area[href], button, input, select, textarea, summary, iframe, [tabindex], [contenteditable]:not([contenteditable="false"])';

/** Whether `element` is rendered: checkVisibility where the browser has it (Safari 17.4+). */
function visible(element: HTMLElement): boolean {
  return typeof element.checkVisibility === 'function'
    ? element.checkVisibility({ visibilityProperty: true })
    : element.getClientRects().length > 0;
}

const isRadio = (element: HTMLElement): element is HTMLInputElement =>
  element instanceof HTMLInputElement && element.type === 'radio' && element.name !== '';

/**
 * The elements Tab stops on inside `root`, in document order: no disabled control, including
 * those in a disabled fieldset, and one radio per group, the checked one or else the first.
 */
function tabbables(root: HTMLElement): HTMLElement[] {
  const candidates = [...root.querySelectorAll<HTMLElement>(TABBABLE)].filter(
    (element) =>
      element.tabIndex >= 0 &&
      !element.matches(':disabled') &&
      !(element instanceof HTMLInputElement && element.type === 'hidden') &&
      visible(element),
  );
  const radios = new Map<string, HTMLInputElement>();
  for (const element of candidates) {
    if (!isRadio(element)) continue;
    const chosen = radios.get(element.name);
    if (!chosen || (!chosen.checked && element.checked)) radios.set(element.name, element);
  }
  return candidates.filter((element) => !isRadio(element) || radios.get(element.name) === element);
}

// The element a pointer last activated. Where a click doesn't focus what it hits (Safari,
// Firefox on macOS), focus is still on body when the modal opens, and this is the trigger.
let lastActivated: { element: HTMLElement; at: number } | null = null;
if (typeof document !== 'undefined') {
  const remember = (event: Event) => {
    const target = event.target instanceof Element ? event.target.closest<HTMLElement>(TABBABLE) : null;
    if (target) lastActivated = { element: target, at: performance.now() };
  };
  document.addEventListener('pointerdown', remember, true);
  document.addEventListener('click', remember, true);
}

/** What opened the modal: the focused element, or, with focus on body, the element just clicked. */
function opener(): HTMLElement | null {
  const active = document.activeElement;
  if (active instanceof HTMLElement && active !== document.body) return active;
  return lastActivated && performance.now() - lastActivated.at < 1000 ? lastActivated.element : null;
}

/** Whether focus can usefully return to `element`: still in the page, shown and enabled. */
function focusable(element: HTMLElement | null | undefined): element is HTMLElement {
  return (
    !!element &&
    element.isConnected &&
    element !== document.body &&
    !element.matches(':disabled') &&
    !element.closest('[inert]') &&
    visible(element)
  );
}

/** The page's main heading, made focusable from script if it isn't already. */
function mainHeading(): HTMLElement | null {
  const heading = document.querySelector<HTMLElement>('main h1') ?? document.querySelector<HTMLElement>('h1');
  if (heading && !heading.hasAttribute('tabindex')) heading.tabIndex = -1;
  return heading;
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
  const token = useId();
  const titleId = `${token}-title`;
  const dialog = useRef<HTMLDialogElement>(null);
  const wanted = useRef(false);
  // The latest callbacks, read when an event or the close happens, never stale.
  const latest = useRef({ onClose, dismissible, fallbackFocus, initialFocus });
  useLayoutEffect(() => {
    latest.current = { onClose, dismissible, fallbackFocus, initialFocus };
  });

  useLayoutEffect(() => {
    const element = dialog.current;
    if (!open || !element) return;
    const trigger = opener();
    if (!claimModal(token, element)) {
      console.error('Modal: another modal is already open. Modals are one level deep, so this one stays closed.');
      latest.current.onClose();
      return;
    }
    wanted.current = true;
    if (!element.open) element.showModal();
    // After the commit and any synchronous rerender it set off, so the content focus lands
    // on is the content the modal opens with.
    queueMicrotask(() => {
      if (!wanted.current || !element.open) return;
      const first = latest.current.initialFocus?.() ?? tabbables(element)[0];
      (first ?? element).focus();
    });

    return () => {
      wanted.current = false;
      releaseModal(token);
      if (element.open) element.close();
      // Once the whole commit is done, so a trigger the same update removes counts as gone,
      // and not at all if the modal opened again meanwhile (as StrictMode's rerun does).
      queueMicrotask(() => {
        if (wanted.current) return;
        const target = focusable(trigger) ? trigger : latest.current.fallbackFocus?.();
        (focusable(target) ? target : mainHeading())?.focus();
      });
    };
  }, [open, token]);

  // Unexpected closes, such as dialog.close() or a form with method="dialog": a dismissible
  // modal releases the registry, so another can open even if its caller keeps `open` true,
  // and reports it; one that isn't dismissible reopens, so only its caller can close it.
  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    const onNativeClose = () => {
      if (!wanted.current || element.open) return;
      if (latest.current.dismissible) {
        wanted.current = false;
        releaseModal(token);
        latest.current.onClose();
      } else {
        element.showModal();
      }
    };
    element.addEventListener('close', onNativeClose);
    return () => element.removeEventListener('close', onNativeClose);
  }, [token]);

  function handleKeyDown(event: KeyboardEvent<HTMLDialogElement>) {
    const element = event.currentTarget;
    if (event.key === 'Escape') {
      // A control inside that handled Esc itself, such as an open listbox, or an IME
      // composition that Esc cancels, keeps the modal open.
      if (event.defaultPrevented || event.nativeEvent.isComposing) return;
      // Cancelling the key stops the browser's own close request, so Esc closes only through
      // onClose, and not at all while the modal isn't dismissible.
      event.preventDefault();
      if (latest.current.dismissible) latest.current.onClose();
      return;
    }
    if (event.key !== 'Tab' || event.altKey || event.ctrlKey || event.metaKey) return;
    const stops = tabbables(element);
    const first = stops[0];
    const last = stops[stops.length - 1];
    const active = document.activeElement;
    if (!first || !last) {
      event.preventDefault();
      element.focus();
    } else if (event.shiftKey && (active === first || active === element || !element.contains(active))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || !element.contains(active))) {
      event.preventDefault();
      first.focus();
    }
  }

  // A close request Esc didn't cover, such as a browser gesture.
  function handleCancel(event: SyntheticEvent<HTMLDialogElement>) {
    event.preventDefault();
    if (latest.current.dismissible) latest.current.onClose();
  }

  return (
    <dialog
      ref={dialog}
      className={cx(styles.modal, motion.rise, className)}
      // The title and body render only while open, so the references do too.
      aria-labelledby={open ? titleId : undefined}
      aria-describedby={open ? describedBy : undefined}
      data-gk-surface={surface}
      data-testid={testId}
      tabIndex={-1}
      onKeyDown={handleKeyDown}
      onCancel={handleCancel}
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
