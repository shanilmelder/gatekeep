import { useEffect, useId, useLayoutEffect, useRef, type KeyboardEvent, type SyntheticEvent } from 'react';
import { claimModal, releaseModal } from './modalRegistry';

/*
 * The behaviour every modal `<dialog>` in @gatekeep/ui shares, Modal (Story 1.16) and Drawer
 * (Story 1.17) alike: showModal(), so the page behind is inert; the one-per-document
 * registry, so a modal and a drawer never stack in either order; the Tab wrap; Esc, unless a
 * control inside handled it; and focus returning to the trigger, or a fallback, on close.
 */

export interface ModalDialogOptions {
  /** Whether the dialog is open. The caller owns it, and closes it from `onClose`. */
  open: boolean;
  /** Esc, a close button, a native close, or a refused open asked to close. */
  onClose: () => void;
  /** Whether Esc closes it. Off, Esc does nothing at all. */
  dismissible: boolean;
  /** Where focus goes on close when the trigger is gone or hidden. The page's main heading otherwise. */
  fallbackFocus?: () => HTMLElement | null | undefined;
  /** The element to focus on open. The first tabbable one otherwise. */
  initialFocus?: () => HTMLElement | null | undefined;
  /** What console.error says when the open is refused because another one is open. */
  refusal: string;
}

const TABBABLE =
  'a[href], area[href], button, input, select, textarea, summary, iframe, [tabindex], [contenteditable]:not([contenteditable="false"])';

/** Whether `element` is rendered: checkVisibility where the browser has it (Safari 17.4+). */
export function visible(element: HTMLElement): boolean {
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
export function tabbables(root: HTMLElement): HTMLElement[] {
  const candidates = [...root.querySelectorAll<HTMLElement>(TABBABLE)].filter(
    (element) =>
      element.tabIndex >= 0 &&
      !element.matches(':disabled') &&
      !(element instanceof HTMLInputElement && element.type === 'hidden') &&
      // A closed menu's hidden popup, or any other hidden subtree, takes no Tab stop.
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
// Firefox on macOS), focus is still on body when the dialog opens, and this is the trigger.
let lastActivated: { element: HTMLElement; at: number } | null = null;
if (typeof document !== 'undefined') {
  const remember = (event: Event) => {
    const target = event.target instanceof Element ? event.target.closest<HTMLElement>(TABBABLE) : null;
    if (target) lastActivated = { element: target, at: performance.now() };
  };
  document.addEventListener('pointerdown', remember, true);
  document.addEventListener('click', remember, true);
}

/** What opened the dialog: the focused element, or, with focus on body, the element just clicked. */
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
 * Drives a modal `<dialog>`: put `ref`, `onKeyDown` and `onCancel` on it, and name it with
 * `titleId`. On open it claims the document's one modal registry, or, if another dialog holds
 * it, refuses with a console.error in every build and calls `onClose`, so its caller's state
 * falls back to closed. On close, focus returns to what opened it, or, if that's gone, to
 * `fallbackFocus`, or else to the page's main heading.
 */
export function useModalDialog({ open, onClose, dismissible, fallbackFocus, initialFocus, refusal }: ModalDialogOptions) {
  const token = useId();
  const dialog = useRef<HTMLDialogElement>(null);
  const wanted = useRef(false);
  // The latest callbacks, read when an event or the close happens, never stale.
  const latest = useRef({ onClose, dismissible, fallbackFocus, initialFocus, refusal });
  useLayoutEffect(() => {
    latest.current = { onClose, dismissible, fallbackFocus, initialFocus, refusal };
  });

  useLayoutEffect(() => {
    const element = dialog.current;
    if (!open || !element) return;
    const trigger = opener();
    if (!claimModal(token, element)) {
      console.error(latest.current.refusal);
      latest.current.onClose();
      return;
    }
    wanted.current = true;
    if (!element.open) element.showModal();
    // After the commit and any synchronous rerender it set off, so the content focus lands
    // on is the content the dialog opens with.
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
      // and not at all if the dialog opened again meanwhile (as StrictMode's rerun does).
      queueMicrotask(() => {
        if (wanted.current) return;
        const target = focusable(trigger) ? trigger : latest.current.fallbackFocus?.();
        (focusable(target) ? target : mainHeading())?.focus();
      });
    };
  }, [open, token]);

  // Unexpected closes, such as dialog.close() or a form with method="dialog": a dismissible
  // dialog releases the registry, so another can open even if its caller keeps `open` true,
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

  function onKeyDown(event: KeyboardEvent<HTMLDialogElement>) {
    const element = event.currentTarget;
    if (event.key === 'Escape') {
      // A control inside that handled Esc itself, such as an open listbox or menu, or an IME
      // composition that Esc cancels, keeps the dialog open.
      if (event.defaultPrevented || event.nativeEvent.isComposing) return;
      // Cancelling the key stops the browser's own close request, so Esc closes only through
      // onClose, and not at all while the dialog isn't dismissible.
      event.preventDefault();
      if (latest.current.dismissible) latest.current.onClose();
      return;
    }
    if (event.key !== 'Tab' || event.altKey || event.ctrlKey || event.metaKey) return;
    // An open menu inside moves focus back to its trigger first, so Tab moves on from there.
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
  function onCancel(event: SyntheticEvent<HTMLDialogElement>) {
    event.preventDefault();
    if (latest.current.dismissible) latest.current.onClose();
  }

  return { ref: dialog, titleId: `${token}-title`, onKeyDown, onCancel };
}
