import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { cx, type Surface } from '../util';
import { openModalElement, subscribeModal } from './modalRegistry';
import motion from './motion.module.css';
import styles from './Toast.module.css';

/** How long an Admin toast shows (EXPERIENCE.md, Component Patterns: 2.4 seconds, as in the export). */
export const TOAST_MS = 2400;

/**
 * Shows a toast confirming a completed action. Only a plain string: a toast never carries an
 * error, a value to copy, an action or any other content (EXPERIENCE.md). Errors go in a
 * Banner or inline.
 */
export type Toast = (message: string) => void;

const ToastContext = createContext<Toast | null>(null);

export interface ToastProviderProps {
  /**
   * Admin toasts leave after 2.4 seconds; Hosted (Account Portal) ones stay until the next
   * toast or the next action. Taken from the nearest data-gk-surface when absent, Admin
   * when there is none.
   */
  surface?: Surface;
  children?: ReactNode;
}

interface Shown {
  message: string;
  id: number;
}

type Placement = 'bottom' | 'top' | 'aside';

// The focus ring's outline and offset, kept clear around the focused control.
const RING = 4;

/** The toast's box where it comes to rest, without the rise animation's offset. */
function restingRect(element: HTMLElement): DOMRect {
  const rect = element.getBoundingClientRect();
  const [x = '0', y = '0'] = getComputedStyle(element).translate.split(' ');
  const dx = x === 'none' ? 0 : parseFloat(x) || 0;
  const dy = parseFloat(y) || 0;
  return new DOMRect(rect.x - dx, rect.y - dy, rect.width, rect.height);
}

function overlaps(a: DOMRect, b: DOMRect) {
  return a.left < b.right + RING && b.left - RING < a.right && a.top < b.bottom + RING && b.top - RING < a.bottom;
}

/**
 * Holds the one polite role="status" region toasts are announced through, and shows one
 * toast at a time: a new one replaces the last, and is announced afresh even when its text
 * is the same. The toast never covers the focused control: it sits at the bottom, moves to
 * the top when the focused control is under it, and, if it would cover that too, stays only
 * in the region for assistive technology.
 *
 * The region is a manual popover, so it sits in the top layer above any app chrome. While a
 * modal is open, the region renders inside that modal, the one part of the page that isn't
 * inert, and is shown after it, so a toast then is both seen above the modal and announced.
 * A toast asked for before the provider has mounted, such as from a child's mount effect,
 * waits and shows once it has.
 */
export function ToastProvider({ surface, children }: ToastProviderProps) {
  const [shown, setShown] = useState<Shown | null>(null);
  const region = useRef<HTMLDivElement>(null);
  const toastRef = useRef<HTMLDivElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const frame = useRef<number | undefined>(undefined);
  const next = useRef(0);
  const mounted = useRef(false);
  const queued = useRef<string | null>(null);
  const [modal, setModal] = useState<HTMLDialogElement | null>(openModalElement);
  const surfaceProp = useRef(surface);
  useLayoutEffect(() => {
    surfaceProp.current = surface;
  });

  const toast = useCallback<Toast>((message) => {
    if (typeof message !== 'string' || message === '') {
      console.error('toast: takes one non-empty plain string. Errors, values to copy and actions belong in a Banner or inline.');
      return;
    }
    if (!mounted.current) {
      queued.current = message;
      return;
    }
    const id = ++next.current;
    clearTimeout(timer.current);
    if (frame.current !== undefined) cancelAnimationFrame(frame.current);
    // Empty the region now and fill it a frame later, so the same text twice is a change.
    setShown(null);
    frame.current = requestAnimationFrame(() => {
      frame.current = undefined;
      if (!mounted.current || id !== next.current) return;
      setShown({ message, id });
      if (region.current && isHosted(region.current, surfaceProp.current)) return;
      timer.current = setTimeout(() => setShown((current) => (current?.id === id ? null : current)), TOAST_MS);
    });
  }, []);

  useEffect(() => {
    mounted.current = true;
    const waiting = queued.current;
    queued.current = null;
    if (waiting !== null) toast(waiting);
    return () => {
      mounted.current = false;
      clearTimeout(timer.current);
      if (frame.current !== undefined) cancelAnimationFrame(frame.current);
    };
  }, [toast]);

  // Follows the open modal, so the region moves inside it and back out.
  useEffect(() => {
    const sync = () => setModal(openModalElement());
    sync();
    return subscribeModal(sync);
  }, []);

  // Shows the region in the top layer whenever it mounts, here or inside a modal just opened.
  const regionRef = useCallback((element: HTMLDivElement | null) => {
    region.current = element;
    if (!element || typeof element.showPopover !== 'function' || element.matches(':popover-open')) return;
    try {
      element.showPopover();
    } catch {
      // Not connected yet, or already shown: the fixed region still works without the top layer.
    }
  }, []);

  // A Hosted toast stays until the next action: the next click or submit after it shows.
  useEffect(() => {
    if (!shown || !(region.current && isHosted(region.current, surfaceProp.current))) return;
    const id = shown.id;
    const dismiss = () => setShown((current) => (current?.id === id ? null : current));
    // Listening from the next task, so the click that led to this toast doesn't end it.
    const start = setTimeout(() => {
      document.addEventListener('click', dismiss, true);
      document.addEventListener('submit', dismiss, true);
    });
    return () => {
      clearTimeout(start);
      document.removeEventListener('click', dismiss, true);
      document.removeEventListener('submit', dismiss, true);
    };
  }, [shown]);

  // Keeps the toast off the focused control, now and whenever focus, scroll or size change.
  useLayoutEffect(() => {
    const element = toastRef.current;
    const container = region.current;
    if (!shown || !element || !container) return;
    const place = () => {
      const focused = document.activeElement;
      const target = focused instanceof HTMLElement && focused !== document.body ? focused.getBoundingClientRect() : null;
      let placement: Placement = 'bottom';
      for (const candidate of ['bottom', 'top'] as const) {
        container.dataset.placement = candidate;
        placement = candidate;
        if (!target || !overlaps(restingRect(element), target)) break;
        placement = 'aside';
      }
      container.dataset.placement = placement;
    };
    place();
    element.addEventListener('animationend', place);
    document.addEventListener('focusin', place);
    window.addEventListener('scroll', place, true);
    window.addEventListener('resize', place);
    return () => {
      element.removeEventListener('animationend', place);
      document.removeEventListener('focusin', place);
      window.removeEventListener('scroll', place, true);
      window.removeEventListener('resize', place);
    };
  }, [shown, modal]);

  const regionElement = (
    <div
      ref={regionRef}
      role="status"
      popover="manual"
      className={styles.region}
      data-gk-surface={surface}
      data-testid="toast-region"
    >
      {shown && (
        <div ref={toastRef} key={shown.id} className={cx(styles.toast, motion.riseQuick)} data-testid="toast">
          <svg className={styles.check} viewBox="0 0 16 16" aria-hidden="true" focusable="false">
            <path d="m3.5 8.5 3 3 6-7" />
          </svg>
          <span className={styles.message}>{shown.message}</span>
        </div>
      )}
    </div>
  );

  return (
    <ToastContext.Provider value={toast}>
      {children}
      {modal ? createPortal(regionElement, modal) : regionElement}
    </ToastContext.Provider>
  );
}

function isHosted(element: HTMLElement, surface: Surface | undefined) {
  return (surface ?? element.closest('[data-gk-surface]')?.getAttribute('data-gk-surface')) === 'hosted';
}

/**
 * The `toast(message)` of the nearest ToastProvider. Outside one it only reports the mistake,
 * with a console.error in every build.
 */
export function useToast(): Toast {
  const toast = useContext(ToastContext);
  return toast ?? missingProvider;
}

function missingProvider() {
  console.error('useToast: no ToastProvider above this component, so the toast was not shown.');
}
