import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type FocusEvent,
  type KeyboardEvent,
  type MouseEvent,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
} from 'react';
import { cx, type Surface } from '../util';
import { Button } from './Button';
import styles from './Menu.module.css';

/** One entry: an action (`onSelect`), a link (`href`), or a divider. No checkbox, radio or submenu in v1. */
export type MenuItem =
  | {
      type?: 'item';
      label: ReactNode;
      /** A link: activating it navigates there. */
      href?: string;
      /** An action: called when the item is activated, after the menu closes. */
      onSelect?: () => void;
      /** Skipped by the arrow keys and can't be activated. */
      disabled?: boolean;
      /** Drawn in bad, such as Delete. Its action still leads to a confirming modal. */
      tone?: 'destructive';
      /** A stable React key. The item's index otherwise. */
      key?: string;
    }
  | { type: 'separator'; key?: string };

export interface MenuProps {
  /** The trigger's content, such as the Tenant's name, or an avatar with `aria-label`. */
  label: ReactNode;
  /**
   * The trigger's name when its content alone doesn't say what it is, such as an avatar's
   * initials. Start it with the visible text (WCAG 2.5.3), such as "AL, account".
   */
  'aria-label'?: string;
  items: readonly MenuItem[];
  /** The trigger's look. Ghost by default, as in the top bar. */
  variant?: 'secondary' | 'ghost';
  size?: 'md' | 'sm';
  /** Which edge of the trigger the popup lines up with. It moves in to stay in the viewport. */
  align?: 'start' | 'end';
  surface?: Surface;
  className?: string;
  'data-testid'?: string;
}

type Item = Extract<MenuItem, { label: ReactNode }>;
const isItem = (item: MenuItem): item is Item => item.type !== 'separator';
const enabled = (item: MenuItem | undefined): item is Item => item !== undefined && isItem(item) && !item.disabled;

/** How long typed characters keep adding to one typeahead search. */
const TYPEAHEAD_MS = 500;

/** A length custom property on `element`, in px, or `fallback`. */
function px(element: Element, name: string, fallback: number): number {
  const value = parseFloat(getComputedStyle(element).getPropertyValue(name));
  return Number.isFinite(value) ? value : fallback;
}

/** The nearest enabled item in `items` from `start`, inclusive, stepping by `step` and wrapping. */
function nearest(items: readonly MenuItem[], start: number, step: 1 | -1): number | undefined {
  const count = items.length;
  for (let offset = 0; offset < count; offset++) {
    const index = (((start + offset * step) % count) + count) % count;
    if (enabled(items[index])) return index;
  }
  return undefined;
}

/**
 * A menu button (WAI-ARIA APG menu button pattern), for the Tenant switcher, the avatar menu
 * and the User actions menu (EXPERIENCE.md, menu). A click, Enter, Space or ArrowDown on the
 * trigger opens it on the first item, ArrowUp on the last. Arrow keys move to the nearest
 * enabled neighbour and wrap, Home and End jump to the ends, and typing finds the next item
 * starting with what was typed in the last half second. Hovering an item focuses it, so only
 * one item is ever highlighted. Enter or Space activates an item and closes the menu, with
 * focus on the trigger unless the action moved it. Esc closes it and returns focus to the
 * trigger; Tab does too and then moves on. A press outside, focus leaving by any other route,
 * or the trigger leaving the viewport just closes it. With no enabled item, the trigger is
 * aria-disabled and never opens.
 *
 * It isn't modal: the page stays interactive. The popup is a manual popover in the top layer
 * (the Popover API is required), below the trigger and inside the viewport, and renders only
 * the items it's given.
 */
export function Menu({
  label,
  'aria-label': ariaLabel,
  items,
  variant = 'ghost',
  size = 'md',
  align = 'start',
  surface,
  className,
  'data-testid': testId,
}: MenuProps) {
  const id = useId();
  const triggerId = `${id}-trigger`;
  const menuId = `${id}-menu`;
  const [open, setOpen] = useState(false);
  const focusOnOpen = useRef<'first' | 'last'>('first');
  const wrapper = useRef<HTMLSpanElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const popup = useRef<HTMLUListElement>(null);
  const itemElements = useRef<(HTMLElement | null)[]>([]);
  const lastFocused = useRef(0);
  const typed = useRef({ text: '', at: 0 });
  const wasOpen = useRef(false);
  const frame = useRef<number | undefined>(undefined);
  // The items of the latest render, for effects that run only on opening.
  const latestItems = useRef(items);
  latestItems.current = items;

  const hasEnabled = items.some(enabled);

  const focusItem = (index: number | undefined) => {
    if (index !== undefined) itemElements.current[index]?.focus();
  };

  const show = (which: 'first' | 'last') => {
    if (!hasEnabled) return;
    focusOnOpen.current = which;
    if (open) focusItem(which === 'first' ? nearest(items, 0, 1) : nearest(items, items.length - 1, -1));
    setOpen(true);
  };

  /** Closes the menu. With `refocus`, focus goes back to the trigger first; without, it leaves the popup. */
  const close = useCallback((refocus: boolean) => {
    const active = document.activeElement;
    if (refocus) trigger.current?.focus();
    else if (active instanceof HTMLElement && popup.current?.contains(active)) active.blur();
    setOpen(false);
  }, []);

  const place = useCallback(() => {
    const button = trigger.current;
    const element = popup.current;
    if (!button || !element) return;
    const gap = px(element, '--gk-space-4', 4);
    const margin = px(element, '--gk-space-8', 8);
    const viewWidth = document.documentElement.clientWidth;
    const viewHeight = document.documentElement.clientHeight;
    const anchor = button.getBoundingClientRect();
    // A trigger scrolled out of view takes its menu with it.
    if (anchor.bottom <= 0 || anchor.top >= viewHeight || anchor.right <= 0 || anchor.left >= viewWidth) {
      close(false);
      return;
    }
    element.style.maxHeight = '';
    element.style.maxWidth = `${Math.max(viewWidth - 2 * margin, 0)}px`;
    const { width, height } = element.getBoundingClientRect();
    const below = viewHeight - anchor.bottom - gap - margin;
    const above = anchor.top - gap - margin;
    let top: number;
    // Below the trigger, unless it only fits, or fits better, above.
    if (height <= below || below >= above) {
      top = anchor.bottom + gap;
      if (height > below) element.style.maxHeight = `${Math.max(below, 0)}px`;
    } else {
      top = Math.max(margin, anchor.top - gap - height);
      if (height > above) element.style.maxHeight = `${Math.max(above, 0)}px`;
    }
    const rtl = getComputedStyle(button).direction === 'rtl';
    let left = (align === 'start') !== rtl ? anchor.left : anchor.right - width;
    left = Math.max(margin, Math.min(left, viewWidth - margin - width));
    element.style.top = `${top}px`;
    element.style.left = `${left}px`;
  }, [align, close]);

  // Opening and closing, in and out of the top layer. Focus moves to the first or last enabled
  // item only on opening, never when the menu is only placed again.
  useLayoutEffect(() => {
    const element = popup.current;
    if (!element) return;
    if (!open) {
      wasOpen.current = false;
      if (element.matches(':popover-open')) element.hidePopover();
      return;
    }
    if (wasOpen.current) return;
    wasOpen.current = true;
    if (!element.matches(':popover-open')) element.showPopover();
    // Placed before focus lands, so focusing an item never scrolls the page to an unplaced popup.
    place();
    const list = latestItems.current;
    const index = focusOnOpen.current === 'first' ? nearest(list, 0, 1) : nearest(list, list.length - 1, -1);
    (index === undefined ? element : itemElements.current[index])?.focus();
    // Only on opening: `place` changing (a new alignment) is the next effect's job.
  }, [open]);

  // Placed on opening and whenever the alignment changes, without moving focus.
  useLayoutEffect(() => {
    if (open) place();
  }, [open, place]);

  // Items that change while open: if the focused one went away or turned disabled, focus moves
  // to the nearest enabled item, or the popup itself when none is left.
  useLayoutEffect(() => {
    const element = popup.current;
    if (!open || !wasOpen.current || !element) return;
    const active = document.activeElement;
    const at = itemElements.current.findIndex((item) => item !== null && item === active);
    if (at !== -1 && enabled(items[at])) return;
    if (active && active !== document.body && active !== element && !element.contains(active)) return;
    if (active === element && !hasEnabled) return;
    const index = items.length > 0 ? nearest(items, Math.min(lastFocused.current, items.length - 1), 1) : undefined;
    (index === undefined ? element : itemElements.current[index])?.focus();
  }, [items, open, hasEnabled]);

  // While open: follow scrolling and resizing, once a frame, and close on a press outside.
  useEffect(() => {
    if (!open) return;
    const schedule = () => {
      if (frame.current !== undefined) return;
      frame.current = requestAnimationFrame(() => {
        frame.current = undefined;
        place();
      });
    };
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node | null;
      if (target && wrapper.current?.contains(target)) return;
      close(false);
    };
    document.addEventListener('pointerdown', onPointerDown, true);
    window.addEventListener('resize', schedule);
    window.addEventListener('scroll', schedule, true);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown, true);
      window.removeEventListener('resize', schedule);
      window.removeEventListener('scroll', schedule, true);
      if (frame.current !== undefined) cancelAnimationFrame(frame.current);
      frame.current = undefined;
    };
  }, [open, place, close]);

  // Focus leaving the trigger and popup by any route closes the menu. With no new target, as
  // when the focused item is removed, it waits to see where focus settles.
  function onBlur(event: FocusEvent<HTMLSpanElement>) {
    if (!open) return;
    const next = event.relatedTarget;
    if (next instanceof Node) {
      if (!event.currentTarget.contains(next)) close(false);
      return;
    }
    setTimeout(() => {
      const active = document.activeElement;
      if (active && active !== document.body && !wrapper.current?.contains(active)) close(false);
    });
  }

  function onTriggerKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      show('first');
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      show('last');
    } else if (event.key === 'Escape' && open) {
      event.preventDefault();
      close(true);
    }
  }

  function onTriggerClick() {
    if (open) close(true);
    else show('first');
  }

  function current(): number {
    return itemElements.current.findIndex((element) => element !== null && element === document.activeElement);
  }

  function typeahead(from: number, character: string) {
    const now = performance.now();
    const text = (now - typed.current.at > TYPEAHEAD_MS ? '' : typed.current.text) + character.toLocaleLowerCase();
    typed.current = { text, at: now };
    // The same letter again cycles through the items it starts; more letters refine the match
    // from the current item on.
    const repeated = [...text].every((letter) => letter === text[0]);
    const wanted = repeated ? text[0]! : text;
    const start = repeated ? from + 1 : Math.max(from, 0);
    const count = items.length;
    for (let offset = 0; offset < count; offset++) {
      const index = (((start + offset) % count) + count) % count;
      if (!enabled(items[index])) continue;
      const name = itemElements.current[index]?.textContent?.trim().toLocaleLowerCase() ?? '';
      if (name.startsWith(wanted)) {
        focusItem(index);
        return;
      }
    }
  }

  function onMenuKeyDown(event: KeyboardEvent<HTMLUListElement>) {
    const from = current();
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        focusItem(nearest(items, from === -1 ? 0 : from + 1, 1));
        return;
      case 'ArrowUp':
        event.preventDefault();
        focusItem(nearest(items, from === -1 ? items.length - 1 : from - 1, -1));
        return;
      case 'Home':
        event.preventDefault();
        focusItem(nearest(items, 0, 1));
        return;
      case 'End':
        event.preventDefault();
        focusItem(nearest(items, items.length - 1, -1));
        return;
      case 'Escape':
        // Handled here, so a drawer or modal the menu sits in stays open.
        event.preventDefault();
        close(true);
        return;
      case 'Tab':
        // Back on the trigger first, so the browser's own Tab moves on from there.
        close(true);
        return;
      case 'Enter':
      case ' ':
        event.preventDefault();
        if (from !== -1) itemElements.current[from]?.click();
        return;
    }
    if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey && event.key.trim() !== '') {
      event.preventDefault();
      typeahead(from, event.key);
    }
  }

  function onItemClick(item: Item, event: MouseEvent<HTMLElement>) {
    if (item.disabled) {
      event.preventDefault();
      return;
    }
    // Focus is on the trigger before the action runs, so a modal the action opens returns
    // focus there, and an action that moves focus elsewhere keeps it there. A link stays in
    // the page, hidden, so its navigation still happens.
    close(true);
    item.onSelect?.();
  }

  itemElements.current.length = items.length;

  return (
    <span ref={wrapper} className={cx(styles.wrapper, className)} data-gk-surface={surface} data-testid={testId} onBlur={onBlur}>
      <Button
        ref={trigger}
        id={triggerId}
        variant={variant}
        size={size}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={menuId}
        aria-label={ariaLabel}
        aria-disabled={hasEnabled ? undefined : true}
        onClick={onTriggerClick}
        onKeyDown={onTriggerKeyDown}
        data-menu-trigger=""
      >
        {label}
      </Button>
      <ul
        ref={popup}
        id={menuId}
        role="menu"
        aria-labelledby={triggerId}
        className={styles.menu}
        popover="manual"
        tabIndex={-1}
        onKeyDown={onMenuKeyDown}
      >
        {items.map((item, index) => {
          const key = item.key ?? index;
          if (!isItem(item)) {
            itemElements.current[index] = null;
            return <li key={key} role="separator" className={styles.separator} />;
          }
          const props = {
            ref: (element: HTMLElement | null) => {
              itemElements.current[index] = element;
            },
            role: 'menuitem',
            tabIndex: -1,
            className: cx(styles.item, item.tone === 'destructive' && styles.destructive),
            'aria-disabled': item.disabled || undefined,
            onClick: (event: MouseEvent<HTMLElement>) => onItemClick(item, event),
            onFocus: () => {
              lastFocused.current = index;
            },
            // Hover moves focus, so the pointer and the keyboard share the one highlight.
            onPointerMove: (event: ReactPointerEvent<HTMLElement>) => {
              if (!item.disabled && document.activeElement !== event.currentTarget) event.currentTarget.focus();
            },
          };
          return (
            <li key={key} role="none">
              {item.href !== undefined ? (
                <a {...props} href={item.disabled ? undefined : item.href}>
                  {item.label}
                </a>
              ) : (
                <button {...props} type="button">
                  {item.label}
                </button>
              )}
            </li>
          );
        })}
      </ul>
    </span>
  );
}
