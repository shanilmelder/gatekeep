import { useEffect, useId, useLayoutEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { cx, type Surface } from '../util';
import styles from './Tabs.module.css';
import { allowed, useUrlTab } from './useUrlTab';

export interface TabItem {
  /** Unique among the tabs. It's the value kept in the URL, and may hold any characters. */
  id: string;
  label: ReactNode;
  /** Rendered only while the tab is selected. */
  panel: ReactNode;
}

export interface TabsProps {
  /** Names the tab list, such as "Application settings". */
  label: string;
  tabs: readonly TabItem[];
  /**
   * Keeps the selected tab in the URL under this query parameter (useUrlTab), so the tab is
   * addressable and Back and Forward restore it. The URL wins over `selected`.
   */
  param?: string;
  /** The selected id, when the caller controls it: a selection then waits for the caller to update it. */
  selected?: string;
  /** The first selection when neither the URL nor `selected` gives one. The first tab when absent. */
  defaultSelected?: string;
  onSelect?: (id: string) => void;
  /**
   * Runs before the selection changes, by a click, a key, or Back and Forward, such as to
   * confirm leaving unsaved changes. When it returns or resolves to false, or throws, the
   * tab and the URL stay as they are.
   */
  canLeave?: (from: string, to: string) => boolean | Promise<boolean>;
  surface?: Surface;
  className?: string;
}

type Move = (index: number, count: number) => number;
const next: Move = (index, count) => (index + 1) % count;
const previous: Move = (index, count) => (index - 1 + count) % count;
const KEYS: Record<string, Move> = { ArrowRight: next, ArrowLeft: previous, Home: () => 0, End: (_, count) => count - 1 };
// Right to left, the arrows follow the reading direction.
const RTL_KEYS: Record<string, Move> = { ...KEYS, ArrowRight: previous, ArrowLeft: next };

// What a keyboard can reach inside a panel. With none, the panel itself is the tab stop.
const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), summary, [contenteditable]:not([contenteditable="false"]), [tabindex]:not([tabindex="-1"])';

/**
 * Tabs on the ARIA tab pattern with manual activation (UX-DR10). The tab list is one tab
 * stop, on the selected tab. Arrow keys move focus, wrapping at the ends, and Home and End
 * reach them, but only Enter, Space or a click selects, so moving focus never navigates.
 */
export function Tabs({ label, tabs, param, selected, defaultSelected, onSelect, canLeave, surface, className }: TabsProps) {
  const ids = tabs.map((tab) => tab.id);
  const idList = ids.join('\u0000');
  // Reported in every build, not only in development.
  useEffect(() => {
    if (new Set(ids).size !== ids.length) console.error(`Tabs need unique ids: ${ids.join(', ')}.`);
  }, [idList]);

  const base = useId();
  const [own, setOwn] = useState(defaultSelected);
  const buttons = useRef<(HTMLButtonElement | null)[]>([]);
  const panelRef = useRef<HTMLDivElement>(null);
  const [panelFocusable, setPanelFocusable] = useState(true);
  const guarding = useRef(false);

  // The first of these that names a tab is selected; none selects the first tab.
  const resolve = (fromUrl: string | null) => {
    const found = [fromUrl, selected, own, defaultSelected]
      .map((id) => (id == null ? -1 : tabs.findIndex((tab) => tab.id === id)))
      .find((index) => index !== -1);
    return found ?? 0;
  };

  // The latest render, for the checks that run after an awaited guard.
  const latest = useRef({ tabs, selectedIndex: 0, resolve, canLeave });

  const [fromUrl, selectInUrl] = useUrlTab(param ?? null, {
    canChange: (to) => {
      const now = latest.current;
      const from = now.tabs[now.selectedIndex];
      const target = now.tabs[now.resolve(to)];
      if (!from || !target || target.id === from.id || !now.canLeave) return true;
      return now.canLeave(from.id, target.id);
    },
  });

  const selectedIndex = resolve(fromUrl);
  const current = tabs[selectedIndex];
  latest.current = { tabs, selectedIndex, resolve, canLeave };

  // A panel holding a focusable element leaves the tab stop to it.
  useLayoutEffect(() => {
    const needsStop = panelRef.current?.querySelector(FOCUSABLE) == null;
    if (needsStop !== panelFocusable) setPanelFocusable(needsStop);
  });

  async function activate(target: number) {
    const tab = tabs[target];
    if (!tab || !current || target === selectedIndex || guarding.current) return;
    const href = window.location.href;
    guarding.current = true;
    let ok: boolean;
    try {
      ok = await allowed(canLeave && (() => canLeave(current.id, tab.id)));
    } finally {
      guarding.current = false;
    }
    if (!ok) return;
    // While the guard was out, the tab may have gone, been selected, or the URL moved on.
    const now = latest.current;
    const at = now.tabs.findIndex((candidate) => candidate.id === tab.id);
    if (at === -1 || at === now.selectedIndex || window.location.href !== href) return;
    if (param !== undefined) selectInUrl(tab.id);
    else if (selected === undefined) setOwn(tab.id);
    onSelect?.(tab.id);
  }

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>, at: number) {
    const keys = getComputedStyle(event.currentTarget).direction === 'rtl' ? RTL_KEYS : KEYS;
    const move = keys[event.key];
    if (!move || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
    event.preventDefault();
    buttons.current[move(at, tabs.length)]?.focus();
  }

  // DOM ids come from the index, so a tab id with spaces or any other character is safe.
  const tabId = (at: number) => `${base}-tab-${at}`;
  const panelId = (at: number) => `${base}-panel-${at}`;

  return (
    <div className={cx(styles.tabs, className)} data-gk-surface={surface}>
      <div role="tablist" aria-label={label} className={styles.list}>
        {tabs.map((tab, at) => (
          <button
            key={`${at}-${tab.id}`}
            ref={(element) => {
              buttons.current[at] = element;
            }}
            type="button"
            role="tab"
            id={tabId(at)}
            aria-selected={at === selectedIndex}
            aria-controls={panelId(at)}
            tabIndex={at === selectedIndex ? 0 : -1}
            className={styles.tab}
            onClick={() => void activate(at)}
            onKeyDown={(event) => handleKeyDown(event, at)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {tabs.map((tab, at) => (
        <div
          key={`${at}-${tab.id}`}
          ref={at === selectedIndex ? panelRef : undefined}
          role="tabpanel"
          id={panelId(at)}
          aria-labelledby={tabId(at)}
          hidden={at !== selectedIndex}
          tabIndex={at === selectedIndex && panelFocusable ? 0 : undefined}
          className={styles.panel}
        >
          {at === selectedIndex ? tab.panel : null}
        </div>
      ))}
    </div>
  );
}
