import type { MouseEvent } from 'react';

/**
 * A link click the page handles itself: a plain primary click, unmodified. A click with a
 * modifier or another button opens a tab or window, so the browser keeps it.
 */
export function inPageClick(event: MouseEvent<HTMLAnchorElement>): boolean {
  return !event.defaultPrevented && event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey;
}
