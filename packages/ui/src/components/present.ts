import type { ReactNode } from 'react';

/** Whether an optional slot has something to render: undefined, null and false mean absent. */
export function present(node: ReactNode): boolean {
  return node !== undefined && node !== null && node !== false;
}
