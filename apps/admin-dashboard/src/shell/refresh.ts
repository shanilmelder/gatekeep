// The Tenants list refresh (Stories 1.27 and 1.29): which rows are still changing on their own,
// how long to wait before reading again, and how a refresh's rows replace the loaded ones.
//
// This module is plain TypeScript with type-only imports, so Node runs its tests directly
// (test/refresh.test.mjs).

import type { TenantListResponse, TenantResponse } from '@gatekeep/api-client';

/** The first wait before the list is read again while a row is still changing. */
export const REFRESH_MS = 2000;

/** The longest wait the backoff reaches: a long deletion is still read twice a minute, for good. */
export const REFRESH_MAX_MS = 30_000;

/** Refreshes at each wait before it doubles. */
const REFRESHES_PER_STEP = 10;

/**
 * The wait before the refresh after `done` refreshes: REFRESH_MS for the first ten, then doubling
 * every ten, up to REFRESH_MAX_MS. It never stops, so a Tenant being deleted for a long time is
 * never shown "Deleting" for good; it only costs fewer reads.
 */
export function refreshDelay(done: number): number {
  const steps = Math.min(Math.floor(Math.max(0, done) / REFRESHES_PER_STEP), 10);
  return Math.min(REFRESH_MS * 2 ** steps, REFRESH_MAX_MS);
}

/** The parts of a row this module reads. */
export type RefreshRow = Pick<TenantResponse, 'id' | 'createdAt' | 'status'> & {
  creation?: TenantResponse['creation'];
  deletion?: TenantResponse['deletion'];
};

/**
 * Whether a row is still changing on its own, so the list is read again: being created or deleted
 * by an Operation that is still running. A failed one waits for its Retry: it isn't read again.
 */
export function inProgress(row: Pick<RefreshRow, 'status' | 'creation' | 'deletion'>): boolean {
  if (row.status === 'creating') return row.creation?.status !== 'failed';
  if (row.status === 'deleting') return row.deletion?.status !== 'failed';
  return false;
}

/** Whether `row` sorts before or at `last` in the list's order: creation time, then ID. */
export function atOrBefore(row: RefreshRow, last: RefreshRow): boolean {
  return row.createdAt < last.createdAt || (row.createdAt === last.createdAt && row.id <= last.id);
}

/**
 * Whether the pages a refresh read so far reach the last loaded row, so the refresh can stop: it
 * reads pages from the first until one ends at or past it, or there is no next page.
 */
export function reaches(fresh: Pick<TenantListResponse, 'tenants' | 'nextCursor'>, loaded: readonly RefreshRow[]): boolean {
  const lastLoaded = loaded[loaded.length - 1];
  const lastFresh = fresh.tenants[fresh.tenants.length - 1];
  if (fresh.nextCursor == null || lastLoaded === undefined) return true;
  return lastFresh !== undefined && atOrBefore(lastLoaded, lastFresh);
}

/**
 * A refresh's rows over the loaded ones: `fresh` is every page the refresh read, in order, and its
 * `nextCursor` the last one's. Each loaded row the refresh has is replaced by it; a row being
 * deleted that the refresh no longer has, where the pages it read cover it, is gone, as a deleted
 * Tenant is never listed. Every other row stays as it was, and no row is added: Load more does that.
 */
export function merge<T extends RefreshRow>(current: readonly T[], fresh: { tenants: readonly T[]; nextCursor?: string | null }): T[] {
  const byId = new Map(fresh.tenants.map((row) => [row.id, row] as const));
  const last = fresh.tenants[fresh.tenants.length - 1];
  const covered = (row: T) => fresh.nextCursor == null || (last !== undefined && atOrBefore(row, last));
  return current.flatMap((row) => {
    const next = byId.get(row.id);
    if (next) return [next];
    return row.status === 'deleting' && covered(row) ? [] : [row];
  });
}
