// The lost Tenant (Story 1.29, UX-DR22): a Tenant the Admin was working in that has gone for them,
// deleted or their role in it removed. The server answers both alike, with the same 403
// access_denied it gives any Tenant where the Admin holds no role, so it discloses nothing; the
// shell decides from what it knows itself. A path Tenant is lost when the Tenants list just read
// lacks it, and either the list this document held before had it, or it is the one this browser
// remembers. A Tenant never listed or remembered, such as a URL typed for another Tenant, isn't
// lost: its forbidden page stays as it was.
//
// This module is plain TypeScript with no import, so Node runs its tests directly
// (test/lostTenant.test.mjs).

/** The parts of a listed Tenant this module reads. */
export interface Listed {
  id: string;
}

/**
 * Whether `pathTenant` is lost: not in `listedNow`, and either in `listedBefore` (the switcher list
 * this document last held) or `remembered` (this browser's last Tenant). No path Tenant is never lost.
 */
export function isLost(
  pathTenant: string | null,
  listedBefore: readonly Listed[],
  remembered: string | null,
  listedNow: readonly Listed[],
): boolean {
  if (pathTenant === null || pathTenant === '') return false;
  if (listedNow.some((tenant) => tenant.id === pathTenant)) return false;
  return listedBefore.some((tenant) => tenant.id === pathTenant) || remembered === pathTenant;
}

/**
 * The lost Tenant's name, from the list held before, or null when it wasn't listed there: the
 * banner then names it by its ID.
 */
export function lostName<T extends Listed & { name: string }>(tenantId: string, listedBefore: readonly T[]): string | null {
  return listedBefore.find((tenant) => tenant.id === tenantId)?.name ?? null;
}

/**
 * Whether an answer is the server refusing a request in the page's own Tenant outright: a 403
 * access_denied to a request on /api/v1/tenants/{pageTenant}/…, which the shell answers by reading
 * its lists again. `path` is the request's path as sent, its IDs encoded; `page` is the Tenant the
 * page's path names.
 */
export function refusedInPageTenant(
  status: number,
  code: unknown,
  path: unknown,
  page: string | null,
): boolean {
  if (status !== 403 || code !== 'access_denied' || typeof path !== 'string' || page === null) return false;
  const match = /^\/api\/v1\/tenants\/([^/?#]+)(?:[/?#]|$)/.exec(path);
  if (!match) return false;
  try {
    return decodeURIComponent(match[1]!) === page;
  } catch {
    return false;
  }
}
