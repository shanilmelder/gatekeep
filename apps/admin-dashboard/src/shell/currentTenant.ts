// The current Tenant (Story 1.28, AD-19). On a /tenants/{tenantId}/… path it is the path's Tenant
// and nothing else. Elsewhere it is the Tenant this browser last visited, if the Admin still holds
// a role there, else the first one listed. The remembered one is a per-browser convenience in
// localStorage: it chooses only which listed Tenant the top bar names and the landing opens. It is
// filtered to the listed Tenants, so it grants nothing, and every request still names its Tenant
// in its own path. A storage that fails or is missing means none.
//
// This module is plain TypeScript with no import, so Node runs its tests directly
// (test/currentTenant.test.mjs).

/** The parts of a listed Tenant this module reads. */
export interface Listed {
  id: string;
}

/** The storage this module uses: localStorage, or a test's stand-in. */
export interface Store {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem?(key: string): void;
}

const TENANT_PATH = /^\/tenants\/([^/]+)(\/.*)?$/;

/**
 * The Tenant a path names: its /tenants/ segment decoded once, `malformed` when its escapes
 * don't decode, or null on any other path. Never validated here: only the server decides.
 */
export function tenantOfPath(path: string): string | 'malformed' | null {
  const match = TENANT_PATH.exec(path);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]!);
  } catch {
    return 'malformed';
  }
}

/** A Tenant's public ID in its canonical shape: `ten_` and 26 lowercase base32 characters. */
const TENANT_ID = /^ten_[a-z2-7]{26}$/;

/**
 * The Tenant the page shows, for the X-Gatekeep-Tenant header: the path's Tenant when it has the
 * shape of a `ten_` ID, else null, so nothing else is ever sent. Read at send time, so a page
 * whose URL has moved on sends the new one.
 */
export function pageTenant(path: string): string | null {
  const tenant = tenantOfPath(path);
  return typeof tenant === 'string' && TENANT_ID.test(tenant) ? tenant : null;
}

/**
 * The current Tenant: on a Tenant path, the path's Tenant when it is listed and null when it
 * isn't; elsewhere the remembered one when listed, else the first, else null.
 */
export function current<T extends Listed>(path: string, tenants: readonly T[], remembered: string | null): T | null {
  const onPath = tenantOfPath(path);
  if (onPath !== null) return typeof onPath === 'string' ? (tenants.find((tenant) => tenant.id === onPath) ?? null) : null;
  return (remembered === null ? undefined : tenants.find((tenant) => tenant.id === remembered)) ?? tenants[0] ?? null;
}

/**
 * Where choosing Tenant `to` goes from `path`: the same page in that Tenant on a Tenant path,
 * else the Tenant's own landing. One Application's page is the other Tenant's Applications list,
 * as its Application isn't that Tenant's (Story 3.1). The search and hash are dropped, and the
 * result always starts with /tenants/, so it is same-origin and path-absolute whatever `path` holds.
 */
export function switchHref(path: string, to: string): string {
  const target = `/tenants/${encodeURIComponent(to)}`;
  const match = TENANT_PATH.exec(path);
  const rest = (match?.[2] ?? '').replace(/^\/applications\/.*$/, '/applications');
  // Only plain path segments carry over: anything that could leave the path is dropped.
  return /^(?:\/[A-Za-z0-9._~%!$&'()*+,;=:@-]*)*$/.test(rest) ? `${target}${rest}` : target;
}

/** The localStorage key for an Admin's last Tenant. */
export function rememberKey(adminId: string): string {
  return `gatekeep.admin.lastTenant.${adminId}`;
}

function storage(store?: Store | null): Store | null {
  if (store !== undefined) return store;
  try {
    return (globalThis as { localStorage?: Store }).localStorage ?? null;
  } catch {
    return null;
  }
}

/** Remembers `tenantId` as this browser's last Tenant for the Admin. A failure remembers nothing. */
export function remember(adminId: string, tenantId: string, store?: Store | null): void {
  try {
    storage(store)?.setItem(rememberKey(adminId), tenantId);
  } catch {
    // Storage blocked or full: the top bar falls back to the first listed Tenant.
  }
}

/** Forgets the Admin's last Tenant in this browser (Story 1.29), as when it is lost. A failure forgets nothing. */
export function forget(adminId: string, store?: Store | null): void {
  try {
    storage(store)?.removeItem?.(rememberKey(adminId));
  } catch {
    // Storage blocked: the remembered Tenant is still filtered to the listed ones, so it grants nothing.
  }
}

/** The Admin's last Tenant in this browser, or null when none, or storage fails. */
export function remembered(adminId: string, store?: Store | null): string | null {
  try {
    const value = storage(store)?.getItem(rememberKey(adminId));
    return typeof value === 'string' && value !== '' ? value : null;
  } catch {
    return null;
  }
}
