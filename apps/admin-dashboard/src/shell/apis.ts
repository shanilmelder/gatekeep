// APIs (Story 3.6): the pages' paths, and the browser's checks before a create or a Permission add. The server's rules
// are the same: the name trimmed, then 1 to 200 UTF-16 units with no control character; the identifier 1 to 255
// characters, an absolute URI with a scheme and no fragment or white space, never under urn:gatekeep:; a Permission
// resource:action. This is feedback only: the server runs every rule again and decides every request.
//
// Plain TypeScript with no import, so Node runs its tests directly (test/apis.test.mjs).

export const API_NAME_MAX_LENGTH = 200;
export const API_IDENTIFIER_MAX_LENGTH = 255;
export const PERMISSION_DESCRIPTION_MAX_LENGTH = 200;

/** The prefix only the built-in Gatekeep Management API's identifier has. */
export const RESERVED_IDENTIFIER_PREFIX = 'urn:gatekeep:';

const CONTROL = /\p{Cc}/u;
const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:./;
const SPACE = /\s/u;
const PERMISSION = /^[a-z0-9][a-z0-9_.-]{0,63}:[a-z0-9][a-z0-9_.-]{0,63}$/;

export type ApiNameCheck = { kind: 'ok'; name: string } | { kind: 'empty' } | { kind: 'invalid' };

/** The trimmed name, or why it can't be one. */
export function checkApiName(value: string): ApiNameCheck {
  const name = value.trim();
  if (name === '') return { kind: 'empty' };
  if (name.length > API_NAME_MAX_LENGTH || CONTROL.test(name)) return { kind: 'invalid' };
  return { kind: 'ok', name };
}

export type ApiIdentifierCheck = { kind: 'ok' } | { kind: 'empty' } | { kind: 'invalid' } | { kind: 'reserved' };

/** Whether `value` may be an identifier, exactly as typed: it is never trimmed, since it is matched exactly. */
export function checkApiIdentifier(value: string): ApiIdentifierCheck {
  if (value === '') return { kind: 'empty' };
  if (
    value.length > API_IDENTIFIER_MAX_LENGTH ||
    SPACE.test(value) ||
    CONTROL.test(value) ||
    value.includes('#') ||
    !SCHEME.test(value)
  )
    return { kind: 'invalid' };
  if (value.toLowerCase().startsWith(RESERVED_IDENTIFIER_PREFIX)) return { kind: 'reserved' };
  return { kind: 'ok' };
}

/** Whether `value` is a resource:action Permission value. */
export function isPermissionValue(value: string): boolean {
  return PERMISSION.test(value);
}

/** Whether `value`, trimmed, may be a Permission's description: 0 to 200 characters with no control character. */
export function isPermissionDescription(value: string): boolean {
  const text = value.trim();
  return text.length <= PERMISSION_DESCRIPTION_MAX_LENGTH && !CONTROL.test(text);
}

/** The Tenant's APIs list. */
export function apisPath(tenantId: string): string {
  return `/tenants/${encodeURIComponent(tenantId)}/apis`;
}

/** One API's detail page. */
export function apiPath(tenantId: string, apiId: string): string {
  return `${apisPath(tenantId)}/${encodeURIComponent(apiId)}`;
}

const DETAIL_PATH = /^\/tenants\/[^/]+\/apis\/([^/]+)$/;

/**
 * The API a detail path names, decoded once, or as written when its escapes don't decode, so the server answers it as
 * the unknown API it is; null on any other path.
 */
export function apiOfPath(path: string): string | null {
  const match = DETAIL_PATH.exec(path);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]!);
  } catch {
    return match[1]!;
  }
}

// Machine-to-machine grants (Story 3.7): the API detail page's table, every machine Application of the Tenant with its
// grant on the API, if any.

/** One Application's grant on an API, as the API detail returns it. */
export interface ApiGrantView {
  applicationId: string;
  name: string;
  permissions: readonly string[];
}

/** One row of the machine-to-machine table: authorized when it holds at least one of the API's Permissions. */
export interface MachineGrantRow {
  applicationId: string;
  name: string;
  authorized: boolean;
  permissions: readonly string[];
}

/** Every machine Application of `applications`, in their order, each with its grant from `grants` or none. */
export function machineGrantRows(
  applications: readonly { id: string; name: string; type: string }[],
  grants: readonly ApiGrantView[],
): MachineGrantRow[] {
  const byApplication = new Map(grants.map((grant) => [grant.applicationId, grant]));
  return applications
    .filter((application) => application.type === 'machine')
    .map((application) => {
      const permissions = byApplication.get(application.id)?.permissions ?? [];
      return { applicationId: application.id, name: application.name, authorized: permissions.length > 0, permissions };
    });
}

/** The grants once the Permission `value` is removed from the API: removed from each, and a grant left with none gone. */
export function grantsWithout<G extends ApiGrantView>(grants: readonly G[], value: string): G[] {
  return grants
    .map((grant) => ({ ...grant, permissions: grant.permissions.filter((permission) => permission !== value) }))
    .filter((grant) => grant.permissions.length > 0);
}
