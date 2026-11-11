// Applications (Story 3.1): the four types, which of them need a credential, the name rule as
// the browser checks it before a create, and the pages' paths. The server's rule is the same: the
// name is trimmed, then must be 1 to 200 UTF-16 units with no control character (Unicode Cc).
// This is feedback only: the server runs the rule again and decides every request.
//
// Plain TypeScript with no import, so Node runs its tests directly (test/applications.test.mjs).

/** An Application's type, as stored and as the API names it. */
export type ApplicationKind = 'spa' | 'web' | 'native' | 'machine';

/** The types in the order Create Application offers them. */
export const APPLICATION_KINDS: readonly ApplicationKind[] = Object.freeze(['spa', 'web', 'native', 'machine']);

export const APPLICATION_NAME_MAX_LENGTH = 200;

const CONTROL = /\p{Cc}/u;

export type ApplicationNameCheck = { kind: 'ok'; name: string } | { kind: 'empty' } | { kind: 'invalid' };

/** The trimmed name, or why it can't be one: empty after trimming, or too long or with a control character. */
export function checkApplicationName(value: string): ApplicationNameCheck {
  const name = value.trim();
  if (name === '') return { kind: 'empty' };
  if (name.length > APPLICATION_NAME_MAX_LENGTH || CONTROL.test(name)) return { kind: 'invalid' };
  return { kind: 'ok', name };
}

/** Whether a type authenticates with a client secret: regular web and machine-to-machine do. */
export function credentialRequired(kind: string): boolean {
  return kind === 'web' || kind === 'machine';
}

/** The Tenant's Applications list. */
export function applicationsPath(tenantId: string): string {
  return `/tenants/${encodeURIComponent(tenantId)}/applications`;
}

/** One Application's detail page. */
export function applicationPath(tenantId: string, applicationId: string): string {
  return `${applicationsPath(tenantId)}/${encodeURIComponent(applicationId)}`;
}

const DETAIL_PATH = /^\/tenants\/[^/]+\/applications\/([^/]+)$/;

/** The Application a detail path names, decoded once; null on any other path, or one whose escapes don't decode. */
export function applicationOfPath(path: string): string | null {
  const match = DETAIL_PATH.exec(path);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]!);
  } catch {
    return null;
  }
}
