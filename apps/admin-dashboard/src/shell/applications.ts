// Applications (Story 3.1): the four types, the name rule as
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

/** The Tenant's Applications list. */
export function applicationsPath(tenantId: string): string {
  return `/tenants/${encodeURIComponent(tenantId)}/applications`;
}

/** One Application's detail page. */
export function applicationPath(tenantId: string, applicationId: string): string {
  return `${applicationsPath(tenantId)}/${encodeURIComponent(applicationId)}`;
}

const DETAIL_PATH = /^\/tenants\/[^/]+\/applications\/([^/]+)$/;

/**
 * The Application a detail path names, decoded once, or as written when its escapes don't decode,
 * so the server answers it as the unknown Application it is; null on any other path.
 */
export function applicationOfPath(path: string): string | null {
  const match = DETAIL_PATH.exec(path);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]!);
  } catch {
    return match[1]!;
  }
}

// Settings (Story 3.2): the URL textareas' lines, the grant switches, and which custom-scheme URLs
// are new. Feedback only: the server checks every line again, decides, and names each it refuses.

/** A grant type, as the API names it. */
export type GrantType = 'authorization_code' | 'client_credentials' | 'refresh_token';

/** The grants in the order the API stores them: sorted. */
export const GRANT_TYPES: readonly GrantType[] = Object.freeze(['authorization_code', 'client_credentials', 'refresh_token']);

/** Whether an Application of `kind` can ever hold `grant`: machine-to-machine only Client Credentials, the others the code flow's two. */
export function grantAvailable(kind: ApplicationKind, grant: GrantType): boolean {
  return kind === 'machine' ? grant === 'client_credentials' : grant !== 'client_credentials';
}

/** Whether an Application of `kind` has URL fields at all. */
export function hasUrls(kind: ApplicationKind): boolean {
  return kind !== 'machine';
}

/** Whether an Application of `kind` has Allowed Web Origins: single-page and regular web only. */
export function hasWebOrigins(kind: ApplicationKind): boolean {
  return kind === 'spa' || kind === 'web';
}

/** A textarea's URLs: one per line, each trimmed, blank lines dropped; and each URL's 1-based line in the textarea. */
export function urlLines(text: string): { values: string[]; lines: number[] } {
  const values: string[] = [];
  const lines: number[] = [];
  text.split('\n').forEach((raw, index) => {
    const value = raw.trim();
    if (value === '') return;
    values.push(value);
    lines.push(index + 1);
  });
  return { values, lines };
}

/** A stored list as its textarea shows it: one URL per line. */
export function urlText(values: readonly string[]): string {
  return values.join('\n');
}

const SCHEME = /^([A-Za-z][A-Za-z0-9+.-]*):/;

/** Whether `url` has a scheme that isn't http or https, such as com.example.app:/callback. */
export function isCustomScheme(url: string): boolean {
  const match = SCHEME.exec(url);
  if (!match) return false;
  const scheme = match[1]!.toLowerCase();
  return scheme !== 'http' && scheme !== 'https';
}

/** The custom-scheme URLs in `submitted` that `stored` doesn't hold: what a Prod Tenant must acknowledge. */
export function newCustomSchemes(submitted: readonly string[], stored: readonly string[]): string[] {
  return submitted.filter((url) => isCustomScheme(url) && !stored.includes(url));
}

/** Whether two lists hold the same strings in the same order. */
export function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

// Client secrets (Story 3.3): which Credentials controls apply, and the Owner's create flow's one hand-off.

/** A live secret as the list shows it: `expiresAt` is null for the current secret, and set for an old one still overlapping. */
export interface LiveSecret {
  id: string;
  createdAt: string;
  expiresAt?: string | null;
}

/** The most live secrets an Application holds: the current one and one old one (the server's limit). */
export const MAX_LIVE_SECRETS = 2;

/** The current secret, if any: the one with no expiry. */
export function currentSecret<T extends LiveSecret>(secrets: readonly T[]): T | null {
  return secrets.find((secret) => secret.expiresAt == null) ?? null;
}

/** Whether a create or rotation may be sent: not while an old secret still overlaps the current one. */
export function canAddSecret(secrets: readonly LiveSecret[]): boolean {
  return secrets.length < MAX_LIVE_SECRETS;
}

const pendingSecretCreates = new Set<string>();

/** Asks the Application's Credentials tab to create its first secret once it opens: the Owner's create flow. */
export function requestSecretCreate(applicationId: string): void {
  pendingSecretCreates.add(applicationId);
}

/** Whether a first secret was asked for the Application. Taking it ends the ask, so it runs once. */
export function takeSecretCreate(applicationId: string): boolean {
  return pendingSecretCreates.delete(applicationId);
}

/** Whether a first secret was asked for the Application, without taking it. */
export function secretCreateRequested(applicationId: string): boolean {
  return pendingSecretCreates.has(applicationId);
}
