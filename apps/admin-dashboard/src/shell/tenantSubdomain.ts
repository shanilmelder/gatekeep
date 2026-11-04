// The Tenant Subdomain rule, as the browser checks it before a create (Story 1.27): the server's
// TenantSubdomain.TryParse without its reserved list, which stays the server's alone, so a
// reserved name is refused there with the same answer as a taken one. The value is taken exactly
// as typed, with no trimming or case folding. This is feedback only: the server runs every rule
// again. Its test vectors (test/tenant-subdomain-vectors.json) are the server's too, so the two
// rules can't drift.
//
// Plain TypeScript with no import, so Node runs its tests directly (test/tenantSubdomain.test.mjs).

export const SUBDOMAIN_MIN_LENGTH = 3;

export const SUBDOMAIN_MAX_LENGTH = 63;

/** The longest whole host, `{subdomain}.{zone}`. */
export const HOST_MAX_LENGTH = 253;

const LDH = /^[a-z0-9-]+$/;

/**
 * Whether `value` is a well-formed Tenant Subdomain: 3–63 of a–z, 0–9 and -, not starting or
 * ending with -, with no -- at positions 3–4 (so no xn-- or other IDNA label), and, given the
 * zone, a whole host of at most 253 characters.
 */
export function isTenantSubdomain(value: string, zone?: string): boolean {
  if (value.length < SUBDOMAIN_MIN_LENGTH || value.length > SUBDOMAIN_MAX_LENGTH) return false;
  if (!LDH.test(value)) return false;
  if (value.startsWith('-') || value.endsWith('-')) return false;
  if (value.slice(2, 4) === '--') return false;
  if (zone !== undefined && value.length + 1 + zone.length > HOST_MAX_LENGTH) return false;
  return true;
}
