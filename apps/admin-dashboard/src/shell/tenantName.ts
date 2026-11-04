// The Tenant name rule, as the browser checks it before a create (Story 1.27): the server's
// TenantName.TryNormalize. The name is trimmed, then must be 1 to 100 UTF-16 units with no
// control character (Unicode Cc), no invisible formatting character (Unicode Cf, such as bidi
// controls and zero-width characters) and no lone surrogate. This is feedback only: the server
// runs the rule again. Its test vectors (test/tenant-name-vectors.json) are the server's too.
//
// Plain TypeScript with no import, so Node runs its tests directly (test/tenantName.test.mjs).

export const NAME_MAX_LENGTH = 100;

const CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}]/u;

// Without the u flag, so each surrogate is one unit: a high one not followed by a low one, or a
// low one not preceded by a high one.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export type TenantNameCheck = { kind: 'ok'; name: string } | { kind: 'empty' } | { kind: 'invalid' };

/** The trimmed name, or why it can't be one: empty after trimming, or too long or with a refused character. */
export function checkTenantName(value: string): TenantNameCheck {
  const name = value.trim();
  if (name === '') return { kind: 'empty' };
  if (name.length > NAME_MAX_LENGTH || CONTROL_OR_FORMAT.test(name) || LONE_SURROGATE.test(name)) return { kind: 'invalid' };
  return { kind: 'ok', name };
}
