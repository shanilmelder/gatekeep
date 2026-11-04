// Story 1.27: the browser's Tenant Subdomain rule, on tenantSubdomain.ts. Node runs the
// TypeScript source directly, its types stripped. The vectors are the server's too
// (test/tenant-subdomain-vectors.json), so the two rules can't drift; the reserved names pass
// here, since only the server holds that list.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { HOST_MAX_LENGTH, isTenantSubdomain } from '../src/shell/tenantSubdomain.ts';

const vectors = JSON.parse(readFileSync(new URL('./tenant-subdomain-vectors.json', import.meta.url), 'utf8'));

describe('tenant subdomain rule', () => {
  it('refuses every malformed value, exactly as typed', () => {
    assert.ok(vectors.malformed.length > 0);
    for (const value of vectors.malformed) assert.equal(isTenantSubdomain(value), false, JSON.stringify(value));
  });

  it("refuses the matrix's malformed values", () => {
    for (const value of ['Acme', 'ab', '-acme', 'acme-', 'xn--acme', 'ac--me', 'a_b', ' acme', 'a'.repeat(64)]) {
      assert.ok(vectors.malformed.includes(value), JSON.stringify(value));
      assert.equal(isTenantSubdomain(value), false, JSON.stringify(value));
    }
  });

  it('accepts every valid value', () => {
    assert.ok(vectors.valid.includes('a'.repeat(63)));
    for (const value of vectors.valid) assert.equal(isTenantSubdomain(value), true, JSON.stringify(value));
  });

  it('has no reserved list: the server alone refuses a reserved name', () => {
    for (const value of vectors.reserved) assert.equal(isTenantSubdomain(value), true, JSON.stringify(value));
  });

  it('refuses a value whose whole host would pass 253 characters', () => {
    const zone = `${'z'.repeat(63)}.${'y'.repeat(63)}.${'x'.repeat(63)}.${'w'.repeat(57)}`;
    assert.equal('acme'.length + 1 + zone.length, HOST_MAX_LENGTH + 1);
    assert.equal(isTenantSubdomain('acme', zone), false);
    assert.equal(isTenantSubdomain('acm', zone), true);
    assert.equal(isTenantSubdomain('acme-dev', 'gatekeep.test'), true);
  });
});
