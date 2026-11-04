// Story 1.27: the browser's Tenant name rule, on tenantName.ts. Node runs the TypeScript source
// directly, its types stripped. The vectors are the server's too (test/tenant-name-vectors.json),
// so the two rules can't drift.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { NAME_MAX_LENGTH, checkTenantName } from '../src/shell/tenantName.ts';

const vectors = JSON.parse(readFileSync(new URL('./tenant-name-vectors.json', import.meta.url), 'utf8'));

describe('tenant name rule', () => {
  it('accepts every valid name, trimmed', () => {
    assert.ok(vectors.valid.length > 0);
    for (const value of vectors.valid) {
      const check = checkTenantName(value);
      assert.equal(check.kind, 'ok', JSON.stringify(value));
      assert.equal(check.name, value.trim());
    }
  });

  it('refuses every invalid name', () => {
    assert.ok(vectors.invalid.length > 0);
    for (const value of vectors.invalid) assert.notEqual(checkTenantName(value).kind, 'ok', JSON.stringify(value));
  });

  it('says a blank name is empty and any other refusal is invalid', () => {
    assert.equal(checkTenantName('').kind, 'empty');
    assert.equal(checkTenantName('   ').kind, 'empty');
    assert.equal(checkTenantName('a​b').kind, 'invalid');
    assert.equal(checkTenantName('n'.repeat(NAME_MAX_LENGTH + 1)).kind, 'invalid');
  });

  it('holds the review cases: control, bidi, zero-width and lone surrogates', () => {
    for (const value of ['a\u0007b', 'a‮b', 'a⁦b', 'a‎b', 'a﻿b', 'a\ud800b', 'a\udc00']) {
      assert.ok(vectors.invalid.includes(value), JSON.stringify(value));
    }
  });

  it('keeps a paired surrogate, and counts length in UTF-16 units as the server does', () => {
    assert.equal(checkTenantName('\u{1F642}').kind, 'ok');
    assert.equal(checkTenantName('\u{1F642}'.repeat(50)).kind, 'ok');
    assert.equal(checkTenantName('\u{1F642}'.repeat(50) + 'n').kind, 'invalid');
  });
});
