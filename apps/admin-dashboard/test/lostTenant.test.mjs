// Story 1.29: the lost Tenant's rules, on lostTenant.ts, and forgetting the remembered Tenant, on
// currentTenant.ts. Node runs the TypeScript sources directly, their types stripped. The browser
// tests (admin-tenant-delete.spec.ts) drive the same modules through the built dashboard.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { forget, remember, rememberKey, remembered } from '../src/shell/currentTenant.ts';
import { isLost, lostName, refusedInPageTenant } from '../src/shell/lostTenant.ts';

const A = { id: 'ten_a', name: 'Alpha' };
const B = { id: 'ten_b', name: 'Beta' };

/** A storage that holds what it is given, or throws on every call. */
function store({ throws = false, removable = true } = {}) {
  const values = new Map();
  const result = {
    values,
    getItem(key) {
      if (throws) throw new Error('blocked');
      return values.has(key) ? values.get(key) : null;
    },
    setItem(key, value) {
      if (throws) throw new Error('blocked');
      values.set(key, value);
    },
  };
  if (removable) {
    result.removeItem = (key) => {
      if (throws) throw new Error('blocked');
      values.delete(key);
    };
  }
  return result;
}

describe('lost Tenant', () => {
  it('is a Tenant listed before and gone from the list now', () => {
    assert.equal(isLost('ten_a', [A, B], null, [B]), true);
  });

  it('is the remembered Tenant gone from the list, even never listed in this document', () => {
    assert.equal(isLost('ten_a', [], 'ten_a', [B]), true);
  });

  it('is never a Tenant still listed', () => {
    assert.equal(isLost('ten_a', [A], 'ten_a', [A, B]), false);
  });

  it('is never a Tenant this document never listed and this browser never remembered', () => {
    assert.equal(isLost('ten_c', [A, B], 'ten_a', [B]), false);
    assert.equal(isLost('ten_c', [], null, []), false);
  });

  it('is never without a path Tenant', () => {
    assert.equal(isLost(null, [A], 'ten_a', []), false);
    assert.equal(isLost('', [A], '', []), false);
  });

  it('names the Tenant from the list held before, else nothing', () => {
    assert.equal(lostName('ten_a', [A, B]), 'Alpha');
    assert.equal(lostName('ten_c', [A, B]), null);
  });
});

describe('a refusal in the page Tenant', () => {
  it('is a 403 access_denied on the page Tenant’s own path', () => {
    assert.equal(refusedInPageTenant(403, 'access_denied', '/api/v1/tenants/ten_a/label', 'ten_a'), true);
    assert.equal(refusedInPageTenant(403, 'access_denied', '/api/v1/tenants/ten_a', 'ten_a'), true);
    assert.equal(refusedInPageTenant(403, 'access_denied', '/api/v1/tenants/ten_a%2Fx/label', 'ten_a/x'), true);
  });

  it('is nothing else', () => {
    assert.equal(refusedInPageTenant(403, 'access_denied', '/api/v1/tenants/ten_b/label', 'ten_a'), false);
    assert.equal(refusedInPageTenant(403, 'fresh_assertion_required', '/api/v1/tenants/ten_a/label', 'ten_a'), false);
    assert.equal(refusedInPageTenant(409, 'access_denied', '/api/v1/tenants/ten_a/label', 'ten_a'), false);
    assert.equal(refusedInPageTenant(403, 'access_denied', '/api/v1/deployment/tenants/ten_a/deletion', 'ten_a'), false);
    assert.equal(refusedInPageTenant(403, 'access_denied', '/api/v1/tenants/ten_a/label', null), false);
    assert.equal(refusedInPageTenant(403, undefined, '/api/v1/tenants/ten_a/label', 'ten_a'), false);
    assert.equal(refusedInPageTenant(403, 'access_denied', undefined, 'ten_a'), false);
    assert.equal(refusedInPageTenant(403, 'access_denied', '/api/v1/tenants/%E0%A4%A/label', 'ten_a'), false);
  });
});

describe('forgetting the remembered Tenant', () => {
  it('removes this Admin’s, and only theirs', () => {
    const s = store();
    remember('admin-1', 'ten_a', s);
    remember('admin-2', 'ten_b', s);

    forget('admin-1', s);

    assert.equal(remembered('admin-1', s), null);
    assert.equal(remembered('admin-2', s), 'ten_b');
    assert.equal(s.values.has(rememberKey('admin-1')), false);
  });

  it('never throws on a storage that fails, or has no removeItem', () => {
    assert.doesNotThrow(() => forget('admin-1', store({ throws: true })));
    assert.doesNotThrow(() => forget('admin-1', store({ removable: false })));
    assert.doesNotThrow(() => forget('admin-1', null));
  });
});
