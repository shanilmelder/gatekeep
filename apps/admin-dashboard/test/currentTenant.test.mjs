// Story 1.28: the current Tenant's rules, on currentTenant.ts. Node runs the TypeScript source
// directly, its types stripped. The browser tests (admin-tenant-switcher.spec.ts) drive the same
// module through the built dashboard.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { current, pageTenant, remember, rememberKey, remembered, switchHref, tenantOfPath } from '../src/shell/currentTenant.ts';

const A = { id: 'ten_a' };
const B = { id: 'ten_b' };
const C = { id: 'ten_c' };

/** A storage that holds what it is given, or throws on every call. */
function store({ throws = false } = {}) {
  const values = new Map();
  return {
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
}

describe('current Tenant', () => {
  it('is the listed path Tenant on a Tenant path, and none for an unlisted one', () => {
    assert.equal(current('/tenants/ten_b/settings', [A, B], 'ten_a'), B);
    assert.equal(current('/tenants/ten_b', [A, B], null), B);
    assert.equal(current('/tenants/ten_x/settings', [A, B], 'ten_a'), null);
    assert.equal(current('/tenants/%E0%A4%A/settings', [A, B], 'ten_a'), null);
  });

  it('is the remembered one elsewhere when listed, else the first, else none', () => {
    assert.equal(current('/deployment/tenants', [A, B, C], 'ten_c'), C);
    assert.equal(current('/account/credentials', [A, B], 'ten_gone'), A);
    assert.equal(current('/', [A, B], null), A);
    assert.equal(current('/', [], 'ten_a'), null);
  });

  it('reads the path Tenant decoded once, and the page Tenant only as a ten_ ID', () => {
    assert.equal(tenantOfPath('/tenants/ten_a%2Fb/settings'), 'ten_a/b');
    assert.equal(tenantOfPath('/tenants/%E0%A4%A'), 'malformed');
    assert.equal(tenantOfPath('/deployment/tenants'), null);
    assert.equal(tenantOfPath('/tenantsx/ten_a'), null);
    const id = `ten_${'a'.repeat(25)}q`;
    assert.equal(pageTenant(`/tenants/${id}/settings`), id);
    assert.equal(pageTenant('/tenants/ten_a/settings'), null);
    assert.equal(pageTenant(`/tenants/${id.toUpperCase()}/settings`), null);
    assert.equal(pageTenant(`/tenants/${id}x/settings`), null);
    assert.equal(pageTenant(`/tenants/ten_${'a'.repeat(25)}1/settings`), null);
    assert.equal(pageTenant(`/tenants/${id}%0A/settings`), null);
    assert.equal(pageTenant('/tenants/other/settings'), null);
    assert.equal(pageTenant('/tenants/%E0%A4%A/settings'), null);
    assert.equal(pageTenant('/account/credentials'), null);
  });
});

describe('switching', () => {
  it('keeps the page on a Tenant path and opens the Tenant elsewhere', () => {
    assert.equal(switchHref('/tenants/ten_a/settings', 'ten_c'), '/tenants/ten_c/settings');
    assert.equal(switchHref('/tenants/ten_a', 'ten_c'), '/tenants/ten_c');
    assert.equal(switchHref('/deployment/tenants', 'ten_c'), '/tenants/ten_c');
    assert.equal(switchHref('/', 'ten_c'), '/tenants/ten_c');
  });

  it('is always same-origin and path-absolute, with the ID encoded', () => {
    assert.equal(switchHref('/deployment', 'ten_a/../../evil'), '/tenants/ten_a%2F..%2F..%2Fevil');
    assert.equal(switchHref('/deployment', '//evil.example'), '/tenants/%2F%2Fevil.example');
    assert.equal(switchHref('/tenants/ten_a/settings?x=1#y', 'ten_b'), '/tenants/ten_b');
    assert.equal(switchHref('/tenants/ten_a/a\\b', 'ten_b'), '/tenants/ten_b');
    for (const href of [switchHref('/tenants/ten_a//evil.example', 'ten_b'), switchHref('/x', 'ten_b')]) {
      assert.ok(href.startsWith('/tenants/'));
      assert.equal(new URL(href, 'https://admin.example').origin, 'https://admin.example');
    }
  });
});

describe('remembering', () => {
  it('keeps one Tenant per Admin under its own key', () => {
    const storage = store();
    remember('adm_1', 'ten_a', storage);
    remember('adm_2', 'ten_b', storage);
    assert.equal(rememberKey('adm_1'), 'gatekeep.admin.lastTenant.adm_1');
    assert.equal(storage.values.get('gatekeep.admin.lastTenant.adm_1'), 'ten_a');
    assert.equal(remembered('adm_1', storage), 'ten_a');
    assert.equal(remembered('adm_2', storage), 'ten_b');
    assert.equal(remembered('adm_3', storage), null);
  });

  it('treats a failing or missing storage as none', () => {
    const storage = store({ throws: true });
    assert.doesNotThrow(() => remember('adm_1', 'ten_a', storage));
    assert.equal(remembered('adm_1', storage), null);
    assert.equal(remembered('adm_1', null), null);
    assert.doesNotThrow(() => remember('adm_1', 'ten_a', null));
  });
});
