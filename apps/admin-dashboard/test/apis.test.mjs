// Story 3.6: the browser's API and Permission rules and paths, on apis.ts. Node runs the TypeScript source directly,
// its types stripped.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  API_IDENTIFIER_MAX_LENGTH,
  API_NAME_MAX_LENGTH,
  apiOfPath,
  apiPath,
  apisPath,
  checkApiIdentifier,
  checkApiName,
  grantsWithout,
  isPermissionDescription,
  isPermissionValue,
  machineGrantRows,
} from '../src/shell/apis.ts';

describe('apis', () => {
  it('trims a name and refuses an empty, too long or control-character one', () => {
    assert.deepEqual(checkApiName('  Billing  '), { kind: 'ok', name: 'Billing' });
    assert.deepEqual(checkApiName('   '), { kind: 'empty' });
    assert.deepEqual(checkApiName('a'.repeat(API_NAME_MAX_LENGTH + 1)), { kind: 'invalid' });
    assert.deepEqual(checkApiName('a\u0007b'), { kind: 'invalid' });
  });

  it("checks an identifier exactly as the server does, and reserves urn:gatekeep:", () => {
    assert.deepEqual(checkApiIdentifier('https://api.example.com'), { kind: 'ok' });
    assert.deepEqual(checkApiIdentifier('urn:example:billing'), { kind: 'ok' });
    assert.deepEqual(checkApiIdentifier(''), { kind: 'empty' });
    assert.deepEqual(checkApiIdentifier('api.example.com'), { kind: 'invalid' });
    assert.deepEqual(checkApiIdentifier('https://api.example.com#frag'), { kind: 'invalid' });
    assert.deepEqual(checkApiIdentifier(' https://api.example.com'), { kind: 'invalid' });
    assert.deepEqual(checkApiIdentifier(`https://${'a'.repeat(API_IDENTIFIER_MAX_LENGTH)}`), { kind: 'invalid' });
    assert.deepEqual(checkApiIdentifier('urn:gatekeep:x'), { kind: 'reserved' });
    assert.deepEqual(checkApiIdentifier('URN:GATEKEEP:x'), { kind: 'reserved' });
  });

  it('accepts only resource:action Permission values', () => {
    for (const value of ['invoices:read', 'log_detail:read', 'a.b-c:d_e', '0:1']) assert.equal(isPermissionValue(value), true, value);
    for (const value of ['Invoices:read', 'invoices', ':read', 'invoices:', 'a:b:c', '_a:b', `${'a'.repeat(65)}:b`, 'invoices:read\n'])
      assert.equal(isPermissionValue(value), false, JSON.stringify(value));
  });

  it('allows an empty description and refuses a long or control-character one', () => {
    assert.equal(isPermissionDescription(''), true);
    assert.equal(isPermissionDescription('Read invoices'), true);
    assert.equal(isPermissionDescription('a'.repeat(201)), false);
    assert.equal(isPermissionDescription('a\u0000b'), false);
  });

  it("builds and reads the pages' paths, encoding the IDs", () => {
    assert.equal(apisPath('ten_a'), '/tenants/ten_a/apis');
    assert.equal(apiPath('ten_a', 'api_b/c'), '/tenants/ten_a/apis/api_b%2Fc');
    assert.equal(apiOfPath('/tenants/ten_a/apis/api_b%2Fc'), 'api_b/c');
    assert.equal(apiOfPath('/tenants/ten_a/apis/%E0%A4%A'), '%E0%A4%A');
    assert.equal(apiOfPath('/tenants/ten_a/apis'), null);
    assert.equal(apiOfPath('/tenants/ten_a/applications/app_b'), null);
  });

  it('lists every machine Application, authorized only when it holds a Permission (Story 3.7)', () => {
    const rows = machineGrantRows(
      [
        { id: 'app_b', name: 'Billing worker', type: 'machine' },
        { id: 'app_s', name: 'Storefront', type: 'spa' },
        { id: 'app_r', name: 'Reports', type: 'machine' },
      ],
      [{ applicationId: 'app_b', name: 'Billing worker', permissions: ['invoices:read', 'payments:write'] }],
    );
    assert.deepEqual(rows, [
      { applicationId: 'app_b', name: 'Billing worker', authorized: true, permissions: ['invoices:read', 'payments:write'] },
      { applicationId: 'app_r', name: 'Reports', authorized: false, permissions: [] },
    ]);
    assert.deepEqual(machineGrantRows([], []), []);
  });

  it("drops a removed Permission from every grant, and a grant left with none (Story 3.7)", () => {
    const grants = [
      { applicationId: 'app_a', name: 'A', permissions: ['invoices:read', 'payments:write'] },
      { applicationId: 'app_b', name: 'B', permissions: ['invoices:read'] },
    ];
    assert.deepEqual(grantsWithout(grants, 'invoices:read'), [{ applicationId: 'app_a', name: 'A', permissions: ['payments:write'] }]);
    assert.deepEqual(grantsWithout(grants, 'reports:read'), grants);
  });
});
