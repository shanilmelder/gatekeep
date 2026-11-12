// Story 3.1: the browser's Application rules and paths, on applications.ts. Node runs the
// TypeScript source directly, its types stripped.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  APPLICATION_KINDS,
  APPLICATION_NAME_MAX_LENGTH,
  applicationOfPath,
  applicationPath,
  applicationsPath,
  checkApplicationName,
} from '../src/shell/applications.ts';

describe('applications', () => {
  it('offers the four types', () => {
    assert.deepEqual([...APPLICATION_KINDS], ['spa', 'web', 'native', 'machine']);
  });

  it('trims a name and accepts 1 to 200 characters', () => {
    assert.deepEqual(checkApplicationName('  Web app  '), { kind: 'ok', name: 'Web app' });
    assert.deepEqual(checkApplicationName('x'.repeat(APPLICATION_NAME_MAX_LENGTH)), { kind: 'ok', name: 'x'.repeat(200) });
    assert.deepEqual(checkApplicationName(` ${'x'.repeat(200)} `), { kind: 'ok', name: 'x'.repeat(200) });
  });

  it('refuses an empty, too long or control-character name', () => {
    assert.equal(checkApplicationName('').kind, 'empty');
    assert.equal(checkApplicationName(' \t\n ').kind, 'empty');
    assert.equal(checkApplicationName('x'.repeat(201)).kind, 'invalid');
    assert.equal(checkApplicationName('a\u0007b').kind, 'invalid');
    assert.equal(checkApplicationName('a\u0000b').kind, 'invalid');
  });

  it('builds and reads the pages paths, every ID encoded', () => {
    assert.equal(applicationsPath('ten_a/b'), '/tenants/ten_a%2Fb/applications');
    assert.equal(applicationPath('ten_a', 'app_c/d'), '/tenants/ten_a/applications/app_c%2Fd');
    assert.equal(applicationOfPath('/tenants/ten_a/applications/app_c%2Fd'), 'app_c/d');
    assert.equal(applicationOfPath('/tenants/ten_a/applications'), null);
    assert.equal(applicationOfPath('/tenants/ten_a/applications/a/b'), null);
    assert.equal(applicationOfPath('/tenants/ten_a/applications/%E0%A4%A'), '%E0%A4%A');
  });
});
