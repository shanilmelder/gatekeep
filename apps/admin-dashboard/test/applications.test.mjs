// Story 3.1: the browser's Application rules and paths, on applications.ts. Node runs the
// TypeScript source directly, its types stripped.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  APPLICATION_KINDS,
  APPLICATION_NAME_MAX_LENGTH,
  MAX_LIVE_SECRETS,
  canAddSecret,
  currentSecret,
  requestSecretCreate,
  secretCreateRequested,
  takeSecretCreate,
  applicationOfPath,
  applicationPath,
  applicationsPath,
  checkApplicationName,
  grantAvailable,
  hasUrls,
  hasWebOrigins,
  isCustomScheme,
  newCustomSchemes,
  sameList,
  urlLines,
  urlText,
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

  // Story 3.2: the Settings tab's lines and switches.
  it('reads one URL per line, trimmed, blank lines dropped, each with its line in the textarea', () => {
    assert.deepEqual(urlLines(''), { values: [], lines: [] });
    assert.deepEqual(urlLines('  https://a.example/cb  \n\n\r\nhttps://b.example/cb\r\n'), {
      values: ['https://a.example/cb', 'https://b.example/cb'],
      lines: [1, 4],
    });
    assert.equal(urlText(['https://a.example/cb', 'https://b.example/cb']), 'https://a.example/cb\nhttps://b.example/cb');
  });

  it('offers each type only its own grants and fields', () => {
    for (const kind of ['spa', 'web', 'native']) {
      assert.equal(grantAvailable(kind, 'authorization_code'), true);
      assert.equal(grantAvailable(kind, 'refresh_token'), true);
      assert.equal(grantAvailable(kind, 'client_credentials'), false);
      assert.equal(hasUrls(kind), true);
    }
    assert.equal(grantAvailable('machine', 'client_credentials'), true);
    assert.equal(grantAvailable('machine', 'authorization_code'), false);
    assert.equal(grantAvailable('machine', 'refresh_token'), false);
    assert.equal(hasUrls('machine'), false);
    assert.deepEqual(['spa', 'web', 'native', 'machine'].map(hasWebOrigins), [true, true, false, false]);
  });

  it('finds the custom-scheme URLs that are new', () => {
    assert.equal(isCustomScheme('com.example.app:/callback'), true);
    assert.equal(isCustomScheme('HTTPS://a.example/cb'), false);
    assert.equal(isCustomScheme('http://127.0.0.1/cb'), false);
    assert.equal(isCustomScheme('/cb'), false);
    assert.deepEqual(newCustomSchemes(['com.example.app:/cb', 'com.example.app:/new', 'https://a.example/cb'], ['com.example.app:/cb']), [
      'com.example.app:/new',
    ]);
    assert.equal(sameList(['a', 'b'], ['a', 'b']), true);
    assert.equal(sameList(['a', 'b'], ['b', 'a']), false);
  });
});

describe('client secrets (Story 3.3)', () => {
  const current = { id: 'sec_b', createdAt: '2026-11-13T10:00:00.000Z', expiresAt: null };
  const old = { id: 'sec_a', createdAt: '2026-11-12T10:00:00.000Z', expiresAt: '2026-11-14T10:00:00.000Z' };

  it('finds the current secret: the one with no expiry', () => {
    assert.equal(currentSecret([current, old]), current);
    assert.equal(currentSecret([old]), null);
    assert.equal(currentSecret([]), null);
  });

  it('allows a create or rotation only below the live-secret limit', () => {
    assert.equal(MAX_LIVE_SECRETS, 2);
    assert.equal(canAddSecret([]), true);
    assert.equal(canAddSecret([current]), true);
    assert.equal(canAddSecret([old]), true);
    assert.equal(canAddSecret([current, old]), false);
  });

  it("hands the Owner's first-secret ask over once", () => {
    assert.equal(secretCreateRequested('app_x'), false);
    requestSecretCreate('app_x');
    assert.equal(secretCreateRequested('app_x'), true);
    assert.equal(takeSecretCreate('app_x'), true);
    assert.equal(takeSecretCreate('app_x'), false);
    assert.equal(secretCreateRequested('app_x'), false);
  });
});
