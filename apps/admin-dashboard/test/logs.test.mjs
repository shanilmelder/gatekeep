// Story 7.4: the Logs field search's URL-to-query mapping, on logs.ts. Node runs the TypeScript
// source directly, its types stripped. The browser tests (admin-logs.spec.ts) drive the same
// module through the built dashboard; the server's own checks are the Isolation tests'.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  DEFAULT_FIELD,
  LOG_FIELDS,
  choices,
  initialValue,
  paramsOf,
  queryOf,
  referenceOf,
  searchOf,
  utcTime,
} from '../src/shell/logs.ts';

const NOW = Date.parse('2026-11-06T12:00:00.000Z');

describe('Logs field search', () => {
  it('offers the five fields in order', () => {
    assert.deepEqual([...LOG_FIELDS], ['type', 'user', 'application', 'outcome', 'range']);
    assert.equal(DEFAULT_FIELD, 'type');
  });

  it('reads the URL field and value, trimmed, defaulting an unknown or missing field', () => {
    assert.deepEqual(searchOf({ field: 'user', value: '  a@b.test ' }), { field: 'user', value: 'a@b.test' });
    assert.deepEqual(searchOf({ field: null, value: 'admin.access.denied' }), { field: 'type', value: 'admin.access.denied' });
    assert.deepEqual(searchOf({ field: 'nope', value: 'x' }), { field: 'type', value: 'x' });
    assert.deepEqual(searchOf({ field: 'type', value: null }), { field: 'type', value: '' });
    assert.deepEqual(searchOf({ field: '__proto__', value: 'x' }), { field: 'type', value: 'x' });
  });

  it('drops a choice field value outside its choices', () => {
    assert.deepEqual(searchOf({ field: 'outcome', value: 'failure' }), { field: 'outcome', value: 'failure' });
    assert.deepEqual(searchOf({ field: 'outcome', value: 'Failure' }), { field: 'outcome', value: '' });
    assert.deepEqual(searchOf({ field: 'range', value: '7d' }), { field: 'range', value: '7d' });
    assert.deepEqual(searchOf({ field: 'range', value: '1y' }), { field: 'range', value: '' });
  });

  it('maps each field to its one API parameter', () => {
    assert.deepEqual(queryOf({ field: 'type', value: 'admin.cross_tenant.rejected' }, NOW), { type: 'admin.cross_tenant.rejected' });
    assert.deepEqual(queryOf({ field: 'user', value: 'a@b.test' }, NOW), { user: 'a@b.test' });
    assert.deepEqual(queryOf({ field: 'user', value: '7c9e6679-7425-40de-944b-e07fc1f90ae7' }, NOW), {
      user: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
    });
    assert.deepEqual(queryOf({ field: 'application', value: '7c9e6679-7425-40de-944b-e07fc1f90ae7' }, NOW), {
      application: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
    });
    assert.deepEqual(queryOf({ field: 'outcome', value: 'success' }, NOW), { outcome: 'success' });
  });

  it('maps a time range to from, that long before now, in UTC', () => {
    assert.deepEqual(queryOf({ field: 'range', value: '1h' }, NOW), { from: '2026-11-06T11:00:00.000Z' });
    assert.deepEqual(queryOf({ field: 'range', value: '24h' }, NOW), { from: '2026-11-05T12:00:00.000Z' });
    assert.deepEqual(queryOf({ field: 'range', value: '7d' }, NOW), { from: '2026-10-30T12:00:00.000Z' });
    assert.deepEqual(queryOf({ field: 'range', value: '30d' }, NOW), { from: '2026-10-07T12:00:00.000Z' });
    assert.deepEqual(queryOf({ field: 'range', value: '90d' }, NOW), { from: '2026-08-08T12:00:00.000Z' });
  });

  it('sends no filter for no value, or a choice outside the list', () => {
    assert.deepEqual(queryOf({ field: 'type', value: '' }, NOW), {});
    assert.deepEqual(queryOf({ field: 'user', value: '   ' }, NOW), {});
    assert.deepEqual(queryOf({ field: 'outcome', value: 'maybe' }, NOW), {});
    assert.deepEqual(queryOf({ field: 'range', value: '1y' }, NOW), {});
  });

  it('keeps field and value in the URL, or neither for no value', () => {
    assert.deepEqual(paramsOf({ field: 'user', value: ' a@b.test ' }), { field: 'user', value: 'a@b.test' });
    assert.deepEqual(paramsOf({ field: 'outcome', value: 'failure' }), { field: 'outcome', value: 'failure' });
    assert.deepEqual(paramsOf({ field: 'user', value: '' }), { field: null, value: null });
  });

  it('round-trips a search through the URL', () => {
    for (const search of [
      { field: 'type', value: 'admin.access.denied' },
      { field: 'user', value: 'a@b.test' },
      { field: 'range', value: '30d' },
    ]) {
      assert.deepEqual(searchOf(paramsOf(search)), search);
    }
  });

  it('starts a choice field on its first choice and a typed field empty', () => {
    assert.equal(initialValue('outcome'), 'success');
    assert.equal(initialValue('range'), '1h');
    assert.equal(initialValue('type'), '');
    assert.deepEqual(choices('user'), []);
  });

  it('shows the User or Application an event names, as Actor first', () => {
    const user = { kind: 'user', id: 'u-1' };
    const client = { kind: 'client', id: 'c-1' };
    assert.equal(referenceOf({ actor: user, target: client }, 'user'), 'u-1');
    assert.equal(referenceOf({ actor: user, target: client }, 'client'), 'c-1');
    assert.equal(referenceOf({ actor: { kind: 'admin', id: 'a-1' }, target: user }, 'user'), 'u-1');
    assert.equal(referenceOf({ actor: { kind: 'system', id: null }, target: null }, 'user'), null);
  });

  it('shows times in UTC to the second', () => {
    assert.equal(utcTime('2026-11-06T09:00:02.123+00:00'), '2026-11-06 09:00:02');
    assert.equal(utcTime('2026-11-06T10:00:02+01:00'), '2026-11-06 09:00:02');
    assert.equal(utcTime('not a time'), 'not a time');
  });
});
