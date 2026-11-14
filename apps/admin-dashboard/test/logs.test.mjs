// Story 7.4: the Logs field search's URL-to-query mapping, on logs.ts. Node runs the TypeScript
// source directly, its types stripped. The browser tests (admin-logs.spec.ts) drive the same
// module through the built dashboard; the server's own checks are the Isolation tests'.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  DEFAULT_FIELD,
  DEPLOYMENT_LOG_FIELDS,
  LOG_FIELDS,
  choices,
  fieldsOf,
  initialValue,
  paramsOf,
  queryOf,
  referenceOf,
  searchOf,
  utcTime,
} from '../src/shell/logs.ts';
import { eventSummary, referenceText } from '../src/shell/logEvent.ts';

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

// Story 7.7: the Deployment Log's field search, the same mapping over its own fields: Admin and
// Tenant in place of User and Application.
describe('Deployment Log field search', () => {
  const FIELDS = DEPLOYMENT_LOG_FIELDS;

  it('offers its five fields in order, and each scope its own', () => {
    assert.deepEqual([...FIELDS], ['type', 'admin', 'tenant', 'outcome', 'range']);
    assert.equal(fieldsOf('deployment'), DEPLOYMENT_LOG_FIELDS);
    assert.equal(fieldsOf('tenant'), LOG_FIELDS);
  });

  it('maps Admin and Tenant to their one API parameter, and the shared fields as a Tenant Log does', () => {
    assert.deepEqual(queryOf({ field: 'admin', value: ' 7c9e6679-7425-40de-944b-e07fc1f90ae7 ' }, NOW, FIELDS), {
      admin: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
    });
    assert.deepEqual(queryOf({ field: 'tenant', value: 'ten_aaaaaaaaaaaaaaaaaaaaaaaaaa' }, NOW, FIELDS), { tenant: 'ten_aaaaaaaaaaaaaaaaaaaaaaaaaa' });
    assert.deepEqual(queryOf({ field: 'type', value: 'bootstrap.admin.created' }, NOW, FIELDS), { type: 'bootstrap.admin.created' });
    assert.deepEqual(queryOf({ field: 'outcome', value: 'failure' }, NOW, FIELDS), { outcome: 'failure' });
    assert.deepEqual(queryOf({ field: 'range', value: '7d' }, NOW, FIELDS), { from: '2026-10-30T12:00:00.000Z' });
    assert.deepEqual(queryOf({ field: 'tenant', value: '' }, NOW, FIELDS), {});
  });

  it("reads only its own fields from the URL: a Tenant Log's User or Application is the default field", () => {
    assert.deepEqual(searchOf({ field: 'admin', value: 'a-1' }, FIELDS), { field: 'admin', value: 'a-1' });
    assert.deepEqual(searchOf({ field: 'tenant', value: 'ten_a' }, FIELDS), { field: 'tenant', value: 'ten_a' });
    assert.deepEqual(searchOf({ field: 'user', value: 'u-1' }, FIELDS), { field: 'type', value: 'u-1' });
    assert.deepEqual(searchOf({ field: 'application', value: 'c-1' }, FIELDS), { field: 'type', value: 'c-1' });
    assert.deepEqual(queryOf({ field: 'user', value: 'u-1' }, NOW, FIELDS), { type: 'u-1' });
    // And a Tenant's Log never reads the Deployment Log's.
    assert.deepEqual(searchOf({ field: 'admin', value: 'a-1' }), { field: 'type', value: 'a-1' });
    assert.deepEqual(queryOf({ field: 'tenant', value: 'ten_a' }, NOW), { type: 'ten_a' });
  });

  it('round-trips a Deployment search through the URL', () => {
    for (const search of [
      { field: 'admin', value: '7c9e6679-7425-40de-944b-e07fc1f90ae7' },
      { field: 'tenant', value: 'ten_aaaaaaaaaaaaaaaaaaaaaaaaaa' },
      { field: 'outcome', value: 'success' },
    ]) {
      assert.deepEqual(searchOf(paramsOf(search), FIELDS), search);
    }
  });

  it('shows the Admin an event names, Actor first, and the Tenant it targets', () => {
    const admin = { kind: 'admin', id: 'a-1' };
    const tenant = { kind: 'tenant', id: 'ten_a' };
    assert.equal(referenceOf({ actor: admin, target: tenant }, 'admin'), 'a-1');
    assert.equal(referenceOf({ actor: admin, target: tenant }, 'tenant'), 'ten_a');
    assert.equal(referenceOf({ actor: { kind: 'anonymous', id: null }, target: { kind: 'admin', id: 'a-2' } }, 'admin'), 'a-2');
    assert.equal(referenceOf({ actor: { kind: 'system', id: null }, target: null }, 'tenant'), null);
  });
});

// Story 7.5: the event drawer's summary rows. Detail rows come only from `raw`, which the server
// sends to an Editor or Owner alone.
describe('Log event summary', () => {
  const LABELS = {
    time: 'Time (UTC)',
    actor: 'Actor',
    target: 'Target',
    user: 'User',
    application: 'Application',
    ipAddress: 'IP address',
    userAgent: 'User-Agent',
    email: 'Email',
  };
  const envelope = {
    id: 'evt_a',
    occurredAt: '2026-11-14T09:30:05.000Z',
    type: 'sessions.session.started',
    actor: { kind: 'user', id: 'u-1' },
    target: { kind: 'client', id: 'c-1' },
  };
  const summaryEvent = { ...envelope, outcome: 'success', summary: "A User's Session started.", raw: null };
  const detail = { ipAddress: '198.51.100.23', userAgent: 'Agent/1.0', email: 'u1@example.test' };
  const raw = { ...envelope, seal: { seq: 2, prevHash: 'a1'.repeat(32), hash: 'b2'.repeat(32) }, detail };

  const keys = (rows) => rows.map((row) => row.key);

  it('lists Time, Actor, Target, User and Application from the envelope, without detail when raw is null', () => {
    const rows = eventSummary(summaryEvent, LABELS);
    assert.deepEqual(keys(rows), ['time', 'actor', 'target', 'user', 'application']);
    assert.deepEqual(rows[0], { key: 'time', label: 'Time (UTC)', value: '2026-11-14 09:30:05', code: false });
    assert.equal(rows[1].value, 'user u-1');
    assert.equal(rows[2].value, 'client c-1');
    assert.equal(rows[3].value, 'u-1');
    assert.equal(rows[4].value, 'c-1');
    const text = JSON.stringify(rows);
    for (const planted of Object.values(detail)) assert.equal(text.includes(planted), false);
  });

  it('adds IP address, User-Agent and Email only from raw.detail, and only the ones it holds', () => {
    assert.deepEqual(keys(eventSummary({ ...summaryEvent, raw }, LABELS)), [
      'time',
      'actor',
      'target',
      'user',
      'application',
      'ipAddress',
      'userAgent',
      'email',
    ]);
    const rows = eventSummary({ ...summaryEvent, raw: { ...raw, detail: { ipAddress: null, userAgent: 'Agent/1.0', email: null } } }, LABELS);
    assert.deepEqual(keys(rows).slice(5), ['userAgent']);
    assert.deepEqual(keys(eventSummary({ ...summaryEvent, raw: { ...raw, detail: null } }, LABELS)), ['time', 'actor', 'target', 'user', 'application']);
  });

  it('in the Deployment Log, lists no User or Application row, and the detail rows from raw', () => {
    const deployment = { ...summaryEvent, actor: { kind: 'admin', id: 'a-1' }, target: { kind: 'tenant', id: 'ten_a' }, raw };
    const rows = eventSummary(deployment, LABELS, 'deployment');
    assert.deepEqual(keys(rows), ['time', 'actor', 'target', 'ipAddress', 'userAgent', 'email']);
    assert.equal(rows[1].value, 'admin a-1');
    assert.equal(rows[2].value, 'tenant ten_a');
    // A User or Application the envelope names is still only in Actor and Target.
    assert.deepEqual(keys(eventSummary({ ...summaryEvent, raw: { ...raw, detail: null } }, LABELS, 'deployment')), ['time', 'actor', 'target']);
  });

  it('leaves out a Target, User or Application the envelope does not name', () => {
    const system = { ...summaryEvent, actor: { kind: 'system', id: null }, target: null };
    assert.deepEqual(keys(eventSummary(system, LABELS)), ['time', 'actor']);
    assert.equal(eventSummary(system, LABELS)[1].value, 'system');
    assert.equal(referenceText({ kind: 'tenant', id: 'ten_a' }), 'tenant ten_a');
  });
});
