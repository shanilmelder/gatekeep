// Story 1.29 review: the Tenants list refresh rules, on refresh.ts. Node runs the TypeScript source
// directly, its types stripped. The browser tests (admin-tenants.spec.ts) drive the same module
// through the built dashboard.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { REFRESH_MAX_MS, REFRESH_MS, inProgress, merge, reaches, refreshDelay } from '../src/shell/refresh.ts';

const row = (n, extra = {}) => ({
  id: `ten_${String(n).padStart(2, '0')}`,
  createdAt: `2026-11-05T00:00:${String(n).padStart(2, '0')}Z`,
  status: 'active',
  creation: null,
  deletion: null,
  ...extra,
});
const deleting = (n, status = 'running') => row(n, { status: 'deleting', deletion: { operationId: `opr_${n}`, status } });

describe('inProgress', () => {
  it('is a running creation or deletion, never a failed one, and never an active row', () => {
    assert.equal(inProgress(row(1, { status: 'creating', creation: { operationId: 'opr_1', status: 'running' } })), true);
    assert.equal(inProgress(row(1, { status: 'creating', creation: { operationId: 'opr_1', status: 'failed' } })), false);
    assert.equal(inProgress(deleting(1)), true);
    assert.equal(inProgress(deleting(1, 'failed')), false);
    assert.equal(inProgress(row(1)), false);
  });
});

describe('refreshDelay', () => {
  it('starts at REFRESH_MS, doubles every ten refreshes, and stops growing at REFRESH_MAX_MS', () => {
    assert.equal(refreshDelay(0), REFRESH_MS);
    assert.equal(refreshDelay(9), REFRESH_MS);
    assert.equal(refreshDelay(10), REFRESH_MS * 2);
    assert.equal(refreshDelay(20), REFRESH_MS * 4);
    assert.equal(refreshDelay(1000), REFRESH_MAX_MS);
    assert.equal(refreshDelay(-1), REFRESH_MS);
  });
});

describe('reaches', () => {
  const loaded = [row(1), row(2), row(3), deleting(4)];

  it('is reached once a page ends at or past the last loaded row, or there is no next page', () => {
    assert.equal(reaches({ tenants: [row(1), row(2)], nextCursor: 'ten_02' }, loaded), false);
    assert.equal(reaches({ tenants: [row(1), row(2), row(3), deleting(4)], nextCursor: 'ten_04' }, loaded), true);
    assert.equal(reaches({ tenants: [row(1), row(2), row(3), row(5)], nextCursor: 'ten_05' }, loaded), true);
    assert.equal(reaches({ tenants: [row(1)], nextCursor: null }, loaded), true);
    assert.equal(reaches({ tenants: [], nextCursor: 'x' }, []), true);
  });
});

describe('merge', () => {
  it('replaces each loaded row the refresh has, and adds none', () => {
    const current = [row(1), deleting(2), row(3)];
    const merged = merge(current, { tenants: [row(1, { name: 'renamed' }), deleting(2, 'failed')], nextCursor: 'ten_02' });

    assert.deepEqual(merged.map((r) => r.id), ['ten_01', 'ten_02', 'ten_03']);
    assert.equal(merged[0].name, 'renamed');
    assert.equal(merged[1].deletion.status, 'failed');
    assert.equal(merged[2], current[2]);
  });

  it('drops a deleting row the pages read cover but no longer list: it was deleted', () => {
    const merged = merge([row(1), deleting(2), row(3)], { tenants: [row(1), row(3)], nextCursor: null });

    assert.deepEqual(merged.map((r) => r.id), ['ten_01', 'ten_03']);
  });

  it('keeps a deleting row past the pages read, with its badge, until a refresh reaches it', () => {
    const later = deleting(60);
    const merged = merge([row(1), row(2), later], { tenants: [row(1), row(2)], nextCursor: 'ten_02' });

    assert.deepEqual(merged.map((r) => r.id), ['ten_01', 'ten_02', 'ten_60']);
    assert.equal(merged[2], later);
  });

  it('updates a busy row on a later page once the refresh reads through it', () => {
    const merged = merge(
      [row(1), row(2), deleting(60)],
      { tenants: [row(1), row(2), deleting(60, 'failed')], nextCursor: null },
    );

    assert.equal(merged[2].deletion.status, 'failed');
  });

  it('keeps an active row the refresh no longer lists: only a deleting one is taken as deleted', () => {
    const merged = merge([row(1), row(2)], { tenants: [row(1)], nextCursor: null });

    assert.deepEqual(merged.map((r) => r.id), ['ten_01', 'ten_02']);
  });
});
