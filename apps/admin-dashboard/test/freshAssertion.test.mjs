// Story 1.26: the fresh-assertion helper's rules, on freshAssertion.ts with fake calls. Node runs
// the TypeScript source directly, its types stripped. The browser tests
// (admin-credentials.spec.ts) drive the same module through the built dashboard.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createFreshAssertion, needsFreshAssertion } from '../src/shell/freshAssertion.ts';

const headers = (values = {}) => ({ get: (name) => values[name] ?? null });
const answer = (status, extra = {}) => ({ ok: status >= 200 && status < 300, status, headers: headers(), problem: null, ...extra });
const problem = (status, code, extra = {}) => ({ ...answer(status), problem: { code }, ...extra });
const OPTIONS = { challenge: 'c', rpId: 'localhost', timeout: 1, userVerification: 'required', allowCredentials: [] };

/** Calls answering as the test says, each recorded. */
function harness({ begin = answer(200, { data: OPTIONS }), complete = answer(204), sheet = async () => ({ id: 'assertion' }) } = {}) {
  const log = [];
  const calls = {
    begin: async (binding) => {
      log.push(['begin', binding]);
      return typeof begin === 'function' ? begin() : begin;
    },
    complete: async (assertion) => {
      log.push(['complete', assertion]);
      return typeof complete === 'function' ? complete() : complete;
    },
    assert: async (options, signal) => {
      log.push(['sheet', options]);
      return sheet(signal);
    },
  };
  return { log, fresh: createFreshAssertion(calls) };
}

const domError = (name) => Object.assign(new Error(name), { name });

describe('confirmItsYou', () => {
  it('begins for the binding, opens the sheet with its options and completes: confirmed', async () => {
    const { log, fresh } = harness();
    assert.deepEqual(await fresh.confirmItsYou({ action: 'self.credentials.remove', target: 'acr_x' }), { kind: 'confirmed' });
    assert.deepEqual(log, [
      ['begin', { action: 'self.credentials.remove', target: 'acr_x' }],
      ['sheet', OPTIONS],
      ['complete', { id: 'assertion' }],
    ]);
  });

  it('sends a missing target as null', async () => {
    const { log, fresh } = harness();
    await fresh.confirmItsYou({ action: 'self.credentials.add' });
    assert.deepEqual(log[0], ['begin', { action: 'self.credentials.add', target: null }]);
  });

  for (const name of ['NotAllowedError', 'AbortError']) {
    it(`treats ${name} from the sheet as cancelled, and sends no complete`, async () => {
      const { log, fresh } = harness({ sheet: async () => Promise.reject(domError(name)) });
      assert.deepEqual(await fresh.confirmItsYou({ action: 'self.credentials.add' }), { kind: 'cancelled' });
      assert.equal(log.filter(([step]) => step === 'complete').length, 0);
    });
  }

  it('treats any other sheet failure, or no credential, as unavailable', async () => {
    for (const sheet of [async () => Promise.reject(domError('SecurityError')), async () => null]) {
      const { fresh } = harness({ sheet });
      assert.deepEqual(await fresh.confirmItsYou({ action: 'self.credentials.add' }), { kind: 'unavailable' });
    }
  });

  it('maps a refused begin or complete: 400 refused, 429 rate-limited with Retry-After, the rest unavailable', async () => {
    const cases = [
      [{ begin: problem(400, 'assertion_refused') }, { kind: 'refused' }],
      [{ complete: problem(400, 'assertion_refused') }, { kind: 'refused' }],
      [{ begin: problem(429, 'rate_limited', { headers: headers({ 'Retry-After': '30' }) }) }, { kind: 'rateLimited', seconds: 30 }],
      [{ complete: problem(429, 'rate_limited', { headers: headers({ 'Retry-After': 'soon' }) }) }, { kind: 'rateLimited', seconds: null }],
      [{ begin: problem(403, 'access_denied') }, { kind: 'unavailable' }],
      [{ complete: answer(503) }, { kind: 'unavailable' }],
      [{ begin: answer(200) }, { kind: 'unavailable' }],
      [{ complete: answer(200, { data: {} }) }, { kind: 'unavailable' }],
      [{ begin: () => Promise.reject(new TypeError('offline')) }, { kind: 'unavailable' }],
    ];
    for (const [options, expected] of cases) {
      const { fresh } = harness(options);
      assert.deepEqual(await fresh.confirmItsYou({ action: 'self.credentials.add' }), expected, JSON.stringify(expected));
    }
  });

  it('stops once its signal fires, without opening the sheet', async () => {
    const controller = new AbortController();
    controller.abort();
    const { log, fresh } = harness();
    assert.deepEqual(await fresh.confirmItsYou({ action: 'self.credentials.add' }, controller.signal), { kind: 'cancelled' });
    assert.deepEqual(log, []);
  });
});

describe('withFreshAssertion', () => {
  const binding = { action: 'self.credentials.remove', target: 'acr_x' };

  it('sends once, and confirms nothing, when the server needs no fresh assertion', async () => {
    const { log, fresh } = harness();
    let sent = 0;
    const done = answer(204);
    const result = await fresh.withFreshAssertion(binding, async () => {
      sent++;
      return done;
    });
    assert.deepEqual(result, { kind: 'answered', answer: done });
    assert.equal(sent, 1);
    assert.deepEqual(log, []);
  });

  it('passes any other refusal straight back, a 403 access_denied included', async () => {
    const { log, fresh } = harness();
    const denied = problem(403, 'access_denied');
    assert.deepEqual(await fresh.withFreshAssertion(binding, async () => denied), { kind: 'answered', answer: denied });
    assert.deepEqual(log, []);
  });

  it('on fresh_assertion_required confirms for the binding, then sends once more', async () => {
    const { log, fresh } = harness();
    const answers = [problem(403, 'fresh_assertion_required'), answer(204)];
    let sent = 0;
    const result = await fresh.withFreshAssertion(binding, async () => answers[sent++]);
    assert.deepEqual(result, { kind: 'answered', answer: answers[1] });
    assert.equal(sent, 2);
    assert.deepEqual(log[0], ['begin', { action: 'self.credentials.remove', target: 'acr_x' }]);
  });

  it('a second fresh_assertion_required is refused, and nothing is sent a third time', async () => {
    const { fresh } = harness();
    let sent = 0;
    const result = await fresh.withFreshAssertion(binding, async () => {
      sent++;
      return problem(403, 'fresh_assertion_required');
    });
    assert.deepEqual(result, { kind: 'unconfirmed', confirmation: { kind: 'refused' } });
    assert.equal(sent, 2);
  });

  it('an unconfirmed confirmation sends the action no second time', async () => {
    for (const [options, expected] of [
      [{ sheet: async () => Promise.reject(domError('NotAllowedError')) }, { kind: 'cancelled' }],
      [{ complete: problem(400, 'assertion_refused') }, { kind: 'refused' }],
      [{ begin: answer(503) }, { kind: 'unavailable' }],
    ]) {
      const { fresh } = harness(options);
      let sent = 0;
      const result = await fresh.withFreshAssertion(binding, async () => {
        sent++;
        return problem(403, 'fresh_assertion_required');
      });
      assert.deepEqual(result, { kind: 'unconfirmed', confirmation: expected });
      assert.equal(sent, 1);
    }
  });

  it('a later answer after the confirmation is passed back as it is, a 409 included', async () => {
    const { fresh } = harness();
    const answers = [problem(403, 'fresh_assertion_required'), problem(409, 'credentials_minimum')];
    let sent = 0;
    const result = await fresh.withFreshAssertion(binding, async () => answers[sent++]);
    assert.deepEqual(result, { kind: 'answered', answer: answers[1] });
  });
});

describe('needsFreshAssertion', () => {
  it('is the 403 fresh_assertion_required only', () => {
    assert.equal(needsFreshAssertion(problem(403, 'fresh_assertion_required')), true);
    assert.equal(needsFreshAssertion(problem(403, 'access_denied')), false);
    assert.equal(needsFreshAssertion(answer(403)), false);
    assert.equal(needsFreshAssertion(problem(400, 'fresh_assertion_required')), false);
    assert.equal(needsFreshAssertion(null), false);
  });
});
