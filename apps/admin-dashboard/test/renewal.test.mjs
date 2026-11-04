// Story 1.25: Session renewal's rules, on renewal.ts with a fake sign-in. Node runs the
// TypeScript source directly, its types stripped. The browser tests (admin-shell.spec.ts) drive
// the same module through the built dashboard; these cover what no shell page can reach yet,
// such as a state-changing request interrupted by a 401.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createRenewal, retryAfterSeconds } from '../src/shell/renewal.ts';

const ADMIN = '01900000-0000-7000-8000-000000000123';
const OTHER = '01900000-0000-7000-8000-000000000999';

/** Lets every pending promise callback run. setImmediate, so mocked timers don't hold it. */
const settle = async () => {
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve));
};

/** A sign-in the test answers by hand, one outcome per call. */
function harness() {
  const states = [];
  const tokens = [];
  const left = [];
  const pendingSignIns = [];
  const signals = [];
  const renewal = createRenewal({
    adminId: ADMIN,
    signIn: (signal) => {
      signals.push(signal);
      return new Promise((resolve) => pendingSignIns.push(resolve));
    },
    setCsrfToken: (token) => tokens.push(token),
    onChange: (state) => states.push(state),
    leave: (reason) => left.push(reason),
  });
  const answer = async (outcome) => {
    const resolve = pendingSignIns.shift();
    assert.ok(resolve, 'a sign-in is open');
    resolve(outcome);
    await settle();
  };
  return { renewal, states, tokens, left, pendingSignIns, signals, answer };
}

/** A call answering each status in turn, counting its sends. */
function call(...statuses) {
  const sent = { count: 0 };
  const fn = async () => ({ status: statuses[Math.min(sent.count++, statuses.length - 1)] });
  return { fn, sent };
}

/** A call the test answers by hand, for a 401 that arrives late. */
function heldCall() {
  const sent = { count: 0 };
  const answers = [];
  const fn = () => {
    sent.count++;
    return new Promise((resolve) => answers.push(resolve));
  };
  const reply = async (status) => {
    answers.shift()({ status });
    await settle();
  };
  return { fn, sent, reply };
}

const signedIn = (adminId = ADMIN, setupComplete = true) => ({ kind: 'signedIn', adminId, csrfToken: 'csrf-2', setupComplete });

describe('Session renewal', () => {
  it('passes anything but a 401 straight through, with no banner', async () => {
    const { renewal, states, pendingSignIns } = harness();
    const { fn, sent } = call(200);
    assert.equal((await renewal.request('get', fn)).status, 200);
    const refused = call(403);
    assert.equal((await renewal.request('post', refused.fn)).status, 403);
    assert.equal(sent.count, 1);
    assert.deepEqual(states, []);
    assert.equal(pendingSignIns.length, 0);
  });

  for (const method of ['get', 'head', ' GET ']) {
    it(`resends an interrupted read (${JSON.stringify(method)}) once after the same Admin signs in again, and clears the banner`, async () => {
      const { renewal, states, tokens, answer, pendingSignIns } = harness();
      const { fn, sent } = call(401, 200);

      const result = renewal.request(method, fn);
      await settle();
      assert.equal(renewal.state().kind, 'expired');
      assert.equal(pendingSignIns.length, 1, 'the sheet opened at once');

      await answer(signedIn());
      assert.equal((await result).status, 200);
      assert.equal(sent.count, 2);
      assert.deepEqual(tokens, ['csrf-2']);
      assert.equal(states.at(-1).kind, 'live');
    });
  }

  for (const method of ['post', 'put', 'patch', 'delete', 'POST', 'options', '', undefined]) {
    it(`never resends ${JSON.stringify(method)}: it resolves with its 401 once the Admin is back`, async () => {
      const { renewal, answer } = harness();
      const { fn, sent } = call(401, 200);

      let done = false;
      const result = renewal.request(method, fn).then((value) => {
        done = true;
        return value;
      });
      await settle();
      assert.equal(done, false, 'held, so the page stays read-only while the Session is gone');
      assert.equal(renewal.state().kind, 'expired');

      await answer(signedIn());
      assert.equal((await result).status, 401);
      assert.equal(sent.count, 1, 'sent once only: the Admin repeats the action');
      assert.equal(renewal.state().kind, 'live');
    });
  }

  it('runs one renewal for concurrent 401s, then resends each read once', async () => {
    const { renewal, answer, pendingSignIns } = harness();
    const a = call(401, 200);
    const b = call(401, 200);

    const both = Promise.all([renewal.request('get', a.fn), renewal.request('get', b.fn)]);
    await settle();
    assert.equal(pendingSignIns.length, 1);

    await answer(signedIn());
    assert.deepEqual((await both).map((r) => r.status), [200, 200]);
    assert.equal(a.sent.count, 2);
    assert.equal(b.sent.count, 2);
    assert.equal(pendingSignIns.length, 0);
  });

  it('a 401 for a request sent before the renewal, answered after it, opens no second sheet', async () => {
    const { renewal, answer, pendingSignIns } = harness();
    const first = call(401, 200);
    const late = heldCall();

    const lateResult = renewal.request('get', late.fn);
    const firstResult = renewal.request('get', first.fn);
    await settle();
    assert.equal(pendingSignIns.length, 1);
    await answer(signedIn());
    assert.equal((await firstResult).status, 200);

    // Sent under the old Session, refused only now: not a new expiry. The read goes again.
    await late.reply(401);
    assert.equal(renewal.state().kind, 'live');
    assert.equal(pendingSignIns.length, 0);
    assert.equal(late.sent.count, 2);
    await late.reply(200);
    assert.equal((await lateResult).status, 200);
  });

  it('a stale write refused after the renewal returns its 401 without a banner', async () => {
    const { renewal, answer, pendingSignIns } = harness();
    const write = heldCall();
    const read = call(401, 200);

    const writeResult = renewal.request('post', write.fn);
    const readResult = renewal.request('get', read.fn);
    await settle();
    await answer(signedIn());
    await readResult;

    await write.reply(401);
    assert.equal((await writeResult).status, 401);
    assert.equal(write.sent.count, 1);
    assert.equal(renewal.state().kind, 'live');
    assert.equal(pendingSignIns.length, 0);
  });

  it('a cancelled sheet keeps the banner and resends nothing; Sign in opens it again', async () => {
    const { renewal, answer, pendingSignIns } = harness();
    const { fn, sent } = call(401, 200);
    const result = renewal.request('get', fn);
    await settle();

    await answer({ kind: 'cancelled' });
    assert.deepEqual(renewal.state(), { kind: 'expired', signingIn: false });
    assert.equal(sent.count, 1);
    assert.equal(pendingSignIns.length, 0);

    renewal.signIn();
    assert.equal(pendingSignIns.length, 1);
    assert.equal(renewal.state().signingIn, true);
    renewal.signIn();
    assert.equal(pendingSignIns.length, 1, 'one sheet at a time');
    await answer(signedIn());
    assert.equal((await result).status, 200);
    assert.equal(sent.count, 2);
  });

  it('after a cancel, new 401s open no sheet by themselves; abandoned reads are never resent', async () => {
    const { renewal, answer, pendingSignIns } = harness();
    const first = new AbortController();
    const firstCall = call(401, 200);
    const firstResult = renewal.request('get', firstCall.fn, first.signal);
    await settle();
    await answer({ kind: 'cancelled' });

    // Three navigations, each abandoning the one before.
    let previous = first;
    const calls = [];
    const results = [firstResult.catch((error) => error.name)];
    for (let i = 0; i < 3; i++) {
      previous.abort();
      const controller = new AbortController();
      const each = call(401, 200);
      calls.push(each);
      results.push(renewal.request('get', each.fn, controller.signal).catch((error) => error.name));
      previous = controller;
      await settle();
    }
    assert.equal(pendingSignIns.length, 0, 'no sheet opened by itself again');

    renewal.signIn();
    await answer(signedIn());
    const settled = await Promise.all(results);
    assert.deepEqual(settled.slice(0, 3), ['AbortError', 'AbortError', 'AbortError']);
    assert.equal(settled[3].status, 200);
    assert.equal(firstCall.sent.count, 1);
    assert.deepEqual(calls.map((each) => each.sent.count), [1, 1, 2], "only the current navigation's read is resent");

    // Live again: the next expiry's sheet opens by itself once more.
    void renewal.request('get', call(401, 200).fn);
    await settle();
    assert.equal(pendingSignIns.length, 1);
  });

  for (const [outcome, kind] of [
    [{ kind: 'refused' }, 'refused'],
    [{ kind: 'rateLimited', seconds: null }, 'rateLimited'],
    [{ kind: 'unavailable' }, 'unavailable'],
  ]) {
    it(`a ${kind} sign-in keeps the page waiting with its banner; a new 401 opens nothing, and Sign in retries`, async () => {
      const { renewal, answer, pendingSignIns } = harness();
      const { fn, sent } = call(401, 200);
      const result = renewal.request('get', fn);
      await settle();

      await answer(outcome);
      assert.equal(renewal.state().kind, kind);
      assert.equal(sent.count, 1);
      void renewal.request('get', call(401, 200).fn);
      await settle();
      assert.equal(pendingSignIns.length, 0);

      renewal.signIn();
      await answer(signedIn());
      assert.equal((await result).status, 200);
    });
  }

  it("a rate limit's Retry-After window holds Sign in back until it ends", async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const { renewal, answer, pendingSignIns } = harness();
    void renewal.request('get', call(401, 200).fn);
    await settle();

    await answer({ kind: 'rateLimited', seconds: 30 });
    assert.deepEqual(renewal.state(), { kind: 'rateLimited', seconds: 30, signingIn: false, cooling: true });
    renewal.signIn();
    assert.equal(pendingSignIns.length, 0, 'no begin during the window');

    t.mock.timers.tick(29_000);
    renewal.signIn();
    assert.equal(pendingSignIns.length, 0);
    t.mock.timers.tick(1_000);
    assert.equal(renewal.state().cooling, false);
    renewal.signIn();
    assert.equal(pendingSignIns.length, 1);
  });

  it('a sign-in that throws counts as unavailable', async () => {
    const renewal = createRenewal({
      adminId: ADMIN,
      signIn: async () => {
        throw new Error('lost');
      },
      setCsrfToken: () => {},
      onChange: () => {},
      leave: () => {},
    });
    void renewal.request('get', call(401).fn);
    await settle();
    assert.equal(renewal.state().kind, 'unavailable');
  });

  it("another Admin's sign-in leaves for a full load and resends nothing", async () => {
    const { renewal, answer, left } = harness();
    const { fn, sent } = call(401, 200);
    let done = false;
    void renewal.request('get', fn).then(() => (done = true));
    await settle();

    await answer(signedIn(OTHER));
    assert.deepEqual(left, ['another-admin']);
    assert.equal(sent.count, 1);
    assert.equal(done, false);
  });

  it('a sign-in still without both credentials goes to credential setup and resends nothing', async () => {
    const { renewal, answer, left } = harness();
    const { fn, sent } = call(401, 200);
    void renewal.request('get', fn);
    await settle();

    await answer(signedIn(ADMIN, false));
    assert.deepEqual(left, ['setup']);
    assert.equal(sent.count, 1);
  });

  it('a resent read refused again shows the banner without opening the sheet: no loop', async () => {
    const { renewal, answer, pendingSignIns } = harness();
    const { fn, sent } = call(401, 401, 200);
    const result = renewal.request('get', fn);
    await settle();

    await answer(signedIn());
    assert.equal(sent.count, 2, 'resent once');
    assert.equal(renewal.state().kind, 'expired');
    assert.equal(pendingSignIns.length, 0, 'the sheet waits for the Admin');

    renewal.signIn();
    await answer(signedIn());
    assert.equal((await result).status, 200);
    assert.equal(sent.count, 3, 'one resend per renewal');
  });

  it('cancel stops the sign-in under way and waits for it: a late Session keeps its token for sign-out, and nothing resumes', async () => {
    const { renewal, signals, pendingSignIns, tokens } = harness();
    const { fn, sent } = call(401, 200);
    void renewal.request('get', fn);
    await settle();

    let cancelled = false;
    const done = renewal.cancel().then(() => (cancelled = true));
    assert.equal(signals[0].aborted, true);
    await settle();
    assert.equal(cancelled, false, 'waits for the sign-in to settle');

    pendingSignIns.shift()(signedIn());
    await done;
    assert.deepEqual(tokens, ['csrf-2']);
    assert.deepEqual(renewal.state(), { kind: 'expired', signingIn: false });
    assert.equal(sent.count, 1, 'nothing resent');
  });

  it('after dispose nothing a late sign-in answers lands', async () => {
    const { renewal, signals, pendingSignIns, tokens, states, left } = harness();
    void renewal.request('get', call(401, 200).fn);
    await settle();
    const before = states.length;

    renewal.dispose();
    assert.equal(signals[0].aborted, true);
    pendingSignIns.shift()(signedIn(OTHER));
    await settle();
    assert.deepEqual(tokens, []);
    assert.deepEqual(left, []);
    assert.equal(states.length, before);
    renewal.signIn();
    assert.equal(pendingSignIns.length, 0);
  });

  it('Sign in does nothing while the Session is live, and cancel resolves at once', async () => {
    const { renewal, pendingSignIns } = harness();
    renewal.signIn();
    assert.equal(pendingSignIns.length, 0);
    await renewal.cancel();
  });

  it('reads Retry-After as whole seconds only', () => {
    assert.equal(retryAfterSeconds('30'), 30);
    assert.equal(retryAfterSeconds(' 5 '), 5);
    assert.equal(retryAfterSeconds('0'), null);
    assert.equal(retryAfterSeconds('1.5'), null);
    assert.equal(retryAfterSeconds('Wed, 21 Oct 2026 07:28:00 GMT'), null);
    assert.equal(retryAfterSeconds(null), null);
  });
});

