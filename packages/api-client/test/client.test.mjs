// Story 1.21: the api-client's fetch wrapper with a fake fetch. Node runs the TypeScript source
// directly, its types stripped.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CSRF_HEADER, createApiClient, parseProblem } from '../src/client.ts';

/** A fetch that records each call and answers with `status` and `body`. */
function fakeFetch(status, body = '', contentType = 'application/json') {
  const calls = [];
  const fetch = async (input, init) => {
    calls.push({ input, init });
    return new Response(status === 204 ? null : body, { status, headers: body === '' ? {} : { 'Content-Type': contentType } });
  };
  return { calls, fetch };
}

describe('api-client', () => {
  it('sends the CSRF header on a state-changing call when a token is set', async () => {
    const { calls, fetch } = fakeFetch(204);
    const client = createApiClient({ fetch, csrfToken: () => 'csrf-1' });

    const result = await client.endSession();

    assert.equal(result.ok, true);
    assert.equal(calls[0].init.method, 'DELETE');
    assert.equal(calls[0].init.headers[CSRF_HEADER], 'csrf-1');
  });

  it('sends no CSRF header without a token, or on a GET', async () => {
    const { calls, fetch } = fakeFetch(201, JSON.stringify({ csrfToken: 'c', adminId: 'a' }));
    const withToken = createApiClient({ fetch, csrfToken: () => 'csrf-1' });
    const withoutToken = createApiClient({ fetch, csrfToken: () => null });

    await withoutToken.claimBootstrap('  token  ');
    await withToken.getSession();

    assert.equal(CSRF_HEADER in calls[0].init.headers, false);
    assert.equal(calls[0].init.method, 'POST');
    assert.equal(calls[0].init.body, JSON.stringify({ token: 'token' }));
    assert.equal(CSRF_HEADER in calls[1].init.headers, false);
    assert.equal(calls[1].init.method, 'GET');
  });

  it("stays on the page's origin with its cookies", async () => {
    const { calls, fetch } = fakeFetch(200, JSON.stringify({ capabilities: [] }));

    const result = await createApiClient({ fetch }).getCapabilities();

    assert.equal(calls[0].input, '/api/v1/deployment/capabilities');
    assert.equal(calls[0].init.credentials, 'same-origin');
    assert.equal(calls[0].init.cache, 'no-store');
    const { headers, ...rest } = result;
    assert.ok(headers instanceof Headers);
    assert.deepEqual(rest, { ok: true, status: 200, data: { capabilities: [] } });
  });

  it('reads a problem body into its code and trace ID only', async () => {
    const { fetch } = fakeFetch(400, JSON.stringify({ code: 'bootstrap_refused', traceId: 't-1', detail: 'x' }), 'application/problem+json');

    const result = await createApiClient({ fetch }).claimBootstrap('x');

    const { headers, ...rest } = result;
    assert.ok(headers instanceof Headers);
    assert.deepEqual(rest, { ok: false, status: 400, problem: { code: 'bootstrap_refused', traceId: 't-1' } });
  });

  it("exposes the response's headers, such as a 429's Retry-After", async () => {
    const fetch = async () =>
      new Response(JSON.stringify({ code: 'rate_limited', traceId: 't-2' }), {
        status: 429,
        headers: { 'Content-Type': 'application/problem+json', 'Retry-After': '300' },
      });

    const result = await createApiClient({ fetch }).claimBootstrap('x');

    assert.equal(result.ok, false);
    assert.equal(result.headers.get('Retry-After'), '300');
  });

  it('has no problem for an empty or non-JSON body', async () => {
    for (const [status, body, type] of [
      [401, '', 'application/json'],
      [404, '', 'application/json'],
      [503, '<html>busy</html>', 'text/html'],
      [403, 'not json', 'text/plain'],
    ]) {
      const { fetch } = fakeFetch(status, body, type);
      const result = await createApiClient({ fetch }).getSession();
      const { headers, ...rest } = result;
      assert.ok(headers instanceof Headers);
      assert.deepEqual(rest, { ok: false, status, problem: null }, `${status} ${body}`);
    }
  });

  it('begins a credential registration with the CSRF header and no body, and completes it with the credential', async () => {
    const { calls, fetch } = fakeFetch(200, JSON.stringify({ credentials: 1, setupComplete: false }));
    const client = createApiClient({ fetch, csrfToken: () => 'csrf-1' });
    const credential = {
      id: 'AQ',
      rawId: 'AQ',
      type: 'public-key',
      response: { clientDataJSON: 'e30', attestationObject: 'oA', transports: ['usb'] },
    };

    await client.beginCredentialRegistration();
    const result = await client.completeCredentialRegistration(credential);

    assert.equal(calls[0].input, '/api/v1/deployment/credentials/registration');
    assert.equal(calls[0].init.method, 'POST');
    assert.equal(calls[0].init.body, undefined);
    assert.equal(calls[0].init.headers[CSRF_HEADER], 'csrf-1');
    assert.equal(calls[1].input, '/api/v1/deployment/credentials/registration/complete');
    assert.equal(calls[1].init.method, 'POST');
    assert.equal(calls[1].init.body, JSON.stringify(credential));
    assert.equal(calls[1].init.headers['Content-Type'], 'application/json');
    assert.equal(calls[1].init.headers[CSRF_HEADER], 'csrf-1');
    assert.deepEqual(result.data, { credentials: 1, setupComplete: false });
  });

  it('begins and completes an Admin sign-in on its own paths, with the body as given', async () => {
    const { calls, fetch } = fakeFetch(200, JSON.stringify({ adminId: 'a', csrfToken: 'c', setupComplete: true }));
    const client = createApiClient({ fetch, csrfToken: () => null });
    const assertion = {
      id: 'AQ',
      rawId: 'AQ',
      type: 'public-key',
      response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'AA', userHandle: 'AQ' },
    };

    await client.beginSignIn();
    const result = await client.completeSignIn(assertion);

    // No Session yet, so no CSRF token: sign-in relies on the exact Origin and its binding cookie.
    assert.equal(calls[0].input, '/api/v1/deployment/signin');
    assert.equal(calls[0].init.method, 'POST');
    assert.equal(calls[0].init.body, undefined);
    assert.equal(CSRF_HEADER in calls[0].init.headers, false);
    assert.equal(calls[1].input, '/api/v1/deployment/signin/complete');
    assert.equal(calls[1].init.body, JSON.stringify(assertion));
    assert.equal(calls[1].init.credentials, 'same-origin');
    assert.deepEqual(result.data, { adminId: 'a', csrfToken: 'c', setupComplete: true });
  });

  it('parses only a string code, and a missing trace ID as empty', () => {
    assert.equal(parseProblem(null), null);
    assert.equal(parseProblem('x'), null);
    assert.equal(parseProblem({ code: 5 }), null);
    assert.equal(parseProblem({ code: '' }), null);
    assert.deepEqual(parseProblem({ code: 'rate_limited' }), { code: 'rate_limited', traceId: '' });
  });
});
