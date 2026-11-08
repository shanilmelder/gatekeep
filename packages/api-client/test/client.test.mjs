// Story 1.21: the api-client's fetch wrapper with a fake fetch. Node runs the TypeScript source
// directly, its types stripped.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CSRF_HEADER, TENANT_HEADER, createApiClient, parseProblem } from '../src/client.ts';

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
    assert.deepEqual(rest, { ok: true, status: 200, data: { capabilities: [] }, path: '/api/v1/deployment/capabilities', pageTenant: null });
  });

  it("puts the Tenant's public ID into the templated path, encoded", async () => {
    const { calls, fetch } = fakeFetch(200, JSON.stringify({ capabilities: ['tenant.configuration.read'] }));
    const client = createApiClient({ fetch, csrfToken: () => 'csrf-1' });

    const result = await client.getTenantCapabilities('ten_aaaaaaaaaaaaaaaaaaaaaaaaab');
    await client.getTenantCapabilities('../deployment/session?x=1#y');

    assert.equal(calls[0].input, '/api/v1/tenants/ten_aaaaaaaaaaaaaaaaaaaaaaaaab/capabilities');
    assert.equal(calls[0].init.method, 'GET');
    assert.equal(CSRF_HEADER in calls[0].init.headers, false);
    assert.deepEqual(result.data, { capabilities: ['tenant.configuration.read'] });
    // Encoded, a hostile ID stays one path segment and can't reach another path.
    assert.equal(calls[1].input, '/api/v1/tenants/..%2Fdeployment%2Fsession%3Fx%3D1%23y/capabilities');
  });

  it('reads an access_denied refusal as its problem', async () => {
    const { fetch } = fakeFetch(403, JSON.stringify({ code: 'access_denied', traceId: 't-3' }), 'application/problem+json');

    const result = await createApiClient({ fetch }).getTenantCapabilities('ten_aaaaaaaaaaaaaaaaaaaaaaaaab');

    const { headers, ...rest } = result;
    assert.ok(headers instanceof Headers);
    assert.deepEqual(rest, {
      ok: false,
      status: 403,
      problem: { code: 'access_denied', traceId: 't-3' },
      path: '/api/v1/tenants/ten_aaaaaaaaaaaaaaaaaaaaaaaaab/capabilities',
      pageTenant: null,
    });
  });

  it('reads a problem body into its code and trace ID only', async () => {
    const { fetch } = fakeFetch(400, JSON.stringify({ code: 'bootstrap_refused', traceId: 't-1', detail: 'x' }), 'application/problem+json');

    const result = await createApiClient({ fetch }).claimBootstrap('x');

    const { headers, ...rest } = result;
    assert.ok(headers instanceof Headers);
    assert.deepEqual(rest, {
      ok: false,
      status: 400,
      problem: { code: 'bootstrap_refused', traceId: 't-1' },
      path: '/api/v1/deployment/bootstrap',
      pageTenant: null,
    });
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
      assert.deepEqual(rest, { ok: false, status, problem: null, path: '/api/v1/deployment/session', pageTenant: null }, `${status} ${body}`);
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

  it('lists, creates and retries Tenants on their own paths, IDs and the cursor encoded', async () => {
    const { calls, fetch } = fakeFetch(202, JSON.stringify({ id: 'opr_a' }));
    const client = createApiClient({ fetch, csrfToken: () => 'csrf-1' });
    const body = { name: 'Acme Dev', subdomain: 'acme-dev', label: 'dev' };

    await client.listTenants();
    await client.listTenants('ten_a&b=c');
    await client.createTenant(body);
    await client.getTenantOperation('ten_a/b', 'opr_c?d');
    const result = await client.retryOperation('opr_e#f');

    assert.equal(calls[0].input, '/api/v1/deployment/tenants');
    assert.equal(calls[0].init.method, 'GET');
    assert.equal(calls[1].input, '/api/v1/deployment/tenants?cursor=ten_a%26b%3Dc');
    assert.equal(calls[2].input, '/api/v1/deployment/tenants');
    assert.equal(calls[2].init.method, 'POST');
    assert.equal(calls[2].init.body, JSON.stringify(body));
    assert.equal(calls[2].init.headers[CSRF_HEADER], 'csrf-1');
    assert.equal(calls[3].input, '/api/v1/tenants/ten_a%2Fb/operations/opr_c%3Fd');
    assert.equal(CSRF_HEADER in calls[3].init.headers, false);
    assert.equal(calls[4].input, '/api/v1/deployment/operations/opr_e%23f/retry');
    assert.equal(calls[4].init.method, 'POST');
    assert.equal(calls[4].init.body, undefined);
    assert.equal(calls[4].init.headers[CSRF_HEADER], 'csrf-1');
    assert.equal(result.status, 202);
  });

  it('deletes a Tenant, reads and retries its deletion on the Deployment paths, the ID encoded', async () => {
    const { calls, fetch } = fakeFetch(202, JSON.stringify({ id: 'opr_a' }));
    const client = createApiClient({ fetch, csrfToken: () => 'csrf-1', pageTenant: () => 'ten_page' });
    const body = { confirmation: 'acme.id.example.com' };

    const deleted = await client.deleteTenant('ten_a/b', body);
    await client.getTenantDeletion('ten_c?d');
    const retried = await client.retryTenantDeletion('ten_e#f');

    assert.equal(calls[0].input, '/api/v1/deployment/tenants/ten_a%2Fb/deletion');
    assert.equal(calls[0].init.method, 'POST');
    assert.equal(calls[0].init.body, JSON.stringify(body));
    assert.equal(calls[0].init.headers['Content-Type'], 'application/json');
    assert.equal(calls[0].init.headers[CSRF_HEADER], 'csrf-1');
    // The Deployment surface: no page Tenant is ever sent.
    assert.equal(TENANT_HEADER in calls[0].init.headers, false);
    assert.equal(deleted.status, 202);
    assert.equal(calls[1].input, '/api/v1/deployment/tenants/ten_c%3Fd/deletion');
    assert.equal(calls[1].init.method, 'GET');
    assert.equal(CSRF_HEADER in calls[1].init.headers, false);
    assert.equal(calls[2].input, '/api/v1/deployment/tenants/ten_e%23f/deletion/retry');
    assert.equal(calls[2].init.method, 'POST');
    assert.equal(calls[2].init.body, undefined);
    assert.equal(calls[2].init.headers[CSRF_HEADER], 'csrf-1');
    assert.equal(TENANT_HEADER in calls[2].init.headers, false);
    assert.equal(retried.status, 202);
  });

  it("reads a Tenant's Signing Keys and its JWKS sample on their own paths, the ID encoded, with no page Tenant", async () => {
    const keys = { keys: [{ keyId: 'sig-a.v1', algorithm: 'RS256', state: 'current', createdAt: '2026-11-06T09:00:00.000Z' }] };
    const { calls, fetch } = fakeFetch(200, JSON.stringify(keys));
    const client = createApiClient({ fetch, csrfToken: () => 'csrf-1', pageTenant: () => 'ten_a' });

    const listed = await client.listSigningKeys('ten_a/b');
    const sample = await client.getSigningKeysJwks('ten_c?d');

    assert.equal(calls[0].input, '/api/v1/tenants/ten_a%2Fb/signing-keys');
    assert.equal(calls[0].init.method, 'GET');
    assert.equal(calls[1].input, '/api/v1/tenants/ten_c%3Fd/signing-keys/jwks');
    assert.equal(calls[1].init.method, 'GET');
    for (const call of calls) {
      assert.equal(call.init.body, undefined);
      assert.equal(CSRF_HEADER in call.init.headers, false);
      assert.equal(TENANT_HEADER in call.init.headers, false);
    }
    assert.equal(listed.ok, true);
    assert.deepEqual(listed.data, keys);
    assert.equal(sample.ok, true);
  });

  it("reads a JWKS sample's 503 as a failure with no problem body", async () => {
    const { fetch } = fakeFetch(503);
    const client = createApiClient({ fetch });

    const sample = await client.getSigningKeysJwks('ten_a');

    assert.equal(sample.ok, false);
    assert.equal(sample.status, 503);
    assert.equal(sample.path, '/api/v1/tenants/ten_a/signing-keys/jwks');
  });

  it('sends the page Tenant only on state-changing Tenant-surface calls, when there is one', async () => {
    const { calls, fetch } = fakeFetch(200, JSON.stringify({ label: 'dev' }));
    let page = 'ten_a';
    const client = createApiClient({ fetch, csrfToken: () => 'csrf-1', pageTenant: () => page });

    await client.setTenantLabel('ten_a', { label: 'dev' });
    await client.beginTenantFreshAssertion('ten_a', { action: 'tenant.label.manage', target: null });
    await client.getTenantLabel('ten_a');
    await client.listMyTenants();
    await client.createTenant({ name: 'A', subdomain: 'acme', label: 'dev' });
    page = null;
    await client.setTenantLabel('ten_a', { label: 'prod' });
    page = 'ten_b';
    await client.setTenantLabel('ten_a/x', { label: 'prod' });

    // The page's Tenant, read at send time, never the path's: the server compares the two.
    assert.equal(calls[0].input, '/api/v1/tenants/ten_a/label');
    assert.equal(calls[0].init.method, 'PUT');
    assert.equal(calls[0].init.body, JSON.stringify({ label: 'dev' }));
    assert.equal(calls[0].init.headers[TENANT_HEADER], 'ten_a');
    assert.equal(calls[0].init.headers[CSRF_HEADER], 'csrf-1');
    assert.equal(calls[1].input, '/api/v1/tenants/ten_a/assertions');
    assert.equal(calls[1].init.method, 'POST');
    assert.equal(calls[1].init.headers[TENANT_HEADER], 'ten_a');
    // Reads, Deployment paths and a page with no Tenant send none.
    assert.equal(calls[2].input, '/api/v1/tenants/ten_a/label');
    assert.equal(calls[2].init.method, 'GET');
    assert.equal(TENANT_HEADER in calls[2].init.headers, false);
    assert.equal(calls[3].input, '/api/v1/deployment/my-tenants');
    assert.equal(TENANT_HEADER in calls[3].init.headers, false);
    assert.equal(TENANT_HEADER in calls[4].init.headers, false);
    assert.equal(TENANT_HEADER in calls[5].init.headers, false);
    assert.equal(calls[6].input, '/api/v1/tenants/ten_a%2Fx/label');
    assert.equal(calls[6].init.headers[TENANT_HEADER], 'ten_b');
  });

  it('returns with each answer the path it sent and the page Tenant it carried, if any', async () => {
    const { fetch } = fakeFetch(409, JSON.stringify({ code: 'tenant_mismatch', traceId: 't' }), 'application/problem+json');
    let page = 'ten_b';
    const client = createApiClient({ fetch, csrfToken: () => 'csrf-1', pageTenant: () => page });

    const mismatch = await client.setTenantLabel('ten_a', { label: 'dev' });
    page = null;
    const none = await client.setTenantLabel('ten_a', { label: 'dev' });
    const read = await client.getTenantLabel('ten_c');

    assert.deepEqual([mismatch.path, mismatch.pageTenant, mismatch.problem?.code], ['/api/v1/tenants/ten_a/label', 'ten_b', 'tenant_mismatch']);
    assert.deepEqual([none.path, none.pageTenant], ['/api/v1/tenants/ten_a/label', null]);
    assert.deepEqual([read.path, read.pageTenant], ['/api/v1/tenants/ten_c/label', null]);
  });

  it('sends no page Tenant without the option', async () => {
    const { calls, fetch } = fakeFetch(200, '{}');
    const client = createApiClient({ fetch, csrfToken: () => 'csrf-1' });

    await client.setTenantLabel('ten_a', { label: 'dev' });

    assert.equal(TENANT_HEADER in calls[0].init.headers, false);
  });

  it('parses only a string code, and a missing trace ID as empty', () => {
    assert.equal(parseProblem(null), null);
    assert.equal(parseProblem('x'), null);
    assert.equal(parseProblem({ code: 5 }), null);
    assert.equal(parseProblem({ code: '' }), null);
    assert.deepEqual(parseProblem({ code: 'rate_limited' }), { code: 'rate_limited', traceId: '' });
  });
});
