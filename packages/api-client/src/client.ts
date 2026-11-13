// The hand-written fetch wrapper over the generated types (Story 1.21). It has no runtime
// dependency: the browser's fetch only. Every call stays on the page's own origin with its
// cookies (credentials: 'same-origin'), a state-changing call carries the Session's CSRF token
// in X-Gatekeep-CSRF, and a refusal's problem body is read into { code, traceId }. Each call's
// request and response types come from the committed OpenAPI document, by path and method.

import type { components, operations, paths } from './schema.generated';

export type ApiProblem = components['schemas']['ApiProblem'];
export type BootstrapClaimResponse = components['schemas']['BootstrapClaimResponse'];
export type AdminSessionResponse = components['schemas']['AdminSessionResponse'];
export type CapabilitiesResponse = components['schemas']['CapabilitiesResponse'];
/** The capabilities the current Admin holds in one Tenant, named by the path. */
export type TenantCapabilities = CapabilitiesResponse;
export type CredentialCreationOptionsResponse = components['schemas']['CredentialCreationOptionsResponse'];
export type CredentialRegistrationRequest = components['schemas']['CredentialRegistrationRequest'];
export type CredentialRegistrationResponse = components['schemas']['CredentialRegistrationResponse'];
export type AdminSignInOptionsResponse = components['schemas']['AdminSignInOptionsResponse'];
export type AdminSignInRequest = components['schemas']['AdminSignInRequest'];
export type AdminSignInResponse = components['schemas']['AdminSignInResponse'];
export type FreshAssertionBeginRequest = components['schemas']['FreshAssertionBeginRequest'];
export type AdminCredentialsResponse = components['schemas']['AdminCredentialsResponse'];
export type AdminCredentialResponse = components['schemas']['AdminCredentialResponse'];
export type AdminRecoveryCodeResponse = components['schemas']['AdminRecoveryCodeResponse'];
export type CreateTenantRequest = components['schemas']['CreateTenantRequest'];
export type TenantResponse = components['schemas']['TenantResponse'];
export type TenantListResponse = components['schemas']['TenantListResponse'];
export type TenantCreatedResponse = components['schemas']['TenantCreatedResponse'];
export type OperationResponse = components['schemas']['OperationResponse'];
export type AdminTenantListResponse = components['schemas']['AdminTenantListResponse'];
export type AdminTenant = components['schemas']['AdminTenantResponse'];
export type TenantLabelResponse = components['schemas']['TenantLabelResponse'];
export type SetTenantLabelRequest = components['schemas']['SetTenantLabelRequest'];
export type DeleteTenantRequest = components['schemas']['DeleteTenantRequest'];
export type TenantDeletion = components['schemas']['TenantDeletion'];
export type TenantLogsResponse = components['schemas']['TenantLogsResponse'];
export type TenantLogEvent = components['schemas']['TenantLogEventResponse'];
export type LogReference = components['schemas']['LogReference'];

/** A Log search's filters (Story 7.4), each optional and sent at most once, and the next page's cursor. */
export type TenantLogsQuery = NonNullable<operations['SearchTenantLogs']['parameters']['query']>;
export type SigningKeysResponse = components['schemas']['SigningKeysResponse'];
export type SigningKey = components['schemas']['SigningKeyResponse'];
export type SigningKeysJwksResponse = components['schemas']['SigningKeysJwksResponse'];
export type Jwk = components['schemas']['JwkResponse'];
export type ApplicationResponse = components['schemas']['ApplicationResponse'];
export type ApplicationListResponse = components['schemas']['ApplicationListResponse'];
export type CreateApplicationRequest = components['schemas']['CreateApplicationRequest'];
/** An Application's type (Story 3.1): single-page, regular web, native or machine-to-machine. */
export type ApplicationType = ApplicationResponse['type'];
export type ApplicationSettingsRequest = components['schemas']['ApplicationSettingsRequest'];
/** One refused line or field of a settings save (Story 3.2). */
export type ApiProblemError = components['schemas']['ApiProblemError'];
/** A grant type an Application can hold (Story 3.2). */
export type ApplicationGrantType = ApplicationResponse['grantTypes'][number];
/** One of an Application's live client secrets (Story 3.3): its `sec_` ID and times, never a value or hash. */
export type ApplicationSecretResponse = components['schemas']['ApplicationSecretResponse'];
/** An Application's live client secrets, newest first. */
export type ApplicationSecretListResponse = components['schemas']['ApplicationSecretListResponse'];
/** A client secret just created or rotated in: the value, shown in this response only, and the live secrets after it. */
export type ApplicationSecretCreatedResponse = components['schemas']['ApplicationSecretCreatedResponse'];

/** A path the committed OpenAPI document has, so a removed endpoint fails to compile. */
export type ApiPath = keyof paths;

type Method = 'get' | 'put' | 'post' | 'delete' | 'patch';

/** The methods the document defines for `P`: an undefined one is `?: never` there. */
export type ApiMethod<P extends ApiPath> = {
  [M in Method]-?: [NonNullable<paths[P][M]>] extends [never] ? never : M;
}[Method];

type Operation<P extends ApiPath, M extends ApiMethod<P>> = NonNullable<paths[P][M]>;

type JsonOf<T> = T extends { content: { 'application/json': infer B } } ? B : undefined;

/** The JSON body of the operation's 2xx response, or undefined when it has none, as a 204. */
export type ApiResponse<P extends ApiPath, M extends ApiMethod<P>> =
  Operation<P, M> extends { responses: infer R }
    ? { [S in keyof R]: S extends 200 | 201 | 202 | 204 ? JsonOf<R[S]> : never }[keyof R]
    : never;

/** The JSON request body the operation takes, or undefined when it takes none. */
export type ApiRequest<P extends ApiPath, M extends ApiMethod<P>> =
  Operation<P, M> extends { requestBody?: infer B } ? JsonOf<NonNullable<B>> : undefined;

/** The CSRF header every state-changing call carries. */
export const CSRF_HEADER = 'X-Gatekeep-CSRF';

/**
 * The Tenant the page shows (Story 1.28), which every state-changing call on the Tenant surface
 * carries. The server only compares it with the path's Tenant: it never selects one.
 */
export const TENANT_HEADER = 'X-Gatekeep-Tenant';

/** The Tenant surface's paths: only these carry TENANT_HEADER. */
const TENANT_SURFACE = '/api/v1/tenants/';

/** What a call sent that its answer is read against (Story 1.28): its path, and the page Tenant it carried. */
export interface ApiSent {
  /** The request's path and query, as sent, its IDs encoded. */
  path: string;
  /** The TENANT_HEADER value it carried, or null when it carried none. */
  pageTenant: string | null;
}

/**
 * The outcome of one call: the body on success, or the problem the server refused it with, and
 * the response's headers either way, such as a 429's Retry-After, and what it sent.
 */
export type ApiResult<T> =
  | ({ ok: true; status: number; headers: Headers; data: T } & ApiSent)
  | ({
      ok: false;
      status: number;
      headers: Headers;
      /** The problem body's code and trace ID. Null when the response had none, such as a 401 or 404. */
      problem: ApiProblem | null;
    } & ApiSent);

export interface ApiClientOptions {
  /** Where the API is. The page's own origin when empty, as on Host.Admin. */
  baseUrl?: string;
  /** The current CSRF token, kept in memory only. Read at each state-changing call. */
  csrfToken?: () => string | null | undefined;
  /** The fetch to use. The browser's by default. */
  fetch?: (input: string, init: RequestInit) => Promise<Response>;
  /**
   * The Tenant the page shows at send time, its `ten_` ID, or null on a page that shows none.
   * Read at each state-changing call on the Tenant surface and sent as TENANT_HEADER.
   */
  pageTenant?: () => string | null | undefined;
}

const STATE_CHANGING: ReadonlySet<string> = new Set(['post', 'put', 'patch', 'delete']);

/** A Log search's parameters, in the order the query string carries them. */
const LOG_QUERY = ['type', 'user', 'application', 'outcome', 'from', 'to', 'cursor'] as const satisfies readonly (keyof TenantLogsQuery)[];

/**
 * `{ code, traceId }` from a problem body, or null for anything else, with `errors` too when the body
 * carries a well-formed list of them (Story 3.2's settings save). Nothing else in it is kept, and a
 * malformed error entry is dropped.
 */
export function parseProblem(body: unknown): ApiProblem | null {
  if (typeof body !== 'object' || body === null) return null;
  const { code, traceId, errors } = body as Record<string, unknown>;
  if (typeof code !== 'string' || code === '') return null;
  const problem: ApiProblem = { code: code as ApiProblem['code'], traceId: typeof traceId === 'string' ? traceId : '' };
  if (Array.isArray(errors)) {
    problem.errors = errors.filter(isProblemError).map(({ field, index, reason }) => ({ field, index, reason }));
  }
  return problem;
}

function isProblemError(value: unknown): value is ApiProblemError {
  if (typeof value !== 'object' || value === null) return false;
  const { field, index, reason } = value as Record<string, unknown>;
  return (
    typeof field === 'string' &&
    typeof reason === 'string' &&
    (index === null || (typeof index === 'number' && Number.isInteger(index) && index >= 0))
  );
}

export function createApiClient(options: ApiClientOptions = {}) {
  const baseUrl = options.baseUrl ?? '';
  const send = options.fetch ?? ((input: string, init: RequestInit) => globalThis.fetch(input, init));

  /** One call to `path` with `method`, its body and response typed by the document. */
  async function request<P extends ApiPath, M extends ApiMethod<P>>(
    path: P,
    method: M,
    ...[body]: ApiRequest<P, M> extends undefined ? [] : [ApiRequest<P, M>]
  ): Promise<ApiResult<ApiResponse<P, M>>> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let pageTenant: string | null = null;
    if (STATE_CHANGING.has(method)) {
      const token = options.csrfToken?.();
      if (token) headers[CSRF_HEADER] = token;
      if (path.startsWith(TENANT_SURFACE)) {
        const page = options.pageTenant?.();
        if (typeof page === 'string' && page !== '') headers[TENANT_HEADER] = pageTenant = page;
      }
    }

    const response = await send(`${baseUrl}${path}`, {
      method: method.toUpperCase(),
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
      cache: 'no-store',
    });

    const text = await response.text();
    let json: unknown;
    if (text !== '') {
      try {
        json = JSON.parse(text);
      } catch {
        json = undefined;
      }
    }

    const { status, headers: responseHeaders } = response;
    const sent: ApiSent = { path, pageTenant };
    return response.ok
      ? { ok: true, status, headers: responseHeaders, data: json as ApiResponse<P, M>, ...sent }
      : { ok: false, status, headers: responseHeaders, problem: parseProblem(json), ...sent };
  }

  return {
    request,
    /** Claims bootstrap with the one-time token. Surrounding whitespace is trimmed here and by the server. */
    claimBootstrap: (token: string) => request('/api/v1/deployment/bootstrap', 'post', { token: token.trim() }),
    /** The current Admin Session and its CSRF token, the same each time. */
    getSession: () => request('/api/v1/deployment/session', 'get'),
    /** Signs out: ends the current Admin Session. A setup Session can't. */
    endSession: () => request('/api/v1/deployment/session', 'delete'),
    /** The Deployment capabilities the current Admin holds: every one for the Deployment Owner, none for anyone else. */
    getCapabilities: () => request('/api/v1/deployment/capabilities', 'get'),
    /**
     * The Tenant capabilities the current Admin holds in the Tenant `tenantId` names, its public ID
     * (`ten_…`). The ID goes into the path encoded, so it can never reach another path. A Tenant
     * where the Admin holds no role is a 403 `access_denied`.
     */
    getTenantCapabilities: (tenantId: string) =>
      request(
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/capabilities` as '/api/v1/tenants/{tenantId}/capabilities',
        'get',
      ),
    /** Begins a WebAuthn credential registration: the options for navigator.credentials.create. */
    beginCredentialRegistration: () => request('/api/v1/deployment/credentials/registration', 'post'),
    /** Completes it with the browser's attestation response, in WebAuthn's JSON form. */
    completeCredentialRegistration: (credential: CredentialRegistrationRequest) =>
      request('/api/v1/deployment/credentials/registration/complete', 'post', credential),
    /** Begins an Admin sign-in: the options for navigator.credentials.get, and the binding cookie. Needs no Session. */
    beginSignIn: () => request('/api/v1/deployment/signin', 'post'),
    /** Completes it with the browser's assertion response, in WebAuthn's JSON form, and starts a Session. */
    completeSignIn: (assertion: AdminSignInRequest) => request('/api/v1/deployment/signin/complete', 'post', assertion),
    /**
     * Begins a fresh WebAuthn assertion for one sensitive action and its target, exactly as the
     * action's own request will name it: the options for navigator.credentials.get (Story 1.26).
     */
    beginFreshAssertion: (binding: FreshAssertionBeginRequest) => request('/api/v1/deployment/assertions', 'post', binding),
    /** Completes it with the browser's assertion: a 204 leaves a grant on the Session, never in the page. */
    completeFreshAssertion: (assertion: AdminSignInRequest) => request('/api/v1/deployment/assertions/complete', 'post', assertion),
    /** Your credentials: the current Admin's own, oldest first. */
    listCredentials: () => request('/api/v1/deployment/credentials', 'get'),
    /** Removes one of them by its `acr_` ID, which goes into the path encoded. It needs a fresh assertion for that ID. */
    removeCredential: (credentialId: string) =>
      request(
        `/api/v1/deployment/credentials/${encodeURIComponent(credentialId)}` as '/api/v1/deployment/credentials/{credentialId}',
        'delete',
      ),
    /** Issues an offline Recovery Code at credential setup, shown in this one response. */
    issueRecoveryCode: () => request('/api/v1/deployment/credentials/recovery-code', 'post'),
    /** Confirms the code the issue `issueId` showed was saved, which completes setup. A later issue makes it 409. */
    confirmRecoveryCode: (issueId: string) => request('/api/v1/deployment/credentials/recovery-code/confirm', 'post', { issueId }),
    /** Redeems a Recovery Code at sign-in, sessionless: a Session that reaches only credential registration. */
    redeemRecoveryCode: (code: string) => request('/api/v1/deployment/signin/recovery-code', 'post', { code }),
    /**
     * Redeems a gatekeep recover-admin enrolment, the fragment of the link it printed, sessionless
     * (Story 1.32): a Session that reaches only credential registration.
     */
    redeemEnrolment: (enrolment: string) => request('/api/v1/deployment/signin/enrolment', 'post', { enrolment }),
    /**
     * The Deployment's Tenants, oldest first, 50 a page, with the Tenant zone (Story 1.27).
     * `cursor` is the previous page's `nextCursor`, which goes into the query encoded.
     */
    listTenants: (cursor?: string) =>
      request(
        (cursor === undefined
          ? '/api/v1/deployment/tenants'
          : `/api/v1/deployment/tenants?cursor=${encodeURIComponent(cursor)}`) as '/api/v1/deployment/tenants',
        'get',
      ),
    /** Creates a Tenant: a 202 with the Tenant, still creating, and the Operation that finishes it. */
    createTenant: (body: CreateTenantRequest) => request('/api/v1/deployment/tenants', 'post', body),
    /** One Operation as the Tenant `tenantId` sees it: only that Tenant's steps. Both IDs go into the path encoded. */
    getTenantOperation: (tenantId: string, operationId: string) =>
      request(
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/operations/${encodeURIComponent(operationId)}` as '/api/v1/tenants/{tenantId}/operations/{operationId}',
        'get',
      ),
    /** The active Tenants the current Admin holds a Tenant Role in, oldest first, for the Tenant switcher (Story 1.28). Never a role. */
    listMyTenants: () => request('/api/v1/deployment/my-tenants', 'get'),
    /** The Tenant's environment label. Its ID goes into the path encoded. */
    getTenantLabel: (tenantId: string) =>
      request(`/api/v1/tenants/${encodeURIComponent(tenantId)}/label` as '/api/v1/tenants/{tenantId}/label', 'get'),
    /**
     * One page of the Tenant's Log (Story 7.4), newest first, 50 a page. Each filter in `query`
     * that is set, and the previous page's `nextCursor` as `cursor`, goes into the query string
     * encoded, in a fixed order; the Tenant's ID goes into the path encoded.
     */
    searchTenantLogs: (tenantId: string, query: TenantLogsQuery = {}) => {
      const search = new URLSearchParams();
      for (const name of LOG_QUERY) {
        const value = query[name];
        if (typeof value === 'string' && value !== '') search.set(name, value);
      }
      const text = search.toString();
      return request(
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/logs${text === '' ? '' : `?${text}`}` as '/api/v1/tenants/{tenantId}/logs',
        'get',
      );
    },
    /** Changes the Tenant's environment label. Removing Prod needs a fresh assertion bound to this Tenant. */
    setTenantLabel: (tenantId: string, body: SetTenantLabelRequest) =>
      request(`/api/v1/tenants/${encodeURIComponent(tenantId)}/label` as '/api/v1/tenants/{tenantId}/label', 'put', body),
    /** The Tenant's Signing Keys in every state (Story 9.1), next first. Never a Management key. Its ID goes into the path encoded. */
    listSigningKeys: (tenantId: string) =>
      request(`/api/v1/tenants/${encodeURIComponent(tenantId)}/signing-keys` as '/api/v1/tenants/{tenantId}/signing-keys', 'get'),
    /** The Tenant's public JWKS sample and its JWKS URI (Story 9.1): a 503 when key custody is down. Its ID goes into the path encoded. */
    getSigningKeysJwks: (tenantId: string) =>
      request(
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/signing-keys/jwks` as '/api/v1/tenants/{tenantId}/signing-keys/jwks',
        'get',
      ),
    /**
     * One page of the Tenant's Applications (Story 3.1), newest first, 50 a page. `cursor` is the
     * previous page's `nextCursor`; it and the Tenant's ID go into the URL encoded.
     */
    listApplications: (tenantId: string, cursor?: string) =>
      request(
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/applications${
          cursor === undefined ? '' : `?cursor=${encodeURIComponent(cursor)}`
        }` as '/api/v1/tenants/{tenantId}/applications',
        'get',
      ),
    /** One of the Tenant's Applications by its `app_` ID, which goes into the path encoded. Any other is a 404 `not_found`. */
    getApplication: (tenantId: string, applicationId: string) =>
      request(
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/applications/${encodeURIComponent(applicationId)}` as '/api/v1/tenants/{tenantId}/applications/{applicationId}',
        'get',
      ),
    /** Creates an Application with a name and a type, and no secret: a 201 with it. Editors and Owners only. */
    createApplication: (tenantId: string, body: CreateApplicationRequest) =>
      request(`/api/v1/tenants/${encodeURIComponent(tenantId)}/applications` as '/api/v1/tenants/{tenantId}/applications', 'post', body),
    /**
     * Saves an Application's full settings (Story 3.2): its callback, logout and web origin URLs and grants.
     * Both IDs go into the path encoded. A Prod Tenant's changed callbacks need a fresh assertion for
     * tenant.application_callbacks.manage with the Application's ID as its target.
     */
    updateApplicationSettings: (tenantId: string, applicationId: string, body: ApplicationSettingsRequest) =>
      request(
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/applications/${encodeURIComponent(applicationId)}/settings` as '/api/v1/tenants/{tenantId}/applications/{applicationId}/settings',
        'put',
        body,
      ),
    /** An Application's live client secrets (Story 3.3), newest first: never a value or hash. Both IDs go into the path encoded. */
    listApplicationSecrets: (tenantId: string, applicationId: string) =>
      request(
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/applications/${encodeURIComponent(applicationId)}/secrets` as '/api/v1/tenants/{tenantId}/applications/{applicationId}/secrets',
        'get',
      ),
    /**
     * Creates or rotates a web or machine Application's client secret (Story 3.3): a 201 with the value, shown this
     * once, and the live secrets. Tenant Owners only, after a fresh assertion for tenant.client_secrets.manage with
     * the Application's ID as its target. Both IDs go into the path encoded.
     */
    createApplicationSecret: (tenantId: string, applicationId: string) =>
      request(
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/applications/${encodeURIComponent(applicationId)}/secrets` as '/api/v1/tenants/{tenantId}/applications/{applicationId}/secrets',
        'post',
      ),
    /**
     * Revokes one of an Application's live client secrets, or ends a rotated-out one's overlap now (Story 3.3): the
     * live secrets after it. The same access as a create. Every ID goes into the path encoded.
     */
    revokeApplicationSecret: (tenantId: string, applicationId: string, secretId: string) =>
      request(
        `/api/v1/tenants/${encodeURIComponent(tenantId)}/applications/${encodeURIComponent(applicationId)}/secrets/${encodeURIComponent(secretId)}/revoke` as '/api/v1/tenants/{tenantId}/applications/{applicationId}/secrets/{secretId}/revoke',
        'post',
      ),
    /** Begins a fresh assertion for a Tenant action, bound to the Tenant `tenantId` names. The Deployment complete finishes it. */
    beginTenantFreshAssertion: (tenantId: string, binding: FreshAssertionBeginRequest) =>
      request(`/api/v1/tenants/${encodeURIComponent(tenantId)}/assertions` as '/api/v1/tenants/{tenantId}/assertions', 'post', binding),
    /** Retries a failed Tenant creation's failed steps: a 202 with the Operation running again, or 409 when it isn't failed. */
    retryOperation: (operationId: string) =>
      request(
        `/api/v1/deployment/operations/${encodeURIComponent(operationId)}/retry` as '/api/v1/deployment/operations/{operationId}/retry',
        'post',
      ),
    /**
     * Deletes the Tenant `tenantId` names (Story 1.29): `confirmation` is its stored host, typed. It
     * needs a fresh assertion for deployment.tenants.delete with this ID as its target. The ID goes
     * into the path encoded. A 202 with its deletion Operation.
     */
    deleteTenant: (tenantId: string, body: DeleteTenantRequest) =>
      request(
        `/api/v1/deployment/tenants/${encodeURIComponent(tenantId)}/deletion` as '/api/v1/deployment/tenants/{targetTenantId}/deletion',
        'post',
        body,
      ),
    /** The Tenant's newest deletion Operation, with every step, or a 404. Its ID goes into the path encoded. */
    getTenantDeletion: (tenantId: string) =>
      request(
        `/api/v1/deployment/tenants/${encodeURIComponent(tenantId)}/deletion` as '/api/v1/deployment/tenants/{targetTenantId}/deletion',
        'get',
      ),
    /** Retries a failed Tenant deletion's failed steps. It needs a new fresh assertion for this Tenant. Its ID goes into the path encoded. */
    retryTenantDeletion: (tenantId: string) =>
      request(
        `/api/v1/deployment/tenants/${encodeURIComponent(tenantId)}/deletion/retry` as '/api/v1/deployment/tenants/{targetTenantId}/deletion/retry',
        'post',
      ),
  };
}

export type ApiClient = ReturnType<typeof createApiClient>;
