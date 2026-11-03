// The hand-written fetch wrapper over the generated types (Story 1.21). It has no runtime
// dependency: the browser's fetch only. Every call stays on the page's own origin with its
// cookies (credentials: 'same-origin'), a state-changing call carries the Session's CSRF token
// in X-Gatekeep-CSRF, and a refusal's problem body is read into { code, traceId }. Each call's
// request and response types come from the committed OpenAPI document, by path and method.

import type { components, paths } from './schema.generated';

export type ApiProblem = components['schemas']['ApiProblem'];
export type BootstrapClaimResponse = components['schemas']['BootstrapClaimResponse'];
export type AdminSessionResponse = components['schemas']['AdminSessionResponse'];
export type CapabilitiesResponse = components['schemas']['CapabilitiesResponse'];
export type CredentialCreationOptionsResponse = components['schemas']['CredentialCreationOptionsResponse'];
export type CredentialRegistrationRequest = components['schemas']['CredentialRegistrationRequest'];
export type CredentialRegistrationResponse = components['schemas']['CredentialRegistrationResponse'];
export type AdminSignInOptionsResponse = components['schemas']['AdminSignInOptionsResponse'];
export type AdminSignInRequest = components['schemas']['AdminSignInRequest'];
export type AdminSignInResponse = components['schemas']['AdminSignInResponse'];

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
 * The outcome of one call: the body on success, or the problem the server refused it with, and
 * the response's headers either way, such as a 429's Retry-After.
 */
export type ApiResult<T> =
  | { ok: true; status: number; headers: Headers; data: T }
  | {
      ok: false;
      status: number;
      headers: Headers;
      /** The problem body's code and trace ID. Null when the response had none, such as a 401 or 404. */
      problem: ApiProblem | null;
    };

export interface ApiClientOptions {
  /** Where the API is. The page's own origin when empty, as on Host.Admin. */
  baseUrl?: string;
  /** The current CSRF token, kept in memory only. Read at each state-changing call. */
  csrfToken?: () => string | null | undefined;
  /** The fetch to use. The browser's by default. */
  fetch?: (input: string, init: RequestInit) => Promise<Response>;
}

const STATE_CHANGING: ReadonlySet<string> = new Set(['post', 'put', 'patch', 'delete']);

/** `{ code, traceId }` from a problem body, or null for anything else. Nothing else in it is kept. */
export function parseProblem(body: unknown): ApiProblem | null {
  if (typeof body !== 'object' || body === null) return null;
  const { code, traceId } = body as Record<string, unknown>;
  if (typeof code !== 'string' || code === '') return null;
  return { code: code as ApiProblem['code'], traceId: typeof traceId === 'string' ? traceId : '' };
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
    if (STATE_CHANGING.has(method)) {
      const token = options.csrfToken?.();
      if (token) headers[CSRF_HEADER] = token;
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
    return response.ok
      ? { ok: true, status, headers: responseHeaders, data: json as ApiResponse<P, M> }
      : { ok: false, status, headers: responseHeaders, problem: parseProblem(json) };
  }

  return {
    request,
    /** Claims bootstrap with the one-time token. Surrounding whitespace is trimmed here and by the server. */
    claimBootstrap: (token: string) => request('/api/v1/deployment/bootstrap', 'post', { token: token.trim() }),
    /** The current Admin Session and its CSRF token, the same each time. */
    getSession: () => request('/api/v1/deployment/session', 'get'),
    /** Signs out: ends the current Admin Session. A setup Session can't. */
    endSession: () => request('/api/v1/deployment/session', 'delete'),
    /** The Deployment capabilities the current Admin holds. */
    getCapabilities: () => request('/api/v1/deployment/capabilities', 'get'),
    /** Begins a WebAuthn credential registration: the options for navigator.credentials.create. */
    beginCredentialRegistration: () => request('/api/v1/deployment/credentials/registration', 'post'),
    /** Completes it with the browser's attestation response, in WebAuthn's JSON form. */
    completeCredentialRegistration: (credential: CredentialRegistrationRequest) =>
      request('/api/v1/deployment/credentials/registration/complete', 'post', credential),
    /** Begins an Admin sign-in: the options for navigator.credentials.get, and the binding cookie. Needs no Session. */
    beginSignIn: () => request('/api/v1/deployment/signin', 'post'),
    /** Completes it with the browser's assertion response, in WebAuthn's JSON form, and starts a Session. */
    completeSignIn: (assertion: AdminSignInRequest) => request('/api/v1/deployment/signin/complete', 'post', assertion),
  };
}

export type ApiClient = ReturnType<typeof createApiClient>;
