// Hosted Login's only network requests (Story 4.2): Continue and Keep going. Each is a same-origin POST
// with the transaction's CSRF token in X-Gatekeep-CSRF, and each answers with a step, which the client
// renders as it renders the page's own. The browser sends the Origin and the HttpOnly transaction cookie;
// the client never reads either.

import { invalidStep, parseStep, type Step } from './step';

/** Login's identifier step. */
export const IDENTIFIER_PATH = '/login/api/identifier';

/** "Keep going": slides the sign-in transaction's life. */
export const EXTEND_PATH = '/login/api/transaction/extend';

/** The header the CSRF token goes in. */
export const CSRF_HEADER = 'X-Gatekeep-CSRF';

/** The code Generic error shows when a request got no step back at all. */
export const REQUEST_FAILED = 'request_failed';

type ApiPath = typeof IDENTIFIER_PATH | typeof EXTEND_PATH;

async function post(path: ApiPath, body: object, csrfToken: string, tenant: string): Promise<Step> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', [CSRF_HEADER]: csrfToken },
      body: JSON.stringify(body),
    });
  } catch {
    return invalidStep(tenant, REQUEST_FAILED);
  }

  try {
    return parseStep(await response.json(), tenant);
  } catch {
    return invalidStep(tenant, REQUEST_FAILED);
  }
}

/** Continue: the email as typed, at the Login step's version. */
export function postIdentifier(stepVersion: number, email: string, csrfToken: string, tenant: string): Promise<Step> {
  return post(IDENTIFIER_PATH, { stepVersion, email }, csrfToken, tenant);
}

/** Keep going. */
export function postExtend(csrfToken: string, tenant: string): Promise<Step> {
  return post(EXTEND_PATH, {}, csrfToken, tenant);
}
