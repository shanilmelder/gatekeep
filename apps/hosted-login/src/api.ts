// Hosted Login's only network requests (Stories 4.2 and 4.7): Continue, Keep going, and sign-up's. Each is a same-origin
// POST with the step's CSRF token in X-Gatekeep-CSRF, and each answers with a step, which the client renders as it
// renders the page's own. The browser sends the Origin and the HttpOnly transaction cookie; the client never reads
// either. The password goes only in Create account's body, and a link only in Send a new link's.

import { invalidStep, parseStep, type Step } from './step';

/** Login's identifier step. */
export const IDENTIFIER_PATH = '/login/api/identifier';

/** "Keep going": slides the sign-in transaction's life. */
export const EXTEND_PATH = '/login/api/transaction/extend';

/** Story 4.7: "Sign up" at Login. */
export const SIGNUP_OPEN_PATH = '/login/api/signup/open';

/** "Already have an account? Log in" at Signup. */
export const SIGNUP_BACK_PATH = '/login/api/signup/back';

/** "Create account". */
export const SIGNUP_PATH = '/login/api/signup';

/** "Resend email". */
export const RESEND_PATH = '/login/api/verification/resend';

/** "I've verified, continue". */
export const VERIFIED_CONTINUE_PATH = '/login/api/verification/continue';

/** "Send a new link", from an expired link's page, with the link-bound CSRF token. */
export const NEW_LINK_PATH = '/login/api/verification/new-link';

/** The header the CSRF token goes in. */
export const CSRF_HEADER = 'X-Gatekeep-CSRF';

/** The code Generic error shows when a request got no step back at all. */
export const REQUEST_FAILED = 'request_failed';

type ApiPath =
  | typeof IDENTIFIER_PATH
  | typeof EXTEND_PATH
  | typeof SIGNUP_OPEN_PATH
  | typeof SIGNUP_BACK_PATH
  | typeof SIGNUP_PATH
  | typeof RESEND_PATH
  | typeof VERIFIED_CONTINUE_PATH
  | typeof NEW_LINK_PATH;

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

/** "Sign up": the email typed at Login, carried to Signup. */
export function postSignupOpen(stepVersion: number, email: string, csrfToken: string, tenant: string): Promise<Step> {
  return post(SIGNUP_OPEN_PATH, { stepVersion, email }, csrfToken, tenant);
}

/** "Log in" from Signup. */
export function postSignupBack(stepVersion: number, csrfToken: string, tenant: string): Promise<Step> {
  return post(SIGNUP_BACK_PATH, { stepVersion }, csrfToken, tenant);
}

/** Create account: the email and password as typed, and (Story 4.8) whether the terms checkbox is ticked. */
export function postSignup(
  stepVersion: number,
  email: string,
  password: string,
  acceptTerms: boolean,
  csrfToken: string,
  tenant: string,
): Promise<Step> {
  return post(SIGNUP_PATH, { stepVersion, email, password, acceptTerms }, csrfToken, tenant);
}

/** Resend email. */
export function postResend(stepVersion: number, csrfToken: string, tenant: string): Promise<Step> {
  return post(RESEND_PATH, { stepVersion }, csrfToken, tenant);
}

/** I've verified, continue. */
export function postVerifiedContinue(stepVersion: number, csrfToken: string, tenant: string): Promise<Step> {
  return post(VERIFIED_CONTINUE_PATH, { stepVersion }, csrfToken, tenant);
}

/** Send a new link: the expired link's own value, with its link-bound CSRF token. */
export function postNewLink(token: string, csrfToken: string, tenant: string): Promise<Step> {
  return post(NEW_LINK_PATH, { token }, csrfToken, tenant);
}
