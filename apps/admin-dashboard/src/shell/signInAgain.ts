// Signing in again from inside the shell, for Session renewal: the same endpoints and the same
// browser sheet as the sign-in page (Story 1.23), with no navigation. What each answer comes to
// is renewal.ts's to act on. `signal` stops it between steps and aborts the sheet, so nothing
// is sent once the shell has moved on (a sign-out, an unmount).

import type { ApiResult } from '@gatekeep/api-client';
import { api } from '../session';
import { assertionRequest, requestOptions } from '../webauthn';
import { retryAfterSeconds, type SignInOutcome } from './renewal';

const CANCELLED: SignInOutcome = { kind: 'cancelled' };
const UNAVAILABLE: SignInOutcome = { kind: 'unavailable' };

/** A refused begin or complete: 400 is a refused credential, 429 a rate limit, anything else unavailable. */
function refusal(result: ApiResult<unknown> | null): SignInOutcome {
  if (result === null || result.ok) return UNAVAILABLE;
  if (result.status === 400) return { kind: 'refused' };
  if (result.status === 429) return { kind: 'rateLimited', seconds: retryAfterSeconds(result.headers.get('Retry-After')) };
  return UNAVAILABLE;
}

export async function signInAgain(signal: AbortSignal): Promise<SignInOutcome> {
  try {
    if (signal.aborted) return CANCELLED;
    const begin = await api.beginSignIn();
    if (!begin.ok || !begin.data) return refusal(begin.ok ? null : begin);
    if (signal.aborted) return CANCELLED;

    // A begin whose options can't be read, or a browser with no WebAuthn, can't open a sheet.
    let options: PublicKeyCredentialRequestOptions;
    try {
      options = requestOptions(begin.data);
    } catch {
      return UNAVAILABLE;
    }
    if (typeof navigator.credentials?.get !== 'function') return UNAVAILABLE;

    let credential: Credential | null;
    try {
      credential = await navigator.credentials.get({ publicKey: options, signal });
    } catch (error) {
      // Cancelled, refused for want of user activation, or aborted by the shell: the banner's
      // Sign in opens it again. Any other failure of the sheet is unavailable.
      if (error instanceof DOMException && (error.name === 'NotAllowedError' || error.name === 'AbortError')) return CANCELLED;
      return UNAVAILABLE;
    }
    if (!(credential instanceof PublicKeyCredential)) return UNAVAILABLE;
    if (signal.aborted) return CANCELLED;

    const complete = await api.completeSignIn(assertionRequest(credential));
    const data = complete.ok ? complete.data : undefined;
    // A 2xx without the Session's Admin and CSRF token isn't one the shell can go on with.
    if (data && typeof data.csrfToken === 'string' && typeof data.adminId === 'string') {
      return { kind: 'signedIn', adminId: data.adminId, csrfToken: data.csrfToken, setupComplete: data.setupComplete === true };
    }
    return refusal(complete.ok ? null : complete);
  } catch {
    return UNAVAILABLE;
  }
}
