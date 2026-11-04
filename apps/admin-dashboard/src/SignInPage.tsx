import type { ApiProblem, ApiResult } from '@gatekeep/api-client';
import { GenericErrorScreen } from '@gatekeep/hosted-screens';
import { Banner, Button, HostedCard, HostedPage, useMessages } from '@gatekeep/ui/admin';
import { useRef, useState } from 'react';
import { navigate } from './navigation';
import { api, setCsrfToken } from './session';
import { assertionRequest, isCancelled, requestOptions } from './webauthn';

/** The codes Generic error shows for a failure with no problem body. */
const UNAVAILABLE = 'unavailable';
const ORIGIN_REFUSED = 'origin_refused';
const SIGNIN_UNAVAILABLE = 'signin_unavailable';

type Failure = { code: string; traceId: string };

/**
 * What a refused call comes to: the banner for a refused sign-in (400), which never says why, as
 * the server doesn't; Generic error for the rest, with the problem's own code and trace ID for a
 * 429, and a fixed code for a 403 (the Origin was refused), a 404 (no Admin to sign in yet) and
 * anything else, such as a 503 or a lost connection.
 */
function outcome(result: ApiResult<unknown> | null): 'refused' | Failure {
  if (result === null || result.ok) return { code: UNAVAILABLE, traceId: '' };
  if (result.status === 400) return 'refused';
  if (result.status === 403) return { code: ORIGIN_REFUSED, traceId: '' };
  if (result.status === 404) return { code: SIGNIN_UNAVAILABLE, traceId: '' };
  const problem: ApiProblem | null = result.problem;
  if (result.status === 429 && problem) return problem;
  return { code: UNAVAILABLE, traceId: '' };
}

/**
 * Admin sign-in (EXPERIENCE.md, Admin: access and Tenants; Story 1.23): a Hosted card in the
 * Gatekeep default theme with one primary action and no field at all: no email, password or
 * username. Sign in begins, opens the browser's own passkey sheet with no credential listed, and
 * completes; a sign-in keeps the CSRF token in memory and goes to the root, which sends an Admin
 * without their two credentials on to credential setup. A cancelled sheet leaves the page as it
 * was. A refused sign-in, or any other failure of the sheet, keeps the screen with one banner that
 * never says why. A rate limit, an outage or a refused Origin shows Generic error, whose action
 * comes back here.
 */
export function SignInPage() {
  const messages = useMessages();
  const [pending, setPending] = useState(false);
  const [refused, setRefused] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  // Set at once, before React re-renders, so a second click starts no second ceremony.
  const inFlight = useRef(false);

  async function signIn() {
    if (inFlight.current) return;
    inFlight.current = true;
    setPending(true);
    setRefused(false);
    const done = () => {
      inFlight.current = false;
      setPending(false);
    };
    const settle = (result: ApiResult<unknown> | null) => {
      done();
      const next = outcome(result);
      if (next === 'refused') setRefused(true);
      else setFailure(next);
    };

    try {
      const begin = await api.beginSignIn();
      if (!begin.ok || !begin.data) {
        settle(begin.ok ? null : begin);
        return;
      }

      let credential: Credential | null;
      try {
        credential = await navigator.credentials.get({ publicKey: requestOptions(begin.data) });
      } catch (error) {
        done();
        // Cancelled: the page stays as it was, with Sign in ready again and nothing shown.
        if (isCancelled(error)) return;
        setRefused(true);
        return;
      }

      if (!(credential instanceof PublicKeyCredential)) {
        done();
        setRefused(true);
        return;
      }

      const complete = await api.completeSignIn(assertionRequest(credential));
      // A 2xx without a CSRF token isn't a sign-in the page can go on with: it fails like a 503.
      if (complete.ok && typeof complete.data?.csrfToken === 'string') {
        setCsrfToken(complete.data.csrfToken);
        navigate('/');
        return;
      }

      settle(complete.ok ? null : complete);
    } catch {
      settle(null);
    }
  }

  const gatekeep = { name: messages.productName };

  if (failure) {
    return (
      <HostedPage>
        <GenericErrorScreen
          tenant={gatekeep}
          code={failure.code}
          traceId={failure.traceId}
          backHref="/signin"
          data-testid="signin-error"
        />
      </HostedPage>
    );
  }

  return (
    <HostedPage>
      <HostedCard
        tenant={gatekeep}
        title={messages.signInTitle}
        subtitle={messages.signInSubtitle}
        action={
          <Button type="button" variant="primary" pending={pending} onClick={signIn}>
            {messages.signInAction}
          </Button>
        }
        link={<a href="/signin/recovery">{messages.recoveryLink}</a>}
        data-testid="signin"
      >
        {refused ? (
          <Banner tone="bad" data-testid="signin-refused">
            {messages.signInRefused}
          </Banner>
        ) : null}
      </HostedCard>
    </HostedPage>
  );
}
