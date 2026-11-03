import type { ApiProblem, ApiResult } from '@gatekeep/api-client';
import { GenericErrorScreen } from '@gatekeep/hosted-screens';
import { Banner, Button, HostedCard, HostedPage, formatMessage, useMessages } from '@gatekeep/ui/admin';
import { useEffect, useRef, useState } from 'react';
import { navigate } from './navigation';
import { api, setCsrfToken } from './session';
import { creationOptions, isAlreadyRegistered, isCancelled, registrationRequest } from './webauthn';

/** The credentials an Admin registers before anything else (FR-2, FR-46). */
const REQUIRED = 2;

/** The code Generic error shows for a failure with no problem body, such as a 503 or a lost connection. */
const UNAVAILABLE = 'unavailable';

/** The code Generic error shows when the browser couldn't make a credential for a reason other than cancelling. */
const CEREMONY_FAILED = 'credential_unavailable';

type Failure = { code: string; traceId: string };

type State = { kind: 'loading' } | { kind: 'ready'; credentials: number } | { kind: 'failed'; failure: Failure };

/** What Generic error shows for a refused call: the problem's own code and trace ID, or a fixed code. */
function failure(result: ApiResult<unknown> | null): Failure {
  const problem: ApiProblem | null = result && !result.ok ? result.problem : null;
  return problem ?? { code: UNAVAILABLE, traceId: '' };
}

/**
 * Admin credential setup (EXPERIENCE.md, Admin: access and Tenants): step 1 of 2, then 2 of 2,
 * each one the browser's own passkey sheet. A cancelled sheet leaves the step as it was, with
 * Register ready again and no error. A refusal shows Generic error, whose action comes back here
 * to try again. There is no navigation away: the page only leaves for the landing page once the
 * second credential is stored, and the root sends an Admin without two back here.
 */
export function CredentialSetupPage() {
  const messages = useMessages();
  const [state, setState] = useState<State>({ kind: 'loading' });
  const [pending, setPending] = useState(false);
  // The authenticator already holds one of the Admin's credentials: guidance, not an error page.
  const [alreadyRegistered, setAlreadyRegistered] = useState(false);
  // Set at once, before React re-renders, so a second click starts no second ceremony.
  const inFlight = useRef(false);

  useEffect(() => {
    let current = true;
    api
      .getSession()
      .then((result) => {
        if (!current) return;
        if (result.ok && typeof result.data?.csrfToken === 'string') {
          setCsrfToken(result.data.csrfToken);
          if (result.data.setupComplete) {
            navigate('/');
            return;
          }
          setState({ kind: 'ready', credentials: Math.max(0, Math.min(REQUIRED - 1, result.data.credentials ?? 0)) });
        } else if (result.status === 401) {
          window.location.replace('/bootstrap');
        } else {
          setState({ kind: 'failed', failure: failure(null) });
        }
      })
      .catch(() => {
        if (current) setState({ kind: 'failed', failure: failure(null) });
      });
    return () => {
      current = false;
    };
  }, []);

  async function register() {
    if (inFlight.current || state.kind !== 'ready') return;
    inFlight.current = true;
    setPending(true);
    setAlreadyRegistered(false);
    const done = () => {
      inFlight.current = false;
      setPending(false);
    };

    try {
      const begin = await api.beginCredentialRegistration();
      if (!begin.ok || !begin.data) {
        if (begin.status === 401) {
          window.location.replace('/bootstrap');
          return;
        }
        done();
        // Already set up, here or in another tab: the landing page.
        if (begin.status === 403) {
          navigate('/');
          return;
        }
        setState({ kind: 'failed', failure: failure(begin) });
        return;
      }

      let credential: Credential | null;
      try {
        credential = await navigator.credentials.create({ publicKey: creationOptions(begin.data) });
      } catch (error) {
        done();
        // Cancelled: the step stays, with Register ready again and nothing shown.
        if (isCancelled(error)) return;
        if (isAlreadyRegistered(error)) {
          setAlreadyRegistered(true);
          return;
        }
        setState({ kind: 'failed', failure: { code: CEREMONY_FAILED, traceId: '' } });
        return;
      }

      if (!(credential instanceof PublicKeyCredential)) {
        done();
        return;
      }

      const complete = await api.completeCredentialRegistration(registrationRequest(credential));
      if (!complete.ok || !complete.data) {
        if (complete.status === 401) {
          window.location.replace('/bootstrap');
          return;
        }
        done();
        setState({ kind: 'failed', failure: failure(complete) });
        return;
      }

      if (complete.data.setupComplete) {
        navigate('/');
        return;
      }

      done();
      setState({ kind: 'ready', credentials: complete.data.credentials });
    } catch {
      done();
      setState({ kind: 'failed', failure: failure(null) });
    }
  }

  const gatekeep = { name: messages.productName };

  if (state.kind === 'loading') return <HostedPage />;

  if (state.kind === 'failed') {
    return (
      <HostedPage>
        <GenericErrorScreen
          tenant={gatekeep}
          code={state.failure.code}
          traceId={state.failure.traceId}
          backHref="/setup/credentials"
          data-testid="credential-setup-error"
        />
      </HostedPage>
    );
  }

  const step = state.credentials + 1;
  return (
    <HostedPage>
      <HostedCard
        tenant={gatekeep}
        title={messages.credentialSetupTitle}
        subtitle={step === 1 ? messages.credentialSetupFirst : messages.credentialSetupSecond}
        action={
          <Button type="button" variant="primary" pending={pending} onClick={register}>
            {messages.credentialSetupRegister}
          </Button>
        }
        data-testid="credential-setup"
      >
        <p data-testid="credential-setup-step">{formatMessage(messages.credentialSetupStep, { step, total: REQUIRED })}</p>
        {alreadyRegistered ? (
          <Banner tone="warn" data-testid="credential-setup-registered">
            {messages.credentialSetupAlreadyRegistered}
          </Banner>
        ) : null}
      </HostedCard>
    </HostedPage>
  );
}
