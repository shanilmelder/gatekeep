import type { ApiProblem, ApiResult } from '@gatekeep/api-client';
import { GenericErrorScreen } from '@gatekeep/hosted-screens';
import { Banner, Button, Checkbox, CopyButton, HostedCard, HostedPage, formatMessage, useMessages } from '@gatekeep/ui/admin';
import { useEffect, useId, useRef, useState } from 'react';
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

/** What the Session says this setup is: how many are registered, a recovery Session's, and whether a Recovery Code may be offered. */
interface Setup {
  credentials: number;
  recovery: boolean;
  recoveryCodeAllowed: boolean;
}

type State =
  | { kind: 'loading' }
  | ({ kind: 'ready' } & Setup)
  /** A Recovery Code, shown this once and held only here, in memory, until it is confirmed or the page goes. */
  | { kind: 'code'; code: string; issueId: string }
  /** The code on screen couldn't be confirmed: it is gone, and the reason says why. */
  | { kind: 'stale'; reason: string }
  | { kind: 'failed'; failure: Failure };

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
 * Admin meets the floor, and the root sends an Admin who doesn't back here.
 *
 * Story 1.26: an Admin who isn't the Deployment Owner may, at step 2, take an offline Recovery Code
 * instead of a second credential, when the Session says so. It is shown once, inside the card, held
 * only in this component's state and cleared on pagehide; ticking "I've saved this code" and
 * Continue confirms it. A recovery Session, after a redeemed code, registers one new credential.
 */
export function CredentialSetupPage() {
  const messages = useMessages();
  const [state, setState] = useState<State>({ kind: 'loading' });
  const [pending, setPending] = useState(false);
  // The authenticator already holds one of the Admin's credentials: guidance, not an error page.
  const [alreadyRegistered, setAlreadyRegistered] = useState(false);
  const [saved, setSaved] = useState(false);
  const [savedMissing, setSavedMissing] = useState(false);
  const savedHelp = useId();
  // Set at once, before React re-renders, so a second click starts no second ceremony.
  const inFlight = useRef(false);

  /** Reads the Session: its CSRF token, and what this setup is. Null when it went elsewhere or failed. */
  async function readSetup(): Promise<Setup | null> {
    const result = await api.getSession();
    if (result.ok && typeof result.data?.csrfToken === 'string') {
      setCsrfToken(result.data.csrfToken);
      if (result.data.setupComplete && result.data.kind !== 'recovery') {
        navigate('/');
        return null;
      }
      const recovery = result.data.kind === 'recovery';
      return {
        credentials: Math.max(0, Math.min(REQUIRED - 1, result.data.credentials ?? 0)),
        recovery,
        recoveryCodeAllowed: result.data.recoveryCodeAllowed === true,
      };
    }
    if (result.status === 401) {
      window.location.replace('/signin');
      return null;
    }
    setState({ kind: 'failed', failure: failure(null) });
    return null;
  }

  useEffect(() => {
    let current = true;
    readSetup()
      .then((setup) => {
        if (current && setup) setState({ kind: 'ready', ...setup });
      })
      .catch(() => {
        if (current) setState({ kind: 'failed', failure: failure(null) });
      });
    return () => {
      current = false;
    };
    // The Session is read once, on arrival.
  }, []);

  // A code on screen is gone with the page: nothing keeps it for a back-forward cache to restore.
  useEffect(() => {
    if (state.kind !== 'code') return;
    const clear = () => setState({ kind: 'loading' });
    window.addEventListener('pagehide', clear);
    return () => window.removeEventListener('pagehide', clear);
  }, [state.kind]);

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
          window.location.replace('/signin');
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
          window.location.replace('/signin');
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

      // The server says again what the next step may offer.
      const setup = await readSetup();
      done();
      if (setup) setState({ kind: 'ready', ...setup, credentials: complete.data.credentials });
    } catch {
      done();
      setState({ kind: 'failed', failure: failure(null) });
    }
  }

  async function issueCode() {
    if (inFlight.current || state.kind !== 'ready') return;
    inFlight.current = true;
    setPending(true);
    try {
      const issued = await api.issueRecoveryCode();
      inFlight.current = false;
      setPending(false);
      if (issued.ok && typeof issued.data?.code === 'string' && typeof issued.data.issueId === 'string') {
        setSaved(false);
        setSavedMissing(false);
        setState({ kind: 'code', code: issued.data.code, issueId: issued.data.issueId });
        return;
      }
      if (issued.status === 401) {
        window.location.replace('/signin');
        return;
      }
      setState({ kind: 'failed', failure: failure(issued) });
    } catch {
      inFlight.current = false;
      setPending(false);
      setState({ kind: 'failed', failure: failure(null) });
    }
  }

  async function confirmCode() {
    if (inFlight.current || state.kind !== 'code') return;
    if (!saved) {
      setSavedMissing(true);
      return;
    }
    inFlight.current = true;
    setPending(true);
    try {
      const confirmed = await api.confirmRecoveryCode(state.issueId);
      if (confirmed.ok) {
        setState({ kind: 'loading' });
        navigate('/');
        return;
      }
      inFlight.current = false;
      setPending(false);
      if (confirmed.status === 401) {
        window.location.replace('/signin');
        return;
      }
      // Not saved: the code is no longer the one to confirm. Say why, and start again from setup.
      if (confirmed.status === 409) {
        setState({ kind: 'stale', reason: messages.recoveryCodeSuperseded });
        return;
      }
      if (confirmed.status === 403) {
        setState({ kind: 'stale', reason: messages.recoveryCodeNotConfirmable });
        return;
      }
      setState({ kind: 'failed', failure: failure(confirmed) });
    } catch {
      inFlight.current = false;
      setPending(false);
      setState({ kind: 'failed', failure: failure(null) });
    }
  }

  // Any Session can sign out (Story 1.26): a setup or recovery one too, from its own card.
  async function signOut() {
    if (inFlight.current) return;
    inFlight.current = true;
    let status: number | null = null;
    try {
      status = (await api.endSession()).status;
    } catch {
      status = null;
    }
    inFlight.current = false;
    if (status === 204 || status === 401) {
      setCsrfToken(null);
      setState({ kind: 'loading' });
      navigate('/signin');
      return;
    }
    setState({ kind: 'failed', failure: failure(null) });
  }

  const signOutLink = (
    <Button type="button" variant="ghost" size="sm" onClick={signOut} data-testid="setup-sign-out">
      {messages.signOut}
    </Button>
  );

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

  if (state.kind === 'stale') {
    return (
      <HostedPage>
        <HostedCard
          tenant={gatekeep}
          title={messages.credentialSetupTitle}
          action={
            <Button
              type="button"
              variant="primary"
              onClick={() => {
                setState({ kind: 'loading' });
                void readSetup().then((setup) => {
                  if (setup) setState({ kind: 'ready', ...setup });
                });
              }}
            >
              {messages.continue}
            </Button>
          }
          link={signOutLink}
          data-testid="recovery-code-stale"
        >
          <Banner tone="bad">{state.reason}</Banner>
        </HostedCard>
      </HostedPage>
    );
  }

  if (state.kind === 'code') {
    return (
      <HostedPage>
        <HostedCard
          tenant={gatekeep}
          title={messages.credentialSetupTitle}
          action={
            <Button type="button" variant="primary" pending={pending} onClick={confirmCode}>
              {messages.continue}
            </Button>
          }
          link={signOutLink}
          data-testid="recovery-code"
        >
          <Banner tone="warn" live={false}>
            {messages.recoveryCodeWarning}
          </Banner>
          <p>
            <code data-testid="recovery-code-value">{state.code}</code> <CopyButton value={state.code} what={messages.recoveryCodeWhat} />
          </p>
          <Checkbox
            label={messages.recoveryCodeSaved}
            checked={saved}
            aria-invalid={savedMissing || undefined}
            aria-describedby={savedMissing ? savedHelp : undefined}
            onChange={(event) => {
              setSaved(event.currentTarget.checked);
              if (event.currentTarget.checked) setSavedMissing(false);
            }}
          />
          {savedMissing && (
            <Banner tone="bad" id={savedHelp} data-testid="recovery-code-unsaved">
              {messages.recoveryCodeSavedRequired}
            </Banner>
          )}
        </HostedCard>
      </HostedPage>
    );
  }

  const step = state.credentials + 1;
  const offerCode = state.recoveryCodeAllowed && step === REQUIRED;
  return (
    <HostedPage>
      <HostedCard
        tenant={gatekeep}
        title={state.recovery ? messages.setupRecoveryTitle : messages.credentialSetupTitle}
        subtitle={state.recovery ? messages.setupRecoverySubtitle : step === 1 ? messages.credentialSetupFirst : messages.credentialSetupSecond}
        action={
          <Button type="button" variant="primary" pending={pending} onClick={register}>
            {messages.credentialSetupRegister}
          </Button>
        }
        link={signOutLink}
        data-testid="credential-setup"
      >
        {!state.recovery && (
          <p data-testid="credential-setup-step">{formatMessage(messages.credentialSetupStep, { step, total: REQUIRED })}</p>
        )}
        {alreadyRegistered ? (
          <Banner tone="warn" data-testid="credential-setup-registered">
            {messages.credentialSetupAlreadyRegistered}
          </Banner>
        ) : null}
        {offerCode && (
          <Button type="button" variant="secondary" disabled={pending} onClick={issueCode} data-testid="credential-setup-recovery-code">
            {messages.setupUseRecoveryCode}
          </Button>
        )}
      </HostedCard>
    </HostedPage>
  );
}
