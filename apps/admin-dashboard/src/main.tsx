import '@gatekeep/ui/styles.css';
import type { ApiProblem } from '@gatekeep/api-client';
import { GenericErrorScreen } from '@gatekeep/hosted-screens';
import { Banner, Button, HostedPage, useMessages } from '@gatekeep/ui/admin';
import { StrictMode, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { BootstrapPage } from './BootstrapPage';
import { CredentialSetupPage } from './CredentialSetupPage';
import { navigate, usePath } from './navigation';
import { api, setCsrfToken } from './session';
import { SignInPage } from './SignInPage';

/** The code Generic error shows for a failure with no problem body, such as a 503 or a lost connection. */
const UNAVAILABLE = 'unavailable';

type Failure = { code: string; traceId: string };

/**
 * The root, a placeholder until the Admin shell (Story 1.25). It asks for the Session, so an
 * Admin without their two credentials goes back to credential setup, which they can't leave, and
 * one with no Session (none, ended or expired) goes to sign-in. Any other failure to read the
 * Session (a 503, 429 or 403, a lost connection, or a 2xx with no Session or CSRF token in it)
 * shows Generic error, whose action loads the root again. Sign out sits here until the shell's
 * avatar menu: it ends the Session with the CSRF token and goes to sign-in.
 */
function RootPage() {
  const messages = useMessages();
  const [signedIn, setSignedIn] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [signOutFailed, setSignOutFailed] = useState(false);
  const [pending, setPending] = useState(false);
  // Set at once, before React re-renders, so a second click sends nothing.
  const inFlight = useRef(false);

  useEffect(() => {
    let current = true;
    api
      .getSession()
      .then((result) => {
        if (!current) return;
        if (result.status === 401) {
          navigate('/signin');
          return;
        }
        if (!result.ok || !result.data || typeof result.data.csrfToken !== 'string') {
          const problem: ApiProblem | null = result.ok ? null : result.problem;
          setFailure(problem ?? { code: UNAVAILABLE, traceId: '' });
          return;
        }
        setCsrfToken(result.data.csrfToken);
        if (!result.data.setupComplete) {
          navigate('/setup/credentials');
          return;
        }
        setSignedIn(true);
      })
      .catch(() => {
        if (current) setFailure({ code: UNAVAILABLE, traceId: '' });
      });
    return () => {
      current = false;
    };
  }, []);

  async function signOut() {
    if (inFlight.current) return;
    inFlight.current = true;
    setPending(true);
    setSignOutFailed(false);
    let status: number | null;
    try {
      status = (await api.endSession()).status;
    } catch {
      status = null;
    }

    // Ended, or already gone: either way there is no Session here now.
    if (status === 204 || status === 401) {
      setCsrfToken(null);
      navigate('/signin');
      return;
    }

    inFlight.current = false;
    setPending(false);
    setSignOutFailed(true);
  }

  if (failure) {
    return (
      <HostedPage>
        <GenericErrorScreen
          tenant={{ name: messages.productName }}
          code={failure.code}
          traceId={failure.traceId}
          backHref="/"
          data-testid="root-error"
        />
      </HostedPage>
    );
  }

  return (
    <main>
      <p>Admin Dashboard</p>
      {signedIn ? (
        <Button type="button" variant="secondary" pending={pending} onClick={signOut}>
          {messages.signOut}
        </Button>
      ) : null}
      {signOutFailed ? (
        <Banner tone="bad" data-testid="signout-failed">
          {messages.signOutFailed}
        </Banner>
      ) : null}
    </main>
  );
}

/** The pages so far. The Admin shell (Story 1.25) replaces the root placeholder. */
function App() {
  const path = usePath();
  switch (path) {
    case '/bootstrap':
      return <BootstrapPage />;
    case '/signin':
      return <SignInPage />;
    case '/setup/credentials':
      return <CredentialSetupPage />;
    case '/':
      return <RootPage />;
    default:
      return <p>Admin Dashboard</p>;
  }
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
