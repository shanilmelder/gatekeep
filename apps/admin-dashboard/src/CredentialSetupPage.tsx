import { GenericErrorScreen } from '@gatekeep/hosted-screens';
import { HostedCard, HostedPage, useMessages } from '@gatekeep/ui/admin';
import { useEffect, useState } from 'react';
import { api, setCsrfToken } from './session';

/** The code credential setup shows when the Session can't be read, such as a 503 or a lost connection. */
const UNAVAILABLE = 'unavailable';

type State = 'loading' | 'ready' | 'failed';

/**
 * Admin credential setup, a placeholder until Story 1.22 registers credentials: it says two
 * passkeys come next. It asks for the Session first, which also renews the in-memory CSRF token
 * after a reload, and shows the setup text only for a live one. Without a Session it goes to
 * /bootstrap as a document request, which the server answers with the unknown-path 404 once
 * bootstrap is complete; when the Session can't be read it shows Generic error.
 */
export function CredentialSetupPage() {
  const messages = useMessages();
  const [state, setState] = useState<State>('loading');

  useEffect(() => {
    let current = true;
    api
      .getSession()
      .then((result) => {
        if (!current) return;
        if (result.ok && typeof result.data?.csrfToken === 'string') {
          setCsrfToken(result.data.csrfToken);
          setState('ready');
        } else if (result.status === 401) {
          window.location.replace('/bootstrap');
        } else {
          setState('failed');
        }
      })
      .catch(() => {
        if (current) setState('failed');
      });
    return () => {
      current = false;
    };
  }, []);

  const gatekeep = { name: messages.productName };

  if (state === 'loading') return <HostedPage />;

  return (
    <HostedPage>
      {state === 'ready' ? (
        <HostedCard
          tenant={gatekeep}
          title={messages.credentialSetupTitle}
          subtitle={messages.credentialSetupBody}
          data-testid="credential-setup"
        />
      ) : (
        <GenericErrorScreen tenant={gatekeep} code={UNAVAILABLE} traceId="" data-testid="credential-setup-error" />
      )}
    </HostedPage>
  );
}
