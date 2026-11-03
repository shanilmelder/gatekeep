import type { ApiProblem } from '@gatekeep/api-client';
import { GenericErrorScreen } from '@gatekeep/hosted-screens';
import { Button, ErrorReference, Field, HostedCard, HostedPage, Input, StatusIcon, useMessages } from '@gatekeep/ui/admin';
import { useRef, useState, type FormEvent } from 'react';
import { navigate } from './navigation';
import { api, setCsrfToken } from './session';

/** The codes Bootstrap shows for a failure with no problem body. */
const UNAVAILABLE = 'unavailable';
const ORIGIN_REFUSED = 'origin_refused';
const BOOTSTRAP_UNAVAILABLE = 'bootstrap_unavailable';

type Failure = { code: string; traceId: string };

/**
 * What Generic error shows for a failed claim: the problem's own code and trace ID for a refused
 * or rate-limited one; a fixed code for a 404 (nothing to claim here), a 403 (the Origin was
 * refused) and anything else, such as a 503 or a lost connection.
 */
function failure(result: Awaited<ReturnType<typeof api.claimBootstrap>> | null): Failure {
  if (result === null || result.ok) return { code: UNAVAILABLE, traceId: '' };
  if (result.status === 404) return { code: BOOTSTRAP_UNAVAILABLE, traceId: '' };
  if (result.status === 403) return { code: ORIGIN_REFUSED, traceId: '' };
  const problem: ApiProblem | null = result.problem;
  if ((result.status === 400 || result.status === 429) && problem) return problem;
  return { code: UNAVAILABLE, traceId: '' };
}

/**
 * Bootstrap (EXPERIENCE.md, Admin: access and Tenants): a Hosted card in the Gatekeep default
 * theme with the one-time token field and Claim. A claim keeps the CSRF token in memory and goes
 * to credential setup. A failed one shows Generic error with its code and trace ID, whose action
 * comes back here with an empty field; with nothing to claim here there is no way back.
 */
export function BootstrapPage() {
  const messages = useMessages();
  const [token, setToken] = useState('');
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<Failure | null>(null);
  // Set at once, before React re-renders, so a second click or Enter sends nothing.
  const inFlight = useRef(false);

  async function claim(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (inFlight.current) return;
    inFlight.current = true;
    setPending(true);

    const submitted = token.trim();
    // The field keeps no value once it's sent, whatever comes back.
    setToken('');

    let result: Awaited<ReturnType<typeof api.claimBootstrap>> | null;
    try {
      result = await api.claimBootstrap(submitted);
    } catch {
      result = null;
    }

    // A 2xx without a CSRF token isn't a claim the page can go on with: it fails like a 503.
    if (result?.ok && typeof result.data?.csrfToken === 'string') {
      setCsrfToken(result.data.csrfToken);
      navigate('/setup/credentials');
      return;
    }

    inFlight.current = false;
    setPending(false);
    setProblem(failure(result));
  }

  const gatekeep = { name: messages.productName };

  if (problem?.code === BOOTSTRAP_UNAVAILABLE) {
    return (
      <HostedPage>
        <HostedCard
          tenant={gatekeep}
          icon={<StatusIcon status="error" />}
          title={messages.bootstrapUnavailableTitle}
          subtitle={messages.bootstrapUnavailableBody}
          data-testid="bootstrap-unavailable"
        >
          <ErrorReference code={problem.code} traceId={problem.traceId} />
        </HostedCard>
      </HostedPage>
    );
  }

  return (
    <HostedPage>
      {problem ? (
        <GenericErrorScreen
          tenant={gatekeep}
          code={problem.code}
          traceId={problem.traceId}
          backHref="/bootstrap"
          data-testid="bootstrap-error"
        />
      ) : (
        <form onSubmit={claim} noValidate>
          <HostedCard
            tenant={gatekeep}
            title={messages.bootstrapTitle}
            subtitle={messages.bootstrapSubtitle}
            action={
              <Button type="submit" variant="primary" pending={pending}>
                {messages.bootstrapClaim}
              </Button>
            }
            data-testid="bootstrap"
          >
            <Field label={messages.bootstrapTokenLabel} helper={messages.bootstrapTokenHelper}>
              <Input
                name="token"
                code
                autoComplete="off"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                value={token}
                onChange={(event) => setToken(event.currentTarget.value)}
              />
            </Field>
          </HostedCard>
        </form>
      )}
    </HostedPage>
  );
}
