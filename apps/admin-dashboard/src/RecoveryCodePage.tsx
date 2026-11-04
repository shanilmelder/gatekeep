import { GenericErrorScreen } from '@gatekeep/hosted-screens';
import { Banner, Button, Field, HostedCard, HostedPage, Input, formatMessage, useMessages } from '@gatekeep/ui/admin';
import { useRef, useState, type FormEvent } from 'react';
import { navigate } from './navigation';
import { api, setCsrfToken } from './session';
import { retryAfterSeconds } from './shell/renewal';

/** The code Generic error shows for a failure with no problem body, such as a 503 or a lost connection. */
const UNAVAILABLE = 'unavailable';

type Refusal = { kind: 'refused' } | { kind: 'rateLimited'; seconds: number | null };

/**
 * Use a recovery code (EXPERIENCE.md, Admin sign-in; Story 1.26): a Hosted card with one field,
 * the offline Recovery Code, and one primary action. The server normalizes what is typed, so
 * nothing here checks its shape. A refusal never says why; a rate limit says how long to wait; an
 * outage shows Generic error. A redeemed code keeps the new Session's CSRF token in memory and
 * goes to credential setup, the only place a recovery Session reaches.
 */
export function RecoveryCodePage() {
  const messages = useMessages();
  const [code, setCode] = useState('');
  const [pending, setPending] = useState(false);
  const [refusal, setRefusal] = useState<Refusal | null>(null);
  const [failed, setFailed] = useState<{ code: string; traceId: string } | null>(null);
  // Set at once, before React re-renders, so a second submit sends nothing.
  const inFlight = useRef(false);

  async function redeem(event: FormEvent) {
    event.preventDefault();
    if (inFlight.current) return;
    inFlight.current = true;
    setPending(true);
    setRefusal(null);
    const done = () => {
      inFlight.current = false;
      setPending(false);
    };

    try {
      const result = await api.redeemRecoveryCode(code);
      if (result.ok && typeof result.data?.csrfToken === 'string') {
        setCsrfToken(result.data.csrfToken);
        setCode('');
        navigate('/setup/credentials');
        return;
      }

      done();
      if (!result.ok && result.status === 400) {
        setRefusal({ kind: 'refused' });
      } else if (!result.ok && result.status === 429) {
        setRefusal({ kind: 'rateLimited', seconds: retryAfterSeconds(result.headers.get('Retry-After')) });
      } else {
        setFailed((!result.ok && result.problem) || { code: UNAVAILABLE, traceId: '' });
      }
    } catch {
      done();
      setFailed({ code: UNAVAILABLE, traceId: '' });
    }
  }

  const gatekeep = { name: messages.productName };

  if (failed) {
    return (
      <HostedPage>
        <GenericErrorScreen tenant={gatekeep} code={failed.code} traceId={failed.traceId} backHref="/signin/recovery" data-testid="recovery-error" />
      </HostedPage>
    );
  }

  const refusalText =
    refusal?.kind === 'refused'
      ? messages.recoveryRefused
      : refusal?.kind === 'rateLimited'
        ? refusal.seconds === null
          ? messages.tooManyAttemptsNoTime
          : formatMessage(messages.tooManyAttempts, { seconds: refusal.seconds })
        : null;

  return (
    <HostedPage>
      <form onSubmit={redeem} noValidate>
        <HostedCard
          tenant={gatekeep}
          title={messages.recoveryTitle}
          subtitle={messages.recoverySubtitle}
          action={
            <Button type="submit" variant="primary" pending={pending}>
              {messages.continue}
            </Button>
          }
          link={<a href="/signin">{messages.recoveryPasskeyLink}</a>}
          data-testid="recovery"
        >
          {refusalText !== null && (
            <Banner tone="bad" data-testid="recovery-refused">
              {refusalText}
            </Banner>
          )}
          <Field label={messages.recoveryCodeLabel} helper={messages.recoveryCodeHelper}>
            <Input
              name="recovery-code"
              code
              inputMode="text"
              autoCapitalize="characters"
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              value={code}
              onChange={(event) => setCode(event.currentTarget.value)}
            />
          </Field>
        </HostedCard>
      </form>
    </HostedPage>
  );
}
