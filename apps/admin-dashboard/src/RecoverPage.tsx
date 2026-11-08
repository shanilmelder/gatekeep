import { GenericErrorScreen } from '@gatekeep/hosted-screens';
import { Banner, Button, HostedCard, HostedPage, formatMessage, useMessages } from '@gatekeep/ui/admin';
import { useLayoutEffect, useRef, useState } from 'react';
import { navigate } from './navigation';
import { api, setCsrfToken } from './session';
import { retryAfterSeconds } from './shell/renewal';

/** The code Generic error shows for a failure with no problem body, such as a 503 or a lost connection. */
const UNAVAILABLE = 'unavailable';

/** The path gatekeep recover-admin's link opens: `https://{Admin host}/recover#{enrolment}`. */
const PATH = '/recover';

type Refusal = { kind: 'refused' } | { kind: 'rateLimited'; seconds: number | null };

/**
 * Recover Admin access (Story 1.32): the page `gatekeep recover-admin`'s link opens. The enrolment
 * is in the link's fragment, which no request line or log carries; the page reads it once, clears
 * it from the address bar and history with `history.replaceState`, and keeps it only in memory.
 * Continue sends it, and a redeemed enrolment keeps the new Session's CSRF token in memory and goes
 * to credential setup, the only place that Session reaches. A refusal never says why; a rate limit
 * says how long to wait; an outage shows Generic error.
 */
export function RecoverPage() {
  const messages = useMessages();
  // Read before the first paint, so the fragment is gone as soon as the page shows.
  const enrolment = useRef<string | null>(null);
  const [missing, setMissing] = useState(false);
  const [pending, setPending] = useState(false);
  const [refusal, setRefusal] = useState<Refusal | null>(null);
  const [failed, setFailed] = useState<{ code: string; traceId: string } | null>(null);
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);

  useLayoutEffect(() => {
    if (enrolment.current === null) {
      const fragment = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : window.location.hash;
      enrolment.current = fragment;
      if (window.location.hash !== '') window.history.replaceState(null, '', PATH);
    }
    if (enrolment.current === '') setMissing(true);
  }, []);

  async function redeem() {
    const value = enrolment.current;
    if (inFlight.current || !value) return;
    inFlight.current = true;
    setPending(true);
    setRefusal(null);
    const done = () => {
      inFlight.current = false;
      setPending(false);
    };

    try {
      const result = await api.redeemEnrolment(value);
      if (result.ok && typeof result.data?.csrfToken === 'string') {
        enrolment.current = '';
        setCsrfToken(result.data.csrfToken);
        navigate('/setup/credentials', { replace: true });
        return;
      }

      done();
      if (!result.ok && result.status === 400) {
        // Used, expired or unknown: it can't work again, so it is dropped.
        enrolment.current = '';
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
    // Unused, the link gatekeep recover-admin printed still works until it expires: open it again.
    return (
      <HostedPage>
        <GenericErrorScreen tenant={gatekeep} code={failed.code} traceId={failed.traceId} backHref="/signin" data-testid="recover-error" />
      </HostedPage>
    );
  }

  const refused = missing || refusal?.kind === 'refused';
  const refusalText = refused
    ? messages.recoverRefused
    : refusal?.kind === 'rateLimited'
      ? refusal.seconds === null
        ? messages.tooManyAttemptsNoTime
        : formatMessage(messages.tooManyAttempts, { seconds: refusal.seconds })
      : null;

  return (
    <HostedPage>
      <HostedCard
        tenant={gatekeep}
        title={messages.recoverTitle}
        subtitle={messages.recoverSubtitle}
        action={
          refused ? undefined : (
            <Button type="button" variant="primary" pending={pending} onClick={redeem}>
              {messages.continue}
            </Button>
          )
        }
        link={<a href="/signin">{messages.recoveryPasskeyLink}</a>}
        data-testid="recover"
      >
        {refusalText !== null && (
          <Banner tone="bad" data-testid="recover-refused">
            {refusalText}
          </Banner>
        )}
      </HostedCard>
    </HostedPage>
  );
}
