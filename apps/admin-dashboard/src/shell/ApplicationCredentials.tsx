import type { ApplicationResponse, ApplicationSecretResponse } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  ConfirmModal,
  ErrorReference,
  OneTimeReveal,
  SkeletonRows,
  formatMessage,
  useMessages,
  useToast,
} from '@gatekeep/ui/admin';
import { useEffect, useId, useRef, useState } from 'react';
import { api } from '../session';
import { failureOf } from './ApplicationsPage';
import { canAddSecret, currentSecret, takeSecretCreate } from './applications';
import type { ShellRequest } from './CredentialsPage';
import type { FreshAssertion } from './freshAssertion';
import styles from './ApplicationCredentials.module.css';
import { confirmationText } from './TenantSettingsPage';

type Failure = { code: string; traceId: string };

type Load = { kind: 'loading' } | { kind: 'ready'; items: ApplicationSecretResponse[] } | { kind: 'failed'; failure: Failure };

type Refusal = { kind: 'failed'; code: string; traceId: string } | { kind: 'forbidden' } | { kind: 'unconfirmed'; text: string } | null;

/** The one-time reveal's value, and whether an old secret still overlaps it, for the toast once it closes. */
type Reveal = { value: string; rotated: boolean };

const DATE = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const DATE_TIME = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

function formatted(format: Intl.DateTimeFormat, value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : format.format(date);
}

function itemsOf(data: unknown): ApplicationSecretResponse[] | null {
  const items = (data as { items?: unknown } | null | undefined)?.items;
  return Array.isArray(items) && items.every((item) => typeof (item as { id?: unknown } | null)?.id === 'string')
    ? (items as ApplicationSecretResponse[])
    : null;
}

export interface ApplicationCredentialsProps {
  request: ShellRequest;
  fresh: FreshAssertion;
  tenantId: string;
  application: ApplicationResponse;
  /** Whether the caller holds tenant.client_secrets.manage, which only Tenant Owners do: without it every write control is disabled. */
  canManage: boolean;
}

/**
 * An Application's Credentials tab (Story 3.3, FR-12; design Application detail, Credentials, as the
 * Design Delta trims it: no method picker, no Reveal, no public keys). Single-page and native need no
 * secret. Regular web and machine-to-machine list their live secrets, the current one by when it was
 * created and an old one still overlapping by when it stops, never a value, hash or prefix. A Tenant
 * Owner creates the first secret, rotates it (the old one keeps working for 24 hours, and Rotate waits
 * while one does), ends an old one now, and revokes the current one after a confirming modal. Every write
 * goes through the fresh-assertion sheet, and a new secret shows once, in the one-time reveal.
 */
export function ApplicationCredentials({ request, fresh, tenantId, application, canManage }: ApplicationCredentialsProps) {
  const messages = useMessages();
  const toast = useToast();
  const ownerOnlyId = useId();
  const needsSecret = application.credentialRequired;
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);
  const [refusal, setRefusal] = useState<Refusal>(null);
  // Which control's write is under way: 'create', or the secret being ended or revoked.
  const [pending, setPending] = useState<string | null>(null);
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);
  const [reveal, setReveal] = useState<Reveal | null>(null);
  const [revealOpen, setRevealOpen] = useState(false);
  const [confirming, setConfirming] = useState<ApplicationSecretResponse | null>(null);
  const addButton = useRef<HTMLButtonElement>(null);
  // The Owner's create flow asked for the first secret: taken once, on mount, so a panel gone before the
  // list is read leaves no ask behind; acted on once the list says there is none.
  const [autoAsked] = useState(() => takeSecretCreate(application.id));
  const autoCreate = useRef(autoAsked);

  useEffect(() => {
    if (!needsSecret) return;
    const controller = new AbortController();
    setLoad({ kind: 'loading' });

    void (async () => {
      let result;
      try {
        result = await request('get', () => api.listApplicationSecrets(tenantId, application.id), controller.signal);
      } catch {
        result = null;
      }
      if (controller.signal.aborted) return;
      const items = result?.ok ? itemsOf(result.data) : null;
      if (items) setLoad({ kind: 'ready', items });
      else setLoad({ kind: 'failed', failure: failureOf(result) });
    })();

    return () => controller.abort();
  }, [request, tenantId, application.id, needsSecret, attempt]);

  /** Sends one write through the fresh-assertion sheet; its answer's data when it succeeded, else null with the refusal shown. */
  async function write<R extends { ok: boolean; status: number; data?: unknown; problem?: { code: string; traceId: string } | null }>(
    key: string,
    send: () => Promise<R>,
  ): Promise<unknown> {
    if (!canManage || inFlight.current) return null;
    inFlight.current = true;
    setPending(key);
    setRefusal(null);

    let outcome;
    try {
      outcome = await fresh.withFreshAssertion(
        { action: 'tenant.client_secrets.manage', target: application.id, tenantId },
        () => request('post', send),
      );
    } catch {
      outcome = null;
    }
    inFlight.current = false;
    setPending(null);

    if (outcome?.kind === 'unconfirmed') {
      setRefusal({ kind: 'unconfirmed', text: confirmationText(outcome.confirmation, messages) });
      return null;
    }
    const answer = outcome?.answer ?? null;
    if (answer?.ok) {
      // Done: the answer's items, or, if they can't be read, the list read again. A created secret is shown either way.
      const items = itemsOf(answer.data);
      if (items) setLoad({ kind: 'ready', items });
      else setAttempt((n) => n + 1);
      return answer.data ?? {};
    }
    if (answer?.status === 401) {
      // The renewal brought the Admin back and didn't send it again.
      return null;
    }
    const problem = answer && !answer.ok ? (answer.problem ?? null) : null;
    if (answer?.status === 409 && problem?.code === 'tenant_mismatch') {
      // The shell's banner names both Tenants: nothing was changed.
      return null;
    }
    if (answer?.status === 403) {
      setRefusal({ kind: 'forbidden' });
      return null;
    }
    // Something else changed the secrets meanwhile (an old one ended, a limit reached): read them again.
    if (answer?.status === 404 || answer?.status === 409) setAttempt((n) => n + 1);
    setRefusal({ kind: 'failed', code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' });
    return null;
  }

  async function create() {
    const data = await write('create', () => api.createApplicationSecret(tenantId, application.id));
    const secret = (data as { secret?: unknown } | null)?.secret;
    if (typeof secret === 'string' && secret !== '') {
      // The 201's own items decide the toast: an old secret still live beside it means a rotation's overlap.
      const items = itemsOf(data);
      setReveal({ value: secret, rotated: items?.some((item) => item.expiresAt != null) ?? false });
      setRevealOpen(true);
    }
  }

  async function revoke(secret: ApplicationSecretResponse, ending: boolean) {
    const data = await write(secret.id, () => api.revokeApplicationSecret(tenantId, application.id, secret.id));
    setConfirming(null);
    if (data) toast(ending ? messages.applicationSecretEnded : messages.applicationSecretRevoked);
  }

  // The Owner's create flow: the first secret, once the list is read and holds none. A cancelled sheet leaves Create secret.
  useEffect(() => {
    if (!autoCreate.current || load.kind !== 'ready') return;
    autoCreate.current = false;
    if (!canManage || load.items.length > 0) return;
    void create();
    // Only the list's first answer decides; create reads the rest as it is then.
  }, [load, application.id, canManage]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!needsSecret) {
    return (
      <section className={styles.section} aria-labelledby="application-credentials-heading" data-testid="application-credentials">
        <h2 id="application-credentials-heading">{messages.applicationCredentialsTitle}</h2>
        <p data-testid="application-credentials-none">{messages.applicationCredentialsNone}</p>
      </section>
    );
  }

  const items = load.kind === 'ready' ? load.items : [];
  const current = currentSecret(items);
  const canAdd = canAddSecret(items);
  const busy = pending !== null;
  const blockedId = `${ownerOnlyId}-blocked`;
  // Revoking the current secret while an old one overlaps leaves that one working until it ends.
  const overlapping = items.find((secret) => secret.expiresAt != null && secret.id !== confirming?.id) ?? null;

  let body;
  if (load.kind === 'loading') {
    body = <SkeletonRows rows={1} caption={false} />;
  } else if (load.kind === 'failed') {
    body = (
      <Banner tone="bad" action={{ label: messages.retry, onClick: () => setAttempt((n) => n + 1) }} data-testid="application-secrets-load-failed">
        <p>{messages.loadFailed}</p>
        <ErrorReference code={load.failure.code} traceId={load.failure.traceId} />
      </Banner>
    );
  } else {
    body = (
      <>
        {items.length === 0 ? (
          <p className={styles.empty} data-testid="application-secrets-none">
            {canManage ? messages.applicationSecretNone : messages.applicationSecretNoneOwnerOnly}
          </p>
        ) : (
          <ul className={styles.list} data-testid="application-secrets">
            {items.map((secret) => {
              const isCurrent = secret.expiresAt == null;
              return (
                <li key={secret.id} className={styles.row} data-testid={isCurrent ? 'application-secret-current' : 'application-secret-old'}>
                  <span className={styles.rowText}>
                    {isCurrent
                      ? formatMessage(messages.applicationSecretCurrent, { date: formatted(DATE, secret.createdAt) })
                      : formatMessage(messages.applicationSecretOld, { datetime: formatted(DATE_TIME, secret.expiresAt!) })}
                  </span>
                  {isCurrent ? (
                    <Button
                      variant="destructive"
                      size="sm"
                      aria-disabled={!canManage || busy || undefined}
                      aria-describedby={!canManage ? ownerOnlyId : undefined}
                      onClick={() => setConfirming(secret)}
                      data-testid="application-secret-revoke"
                    >
                      {messages.applicationSecretRevoke}
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      pending={pending === secret.id}
                      aria-disabled={!canManage || (busy && pending !== secret.id) || undefined}
                      aria-describedby={!canManage ? ownerOnlyId : undefined}
                      onClick={() => void revoke(secret, true)}
                      data-testid="application-secret-end-now"
                    >
                      {messages.applicationSecretEndNow}
                    </Button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
        <div className={styles.actions}>
          <Button
            ref={addButton}
            variant="primary"
            pending={pending === 'create'}
            aria-disabled={!canManage || !canAdd || (busy && pending !== 'create') || undefined}
            aria-describedby={!canManage ? ownerOnlyId : !canAdd ? blockedId : undefined}
            onClick={() => void create()}
            data-testid={current ? 'application-secret-rotate' : 'application-secret-create'}
          >
            {current ? messages.applicationSecretRotate : messages.applicationSecretCreate}
          </Button>
          {!canManage ? (
            <p id={ownerOnlyId} className={styles.note} data-testid="application-secrets-owner-only">
              {messages.tenantOwnerOnly}
            </p>
          ) : (
            !canAdd && (
              <p id={blockedId} className={styles.note} data-testid="application-secret-rotate-blocked">
                {messages.applicationSecretRotateBlocked}
              </p>
            )
          )}
        </div>
      </>
    );
  }

  return (
    <section className={styles.section} aria-labelledby="application-credentials-heading" data-testid="application-credentials">
      <h2 id="application-credentials-heading">{messages.applicationCredentialsTitle}</h2>
      {refusal?.kind === 'failed' && (
        <Banner tone="bad" data-testid="application-secret-failed">
          <p>{messages.applicationSecretFailed}</p>
          <ErrorReference code={refusal.code} traceId={refusal.traceId} />
        </Banner>
      )}
      {refusal?.kind === 'forbidden' && (
        <Banner tone="bad" data-testid="application-secret-forbidden">
          {messages.actionForbidden}
        </Banner>
      )}
      {refusal?.kind === 'unconfirmed' && (
        <Banner tone="bad" data-testid="fresh-assertion-failed">
          {refusal.text}
        </Banner>
      )}
      <div className={styles.card} data-testid="application-secret-card">
        <header className={styles.cardHeader}>
          <h3>{messages.applicationSecretTitle}</h3>
          <p>{messages.applicationSecretDescription}</p>
        </header>
        <div className={styles.cardBody}>{body}</div>
      </div>

      <ConfirmModal
        open={confirming !== null}
        onCancel={() => {
          if (pending === null) setConfirming(null);
        }}
        onConfirm={() => {
          if (confirming) void revoke(confirming, false);
        }}
        tone="destructive"
        pending={confirming !== null && pending === confirming.id}
        title={messages.applicationSecretRevokeTitle}
        confirmLabel={messages.applicationSecretRevokeConfirm}
        data-testid="application-secret-revoke-modal"
      >
        <p>
          {overlapping
            ? formatMessage(messages.applicationSecretRevokeBodyOverlap, { datetime: formatted(DATE_TIME, overlapping.expiresAt!) })
            : messages.applicationSecretRevokeBody}
        </p>
      </ConfirmModal>

      <OneTimeReveal
        open={revealOpen}
        onClose={() => {
          // The value is spent: nothing keeps it once the reveal closes.
          setRevealOpen(false);
          setReveal(null);
          toast(reveal?.rotated ? messages.applicationSecretRotated : messages.applicationSecretCreated);
        }}
        title={messages.applicationSecretRevealTitle}
        value={reveal?.value}
        what={messages.applicationSecretRevealWhat}
        fallbackFocus={() => addButton.current ?? document.querySelector<HTMLElement>('main h1')}
        data-testid="application-secret-reveal"
      >
        <p>{messages.applicationSecretRevealBody}</p>
      </OneTimeReveal>
    </section>
  );
}
