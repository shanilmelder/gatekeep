import type { SigningKey, SigningKeysJwksResponse } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  Checkbox,
  CodeBlock,
  ConfirmModal,
  CopyButton,
  DataTable,
  ErrorReference,
  KeyStateBadge,
  SectionPage,
  SkeletonRows,
  formatMessage,
  useMessages,
  useToast,
  type DataTableColumn,
  type KeyState,
} from '@gatekeep/ui/admin';
import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { api } from '../session';
import { useCapabilities } from './capabilities';
import type { ShellRequest } from './CredentialsPage';
import { fillNodes } from './DeleteTenantModal';
import { ForbiddenPage } from './ForbiddenPage';
import type { FreshAssertion } from './freshAssertion';
import styles from './SigningKeysPage.module.css';
import { confirmationText } from './TenantSettingsPage';

type Failure = { code: string; traceId: string };

type ListLoad =
  | { kind: 'loading' }
  | { kind: 'ready'; keys: readonly SigningKey[] }
  | { kind: 'forbidden'; failure: Failure }
  | { kind: 'failed'; failure: Failure };

type JwksLoad = { kind: 'loading' } | { kind: 'ready'; sample: SigningKeysJwksResponse } | { kind: 'failed'; failure: Failure };

/** Why the last Rotate didn't rotate: the next key too young, with the whole minutes left; refused; or failed. */
type Refusal = { kind: 'notReady'; minutes: number; failure: Failure } | { kind: 'forbidden' } | { kind: 'failed'; failure: Failure } | null;

/** What the revoke confirmation's slot shows: nothing, the sheet's prompt, or a failure, with its reference when it has one. */
type RevokeSlot = { kind: 'none' } | { kind: 'prompt' } | { kind: 'failed'; text: string; reference?: Failure };

/** The states a key can be revoked from: the published ones. Retired and revoked keys have left the JWKS. */
const REVOCABLE = new Set(['next', 'current', 'previous']);

const DATE = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });

/** A date, in the browser's own time zone and locale. */
function day(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : DATE.format(date);
}

/** The whole minutes a not-ready rotation must wait, rounded up and at least one, from its seconds. */
function minutesLeft(seconds: unknown): number {
  return typeof seconds === 'number' && Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds / 60) : 1;
}

/** A refusal's code and trace ID, as far as the answer carries them: a bodiless 503 has neither. */
function failureOf(result: { ok: boolean; problem?: { code?: string; traceId?: string } | null } | null): Failure {
  const problem = result && !result.ok ? result.problem : null;
  return { code: problem?.code ?? '', traceId: problem?.traceId ?? '' };
}

export interface SigningKeysPageProps {
  request: ShellRequest;
  /** The shell's re-authentication sheet: a revocation needs a fresh assertion (Story 9.3). */
  fresh: FreshAssertion;
  /** The path Tenant this page was mounted with: every request it sends names this one. */
  tenantId: string;
}

/**
 * Signing keys (Story 9.1; GEN.keys as the epic changes it): the Tenant's Signing Keys in every
 * state, each key ID in the code type with its own Copy, and below them the public JWKS sample
 * its Tenant host serves, with its URI and its own Copy. The two are read apart: the table is the
 * database's and the sample needs key custody, so a sample that can't be read says so in its
 * place and the table stays. A 403 on the list is the forbidden page.
 *
 * Story 9.2: the page's one action, Rotate now, with tenant.signing_keys.rotate, which only Tenant
 * Owners hold. Without it, an Admin who manages anything else in the Tenant sees it read-only,
 * "Tenant Owner only", and one who manages nothing sees no action and the view-only banner. A
 * rotation replaces the table with the keys it left and reads the sample again; a next key too young
 * to promote, or any failure, shows a banner with its reference.
 *
 * Story 9.3: each published key (next, current, previous) has Revoke, with tenant.signing_keys.revoke,
 * read-only as "Tenant Owner only" for anyone else who manages the Tenant, and absent for a Viewer.
 * It opens a destructive confirmation stating the token impact, which can also end every Session and
 * refresh token in the Tenant. Confirming confirms it's the Admin, bound to the key, in that same modal
 * when the server asks; success replaces the table, reads the sample again and says so, and a failure
 * shows in the modal with its reference. The server decides every request: the page follows the
 * capability lists, never a role (AD-20).
 */
export function SigningKeysPage({ request, fresh, tenantId }: SigningKeysPageProps) {
  const messages = useMessages();
  const toast = useToast();
  const { has, tenantCapabilities } = useCapabilities();
  const ownerOnlyId = useId();
  const [list, setList] = useState<ListLoad>({ kind: 'loading' });
  const [jwks, setJwks] = useState<JwksLoad>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);
  const [jwksAttempt, setJwksAttempt] = useState(0);
  const [rotating, setRotating] = useState(false);
  const [refusal, setRefusal] = useState<Refusal>(null);
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);
  const [revoking, setRevoking] = useState<SigningKey | null>(null);
  const [revokeAccess, setRevokeAccess] = useState(false);
  const [revokePending, setRevokePending] = useState(false);
  const [revokeSlot, setRevokeSlot] = useState<RevokeSlot>({ kind: 'none' });
  // The row whose Revoke opened the modal, for focus once it closes.
  const focusAfter = useRef<string | null>(null);
  const listed = list.kind === 'ready';
  const canRotate = has('tenant.signing_keys.rotate');
  const canRevoke = has('tenant.signing_keys.revoke');
  const viewOnly = ![...tenantCapabilities].some((capability) => capability.startsWith('tenant.') && capability.endsWith('.manage'));

  useEffect(() => {
    const controller = new AbortController();
    setList({ kind: 'loading' });

    void (async () => {
      let result;
      try {
        result = await request('get', () => api.listSigningKeys(tenantId), controller.signal);
      } catch {
        result = null;
      }
      if (controller.signal.aborted) return;
      const keys = result?.ok ? result.data?.keys : undefined;
      if (Array.isArray(keys)) setList({ kind: 'ready', keys });
      else if (result !== null && !result.ok && result.status === 403 && result.problem?.code === 'access_denied')
        setList({ kind: 'forbidden', failure: failureOf(result) });
      else setList({ kind: 'failed', failure: failureOf(result) });
    })();

    return () => controller.abort();
  }, [request, tenantId, attempt]);

  // The sample only once the list has read: a refused page asks custody nothing, and is denied once.
  useEffect(() => {
    if (!listed) return;
    const controller = new AbortController();
    setJwks({ kind: 'loading' });

    void (async () => {
      let result;
      try {
        result = await request('get', () => api.getSigningKeysJwks(tenantId), controller.signal);
      } catch {
        result = null;
      }
      if (controller.signal.aborted) return;
      const sample = result?.ok ? result.data : undefined;
      if (sample && typeof sample.jwksUri === 'string' && Array.isArray(sample.keys)) setJwks({ kind: 'ready', sample });
      else setJwks({ kind: 'failed', failure: failureOf(result) });
    })();

    return () => controller.abort();
  }, [request, tenantId, listed, jwksAttempt]);

  /** Rotates now, once at a time, and shows what it came to. */
  async function rotate() {
    if (!canRotate || !listed || inFlight.current) return;
    inFlight.current = true;
    setRotating(true);
    setRefusal(null);

    let answer;
    try {
      answer = await request('post', () => api.rotateSigningKeys(tenantId));
    } catch {
      answer = null;
    }
    inFlight.current = false;
    setRotating(false);

    if (answer?.ok) {
      // The keys as the rotation left them, or, if they can't be read, the list read again; the sample changed too.
      const keys = answer.data?.keys;
      if (Array.isArray(keys)) setList({ kind: 'ready', keys });
      else setAttempt((n) => n + 1);
      setJwksAttempt((n) => n + 1);
      toast(messages.signingKeysRotated);
      return;
    }
    if (answer?.status === 401) {
      // The renewal brought the Admin back and didn't send it again.
      return;
    }
    const problem = answer && !answer.ok ? (answer.problem ?? null) : null;
    if (answer?.status === 409 && problem?.code === 'tenant_mismatch') {
      // The shell's banner names both Tenants: nothing was changed.
      return;
    }
    const failure = { code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' };
    if (answer?.status === 409 && problem?.code === 'signing_key_not_ready') {
      const seconds = problem.retryAfterSeconds ?? Number(answer.headers.get('Retry-After'));
      setRefusal({ kind: 'notReady', minutes: minutesLeft(seconds), failure });
      return;
    }
    if (answer?.status === 403) {
      setRefusal({ kind: 'forbidden' });
      return;
    }
    setRefusal({ kind: 'failed', failure });
  }

  /** Opens the revoke confirmation for a published key, with its Sessions box unchecked. */
  function openRevoke(row: SigningKey) {
    if (!canRevoke || revokePending) return;
    focusAfter.current = row.keyId;
    setRevokeAccess(false);
    setRevokeSlot({ kind: 'none' });
    setRevoking(row);
  }

  function closeRevoke() {
    if (revokePending) return;
    setRevokeSlot({ kind: 'none' });
    setRevoking(null);
  }

  /** Revokes the key the modal is for, once at a time, confirming it's the Admin when the server asks. */
  async function revoke() {
    if (!canRevoke || !revoking || inFlight.current) return;
    inFlight.current = true;
    setRevokePending(true);
    setRevokeSlot({ kind: 'prompt' });
    const { keyId } = revoking;
    const body = { revokeAccess };

    let outcome;
    try {
      outcome = await fresh.withFreshAssertion({ action: 'tenant.signing_keys.revoke', target: keyId, tenantId }, () =>
        request('post', () => api.revokeSigningKey(tenantId, keyId, body)),
      );
    } catch {
      outcome = null;
    }
    inFlight.current = false;
    setRevokePending(false);

    if (outcome?.kind === 'unconfirmed') {
      setRevokeSlot({ kind: 'failed', text: confirmationText(outcome.confirmation, messages) });
      return;
    }
    const answer = outcome?.answer ?? null;
    if (answer?.ok) {
      // The keys as the revocation left them, or, if they can't be read, the list read again; the sample changed too.
      const keys = answer.data?.keys;
      if (Array.isArray(keys)) setList({ kind: 'ready', keys });
      else setAttempt((n) => n + 1);
      setJwksAttempt((n) => n + 1);
      setRevokeSlot({ kind: 'none' });
      setRevoking(null);
      toast(messages.signingKeysRevoked);
      return;
    }
    const problem = answer && !answer.ok ? (answer.problem ?? null) : null;
    if (answer?.status === 409 && problem?.code === 'tenant_mismatch') {
      // The shell's banner names both Tenants: nothing was changed.
      setRevokeSlot({ kind: 'none' });
      return;
    }
    if (answer?.status === 401) {
      // The renewal brought the Admin back and didn't send it again: nothing changed.
      setRevokeSlot({ kind: 'failed', text: messages.actionRetryAfterSignIn });
      return;
    }
    if (answer?.status === 403) {
      setRevokeSlot({ kind: 'failed', text: messages.actionForbidden });
      return;
    }
    setRevokeSlot({
      kind: 'failed',
      text: messages.signingKeysRevokeFailed,
      reference: { code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' },
    });
  }

  if (list.kind === 'forbidden') return <ForbiddenPage code={list.failure.code} traceId={list.failure.traceId} />;

  const columns: DataTableColumn<SigningKey>[] = [
    {
      key: 'keyId',
      header: messages.signingKeysColumnKeyId,
      rowHeader: true,
      cell: (row) => (
        <span className={styles.keyId}>
          <code data-testid="signing-key-id">{row.keyId}</code>
          <CopyButton value={row.keyId} what={messages.signingKeyIdWhat} />
        </span>
      ),
    },
    { key: 'algorithm', header: messages.signingKeysColumnAlgorithm, cell: (row) => row.algorithm },
    { key: 'state', header: messages.signingKeysColumnStatus, cell: (row) => <KeyStateBadge state={row.state as KeyState} /> },
    { key: 'created', header: messages.signingKeysColumnCreated, cell: (row) => day(row.createdAt) },
  ];
  // A Viewer, who manages nothing in the Tenant, gets no Revoke column; anyone else sees it, off without the capability.
  if (!viewOnly) {
    columns.push({
      key: 'revoke',
      header: messages.signingKeysRevoke,
      cell: (row) =>
        REVOCABLE.has(row.state) ? (
          <Button
            variant="destructive"
            size="sm"
            data-key-id={row.keyId}
            aria-label={formatMessage(messages.signingKeysRevokeNamed, { keyId: row.keyId })}
            aria-disabled={!canRevoke || undefined}
            aria-describedby={!canRevoke ? ownerOnlyId : undefined}
            onClick={() => openRevoke(row)}
            data-testid="signing-key-revoke"
          >
            {messages.signingKeysRevoke}
          </Button>
        ) : null,
    });
  }

  let body: ReactNode;
  if (list.kind === 'loading') {
    body = <SkeletonRows rows={4} caption={false} />;
  } else if (list.kind === 'failed') {
    body = (
      <Banner tone="bad" action={{ label: messages.retry, onClick: () => setAttempt((n) => n + 1) }} data-testid="signing-keys-load-failed">
        <p>{messages.loadFailed}</p>
        <ErrorReference code={list.failure.code} traceId={list.failure.traceId} />
      </Banner>
    );
  } else {
    let sample: ReactNode;
    if (jwks.kind === 'loading') {
      sample = <SkeletonRows rows={1} columns={1} caption={false} />;
    } else if (jwks.kind === 'failed') {
      sample = (
        <Banner
          tone="bad"
          live={false}
          action={{ label: messages.retry, onClick: () => setJwksAttempt((n) => n + 1) }}
          data-testid="signing-keys-jwks-failed"
        >
          <p>{messages.signingKeysJwksFailed}</p>
          <ErrorReference code={jwks.failure.code} traceId={jwks.failure.traceId} />
        </Banner>
      );
    } else {
      sample = (
        <div data-testid="signing-keys-jwks">
          {/* The whole public key set, every modulus in full, so Copy gives a usable JWKS. */}
          <CodeBlock
            filename={formatMessage(messages.signingKeysJwksTitle, { uri: jwks.sample.jwksUri })}
            code={JSON.stringify({ keys: jwks.sample.keys }, null, 2)}
          />
        </div>
      );
    }

    body = (
      <div className={styles.content} data-testid="signing-keys">
        {refusal?.kind === 'notReady' && (
          <Banner tone="warn" data-testid="signing-keys-rotate-not-ready">
            <p>{formatMessage(messages.signingKeysRotateNotReady, { minutes: refusal.minutes })}</p>
            <ErrorReference code={refusal.failure.code} traceId={refusal.failure.traceId} />
          </Banner>
        )}
        {refusal?.kind === 'failed' && (
          <Banner tone="bad" data-testid="signing-keys-rotate-failed">
            <p>{messages.signingKeysRotateFailed}</p>
            <ErrorReference code={refusal.failure.code} traceId={refusal.failure.traceId} />
          </Banner>
        )}
        {refusal?.kind === 'forbidden' && (
          <Banner tone="bad" data-testid="signing-keys-rotate-forbidden">
            {messages.actionForbidden}
          </Banner>
        )}
        <DataTable
          caption={messages.signingKeysTitle}
          hideCaption
          columns={columns}
          rows={list.keys}
          rowKey={(row) => row.keyId}
          // A Tenant has a handful of keys: every one on one page.
          pageSize={Math.max(list.keys.length, 1)}
        />
        {sample}
      </div>
    );
  }

  // A Viewer, who manages nothing in the Tenant, gets no action at all; anyone else sees Rotate, off without the capability.
  const actions = viewOnly ? undefined : (
    <div className={styles.rotate}>
      <Button
        variant="primary"
        pending={rotating}
        aria-disabled={!canRotate || !listed || undefined}
        aria-describedby={!canRotate ? ownerOnlyId : undefined}
        onClick={() => void rotate()}
        data-testid="signing-keys-rotate"
      >
        {messages.signingKeysRotate}
      </Button>
      {/* It describes the read-only Rotate and every read-only Revoke alike. */}
      {(!canRotate || !canRevoke) && (
        <p id={ownerOnlyId} className={styles.note} data-testid="signing-keys-owner-only">
          {messages.tenantOwnerOnly}
        </p>
      )}
    </div>
  );

  const revokeReauthentication =
    revokeSlot.kind === 'prompt' ? (
      <p data-testid="fresh-assertion-prompt">{messages.freshAssertionPrompt}</p>
    ) : revokeSlot.kind === 'failed' ? (
      <Banner tone="bad" data-testid="revoke-signing-key-failed">
        {revokeSlot.reference ? (
          <>
            <p>{revokeSlot.text}</p>
            <ErrorReference code={revokeSlot.reference.code} traceId={revokeSlot.reference.traceId} />
          </>
        ) : (
          revokeSlot.text
        )}
      </Banner>
    ) : null;

  return (
    <SectionPage
      title={messages.signingKeysTitle}
      description={messages.signingKeysDescription}
      actions={actions}
      data-testid="signing-keys-page"
    >
      {viewOnly && (
        <div className={styles.viewOnly}>
          <Banner tone="info" live={false} data-testid="tenant-view-only">
            {messages.tenantViewOnly}
          </Banner>
        </div>
      )}
      {body}
      <ConfirmModal
        open={revoking !== null}
        onCancel={closeRevoke}
        onConfirm={() => void revoke()}
        tone="destructive"
        title={messages.signingKeysRevokeTitle}
        confirmLabel={messages.signingKeysRevokeConfirm}
        pending={revokePending}
        reauthentication={revokeReauthentication}
        fallbackFocus={() =>
          (focusAfter.current ? document.querySelector<HTMLElement>(`[data-key-id="${CSS.escape(focusAfter.current)}"]`) : null) ??
          document.querySelector<HTMLElement>('main h1')
        }
        data-testid="revoke-signing-key"
      >
        <p>{fillNodes(messages.signingKeysRevokeKey, { keyId: <code data-testid="revoke-signing-key-id">{revoking?.keyId}</code> })}</p>
        <p>{messages.signingKeysRevokeImpact}</p>
        {revoking?.state === 'current' && <p data-testid="revoke-signing-key-current">{messages.signingKeysRevokeCurrent}</p>}
        <Checkbox
          label={messages.signingKeysRevokeAccess}
          checked={revokeAccess}
          disabled={revokePending}
          onChange={(event) => setRevokeAccess(event.currentTarget.checked)}
          data-testid="revoke-signing-key-access"
        />
      </ConfirmModal>
    </SectionPage>
  );
}
