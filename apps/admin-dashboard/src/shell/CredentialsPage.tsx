import type { AdminCredentialResponse, AdminCredentialsResponse } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  ConfirmModal,
  DataTable,
  ProtocolBadge,
  SectionPage,
  SkeletonRows,
  formatMessage,
  useMessages,
  useToast,
  type DataTableColumn,
} from '@gatekeep/ui/admin';
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { api, setCsrfToken } from '../session';
import { creationOptions, isAlreadyRegistered, isCancelled, registrationRequest } from '../webauthn';
import { needsFreshAssertion, type Confirmation, type FreshAssertion } from './freshAssertion';
import type { Method } from './renewal';

/** The most credentials an Admin may hold (Story 1.26): the server refuses an 11th, and Add waits for a removal. */
const MAX_CREDENTIALS = 10;

/** Sends one request through the shell's Session renewal (renewal.ts). */
export type ShellRequest = <R extends { status: number }>(method: Method, call: () => Promise<R>, signal?: AbortSignal) => Promise<R>;

type Messages = ReturnType<typeof useMessages>;

type Load = { kind: 'loading' } | { kind: 'ready'; list: AdminCredentialsResponse } | { kind: 'failed' };

/** What a confirming modal's re-authentication slot shows (UX-DR17): nothing, the sheet's prompt, or a failure. */
type Slot = { kind: 'none' } | { kind: 'prompt' } | { kind: 'failed'; text: string };

/** The text a confirmation that didn't pass shows in the modal: never why the server refused. */
function confirmationText(confirmation: Exclude<Confirmation, { kind: 'confirmed' }>, messages: Messages): string {
  switch (confirmation.kind) {
    case 'refused':
      return messages.signInRefused;
    case 'cancelled':
      return messages.freshAssertionCancelled;
    case 'rateLimited':
      return confirmation.seconds === null
        ? messages.tooManyAttemptsNoTime
        : formatMessage(messages.tooManyAttempts, { seconds: confirmation.seconds });
    default:
      return messages.freshAssertionUnavailable;
  }
}

const DATE = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** An absolute date and time, in the browser's own time zone and locale. */
function when(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : DATE.format(date);
}

function SlotView({ slot, messages, children }: { slot: Slot; messages: Messages; children?: ReactNode }) {
  return (
    <>
      {slot.kind === 'prompt' && <p data-testid="fresh-assertion-prompt">{messages.freshAssertionPrompt}</p>}
      {slot.kind === 'failed' && (
        <Banner tone="bad" data-testid="fresh-assertion-failed">
          {slot.text}
        </Banner>
      )}
      {children}
    </>
  );
}

/**
 * Your credentials (EXPERIENCE.md; Story 1.26): the Admin's own passkeys and security keys, with
 * Add and Remove. The server says which may be removed and whether an action needs a fresh
 * assertion: Remove sends the DELETE and confirms only on its 403 fresh_assertion_required, inside
 * the same destructive modal, then sends it once more. Add confirms first, as its first request
 * would start a registration, then registers from its own button, a fresh user activation for the
 * second sheet. No second modal ever opens.
 */
export function CredentialsPage({ request, fresh }: { request: ShellRequest; fresh: FreshAssertion }) {
  const messages = useMessages();
  const toast = useToast();
  const [load, setLoad] = useState<Load>({ kind: 'loading' });

  const [removing, setRemoving] = useState<AdminCredentialResponse | null>(null);
  const [removeSlot, setRemoveSlot] = useState<Slot>({ kind: 'none' });
  const [removePending, setRemovePending] = useState(false);
  // Where focus goes once the removed row is gone: the next row's Remove, or the heading.
  const focusAfter = useRef<string | null>(null);

  const [adding, setAdding] = useState(false);
  const [addStep, setAddStep] = useState<'confirm' | 'register'>('confirm');
  const [addSlot, setAddSlot] = useState<Slot>({ kind: 'none' });
  const [addPending, setAddPending] = useState(false);
  // Set at once, before React re-renders, so a second click starts no second ceremony.
  const inFlight = useRef(false);

  const read = useCallback(async () => {
    try {
      const result = await request('get', () => api.listCredentials());
      const list = result.ok ? result.data : undefined;
      if (list && Array.isArray(list.credentials)) {
        setLoad({ kind: 'ready', list });
        return list;
      }
    } catch {
      // A lost connection is the failure below.
    }
    setLoad({ kind: 'failed' });
    return null;
  }, [request]);

  useEffect(() => {
    void read();
  }, [read]);

  function closeRemove() {
    if (removePending) return;
    setRemoving(null);
    setRemoveSlot({ kind: 'none' });
  }

  async function remove() {
    if (!removing || inFlight.current) return;
    inFlight.current = true;
    const id = removing.id;
    setRemovePending(true);
    setRemoveSlot({ kind: 'prompt' });
    const done = () => {
      inFlight.current = false;
      setRemovePending(false);
    };

    let outcome;
    try {
      outcome = await fresh.withFreshAssertion({ action: 'self.credentials.remove', target: id }, () =>
        request('delete', () => api.removeCredential(id)),
      );
    } catch {
      outcome = null;
    }

    if (outcome?.kind === 'unconfirmed') {
      done();
      setRemoveSlot({ kind: 'failed', text: confirmationText(outcome.confirmation, messages) });
      return;
    }

    const answer = outcome?.answer;
    // The credential that confirmed this removal was the one removed: this Session ended with it.
    if (answer?.ok && answer.status === 200 && (answer.data as { sessionEnded?: unknown } | undefined)?.sessionEnded === true) {
      setCsrfToken(null);
      window.location.replace('/signin');
      return;
    }

    if (answer?.status === 204 || answer?.status === 404) {
      if (answer.status === 204 && load.kind === 'ready') {
        const rows = load.list.credentials;
        const index = rows.findIndex((row) => row.id === id);
        focusAfter.current = rows[index + 1]?.id ?? null;
      } else {
        focusAfter.current = null;
      }

      await read();
      done();
      setRemoving(null);
      setRemoveSlot({ kind: 'none' });
      if (answer.status === 204) toast(messages.credentialsRemoved);
      return;
    }

    done();
    const minimum = answer && !answer.ok && answer.status === 409 && answer.problem?.code === 'credentials_minimum';
    // A 401 after the renewal brought the Admin back: it wasn't sent again, so nothing changed.
    const renewed = answer?.status === 401;
    // Any other 403 is the server refusing this Session the action outright.
    const forbidden = answer?.status === 403;
    setRemoveSlot({
      kind: 'failed',
      text: minimum
        ? messages.credentialsMinimum
        : renewed
          ? messages.actionRetryAfterSignIn
          : forbidden
            ? messages.actionForbidden
            : messages.freshAssertionUnavailable,
    });
  }

  function openAdd() {
    setAdding(true);
    setAddStep('confirm');
    setAddSlot({ kind: 'none' });
  }

  function closeAdd() {
    if (addPending) return;
    setAdding(false);
    setAddStep('confirm');
    setAddSlot({ kind: 'none' });
  }

  async function confirmAdd() {
    if (addStep === 'register') {
      await register();
      return;
    }
    if (inFlight.current) return;
    inFlight.current = true;
    setAddPending(true);
    setAddSlot({ kind: 'prompt' });
    const confirmation = await fresh.confirmItsYou({ action: 'self.credentials.add' });
    inFlight.current = false;
    setAddPending(false);
    if (confirmation.kind === 'confirmed') {
      setAddStep('register');
      setAddSlot({ kind: 'none' });
    } else {
      setAddSlot({ kind: 'failed', text: confirmationText(confirmation, messages) });
    }
  }

  async function register() {
    if (inFlight.current) return;
    inFlight.current = true;
    setAddPending(true);
    const stop = (slot: Slot, step: 'confirm' | 'register' = 'register') => {
      inFlight.current = false;
      setAddPending(false);
      setAddStep(step);
      setAddSlot(slot);
    };
    const unavailable: Slot = { kind: 'failed', text: messages.freshAssertionUnavailable };

    try {
      const begin = await request('post', () => api.beginCredentialRegistration());
      if (!begin.ok || !begin.data) {
        if (needsFreshAssertion(begin.ok ? null : begin)) {
          // The confirmation expired or was used: back to the first step, to confirm again.
          stop({ kind: 'failed', text: messages.freshAssertionCancelled }, 'confirm');
        } else if (!begin.ok && begin.status === 409 && begin.problem?.code === 'credentials_maximum') {
          stop({ kind: 'failed', text: messages.credentialsMaximum });
        } else {
          stop(unavailable);
        }
        return;
      }

      let credential: Credential | null;
      try {
        credential = await navigator.credentials.create({ publicKey: creationOptions(begin.data) });
      } catch (error) {
        // Cancelled: the confirmation was used by the begin, so it goes back to confirming.
        if (isCancelled(error)) stop({ kind: 'failed', text: messages.freshAssertionCancelled }, 'confirm');
        else if (isAlreadyRegistered(error)) stop({ kind: 'failed', text: messages.credentialSetupAlreadyRegistered });
        else stop(unavailable);
        return;
      }

      if (!(credential instanceof PublicKeyCredential)) {
        stop(unavailable);
        return;
      }

      const complete = await request('post', () => api.completeCredentialRegistration(registrationRequest(credential)));
      if (!complete.ok) {
        stop(!complete.ok && complete.status === 409 ? { kind: 'failed', text: messages.credentialsMaximum } : unavailable);
        return;
      }

      await read();
      inFlight.current = false;
      setAddPending(false);
      setAdding(false);
      setAddStep('confirm');
      setAddSlot({ kind: 'none' });
      toast(messages.credentialsAdded);
    } catch {
      stop(unavailable);
    }
  }

  const credentialName = (row: AdminCredentialResponse) => (row.kind === 'passkey' ? messages.credentialPasskey : messages.credentialSecurityKey);

  const rows = load.kind === 'ready' ? load.list.credentials : [];
  const anyRemovable = rows.some((row) => row.removable === true);
  const columns: DataTableColumn<AdminCredentialResponse>[] = [
    {
      key: 'credential',
      header: messages.credentialsColumnCredential,
      rowHeader: true,
      cell: (row) => (
        <>
          {credentialName(row)}
          {row.backedUp ? (
            <>
              {' '}
              <ProtocolBadge>{messages.credentialSynced}</ProtocolBadge>
            </>
          ) : null}
        </>
      ),
    },
    { key: 'added', header: messages.credentialsColumnAdded, cell: (row) => when(row.createdAt) },
    { key: 'used', header: messages.credentialsColumnLastUsed, cell: (row) => (row.lastUsedAt ? when(row.lastUsedAt) : messages.credentialNeverUsed) },
  ];
  if (anyRemovable) {
    columns.push({
      key: 'remove',
      header: messages.credentialsRemove,
      cell: (row) =>
        row.removable ? (
          <Button
            variant="destructive"
            size="sm"
            data-credential={row.id}
            aria-label={formatMessage(messages.credentialsRemoveNamed, { credential: credentialName(row), added: when(row.createdAt) })}
            onClick={() => {
              setRemoving(row);
              setRemoveSlot({ kind: 'none' });
            }}
          >
            {messages.credentialsRemove}
          </Button>
        ) : null,
    });
  }

  let body: ReactNode;
  if (load.kind === 'loading') {
    body = <SkeletonRows rows={2} caption={false} />;
  } else if (load.kind === 'failed') {
    body = (
      <Banner tone="bad" action={{ label: messages.retry, onClick: () => void read() }} data-testid="credentials-failed">
        {messages.loadFailed}
      </Banner>
    );
  } else {
    body = (
      <div data-testid="credentials">
        <DataTable caption={messages.credentialsTitle} hideCaption columns={columns} rows={rows} rowKey={(row) => row.id} />
        {!anyRemovable && <p data-testid="credentials-floor">{messages.credentialsFloor}</p>}
        {load.list.recoveryCode && <p data-testid="credentials-recovery-code">{messages.credentialsRecoveryCode}</p>}
      </div>
    );
  }

  return (
    <SectionPage
      eyebrow={messages.account}
      title={messages.credentialsTitle}
      description={messages.credentialsDescription}
      actions={
        <Button
          variant="primary"
          onClick={openAdd}
          // The server's count: at the maximum, an add would only be refused.
          disabled={load.kind === 'ready' && rows.length >= MAX_CREDENTIALS}
          data-testid="credentials-add"
        >
          {messages.credentialsAdd}
        </Button>
      }
      data-testid="credentials-page"
    >
      {body}
      <ConfirmModal
        open={removing !== null}
        onCancel={closeRemove}
        onConfirm={() => void remove()}
        tone="destructive"
        title={messages.credentialsRemoveTitle}
        confirmLabel={messages.credentialsRemoveConfirm}
        pending={removePending}
        reauthentication={removeSlot.kind === 'none' ? null : <SlotView slot={removeSlot} messages={messages} />}
        fallbackFocus={() =>
          (focusAfter.current ? document.querySelector<HTMLElement>(`[data-credential="${CSS.escape(focusAfter.current)}"]`) : null) ??
          document.querySelector<HTMLElement>('main h1')
        }
        data-testid="remove-credential"
      >
        <p>{messages.credentialsRemoveBody}</p>
      </ConfirmModal>
      <ConfirmModal
        open={adding}
        onCancel={closeAdd}
        onConfirm={() => void confirmAdd()}
        title={messages.credentialsAddTitle}
        confirmLabel={messages.continue}
        pending={addPending}
        reauthentication={
          addStep === 'register' ? (
            <SlotView slot={addSlot} messages={messages}>
              <p data-testid="add-credential-register">{messages.credentialsAddRegister}</p>
              <Button type="button" variant="secondary" pending={addPending} onClick={() => void register()} data-testid="add-credential-register-button">
                {messages.credentialSetupRegister}
              </Button>
            </SlotView>
          ) : addSlot.kind === 'none' ? null : (
            <SlotView slot={addSlot} messages={messages} />
          )
        }
        data-testid="add-credential"
      >
        <p>{messages.credentialsAddBody}</p>
      </ConfirmModal>
    </SectionPage>
  );
}
