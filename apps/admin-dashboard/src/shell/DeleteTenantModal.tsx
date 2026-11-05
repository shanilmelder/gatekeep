import type { ApiResult, OperationResponse, TenantResponse } from '@gatekeep/api-client';
import { Banner, ConfirmModal, ErrorReference, formatMessage, useMessages } from '@gatekeep/ui/admin';
import { Fragment, useRef, useState, type ReactNode } from 'react';
import { api } from '../session';
import type { ShellRequest } from './CredentialsPage';
import type { Confirmation, FreshAssertion } from './freshAssertion';

type Messages = ReturnType<typeof useMessages>;

/** What the modal is for: deleting a Tenant, or retrying its failed deletion. */
export type DeletionAction = { mode: 'delete' | 'retry'; tenant: TenantResponse };

/**
 * How a sent action ended, once the modal has closed: `started` and `retried` ran it; `gone` means
 * the Tenant is already being deleted, or deleted; `notFailed` means its deletion isn't failed any
 * more. The page reads its list again for each.
 */
export type DeletionOutcome = 'started' | 'retried' | 'gone' | 'notFailed';

/** What the re-authentication slot shows: nothing, the sheet's prompt, or a failure, with its reference when it has one. */
type Slot =
  | { kind: 'none' }
  | { kind: 'prompt' }
  | { kind: 'failed'; text: string; reference?: { code: string; traceId: string } };

/** The text a confirmation that didn't pass shows in the modal, as Your credentials shows it. */
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

/** A catalogue template with each placeholder filled by a node, such as a name in <bdi> or a host in code type. */
export function fillNodes(template: string, values: Readonly<Record<string, ReactNode>>): ReactNode[] {
  return template.split(/(\{\w+\})/).map((part, index) => {
    const name = /^\{(\w+)\}$/.exec(part)?.[1];
    return name !== undefined && Object.hasOwn(values, name) ? <Fragment key={index}>{values[name]}</Fragment> : part;
  });
}

export interface DeleteTenantModalProps {
  /** The action and its Tenant, or null when the modal is closed. */
  action: DeletionAction | null;
  request: ShellRequest;
  fresh: FreshAssertion;
  /** Cancel or Esc, with nothing sent or after a failure shown here. */
  onClose: () => void;
  /** The action was answered for good: the modal closes, and the page reads its list again. */
  onDone: (outcome: DeletionOutcome) => void;
}

/**
 * Delete Tenant and Retry deletion (Story 1.29; EXPERIENCE.md, Typed confirmation and the
 * Re-authentication gate). Delete is destructive and needs the Tenant's stored host typed exactly,
 * as the Tenants list shows it; Retry has no typed field. Each sends its request, and only on the
 * server's 403 fresh_assertion_required confirms it's the Admin, bound to this Tenant's ID on the
 * Deployment begin, inside this same modal, then sends it once more. Every outcome but a final one
 * shows here, and the modal stays open; the server decides everything.
 */
export function DeleteTenantModal({ action, request, fresh, onClose, onDone }: DeleteTenantModalProps) {
  const messages = useMessages();
  const [slot, setSlot] = useState<Slot>({ kind: 'none' });
  const [pending, setPending] = useState(false);
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);
  // The action the slot is for: a new one opens with an empty slot.
  const [shownFor, setShownFor] = useState<DeletionAction | null>(null);
  if (shownFor !== action) {
    setShownFor(action);
    setSlot({ kind: 'none' });
  }

  const tenant = action?.tenant ?? null;
  const name = tenant ? <bdi>{tenant.name}</bdi> : null;

  function close() {
    if (pending) return;
    setSlot({ kind: 'none' });
    onClose();
  }

  async function confirm(typed: string) {
    if (!action || inFlight.current) return;
    inFlight.current = true;
    setPending(true);
    setSlot({ kind: 'prompt' });
    const { mode, tenant: row } = action;
    const send: () => Promise<ApiResult<OperationResponse>> =
      mode === 'delete'
        ? () => request('post', () => api.deleteTenant(row.id, { confirmation: typed }))
        : () => request('post', () => api.retryTenantDeletion(row.id));

    let outcome;
    try {
      // The Deployment begin: a Deployment action's binding names no Tenant, only its target.
      outcome = await fresh.withFreshAssertion({ action: 'deployment.tenants.delete', target: row.id }, send);
    } catch {
      outcome = null;
    }
    inFlight.current = false;
    setPending(false);

    if (outcome?.kind === 'unconfirmed') {
      setSlot({ kind: 'failed', text: confirmationText(outcome.confirmation, messages) });
      return;
    }

    const answer = outcome?.answer ?? null;
    const code = answer && !answer.ok ? answer.problem?.code : undefined;
    const done = (result: DeletionOutcome) => {
      setSlot({ kind: 'none' });
      onDone(result);
    };

    if (answer?.status === 202) return done(mode === 'delete' ? 'started' : 'retried');
    // Already being deleted, or gone: the list read next says where it stands.
    if (answer?.status === 404 || (answer?.status === 409 && code === 'tenant_deleted')) return done('gone');
    if (mode === 'retry' && answer?.status === 409 && code === 'operation_not_failed') return done('notFailed');

    if (answer?.status === 409 && code === 'tenant_busy') {
      setSlot({ kind: 'failed', text: messages.deleteTenantBusy });
      return;
    }
    if (answer?.status === 401) {
      // The renewal brought the Admin back and didn't send it again: nothing changed.
      setSlot({ kind: 'failed', text: messages.actionRetryAfterSignIn });
      return;
    }
    if (answer?.status === 403) {
      // access_denied, or the bodiless 403 of an earlier check: the server refuses this outright.
      setSlot({ kind: 'failed', text: messages.actionForbidden });
      return;
    }
    const problem = answer && !answer.ok ? answer.problem : null;
    setSlot({
      kind: 'failed',
      text: messages.deleteTenantFailed,
      reference: { code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' },
    });
  }

  const reauthentication =
    slot.kind === 'prompt' ? (
      <p data-testid="fresh-assertion-prompt">{messages.freshAssertionPrompt}</p>
    ) : slot.kind === 'failed' ? (
      <Banner tone="bad" data-testid="delete-tenant-failed">
        {slot.reference ? (
          <>
            <p>{slot.text}</p>
            <ErrorReference code={slot.reference.code} traceId={slot.reference.traceId} />
          </>
        ) : (
          slot.text
        )}
      </Banner>
    ) : null;

  const deleting = action?.mode !== 'retry';
  return (
    <ConfirmModal
      open={action !== null}
      onCancel={close}
      onConfirm={(typed) => void confirm(typed)}
      tone={deleting ? 'destructive' : 'default'}
      title={fillNodes(deleting ? messages.deleteTenantTitle : messages.retryDeletionTitle, { name })}
      confirmLabel={deleting ? messages.deleteTenantConfirm : messages.retryDeletionConfirm}
      confirmText={deleting ? tenant?.host : undefined}
      confirmTextLabel={messages.deleteTenantConfirmLabel}
      pending={pending}
      reauthentication={reauthentication}
      fallbackFocus={() => document.querySelector<HTMLElement>('main h1')}
      data-testid={deleting ? 'delete-tenant' : 'retry-deletion'}
    >
      <p>{deleting ? fillNodes(messages.deleteTenantBody, { host: <code>{tenant?.host}</code> }) : messages.retryDeletionBody}</p>
    </ConfirmModal>
  );
}
