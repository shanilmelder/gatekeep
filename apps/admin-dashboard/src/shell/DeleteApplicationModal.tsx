import type { ApplicationResponse } from '@gatekeep/api-client';
import { Banner, ConfirmModal, ErrorReference, useMessages } from '@gatekeep/ui/admin';
import { useRef, useState } from 'react';
import { api } from '../session';
import type { ShellRequest } from './CredentialsPage';
import { fillNodes } from './DeleteTenantModal';

/** What the failure slot shows: nothing, or a failure, with its reference when it has one. */
type Slot = { kind: 'none' } | { kind: 'failed'; text: string; reference?: { code: string; traceId: string } };

export interface DeleteApplicationModalProps {
  /** The Application to delete, or null when the modal is closed. */
  application: ApplicationResponse | null;
  request: ShellRequest;
  /** The path Tenant the Application is in. */
  tenantId: string;
  /** Cancel or Esc, with nothing sent or after a failure shown here. */
  onClose: () => void;
  /** The server deleted it: the page leaves for the list and says so. */
  onDeleted: () => void;
}

/**
 * Delete application (Story 3.5; EXPERIENCE.md, Destructive confirmation). Destructive, with no typed
 * confirmation and no fresh assertion: the body states the token effect, Cancel and Esc send nothing, and
 * Delete application sends the DELETE once. A 202, or a 404 for one already gone, closes it; every other refusal
 * shows here as a banner, and the modal stays open. The server decides everything.
 */
export function DeleteApplicationModal({ application, request, tenantId, onClose, onDeleted }: DeleteApplicationModalProps) {
  const messages = useMessages();
  const [slot, setSlot] = useState<Slot>({ kind: 'none' });
  const [pending, setPending] = useState(false);
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);
  // The Application the slot is for: a new opening starts with an empty slot.
  const [shownFor, setShownFor] = useState<ApplicationResponse | null>(null);
  if (shownFor !== application) {
    setShownFor(application);
    setSlot({ kind: 'none' });
  }

  function close() {
    if (pending) return;
    setSlot({ kind: 'none' });
    onClose();
  }

  async function confirm() {
    if (!application || inFlight.current) return;
    inFlight.current = true;
    setPending(true);
    setSlot({ kind: 'none' });

    let answer;
    try {
      answer = await request('delete', () => api.deleteApplication(tenantId, application.id));
    } catch {
      answer = null;
    }
    inFlight.current = false;
    setPending(false);

    // A 404 is an Application already deleted, by someone else or by an earlier answer that didn't arrive: done too.
    if (answer?.status === 202 || answer?.status === 404) {
      onDeleted();
      return;
    }
    const problem = answer && !answer.ok ? answer.problem : null;
    if (answer?.status === 409 && problem?.code === 'tenant_mismatch') {
      // The shell's banner names both Tenants: nothing else here.
      return;
    }
    if (answer?.status === 401) {
      // The renewal brought the Admin back and didn't send it again: nothing changed.
      setSlot({ kind: 'failed', text: messages.actionRetryAfterSignIn });
      return;
    }
    if (answer?.status === 403) {
      setSlot({ kind: 'failed', text: messages.actionForbidden });
      return;
    }
    setSlot({
      kind: 'failed',
      text: messages.deleteApplicationFailed,
      reference: { code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' },
    });
  }

  const failure =
    slot.kind === 'failed' ? (
      <Banner tone="bad" data-testid="delete-application-failed">
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

  return (
    <ConfirmModal
      open={application !== null}
      onCancel={close}
      onConfirm={() => void confirm()}
      tone="destructive"
      title={fillNodes(messages.deleteApplicationTitle, { name: application ? <bdi>{application.name}</bdi> : null })}
      confirmLabel={messages.deleteApplicationConfirm}
      pending={pending}
      reauthentication={failure}
      fallbackFocus={() => document.querySelector<HTMLElement>('main h1')}
      data-testid="delete-application"
    >
      <p>{messages.deleteApplicationBody}</p>
    </ConfirmModal>
  );
}
