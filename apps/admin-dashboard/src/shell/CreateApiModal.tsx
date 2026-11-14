import type { ApiResourceDetail } from '@gatekeep/api-client';
import { Banner, Button, ErrorReference, Field, Input, Modal, useMessages } from '@gatekeep/ui/admin';
import { useRef, useState, type FormEvent } from 'react';
import { api } from '../session';
import { checkApiIdentifier, checkApiName } from './apis';
import type { ShellRequest } from './CredentialsPage';
import styles from './ApplicationsPage.module.css';

type Refusal = { kind: 'saveFailed'; code: string; traceId: string } | { kind: 'forbidden' } | { kind: 'signedInAgain' } | null;

export interface CreateApiModalProps {
  open: boolean;
  request: ShellRequest;
  /** The path Tenant: the create names this one. */
  tenantId: string;
  onClose: () => void;
  /** The 201's API: the modal has closed, and the caller opens its page. */
  onCreated: (created: ApiResourceDetail) => void;
}

/**
 * Create API (Story 3.6; EXPERIENCE.md, APIs): a name and an identifier, with the advice under the identifier to use a
 * different one in each environment, since it can't be changed later. The browser checks both first, as feedback only;
 * the server decides, and its field errors and a taken identifier show inline. A 401 is the shell's renewal, which keeps
 * everything typed and never sends the create again.
 */
export function CreateApiModal({ open, request, tenantId, onClose, onCreated }: CreateApiModalProps) {
  const messages = useMessages();
  const [name, setName] = useState('');
  const [identifier, setIdentifier] = useState('');
  const [nameError, setNameError] = useState<string | null>(null);
  const [identifierError, setIdentifierError] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<Refusal>(null);
  const [pending, setPending] = useState(false);
  const nameInput = useRef<HTMLInputElement>(null);
  const identifierInput = useRef<HTMLInputElement>(null);
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);

  function reset() {
    setName('');
    setIdentifier('');
    setNameError(null);
    setIdentifierError(null);
    setRefusal(null);
  }

  function close() {
    if (pending) return;
    reset();
    onClose();
  }

  function identifierText(reason: string): string {
    switch (reason) {
      case 'empty':
        return messages.createApiIdentifierRequired;
      case 'reserved':
        return messages.createApiIdentifierReserved;
      case 'taken':
        return messages.createApiIdentifierTaken;
      default:
        return messages.createApiIdentifierInvalid;
    }
  }

  async function submit(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    if (inFlight.current) return;
    const checkedName = checkApiName(name);
    const checkedIdentifier = checkApiIdentifier(identifier);
    const nameText =
      checkedName.kind === 'ok' ? null : checkedName.kind === 'empty' ? messages.createApiNameRequired : messages.createApiNameInvalid;
    const identifierProblem = checkedIdentifier.kind === 'ok' ? null : identifierText(checkedIdentifier.kind);
    if (nameText !== null || identifierProblem !== null || checkedName.kind !== 'ok') {
      setNameError(nameText);
      setIdentifierError(identifierProblem);
      (nameText !== null ? nameInput : identifierInput).current?.focus();
      return;
    }

    inFlight.current = true;
    setPending(true);
    setRefusal(null);
    let result;
    try {
      result = await request('post', () => api.createApi(tenantId, { name: checkedName.name, identifier }));
    } catch {
      result = null;
    }
    inFlight.current = false;
    setPending(false);

    if (result?.ok && result.status === 201 && result.data && typeof result.data.api?.id === 'string') {
      reset();
      onCreated(result.data);
      return;
    }
    if (result === null) {
      setRefusal({ kind: 'saveFailed', code: 'unavailable', traceId: '' });
      return;
    }
    if (result.status === 401) {
      // The renewal brought the Admin back and didn't send it again: everything typed is kept.
      setRefusal({ kind: 'signedInAgain' });
      return;
    }
    const problem = result.ok ? null : result.problem;
    if (result.status === 409 && problem?.code === 'tenant_mismatch') {
      // The shell's banner names both Tenants: nothing was created.
      close();
      return;
    }
    if (result.status === 409 && problem?.code === 'api_identifier_taken') {
      setIdentifierError(messages.createApiIdentifierTaken);
      identifierInput.current?.focus();
      return;
    }
    if (result.status === 400 && problem?.code === 'api_invalid' && problem.errors && problem.errors.length > 0) {
      const nameRefused = problem.errors.find((e) => e.field === 'name');
      const identifierRefused = problem.errors.find((e) => e.field === 'identifier');
      setNameError(nameRefused ? messages.createApiNameInvalid : null);
      setIdentifierError(identifierRefused ? identifierText(identifierRefused.reason) : null);
      (nameRefused ? nameInput : identifierInput).current?.focus();
      return;
    }
    if (result.status === 403) {
      setRefusal({ kind: 'forbidden' });
      return;
    }
    setRefusal({ kind: 'saveFailed', code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' });
  }

  return (
    <Modal
      open={open}
      onClose={close}
      dismissible={!pending}
      title={messages.createApiTitle}
      initialFocus={() => nameInput.current}
      fallbackFocus={() => document.querySelector<HTMLElement>('main h1')}
      data-testid="create-api"
      footer={
        <>
          <Button aria-disabled={pending || undefined} onClick={close}>
            {messages.cancel}
          </Button>
          <Button variant="primary" pending={pending} onClick={() => void submit()} data-testid="create-api-submit">
            {messages.createApiSubmit}
          </Button>
        </>
      }
    >
      <form className={styles.form} noValidate onSubmit={(event) => void submit(event)}>
        {refusal?.kind === 'saveFailed' && (
          <Banner tone="bad" data-testid="create-api-failed">
            <p>{messages.createApiFailed}</p>
            <ErrorReference code={refusal.code} traceId={refusal.traceId} />
          </Banner>
        )}
        {refusal?.kind === 'signedInAgain' && (
          <Banner tone="bad" data-testid="create-api-signed-in-again">
            {messages.actionRetryAfterSignIn}
          </Banner>
        )}
        {refusal?.kind === 'forbidden' && (
          <Banner tone="bad" data-testid="create-api-forbidden">
            {messages.actionForbidden}
          </Banner>
        )}
        <Field label={messages.createApiName} error={nameError}>
          <Input
            ref={nameInput}
            name="name"
            value={name}
            autoComplete="off"
            readOnly={pending}
            onChange={(event) => {
              setName(event.currentTarget.value);
              setNameError(null);
            }}
            data-testid="create-api-name"
          />
        </Field>
        <Field label={messages.createApiIdentifier} helper={messages.createApiIdentifierAdvice} error={identifierError}>
          <Input
            ref={identifierInput}
            name="identifier"
            value={identifier}
            code
            autoComplete="off"
            spellCheck={false}
            placeholder="https://api.example.com"
            readOnly={pending}
            onChange={(event) => {
              setIdentifier(event.currentTarget.value);
              setIdentifierError(null);
            }}
            data-testid="create-api-identifier"
          />
        </Field>
        {/* Enter in either field submits, through the same guard as the button. */}
        <button type="submit" hidden aria-hidden tabIndex={-1} />
      </form>
    </Modal>
  );
}
