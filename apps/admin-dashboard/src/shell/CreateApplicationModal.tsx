import type { ApplicationResponse } from '@gatekeep/api-client';
import { Banner, Button, ErrorReference, Field, Input, Modal, Radio, RadioGroup, useMessages } from '@gatekeep/ui/admin';
import { useRef, useState, type FormEvent } from 'react';
import { api } from '../session';
import { APPLICATION_KINDS, checkApplicationName, type ApplicationKind } from './applications';
import type { ShellRequest } from './CredentialsPage';
import styles from './ApplicationsPage.module.css';

type Messages = ReturnType<typeof useMessages>;

/** Each type's name and its line, which says whether it needs a credential. */
export function kindText(kind: string, messages: Messages): { name: string; description: string } {
  switch (kind) {
    case 'spa':
      return { name: messages.applicationTypeSpa, description: messages.applicationTypeSpaDescription };
    case 'web':
      return { name: messages.applicationTypeWeb, description: messages.applicationTypeWebDescription };
    case 'native':
      return { name: messages.applicationTypeNative, description: messages.applicationTypeNativeDescription };
    case 'machine':
      return { name: messages.applicationTypeMachine, description: messages.applicationTypeMachineDescription };
    default:
      return { name: kind, description: '' };
  }
}

type Refusal =
  | { kind: 'saveFailed'; code: string; traceId: string }
  | { kind: 'invalid' }
  | { kind: 'forbidden' }
  | { kind: 'signedInAgain' }
  | null;

export interface CreateApplicationModalProps {
  open: boolean;
  request: ShellRequest;
  /** The path Tenant: the create names this one. */
  tenantId: string;
  onClose: () => void;
  /** The 201's Application: the modal has closed, and the caller opens its page. */
  onCreated: (application: ApplicationResponse) => void;
}

/**
 * Create Application (Story 3.1; EXPERIENCE.md, Create Application): a name and a type, each
 * type's line saying whether it needs a credential. No secret is created here: a regular web or
 * machine-to-machine Application gets one from a Tenant Owner (Story 3.3). When the creator is one,
 * the Applications page opens its Credentials tab, which creates the first secret through the
 * fresh-assertion sheet and shows it once; an Editor's opens on Settings, with no secret. The browser checks the
 * name first, as feedback only; the server decides. A 401 is the shell's renewal, which keeps
 * everything typed and never sends the create again.
 */
export function CreateApplicationModal({ open, request, tenantId, onClose, onCreated }: CreateApplicationModalProps) {
  const messages = useMessages();
  const [name, setName] = useState('');
  const [kind, setKind] = useState<ApplicationKind>('spa');
  const [nameError, setNameError] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<Refusal>(null);
  const [pending, setPending] = useState(false);
  const nameInput = useRef<HTMLInputElement>(null);
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);

  function reset() {
    setName('');
    setKind('spa');
    setNameError(null);
    setRefusal(null);
  }

  function close() {
    if (pending) return;
    reset();
    onClose();
  }

  async function submit(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    if (inFlight.current) return;
    const checked = checkApplicationName(name);
    if (checked.kind !== 'ok') {
      setNameError(checked.kind === 'empty' ? messages.createApplicationNameRequired : messages.createApplicationNameInvalid);
      nameInput.current?.focus();
      return;
    }

    inFlight.current = true;
    setPending(true);
    setRefusal(null);
    let result;
    try {
      result = await request('post', () => api.createApplication(tenantId, { name: checked.name, type: kind }));
    } catch {
      result = null;
    }
    inFlight.current = false;
    setPending(false);

    if (result?.ok && result.status === 201 && result.data && typeof result.data.id === 'string') {
      reset();
      onCreated(result.data);
      return;
    }
    if (result === null) {
      setRefusal({ kind: 'saveFailed', code: 'unavailable', traceId: '' });
    } else if (result.status === 401) {
      // The renewal brought the Admin back and didn't send it again: everything typed is kept.
      setRefusal({ kind: 'signedInAgain' });
    } else if (!result.ok && result.status === 409 && result.problem?.code === 'tenant_mismatch') {
      // The shell's banner names both Tenants: nothing was created.
      close();
    } else if (!result.ok && result.status === 400 && result.problem?.code === 'application_invalid') {
      setRefusal({ kind: 'invalid' });
    } else if (result.status === 403) {
      setRefusal({ kind: 'forbidden' });
    } else {
      const problem = result.ok ? null : result.problem;
      setRefusal({ kind: 'saveFailed', code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' });
    }
  }

  return (
    <Modal
      open={open}
      onClose={close}
      dismissible={!pending}
      title={messages.createApplicationTitle}
      initialFocus={() => nameInput.current}
      fallbackFocus={() => document.querySelector<HTMLElement>('main h1')}
      data-testid="create-application"
      footer={
        <>
          <Button aria-disabled={pending || undefined} onClick={close}>
            {messages.cancel}
          </Button>
          <Button variant="primary" pending={pending} onClick={() => void submit()} data-testid="create-application-submit">
            {messages.createApplicationSubmit}
          </Button>
        </>
      }
    >
      <form className={styles.form} noValidate onSubmit={(event) => void submit(event)}>
        {refusal?.kind === 'saveFailed' && (
          <Banner tone="bad" data-testid="create-application-failed">
            <p>{messages.createApplicationFailed}</p>
            <ErrorReference code={refusal.code} traceId={refusal.traceId} />
          </Banner>
        )}
        {refusal?.kind === 'invalid' && (
          <Banner tone="bad" data-testid="create-application-invalid">
            {messages.createApplicationInvalid}
          </Banner>
        )}
        {refusal?.kind === 'signedInAgain' && (
          <Banner tone="bad" data-testid="create-application-signed-in-again">
            {messages.actionRetryAfterSignIn}
          </Banner>
        )}
        {refusal?.kind === 'forbidden' && (
          <Banner tone="bad" data-testid="create-application-forbidden">
            {messages.actionForbidden}
          </Banner>
        )}
        <Field label={messages.createApplicationName} error={nameError}>
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
          />
        </Field>
        <RadioGroup legend={messages.createApplicationType} value={kind} onChange={(value) => !pending && setKind(value as ApplicationKind)}>
          {APPLICATION_KINDS.map((option) => {
            const text = kindText(option, messages);
            return (
              <Radio
                key={option}
                value={option}
                disabled={pending}
                data-testid={`create-application-type-${option}`}
                label={
                  <span className={styles.option}>
                    <span className={styles.optionName}>{text.name}</span>
                    <span className={styles.optionDescription}>{text.description}</span>
                  </span>
                }
              />
            );
          })}
        </RadioGroup>
        {/* The name is the form's one text field, so Enter in it submits, through the same guard as the button. */}
      </form>
    </Modal>
  );
}
