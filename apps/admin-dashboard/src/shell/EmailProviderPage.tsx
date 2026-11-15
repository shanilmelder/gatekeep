import type { EmailProviderResponse, SetEmailProviderRequest } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  ConfirmModal,
  EmptyState,
  ErrorReference,
  Field,
  Input,
  PasswordField,
  Radio,
  RadioGroup,
  SectionPage,
  Select,
  SkeletonRows,
  useMessages,
  useToast,
} from '@gatekeep/ui/admin';
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { api } from '../session';
import { useCapabilities } from './capabilities';
import type { ShellRequest } from './CredentialsPage';
import {
  EMAIL_PROVIDER_KINDS,
  FROM_ADDRESS_MAX_LENGTH,
  FROM_NAME_MAX_LENGTH,
  KIND_FIELDS,
  SECRET_MAX_LENGTH,
  checkDraft,
  draftOf,
  isDirty,
  isKind,
  requestOf,
  serverErrors,
  usesSecret,
  withKind,
  type DraftErrors,
  type DraftField,
  type EmailProviderDraft,
  type EmailProviderKind,
  type SettingField,
  type SettingName,
} from './emailProvider';
import styles from './EmailProviderPage.module.css';
import { ForbiddenPage } from './ForbiddenPage';
import type { FreshAssertion } from './freshAssertion';
import { confirmationText } from './TenantSettingsPage';
import { useUnsavedChanges } from './unsavedChanges';

type Messages = ReturnType<typeof useMessages>;

type Failure = { code: string; traceId: string };

type Load =
  | { kind: 'loading' }
  | { kind: 'ready'; provider: EmailProviderResponse }
  | { kind: 'forbidden'; failure: Failure }
  | { kind: 'failed'; failure: Failure };

/** Why the last save or removal didn't happen, shown above the form. */
type Refusal =
  | { kind: 'saveFailed'; failure: Failure }
  | { kind: 'removeFailed'; failure: Failure }
  | { kind: 'forbidden' }
  | { kind: 'unconfirmed'; text: string }
  | null;

/** What the removal modal's re-authentication slot shows: nothing, the sheet's prompt, or a failure. */
type Slot = { kind: 'none' } | { kind: 'prompt' } | { kind: 'failed'; text: string };

/** A refusal's code and trace ID, as far as the answer carries them: a bodiless 503 has neither. */
function failureOf(result: { ok: boolean; problem?: { code?: string; traceId?: string } | null } | null): Failure {
  const problem = result && !result.ok ? result.problem : null;
  return { code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' };
}

/** A kind card's name and one line. */
function kindText(kind: EmailProviderKind, messages: Messages): { name: string; description: string } {
  switch (kind) {
    case 'smtp':
      return { name: messages.emailProviderKindSmtp, description: messages.emailProviderKindSmtpDescription };
    case 'sendgrid':
      return { name: messages.emailProviderKindSendgrid, description: messages.emailProviderKindSendgridDescription };
    case 'postmark':
      return { name: messages.emailProviderKindPostmark, description: messages.emailProviderKindPostmarkDescription };
    case 'mailgun':
      return { name: messages.emailProviderKindMailgun, description: messages.emailProviderKindMailgunDescription };
    case 'ses':
      return { name: messages.emailProviderKindSes, description: messages.emailProviderKindSesDescription };
    default:
      return { name: messages.emailProviderKindCustomHttp, description: messages.emailProviderKindCustomHttpDescription };
  }
}

/** The secret field's label: what the kind calls its one secret. */
function secretLabel(kind: EmailProviderKind, messages: Messages): string {
  switch (kind) {
    case 'smtp':
      return messages.emailProviderSecretSmtp;
    case 'postmark':
      return messages.emailProviderSecretServerToken;
    case 'ses':
      return messages.emailProviderSecretAccessKey;
    case 'custom_http':
      return messages.emailProviderSecretHeaderValue;
    default:
      return messages.emailProviderSecretApiKey;
  }
}

/** A setting's label and, where it has one, its helper. */
function settingText(name: SettingName, kind: EmailProviderKind, messages: Messages): { label: string; helper?: string } {
  switch (name) {
    case 'host':
      return { label: messages.emailProviderHost };
    case 'port':
      return { label: messages.emailProviderPort };
    case 'tls':
      return { label: messages.emailProviderTls };
    case 'username':
      return { label: messages.emailProviderUsername, helper: messages.emailProviderOptional };
    case 'region':
      return kind === 'ses' ? { label: messages.emailProviderRegion, helper: messages.emailProviderSesRegionHelper } : { label: messages.emailProviderRegion };
    case 'messageStream':
      return { label: messages.emailProviderMessageStream, helper: messages.emailProviderOptional };
    case 'domain':
      return { label: messages.emailProviderDomain };
    case 'accessKeyId':
      return { label: messages.emailProviderAccessKeyId };
    case 'endpoint':
      return { label: messages.emailProviderEndpoint, helper: messages.emailProviderEndpointHelper };
    default:
      return { label: messages.emailProviderAuthHeaderName, helper: messages.emailProviderAuthHeaderNameHelper };
  }
}

/** A choice's text. */
function optionText(value: string, messages: Messages): string {
  switch (value) {
    case 'starttls':
      return messages.emailProviderTlsStarttls;
    case 'implicit':
      return messages.emailProviderTlsImplicit;
    case 'global':
      return messages.emailProviderRegionGlobal;
    case 'eu':
      return messages.emailProviderRegionEu;
    default:
      return messages.emailProviderRegionUs;
  }
}

/** A refused field's text: the specific one where the field has it, else by reason. */
function errorText(field: DraftField, reason: string | undefined, messages: Messages): string | undefined {
  if (reason === undefined) return undefined;
  if (reason === 'too_long') return messages.emailProviderFieldTooLong;
  if (reason === 'required') return field === 'secret' ? messages.emailProviderSecretRequired : messages.emailProviderFieldRequired;
  switch (field) {
    case 'settings.host':
      return messages.emailProviderHostInvalid;
    case 'settings.port':
      return messages.emailProviderPortInvalid;
    case 'settings.endpoint':
      return messages.emailProviderEndpointInvalid;
    case 'fromAddress':
      return messages.emailProviderFromAddressInvalid;
    default:
      return messages.emailProviderFieldInvalid;
  }
}

/** The order focus looks for the first field in error. */
const FIELD_ORDER: readonly DraftField[] = [
  ...(['host', 'port', 'tls', 'username', 'region', 'messageStream', 'domain', 'accessKeyId', 'endpoint', 'authHeaderName'] as const).map(
    (name) => `settings.${name}` as const,
  ),
  'secret',
  'fromAddress',
  'fromName',
];

export interface EmailProviderPageProps {
  request: ShellRequest;
  /** The shell's re-authentication sheet: every save and removal needs a fresh assertion. */
  fresh: FreshAssertion;
  /** The path Tenant this page was mounted with: every request it sends names this one. */
  tenantId: string;
}

/**
 * Email provider (Story 4.4; GEN.email as the Design Delta trims it to email only): how the Tenant sends its
 * verification and reset messages. With none, "No provider set", with Add for a Tenant Owner. Otherwise, and once
 * Add is pressed, the kind cards (SMTP, SendGrid, Postmark, Mailgun, Amazon SES and Custom HTTP), the chosen kind's
 * settings, its write-only secret and the sender. A stored secret is never shown: the field says it is saved, and
 * left empty it keeps it. Save and Remove need tenant.email_provider.manage, which only Tenant Owners hold, and a
 * fresh assertion each, confirmed when the server asks; both say so in a toast. Anyone else sees the provider
 * read-only, "Tenant Owner only". The server decides every request: the page follows the capability lists, never a
 * role (AD-20).
 */
export function EmailProviderPage({ request, fresh, tenantId }: EmailProviderPageProps) {
  const messages = useMessages();
  const toast = useToast();
  const { has } = useCapabilities();
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState<EmailProviderDraft>(() => draftOf(null));
  const [errors, setErrors] = useState<DraftErrors>({});
  const [refusal, setRefusal] = useState<Refusal>(null);
  const [saving, setSaving] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [removePending, setRemovePending] = useState(false);
  const [slot, setSlot] = useState<Slot>({ kind: 'none' });
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);
  const inputs = useRef(new Map<DraftField, HTMLElement>());

  const canManage = has('tenant.email_provider.manage');
  const stored = load.kind === 'ready' ? load.provider : null;
  const configured = stored?.configured === true;
  const dirty = canManage && (configured || adding) && isDirty(draft, stored);
  useUnsavedChanges(dirty && !saving);

  useEffect(() => {
    const controller = new AbortController();
    setLoad({ kind: 'loading' });

    void (async () => {
      let result;
      try {
        result = await request('get', () => api.getEmailProvider(tenantId), controller.signal);
      } catch {
        result = null;
      }
      if (controller.signal.aborted) return;
      const provider = result?.ok ? result.data : undefined;
      if (provider && typeof provider.configured === 'boolean') {
        setLoad({ kind: 'ready', provider });
        setDraft(draftOf(provider));
      } else if (result !== null && !result.ok && result.status === 403 && result.problem?.code === 'access_denied')
        setLoad({ kind: 'forbidden', failure: failureOf(result) });
      else setLoad({ kind: 'failed', failure: failureOf(result) });
    })();

    return () => controller.abort();
  }, [request, tenantId, attempt]);

  /** Shows each error on its field, and moves focus to the first field in error. */
  function showErrors(next: DraftErrors) {
    setErrors(next);
    const first = FIELD_ORDER.find((field) => next[field] !== undefined);
    if (first) inputs.current.get(first)?.focus();
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canManage || load.kind !== 'ready' || inFlight.current) return;

    // The browser's check first: a draft it refuses is never sent.
    const found = checkDraft(draft, stored);
    if (Object.keys(found).length > 0) {
      showErrors(found);
      return;
    }

    inFlight.current = true;
    setSaving(true);
    setConfirming(false);
    setRefusal(null);
    // The choices are the document's closed sets as typed here; the server checks every value again.
    const body = requestOf(draft) as SetEmailProviderRequest;

    let outcome;
    try {
      outcome = await fresh.withFreshAssertion({ action: 'tenant.email_provider.manage', target: null, tenantId }, () => {
        setConfirming(true);
        return request('put', () => api.setEmailProvider(tenantId, body));
      });
    } catch {
      outcome = null;
    }
    inFlight.current = false;
    setSaving(false);
    setConfirming(false);

    if (outcome?.kind === 'unconfirmed') {
      setRefusal({ kind: 'unconfirmed', text: confirmationText(outcome.confirmation, messages) });
      return;
    }
    const answer = outcome?.answer ?? null;
    if (answer?.ok && answer.data && typeof answer.data.configured === 'boolean') {
      setErrors({});
      setAdding(false);
      setLoad({ kind: 'ready', provider: answer.data });
      setDraft(draftOf(answer.data));
      toast(messages.emailProviderSaved);
      return;
    }
    if (answer?.status === 401) {
      // The renewal brought the Admin back and didn't send it again: everything typed is kept.
      return;
    }
    const problem = answer && !answer.ok ? (answer.problem ?? null) : null;
    if (answer?.status === 400 && problem?.code === 'email_provider_invalid') {
      const next = serverErrors(problem.errors);
      if (next.settings !== undefined || next.kind !== undefined) {
        setRefusal({ kind: 'saveFailed', failure: failureOf(answer) });
      }
      if (Object.keys(next).length > 0) {
        showErrors(next);
        return;
      }
    }
    if (answer?.status === 409 && problem?.code === 'tenant_mismatch') {
      // The shell's banner names both Tenants: nothing else here.
      return;
    }
    if (answer?.status === 403) {
      setRefusal({ kind: 'forbidden' });
      return;
    }
    setRefusal({ kind: 'saveFailed', failure: failureOf(answer) });
  }

  function openRemove() {
    if (!canManage || removePending || inFlight.current) return;
    setSlot({ kind: 'none' });
    setRemoving(true);
  }

  function closeRemove() {
    if (removePending) return;
    setSlot({ kind: 'none' });
    setRemoving(false);
  }

  async function remove() {
    if (!canManage || inFlight.current) return;
    inFlight.current = true;
    setRemovePending(true);
    setSlot({ kind: 'prompt' });
    setRefusal(null);

    let outcome;
    try {
      outcome = await fresh.withFreshAssertion({ action: 'tenant.email_provider.manage', target: null, tenantId }, () =>
        request('delete', () => api.removeEmailProvider(tenantId)),
      );
    } catch {
      outcome = null;
    }
    inFlight.current = false;
    setRemovePending(false);

    if (outcome?.kind === 'unconfirmed') {
      setSlot({ kind: 'failed', text: confirmationText(outcome.confirmation, messages) });
      return;
    }
    const answer = outcome?.answer ?? null;
    if (answer?.ok) {
      setSlot({ kind: 'none' });
      setRemoving(false);
      setAdding(false);
      setErrors({});
      setLoad({ kind: 'ready', provider: { configured: false } });
      setDraft(draftOf(null));
      toast(messages.emailProviderRemoved);
      return;
    }
    const problem = answer && !answer.ok ? (answer.problem ?? null) : null;
    if (answer?.status === 409 && problem?.code === 'tenant_mismatch') {
      setSlot({ kind: 'none' });
      setRemoving(false);
      return;
    }
    if (answer?.status === 401) {
      setSlot({ kind: 'failed', text: messages.actionRetryAfterSignIn });
      return;
    }
    if (answer?.status === 403) {
      setSlot({ kind: 'failed', text: messages.actionForbidden });
      return;
    }
    setSlot({ kind: 'failed', text: messages.emailProviderRemoveFailed });
  }

  if (load.kind === 'forbidden') return <ForbiddenPage code={load.failure.code} traceId={load.failure.traceId} />;

  const editable = canManage && !saving;

  /** Registers a field's control, for focus on an error. */
  const register = (field: DraftField) => (element: HTMLElement | null) => {
    if (element) inputs.current.set(field, element);
    else inputs.current.delete(field);
  };

  const clearError = (field: DraftField) => {
    if (errors[field] !== undefined) setErrors((now) => ({ ...now, [field]: undefined }));
  };

  const settingField = (field: SettingField) => {
    const key = `settings.${field.name}` as const;
    const { label, helper } = settingText(field.name, draft.kind, messages);
    const onChange = (value: string) => {
      setDraft((now) => ({ ...now, settings: { ...now.settings, [field.name]: value } }));
      clearError(key);
    };
    return (
      <Field key={`${draft.kind}-${field.name}`} label={label} helper={helper} error={errorText(key, errors[key], messages)}>
        {field.options ? (
          <Select
            ref={register(key)}
            value={draft.settings[field.name]}
            disabled={!editable}
            onChange={(event) => onChange(event.target.value)}
            data-testid={`email-provider-${field.name}`}
          >
            {field.options.map((option) => (
              <option key={option} value={option}>
                {optionText(option, messages)}
              </option>
            ))}
          </Select>
        ) : (
          <Input
            ref={register(key)}
            code={field.name !== 'username'}
            inputMode={field.numeric ? 'numeric' : undefined}
            autoComplete="off"
            spellCheck={false}
            maxLength={field.maxLength}
            value={draft.settings[field.name]}
            readOnly={!editable}
            onChange={(event) => onChange(event.target.value)}
            data-testid={`email-provider-${field.name}`}
          />
        )}
      </Field>
    );
  };

  const secretStored = configured && stored?.kind === draft.kind && stored?.secretSet === true;
  const secretUsed = usesSecret(draft.kind, draft.settings);

  let body: ReactNode;
  if (load.kind === 'loading') {
    body = <SkeletonRows rows={3} caption={false} />;
  } else if (load.kind === 'failed') {
    body = (
      <Banner tone="bad" action={{ label: messages.retry, onClick: () => setAttempt((n) => n + 1) }} data-testid="email-provider-load-failed">
        <p>{messages.loadFailed}</p>
        <ErrorReference code={load.failure.code} traceId={load.failure.traceId} />
      </Banner>
    );
  } else if (!configured && !adding) {
    body = (
      <div className={styles.empty} data-testid="email-provider-empty">
        <EmptyState
          message={messages.emailProviderEmpty}
          action={canManage ? { label: messages.emailProviderAdd, onClick: () => { setDraft(draftOf(null)); setErrors({}); setAdding(true); } } : undefined}
        />
        {!canManage && (
          <p className={styles.note} data-testid="email-provider-owner-only">
            {messages.tenantOwnerOnly}
          </p>
        )}
      </div>
    );
  } else {
    body = (
      <form className={styles.form} onSubmit={save} noValidate data-testid="email-provider-form">
        {refusal?.kind === 'saveFailed' && (
          <Banner tone="bad" data-testid="email-provider-save-failed">
            <p>{errors.settings !== undefined ? messages.emailProviderSettingsInvalid : messages.emailProviderSaveFailed}</p>
            <ErrorReference code={refusal.failure.code} traceId={refusal.failure.traceId} />
          </Banner>
        )}
        {refusal?.kind === 'forbidden' && (
          <Banner tone="bad" data-testid="email-provider-forbidden">
            {messages.actionForbidden}
          </Banner>
        )}
        {refusal?.kind === 'unconfirmed' && (
          <Banner tone="bad" data-testid="fresh-assertion-failed">
            {refusal.text}
          </Banner>
        )}

        <RadioGroup
          legend={messages.emailProviderKindLegend}
          value={draft.kind}
          className={styles.kinds}
          onChange={(value) => {
            if (!editable || !isKind(value)) return;
            setDraft((now) => withKind(now, value));
            setErrors({});
          }}
        >
          {EMAIL_PROVIDER_KINDS.map((kind) => {
            const text = kindText(kind, messages);
            return (
              <Radio
                key={kind}
                value={kind}
                disabled={!editable}
                className={styles.kind}
                data-testid={`email-provider-kind-${kind}`}
                label={
                  <span className={styles.kindText}>
                    <span className={styles.kindName}>{text.name}</span>
                    <span className={styles.kindDescription}>{text.description}</span>
                  </span>
                }
              />
            );
          })}
        </RadioGroup>

        <section className={styles.card} aria-labelledby="email-provider-settings-heading" data-testid="email-provider-settings">
          <header className={styles.cardHeader}>
            <h2 id="email-provider-settings-heading">{messages.emailProviderSettingsTitle}</h2>
          </header>
          <div className={styles.cardBody}>
            {KIND_FIELDS[draft.kind].map(settingField)}
            <PasswordField
              key={`${draft.kind}-secret`}
              ref={register('secret')}
              label={secretLabel(draft.kind, messages)}
              helper={
                !secretUsed ? messages.emailProviderSecretNotUsed : secretStored ? messages.emailProviderSecretSaved : messages.emailProviderSecretNew
              }
              error={errorText('secret', errors.secret, messages)}
              autoComplete="new-password"
              maxLength={SECRET_MAX_LENGTH}
              value={draft.secret}
              readOnly={!editable}
              disabled={!secretUsed}
              onChange={(event) => {
                const value = event.target.value;
                setDraft((now) => ({ ...now, secret: value }));
                clearError('secret');
              }}
              data-testid="email-provider-secret"
            />
          </div>
        </section>

        <section className={styles.card} aria-labelledby="email-provider-sender-heading" data-testid="email-provider-sender">
          <header className={styles.cardHeader}>
            <h2 id="email-provider-sender-heading">{messages.emailProviderSenderTitle}</h2>
          </header>
          <div className={styles.cardBody}>
            <Field label={messages.emailProviderFromAddress} error={errorText('fromAddress', errors.fromAddress, messages)}>
              <Input
                ref={register('fromAddress')}
                type="email"
                autoComplete="off"
                spellCheck={false}
                maxLength={FROM_ADDRESS_MAX_LENGTH}
                value={draft.fromAddress}
                readOnly={!editable}
                onChange={(event) => {
                  const value = event.target.value;
                  setDraft((now) => ({ ...now, fromAddress: value }));
                  clearError('fromAddress');
                }}
                data-testid="email-provider-from-address"
              />
            </Field>
            <Field
              label={messages.emailProviderFromName}
              helper={messages.emailProviderOptional}
              error={errorText('fromName', errors.fromName, messages)}
            >
              <Input
                ref={register('fromName')}
                autoComplete="off"
                maxLength={FROM_NAME_MAX_LENGTH}
                value={draft.fromName}
                readOnly={!editable}
                onChange={(event) => {
                  const value = event.target.value;
                  setDraft((now) => ({ ...now, fromName: value }));
                  clearError('fromName');
                }}
                data-testid="email-provider-from-name"
              />
            </Field>
          </div>
        </section>

        {canManage ? (
          <div className={styles.actions}>
            <Button type="submit" variant="primary" pending={saving} data-testid="email-provider-save">
              {messages.emailProviderSave}
            </Button>
            {!configured && (
              <Button
                type="button"
                variant="secondary"
                disabled={saving}
                onClick={() => {
                  setAdding(false);
                  setErrors({});
                  setRefusal(null);
                  setDraft(draftOf(stored));
                }}
                data-testid="email-provider-cancel"
              >
                {messages.cancel}
              </Button>
            )}
            {configured && (
              <Button type="button" variant="destructive" disabled={saving} onClick={openRemove} data-testid="email-provider-remove">
                {messages.emailProviderRemove}
              </Button>
            )}
            {confirming && (
              <p className={styles.note} role="status" data-testid="fresh-assertion-prompt">
                {messages.emailProviderConfirming}
              </p>
            )}
          </div>
        ) : (
          <p className={styles.note} data-testid="email-provider-owner-only">
            {messages.tenantOwnerOnly}
          </p>
        )}
      </form>
    );
  }

  return (
    <SectionPage title={messages.emailProviderTitle} description={messages.emailProviderDescription} data-testid="email-provider-page">
      {body}
      <ConfirmModal
        open={removing}
        onCancel={closeRemove}
        onConfirm={() => void remove()}
        tone="destructive"
        title={messages.emailProviderRemoveTitle}
        confirmLabel={messages.emailProviderRemoveConfirm}
        pending={removePending}
        reauthentication={
          slot.kind === 'prompt' ? (
            <p data-testid="fresh-assertion-prompt">{messages.freshAssertionPrompt}</p>
          ) : slot.kind === 'failed' ? (
            <Banner tone="bad" data-testid="fresh-assertion-failed">
              {slot.text}
            </Banner>
          ) : null
        }
        fallbackFocus={() => document.querySelector<HTMLElement>('main h1')}
        data-testid="remove-email-provider"
      >
        <p>{messages.emailProviderRemoveBody}</p>
      </ConfirmModal>
    </SectionPage>
  );
}
