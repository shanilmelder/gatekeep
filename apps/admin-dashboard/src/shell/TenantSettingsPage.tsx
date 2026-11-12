import type { AdminTenant } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  ConfirmModal,
  EnvironmentBadge,
  ErrorReference,
  Radio,
  RadioGroup,
  SectionPage,
  SkeletonRows,
  formatMessage,
  useMessages,
  useToast,
  type Environment,
} from '@gatekeep/ui/admin';
import { useCallback, useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { api } from '../session';
import { useCapabilities } from './capabilities';
import type { ShellRequest } from './CredentialsPage';
import styles from './CreateTenantPage.module.css';
import { ENVIRONMENTS } from './environments';
import { needsFreshAssertion, type Confirmation, type FreshAssertion } from './freshAssertion';
import { useUnsavedChanges } from './unsavedChanges';

type Messages = ReturnType<typeof useMessages>;

type Load =
  | { kind: 'loading' }
  /** The stored label, and whether the Tenant is active: only an active Tenant's label changes. */
  | { kind: 'ready'; label: Environment; active: boolean }
  | { kind: 'failed'; code: string; traceId: string };

type Refusal =
  | { kind: 'saveFailed'; code: string; traceId: string }
  | { kind: 'forbidden' }
  | { kind: 'notActive' }
  | null;

/** What the Prod modal's re-authentication slot shows (UX-DR17): nothing, the sheet's prompt, or a failure. */
type Slot = { kind: 'none' } | { kind: 'prompt' } | { kind: 'failed'; text: string };

const LABELS: ReadonlySet<string> = new Set(['dev', 'staging', 'prod']);

/** The text a confirmation that didn't pass shows in the modal, as Your credentials shows it. */
export function confirmationText(confirmation: Exclude<Confirmation, { kind: 'confirmed' }>, messages: Messages): string {
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

export interface TenantSettingsPageProps {
  request: ShellRequest;
  fresh: FreshAssertion;
  /** The path Tenant this page was mounted with: every request it sends names this one. */
  tenantId: string;
  /** The path Tenant as the switcher lists it, for its name and host, or null when unlisted. */
  tenant: AdminTenant | null;
  /** Reads the shell's lists again, so the top bar's badge follows a saved label at once. */
  onSaved: () => void;
}

/**
 * Tenant settings (Story 1.28; GEN.tenant as the Design Delta changes it): until Story 8.5 only
 * the Tenant's environment. The radios keep each option's tone in view. Without
 * tenant.label.manage they are read-only, "Tenant Owner only"; with no tenant.*.manage at all the
 * page says it is view-only. Save sends only a change. Removing Prod opens the confirming modal
 * first, then sends the change, and only on the server's 403 fresh_assertion_required confirms
 * it's the Admin inside the same modal and sends it once more (UX-DR17). Every decision is the
 * server's: the page follows the capability lists and never a role (AD-20).
 */
export function TenantSettingsPage({ request, fresh, tenantId, tenant, onSaved }: TenantSettingsPageProps) {
  const messages = useMessages();
  const toast = useToast();
  const { has, tenantCapabilities } = useCapabilities();
  const helperId = useId();
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);
  const [choice, setChoice] = useState<Environment>('dev');
  const [saving, setSaving] = useState(false);
  const [refusal, setRefusal] = useState<Refusal>(null);
  const [confirming, setConfirming] = useState(false);
  const [slot, setSlot] = useState<Slot>({ kind: 'none' });
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);

  const canManage = has('tenant.label.manage');
  const viewOnly = ![...tenantCapabilities].some((capability) => capability.startsWith('tenant.') && capability.endsWith('.manage'));
  const loaded = load.kind === 'ready' ? load.label : null;
  const active = load.kind === 'ready' && load.active;
  const editable = canManage && active;
  const dirty = loaded !== null && choice !== loaded;
  useUnsavedChanges(dirty && !saving);

  /** The label and status as the server holds them now, or why they couldn't be read. */
  const readLabel = useCallback(
    async (signal?: AbortSignal): Promise<Load> => {
      try {
        const result = await request('get', () => api.getTenantLabel(tenantId), signal);
        const label = result.ok ? result.data?.label : undefined;
        const status = result.ok ? result.data?.status : undefined;
        if (typeof label === 'string' && LABELS.has(label) && (status === 'active' || status === 'creating')) {
          return { kind: 'ready', label: label as Environment, active: status === 'active' };
        }
        const problem = result.ok ? null : result.problem;
        return { kind: 'failed', code: problem?.code ?? '', traceId: problem?.traceId ?? '' };
      } catch {
        return { kind: 'failed', code: '', traceId: '' };
      }
    },
    [request, tenantId],
  );

  useEffect(() => {
    const controller = new AbortController();
    setLoad({ kind: 'loading' });
    void readLabel(controller.signal).then((next) => {
      if (controller.signal.aborted) return;
      setLoad(next);
      if (next.kind === 'ready') setChoice(next.label);
    });
    return () => controller.abort();
  }, [readLabel, attempt]);

  /** After a refusal, the label as the server holds it now, the Admin's choice kept. */
  const refresh = useCallback(async () => {
    const next = await readLabel();
    if (next.kind === 'ready') setLoad(next);
    return next;
  }, [readLabel]);

  /**
   * Sends the change and shows what it came to. From the Prod modal it goes through the fresh
   * assertion, which confirms only on the server's 403 fresh_assertion_required. Any other change
   * is sent plainly; should the server answer that it needs a confirmation after all (the label
   * became Prod elsewhere), the label is read again and the modal opens, so the sheet still comes
   * only after it.
   */
  const send = useCallback(
    async (label: Environment, removesProd: boolean) => {
      if (inFlight.current) return;
      inFlight.current = true;
      setSaving(true);
      setRefusal(null);
      if (removesProd) setSlot({ kind: 'prompt' });

      const put = () => request('put', () => api.setTenantLabel(tenantId, { label }));
      let answer: Awaited<ReturnType<typeof put>> | null = null;
      try {
        if (removesProd) {
          const outcome = await fresh.withFreshAssertion({ action: 'tenant.label.manage', target: null, tenantId }, put);
          if (outcome.kind === 'unconfirmed') {
            inFlight.current = false;
            setSaving(false);
            setSlot({ kind: 'failed', text: confirmationText(outcome.confirmation, messages) });
            return;
          }
          answer = outcome.answer;
        } else {
          answer = await put();
        }
      } catch {
        answer = null;
      }

      inFlight.current = false;
      setSaving(false);

      const saved = answer?.ok ? answer.data?.label : undefined;
      if (answer?.ok && typeof saved === 'string' && LABELS.has(saved)) {
        setConfirming(false);
        setSlot({ kind: 'none' });
        setLoad({ kind: 'ready', label: saved as Environment, active: true });
        setChoice(saved as Environment);
        toast(messages.tenantEnvironmentSaved);
        onSaved();
        return;
      }
      if (answer?.status === 401) {
        // The renewal brought the Admin back and didn't send it again: the choice is kept.
        setConfirming(false);
        setSlot({ kind: 'none' });
        return;
      }
      if (!removesProd && needsFreshAssertion(answer && !answer.ok ? answer : null)) {
        // The label is Prod on the server now: read it, and confirm in the modal first.
        await refresh();
        setSlot({ kind: 'none' });
        setConfirming(true);
        return;
      }

      // Every other refusal: the label is read again, so the page shows what the server holds.
      setConfirming(false);
      setSlot({ kind: 'none' });
      void refresh();
      if (answer && !answer.ok && answer.status === 409 && answer.problem?.code === 'tenant_mismatch') {
        // The shell's banner names both Tenants: nothing else here.
        return;
      }
      if (answer && !answer.ok && answer.status === 409 && answer.problem?.code === 'tenant_not_active') {
        setRefusal({ kind: 'notActive' });
        return;
      }
      if (answer && !answer.ok && answer.status === 403 && answer.problem?.code !== 'fresh_assertion_required') {
        // access_denied, or the bodiless 403 of an earlier check: the server refuses this outright.
        setRefusal({ kind: 'forbidden' });
        return;
      }
      const problem = answer && !answer.ok ? answer.problem : null;
      setRefusal({ kind: 'saveFailed', code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' });
    },
    [request, fresh, tenantId, messages, toast, onSaved, refresh],
  );

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editable || loaded === null || !dirty || inFlight.current) return;
    if (loaded === 'prod') {
      setSlot({ kind: 'none' });
      setConfirming(true);
      return;
    }
    void send(choice, false);
  }

  function closeModal() {
    if (saving) return;
    setConfirming(false);
    setSlot({ kind: 'none' });
  }

  let body: ReactNode;
  if (load.kind === 'loading') {
    body = <SkeletonRows rows={2} caption={false} />;
  } else if (load.kind === 'failed') {
    body = (
      <Banner tone="bad" action={{ label: messages.retry, onClick: () => setAttempt((n) => n + 1) }} data-testid="tenant-settings-load-failed">
        <p>{messages.loadFailed}</p>
        <ErrorReference code={load.code} traceId={load.traceId} />
      </Banner>
    );
  } else {
    body = (
      <form className={styles.form} onSubmit={submit} noValidate data-testid="tenant-settings">
        {refusal?.kind === 'saveFailed' && (
          <Banner tone="bad" data-testid="tenant-settings-save-failed">
            <p>{messages.tenantSaveFailed}</p>
            <ErrorReference code={refusal.code} traceId={refusal.traceId} />
          </Banner>
        )}
        {refusal?.kind === 'forbidden' && (
          <Banner tone="bad" data-testid="tenant-settings-forbidden">
            {messages.actionForbidden}
          </Banner>
        )}
        {refusal?.kind === 'notActive' && (
          <Banner tone="warn" data-testid="tenant-settings-not-active">
            {messages.tenantNotActive}
          </Banner>
        )}
        {!active && (
          <Banner tone="info" live={false} data-testid="tenant-settings-creating">
            {messages.tenantNotActive}
          </Banner>
        )}
        <RadioGroup
          legend={messages.createTenantEnvironment}
          value={choice}
          onChange={(value) => editable && !saving && setChoice(value as Environment)}
        >
          {ENVIRONMENTS.map((environment) => (
            <Radio
              key={environment.value}
              value={environment.value}
              disabled={!editable}
              aria-describedby={helperId}
              label={
                <span className={styles.option}>
                  {messages[environment.option]}
                  <EnvironmentBadge environment={environment.value}>{messages[environment.tag]}</EnvironmentBadge>
                </span>
              }
            />
          ))}
        </RadioGroup>
        <p id={helperId} className={styles.status} data-testid="tenant-settings-helper">
          {canManage ? messages.tenantEnvironmentHelper : messages.tenantOwnerOnly}
        </p>
        {editable && (
          <div className={styles.actions}>
            <Button type="submit" variant="primary" pending={saving && !confirming} data-testid="tenant-settings-save">
              {messages.tenantSave}
            </Button>
          </div>
        )}
      </form>
    );
  }

  return (
    <SectionPage
      title={messages.tenantSettingsTitle}
      description={tenant ? <code className={styles.host}>{tenant.host}</code> : undefined}
      data-testid="tenant-settings-page"
    >
      {viewOnly && (
        <Banner tone="info" live={false} data-testid="tenant-view-only">
          {messages.tenantViewOnly}
        </Banner>
      )}
      {body}
      <ConfirmModal
        open={confirming}
        onCancel={closeModal}
        onConfirm={() => void send(choice, true)}
        tone="destructive"
        title={messages.tenantRemoveProdTitle}
        confirmLabel={messages.tenantRemoveProdConfirm}
        pending={saving}
        reauthentication={
          slot.kind === 'prompt' ? (
            <p data-testid="fresh-assertion-prompt">{messages.freshAssertionPrompt}</p>
          ) : slot.kind === 'failed' ? (
            <Banner tone="bad" data-testid="fresh-assertion-failed">
              {slot.text}
            </Banner>
          ) : null
        }
        data-testid="remove-prod"
      >
        <p>
          {formatMessage(messages.tenantRemoveProdBody, { name: '\u0000' })
            .split('\u0000')
            .flatMap((part, index) => (index === 0 ? [part] : [<bdi key={index}>{tenant?.name ?? tenantId}</bdi>, part]))}
        </p>
      </ConfirmModal>
    </SectionPage>
  );
}
