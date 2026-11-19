import type { DatabaseConnectionResponse } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  ErrorReference,
  Field,
  Input,
  ProtocolBadge,
  Radio,
  RadioGroup,
  SectionPage,
  SettingsRow,
  SkeletonRows,
  Tabs,
  Toggle,
  formatMessage,
  useMessages,
  useToast,
  passwordRules,
  type PasswordRule,
} from '@gatekeep/ui/admin';
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { api } from '../session';
import { useCapabilities } from './capabilities';
import type { ShellRequest } from './CredentialsPage';
import {
  PASSWORD_HISTORY_MAX,
  PASSWORD_MIN_LENGTH_CEILING,
  PASSWORD_MIN_LENGTH_FLOOR,
  PASSWORD_STRENGTHS,
  checkPolicyDraft,
  isPolicyDirty,
  isStrength,
  policyDraftOf,
  policyRequestOf,
  previewMinLength,
  serverPolicyErrors,
  type FieldError,
  type PolicyDraft,
  type PolicyErrors,
  type PolicyField,
} from './database';
import styles from './DatabasePage.module.css';
import { ForbiddenPage } from './ForbiddenPage';
import { useUnsavedChanges } from './unsavedChanges';

type Messages = ReturnType<typeof useMessages>;

type Failure = { code: string; traceId: string };

type Load =
  | { kind: 'loading' }
  | { kind: 'ready'; connection: DatabaseConnectionResponse }
  | { kind: 'forbidden'; failure: Failure }
  | { kind: 'failed'; failure: Failure };

/** Why a tab's last save didn't happen, shown above its form. */
type Refusal = { kind: 'saveFailed'; failure: Failure } | { kind: 'forbidden' } | { kind: 'notActive' } | null;

/** A refusal's code and trace ID, as far as the answer carries them: a bodiless 503 has neither. */
function failureOf(result: { ok: boolean; problem?: { code?: string; traceId?: string } | null } | null): Failure {
  const problem = result && !result.ok ? result.problem : null;
  return { code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' };
}

/** A refused policy field's text: the server's own rule text when it gave one, else the browser's. */
function policyErrorText(field: PolicyField, error: FieldError | undefined, messages: Messages): string | undefined {
  if (error === undefined) return undefined;
  if (error.detail) return error.detail;
  switch (field) {
    case 'minLength':
      // Below the floor, the browser words it as the server does (FR-18).
      return error.reason === 'below_minimum'
        ? formatMessage(messages.passwordMinLengthFloor, { min: PASSWORD_MIN_LENGTH_FLOOR })
        : formatMessage(messages.passwordMinLengthInvalid, { min: PASSWORD_MIN_LENGTH_FLOOR, max: PASSWORD_MIN_LENGTH_CEILING });
    case 'historyCount':
      return formatMessage(messages.passwordHistoryCountInvalid, { max: PASSWORD_HISTORY_MAX });
    default:
      return messages.passwordFieldInvalid;
  }
}

/** A preview rule's text. */
function ruleText(rule: PasswordRule, messages: Messages): string {
  switch (rule.rule) {
    case 'length':
      return formatMessage(messages.passwordRuleLength, { count: rule.count });
    case 'classes':
      return messages.passwordRuleClasses;
    default:
      return messages.passwordRuleRepeats;
  }
}

/** How a save's refusal reads above the form, or null when the shell or the fields already say it. */
function refusalOf(answer: { ok: boolean; status: number; problem?: { code?: string; traceId?: string } | null } | null): Refusal {
  const problem = answer && !answer.ok ? (answer.problem ?? null) : null;
  if (answer?.status === 409 && problem?.code === 'tenant_mismatch') return null;
  if (answer?.status === 409 && problem?.code === 'tenant_not_active') return { kind: 'notActive' };
  if (answer?.status === 403) return { kind: 'forbidden' };
  return { kind: 'saveFailed', failure: failureOf(answer) };
}

export interface DatabasePageProps {
  request: ShellRequest;
  /** The path Tenant this page was mounted with: every request it sends names this one. */
  tenantId: string;
}

/**
 * Database (Story 4.6; AUTH.database as the Design Delta trims it): the Tenant's one database Connection, "DB"
 * Username-Password, in two tabs. Settings holds the one sign-up row, which tenant.connections.toggle changes (Editors
 * and Owners). Password policy holds the minimum length, the strength, the history rule with its count, and the
 * dictionary and personal-data rules, which only tenant.password_policy.manage changes (Tenant Owners): anyone else
 * sees them read-only, "Tenant Owner only". Beside them, "what users see" lists the rules as met or not for a sample
 * typed into a field that is never sent. Each tab has its own Save and toast; its draft survives a switch of tab. The
 * server decides every request: the page follows the capability lists, never a role (AD-20).
 */
export function DatabasePage({ request, tenantId }: DatabasePageProps) {
  const messages = useMessages();
  const toast = useToast();
  const { has, tenantCapabilities } = useCapabilities();
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);
  const [signup, setSignup] = useState(true);
  const [policy, setPolicy] = useState<PolicyDraft | null>(null);
  const [sample, setSample] = useState('');
  const [errors, setErrors] = useState<PolicyErrors>({});
  const [settingsRefusal, setSettingsRefusal] = useState<Refusal>(null);
  const [policyRefusal, setPolicyRefusal] = useState<Refusal>(null);
  const [savingSettings, setSavingSettings] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);
  // Set at once, before React re-renders, so a second press sends nothing; one per tab, so either saves while the other does.
  const settingsInFlight = useRef(false);
  const policyInFlight = useRef(false);
  const inputs = useRef(new Map<PolicyField, HTMLElement>());

  const canToggle = has('tenant.connections.toggle');
  const canManagePolicy = has('tenant.password_policy.manage');
  const viewOnly = ![...tenantCapabilities].some((capability) => capability.startsWith('tenant.') && capability.endsWith('.manage'));
  const stored = load.kind === 'ready' ? load.connection : null;
  const signupDirty = canToggle && stored !== null && signup !== stored.signupEnabled;
  const policyDirty = canManagePolicy && stored !== null && policy !== null && isPolicyDirty(policy, stored.passwordPolicy);
  useUnsavedChanges((signupDirty && !savingSettings) || (policyDirty && !savingPolicy));

  useEffect(() => {
    const controller = new AbortController();
    setLoad({ kind: 'loading' });

    void (async () => {
      let result;
      try {
        result = await request('get', () => api.getDatabaseConnection(tenantId), controller.signal);
      } catch {
        result = null;
      }
      if (controller.signal.aborted) return;
      const connection = result?.ok ? result.data : undefined;
      if (connection && typeof connection.signupEnabled === 'boolean' && connection.passwordPolicy) {
        setLoad({ kind: 'ready', connection });
        setSignup(connection.signupEnabled);
        setPolicy(policyDraftOf(connection.passwordPolicy));
      } else if (result !== null && !result.ok && result.status === 403 && result.problem?.code === 'access_denied')
        setLoad({ kind: 'forbidden', failure: failureOf(result) });
      else setLoad({ kind: 'failed', failure: failureOf(result) });
    })();

    return () => controller.abort();
  }, [request, tenantId, attempt]);

  /** The Connection as the server now holds it, each tab's draft kept unless it was the one saved. */
  function saved(connection: DatabaseConnectionResponse, which: 'settings' | 'policy') {
    setLoad({ kind: 'ready', connection });
    if (which === 'settings') setSignup(connection.signupEnabled);
    else setPolicy(policyDraftOf(connection.passwordPolicy));
    toast(messages.databaseSaved);
  }

  async function saveSettings(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canToggle || stored === null || settingsInFlight.current) return;
    settingsInFlight.current = true;
    setSavingSettings(true);
    setSettingsRefusal(null);

    let answer;
    try {
      answer = await request('put', () => api.setDatabaseConnectionSettings(tenantId, { signupEnabled: signup }));
    } catch {
      answer = null;
    }
    settingsInFlight.current = false;
    setSavingSettings(false);

    if (answer?.ok && answer.data && typeof answer.data.signupEnabled === 'boolean') {
      saved(answer.data, 'settings');
      return;
    }
    // The renewal brought the Admin back and didn't send it again: the choice is kept.
    if (answer?.status === 401) return;
    setSettingsRefusal(refusalOf(answer));
  }

  function showErrors(next: PolicyErrors) {
    setErrors(next);
    const first = (['minLength', 'strength', 'historyCount', 'dictionary', 'personalData'] as const).find((field) => next[field] !== undefined);
    if (first) inputs.current.get(first)?.focus();
  }

  async function savePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canManagePolicy || stored === null || policy === null || policyInFlight.current) return;

    // The browser's check first: a draft it refuses is never sent.
    const found = checkPolicyDraft(policy);
    if (Object.keys(found).length > 0) {
      showErrors(found);
      return;
    }

    policyInFlight.current = true;
    setSavingPolicy(true);
    setPolicyRefusal(null);

    let answer;
    try {
      answer = await request('put', () => api.setPasswordPolicy(tenantId, policyRequestOf(policy)));
    } catch {
      answer = null;
    }
    policyInFlight.current = false;
    setSavingPolicy(false);

    if (answer?.ok && answer.data?.passwordPolicy) {
      setErrors({});
      saved(answer.data, 'policy');
      return;
    }
    if (answer?.status === 401) return;
    const problem = answer && !answer.ok ? (answer.problem ?? null) : null;
    if (answer?.status === 400 && problem?.code === 'connection_invalid') {
      const next = serverPolicyErrors(problem.errors);
      if (Object.keys(next).length > 0) {
        showErrors(next);
        return;
      }
    }
    setPolicyRefusal(refusalOf(answer));
  }

  if (load.kind === 'forbidden') return <ForbiddenPage code={load.failure.code} traceId={load.failure.traceId} />;

  const title = (
    <span className={styles.title}>
      <ProtocolBadge data-testid="database-badge">{messages.databaseBadge}</ProtocolBadge>
      <bdi data-testid="database-name">{stored?.name ?? messages.databaseName}</bdi>
    </span>
  );

  let body: ReactNode;
  if (load.kind === 'loading' || (load.kind === 'ready' && policy === null)) {
    body = <SkeletonRows rows={3} caption={false} />;
  } else if (load.kind === 'failed') {
    body = (
      <Banner tone="bad" action={{ label: messages.retry, onClick: () => setAttempt((n) => n + 1) }} data-testid="database-load-failed">
        <p>{messages.loadFailed}</p>
        <ErrorReference code={load.failure.code} traceId={load.failure.traceId} />
      </Banner>
    );
  } else {
    body = (
      <Tabs
        label={messages.databaseTabsLabel}
        param="tab"
        defaultSelected="settings"
        tabs={[
          {
            id: 'settings',
            label: messages.databaseTabSettings,
            panel: (
              <SettingsTab
                messages={messages}
                signup={signup}
                editable={canToggle && !savingSettings}
                canToggle={canToggle}
                saving={savingSettings}
                refusal={settingsRefusal}
                onSignup={setSignup}
                onSubmit={saveSettings}
              />
            ),
          },
          {
            id: 'password-policy',
            label: messages.databaseTabPasswordPolicy,
            panel: (
              <PolicyTab
                messages={messages}
                draft={policy!}
                errors={errors}
                editable={canManagePolicy && !savingPolicy}
                canManage={canManagePolicy}
                saving={savingPolicy}
                refusal={policyRefusal}
                sample={sample}
                register={(field) => (element) => {
                  if (element) inputs.current.set(field, element);
                  else inputs.current.delete(field);
                }}
                onChange={(next, field) => {
                  setPolicy(next);
                  if (field && errors[field] !== undefined) setErrors((now) => ({ ...now, [field]: undefined }));
                }}
                onSample={setSample}
                onSubmit={savePolicy}
              />
            ),
          },
        ]}
      />
    );
  }

  return (
    <SectionPage title={title} description={messages.databaseDescription} data-testid="database-page">
      {viewOnly && (
        <Banner tone="info" live={false} data-testid="tenant-view-only">
          {messages.tenantViewOnly}
        </Banner>
      )}
      {body}
    </SectionPage>
  );
}

function RefusalBanner({ refusal, messages, testId }: { refusal: Refusal; messages: Messages; testId: string }) {
  if (refusal === null) return null;
  if (refusal.kind === 'forbidden')
    return (
      <Banner tone="bad" data-testid={`${testId}-forbidden`}>
        {messages.actionForbidden}
      </Banner>
    );
  if (refusal.kind === 'notActive')
    return (
      <Banner tone="warn" data-testid={`${testId}-not-active`}>
        {messages.tenantNotActive}
      </Banner>
    );
  return (
    <Banner tone="bad" data-testid={`${testId}-save-failed`}>
      <p>{messages.databaseSaveFailed}</p>
      <ErrorReference code={refusal.failure.code} traceId={refusal.failure.traceId} />
    </Banner>
  );
}

interface SettingsTabProps {
  messages: Messages;
  signup: boolean;
  editable: boolean;
  canToggle: boolean;
  saving: boolean;
  refusal: Refusal;
  onSignup: (on: boolean) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}

/** The Settings tab: the one sign-up row and its Save. */
function SettingsTab({ messages, signup, editable, canToggle, saving, refusal, onSignup, onSubmit }: SettingsTabProps) {
  return (
    <form className={styles.form} onSubmit={onSubmit} noValidate data-testid="database-settings">
      <RefusalBanner refusal={refusal} messages={messages} testId="database-settings" />
      <section className={styles.card} aria-label={messages.databaseTabSettings}>
        <div className={styles.rows}>
          <SettingsRow label={messages.databaseSignup} description={messages.databaseSignupDescription}>
            <Toggle
              label={messages.databaseSignup}
              hideLabel
              checked={signup}
              disabled={!editable}
              onCheckedChange={onSignup}
              data-testid="database-signup"
            />
          </SettingsRow>
        </div>
      </section>
      {canToggle && (
        <div className={styles.actions}>
          <Button type="submit" variant="primary" pending={saving} data-testid="database-settings-save">
            {messages.databaseSave}
          </Button>
        </div>
      )}
    </form>
  );
}

interface PolicyTabProps {
  messages: Messages;
  draft: PolicyDraft;
  errors: PolicyErrors;
  editable: boolean;
  canManage: boolean;
  saving: boolean;
  refusal: Refusal;
  sample: string;
  register: (field: PolicyField) => (element: HTMLElement | null) => void;
  onChange: (next: PolicyDraft, field?: PolicyField) => void;
  onSample: (sample: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}

/** The Password policy tab: its fields, read-only but for a Tenant Owner, the preview beside them, and its Save. */
function PolicyTab(props: PolicyTabProps) {
  const { messages, draft, errors, editable, canManage, saving, refusal, sample, register, onChange, onSample, onSubmit } = props;
  const rules = passwordRules(previewMinLength(draft), draft.strength, sample);
  const serverChecks = draft.dictionary || draft.personalData || draft.historyOn;

  return (
    <form className={styles.form} onSubmit={onSubmit} noValidate data-testid="database-policy">
      <RefusalBanner refusal={refusal} messages={messages} testId="database-policy" />
      <div className={styles.policy}>
        <section className={styles.card} aria-labelledby="database-policy-heading">
          <header className={styles.cardHeader}>
            <h2 id="database-policy-heading">{messages.databaseTabPasswordPolicy}</h2>
          </header>
          <div className={styles.cardBody}>
            <Field
              label={messages.passwordMinLength}
              helper={formatMessage(messages.passwordMinLengthHelper, { min: PASSWORD_MIN_LENGTH_FLOOR, max: PASSWORD_MIN_LENGTH_CEILING })}
              error={policyErrorText('minLength', errors.minLength, messages)}
            >
              <Input
                ref={register('minLength')}
                inputMode="numeric"
                autoComplete="off"
                maxLength={3}
                value={draft.minLength}
                readOnly={!editable}
                onChange={(event) => onChange({ ...draft, minLength: event.target.value }, 'minLength')}
                data-testid="password-min-length"
              />
            </Field>

            <RadioGroup
              legend={messages.passwordStrength}
              value={draft.strength}
              onChange={(value) => {
                if (editable && isStrength(value)) onChange({ ...draft, strength: value }, 'strength');
              }}
            >
              {PASSWORD_STRENGTHS.map((strength) => (
                <Radio
                  key={strength}
                  value={strength}
                  disabled={!editable}
                  data-testid={`password-strength-${strength}`}
                  label={
                    <span className={styles.option}>
                      <span className={styles.optionName}>
                        {strength === 'good' ? messages.passwordStrengthGood : messages.passwordStrengthExcellent}
                      </span>
                      <span className={styles.optionDescription}>
                        {strength === 'good' ? messages.passwordStrengthGoodDescription : messages.passwordStrengthExcellentDescription}
                      </span>
                    </span>
                  }
                />
              ))}
            </RadioGroup>
          </div>
          <div className={styles.rows}>
            <SettingsRow label={messages.passwordHistory} description={messages.passwordHistoryDescription}>
              <Toggle
                label={messages.passwordHistory}
                hideLabel
                checked={draft.historyOn}
                disabled={!editable}
                onCheckedChange={(on) => onChange({ ...draft, historyOn: on }, 'historyCount')}
                data-testid="password-history"
              />
            </SettingsRow>
            {draft.historyOn && (
              <div className={styles.nested}>
                <Field
                  label={messages.passwordHistoryCount}
                  helper={formatMessage(messages.passwordHistoryCountHelper, { max: PASSWORD_HISTORY_MAX })}
                  error={policyErrorText('historyCount', errors.historyCount, messages)}
                >
                  <Input
                    ref={register('historyCount')}
                    inputMode="numeric"
                    autoComplete="off"
                    maxLength={2}
                    value={draft.historyCount}
                    readOnly={!editable}
                    onChange={(event) => onChange({ ...draft, historyCount: event.target.value }, 'historyCount')}
                    data-testid="password-history-count"
                  />
                </Field>
              </div>
            )}
            <SettingsRow label={messages.passwordDictionary} description={policyErrorText('dictionary', errors.dictionary, messages) ?? messages.passwordDictionaryDescription}>
              <Toggle
                label={messages.passwordDictionary}
                hideLabel
                checked={draft.dictionary}
                disabled={!editable}
                onCheckedChange={(on) => onChange({ ...draft, dictionary: on }, 'dictionary')}
                data-testid="password-dictionary"
              />
            </SettingsRow>
            <SettingsRow
              label={messages.passwordPersonalData}
              description={policyErrorText('personalData', errors.personalData, messages) ?? messages.passwordPersonalDataDescription}
            >
              <Toggle
                label={messages.passwordPersonalData}
                hideLabel
                checked={draft.personalData}
                disabled={!editable}
                onCheckedChange={(on) => onChange({ ...draft, personalData: on }, 'personalData')}
                data-testid="password-personal-data"
              />
            </SettingsRow>
          </div>
        </section>

        <section className={styles.card} aria-labelledby="database-preview-heading" data-testid="password-preview">
          <header className={styles.cardHeader}>
            <h2 id="database-preview-heading">{messages.passwordPreviewTitle}</h2>
          </header>
          <div className={styles.preview}>
            {/* Never named or submitted: the sample is checked here only, and masked as every password is. */}
            <Field label={messages.passwordPreviewSample} helper={messages.passwordPreviewSampleHelper}>
              <Input
                type="password"
                form="database-preview-none"
                autoComplete="off"
                spellCheck={false}
                value={sample}
                onChange={(event) => onSample(event.target.value)}
                data-testid="password-preview-sample"
              />
            </Field>
            <ul className={styles.rules} data-testid="password-preview-rules">
              {rules.map((rule) => (
                <li key={rule.rule} className={rule.met ? styles.met : styles.notMet} data-met={rule.met} data-testid={`password-rule-${rule.rule}`}>
                  <span className={styles.glyph} aria-hidden="true">
                    {rule.met ? '✓' : '✕'}
                  </span>
                  <span>{ruleText(rule, messages)}</span>
                  <span className={styles.ruleState}>{rule.met ? messages.passwordRuleMet : messages.passwordRuleNotMet}</span>
                </li>
              ))}
            </ul>
            {serverChecks && <p className={styles.note}>{messages.passwordPreviewServerChecks}</p>}
          </div>
        </section>
      </div>

      {canManage ? (
        <div className={styles.actions}>
          <Button type="submit" variant="primary" pending={saving} data-testid="database-policy-save">
            {messages.databaseSave}
          </Button>
        </div>
      ) : (
        <p className={styles.note} data-testid="database-policy-owner-only">
          {messages.tenantOwnerOnly}
        </p>
      )}
    </form>
  );
}
