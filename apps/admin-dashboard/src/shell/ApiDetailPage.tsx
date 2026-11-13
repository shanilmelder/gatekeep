import type { ApiPermission, ApiProblemError, ApiResourceDetail, ApiSettingsRequest } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  DataTable,
  EmptyState,
  ErrorReference,
  Field,
  Input,
  Modal,
  ProtocolBadge,
  SectionPage,
  SettingsRow,
  SkeletonRows,
  Toggle,
  formatMessage,
  useMessages,
  useToast,
  type DataTableColumn,
} from '@gatekeep/ui/admin';
import { useEffect, useRef, useState, type FormEvent, type MouseEvent, type RefObject } from 'react';
import { navigate } from '../navigation';
import { api } from '../session';
import { apisPath, isPermissionDescription, isPermissionValue } from './apis';
import { LIFETIME_DEFAULTS, LIFETIME_FIELDS, checkLifetime, type LifetimeField } from './applications';
import { durationText } from './ApplicationTokens';
import { failureOf } from './ApplicationsPage';
import { useCapabilities } from './capabilities';
import type { ShellRequest } from './CredentialsPage';
import { ForbiddenPage } from './ForbiddenPage';
import { useUnsavedChanges } from './unsavedChanges';
import pageStyles from './ApplicationsPage.module.css';
import cards from './ApplicationTokens.module.css';
import styles from './ApiDetailPage.module.css';

type Messages = ReturnType<typeof useMessages>;

type Failure = { code: string; traceId: string };

type Load =
  | { kind: 'loading' }
  | { kind: 'ready'; detail: ApiResourceDetail }
  | { kind: 'notFound' }
  | { kind: 'forbidden'; failure: Failure }
  | { kind: 'failed'; failure: Failure };

type Refusal = { kind: 'saveFailed'; code: string; traceId: string } | { kind: 'forbidden' } | null;

export interface ApiDetailPageProps {
  request: ShellRequest;
  /** The path Tenant this page was mounted with. */
  tenantId: string;
  /** The API the path names, as decoded: the server decides whether it is this Tenant's. */
  apiId: string;
}

/**
 * One API (Story 3.6; design API detail as the epic changes it): the breadcrumb back to APIs, the name with the Built-in
 * badge on the Gatekeep Management API, then Settings and Permissions. Settings shows the identifier read-only ("Can't be
 * changed."), offline access, Enable RBAC and the four token lifetimes as an Application's Tokens tab does; Permissions
 * lists each resource:action with its description, Add and Remove, except on the built-in API, whose Permissions are
 * fixed. Without tenant.apis.manage everything is read-only. A 404 says the Tenant has no such API, a 403 is the forbidden
 * page, and any other failure a banner with Retry.
 */
export function ApiDetailPage({ request, tenantId, apiId }: ApiDetailPageProps) {
  const messages = useMessages();
  const { has } = useCapabilities();
  const canManage = has('tenant.apis.manage');
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoad({ kind: 'loading' });

    void (async () => {
      let result;
      try {
        result = await request('get', () => api.getApi(tenantId, apiId), controller.signal);
      } catch {
        result = null;
      }
      if (controller.signal.aborted) return;
      const detail = result?.ok ? result.data : undefined;
      if (detail && typeof detail.api?.id === 'string') setLoad({ kind: 'ready', detail });
      else if (result !== null && !result.ok && result.status === 404) setLoad({ kind: 'notFound' });
      else if (result !== null && !result.ok && result.status === 403 && result.problem?.code === 'access_denied')
        setLoad({ kind: 'forbidden', failure: failureOf(result) });
      else setLoad({ kind: 'failed', failure: failureOf(result) });
    })();

    return () => controller.abort();
  }, [request, tenantId, apiId, attempt]);

  if (load.kind === 'forbidden') return <ForbiddenPage code={load.failure.code} traceId={load.failure.traceId} />;

  const listHref = apisPath(tenantId);
  const back = (event: MouseEvent<HTMLAnchorElement>) => {
    // A plain click stays in the dashboard; a modified one opens the link as the browser does.
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    navigate(listHref);
  };

  const ready = load.kind === 'ready' ? load.detail : null;
  const eyebrow = (
    <nav aria-label={messages.apiBreadcrumb}>
      <ol className={pageStyles.crumbs} data-testid="api-breadcrumb">
        <li>
          <a href={listHref} onClick={back}>
            {messages.apisTitle}
          </a>
        </li>
        {ready && (
          <li aria-current="page">
            <bdi>{ready.api.name}</bdi>
          </li>
        )}
      </ol>
    </nav>
  );

  if (load.kind === 'loading') {
    return (
      <SectionPage eyebrow={eyebrow} title={messages.apisTitle} data-testid="api-page">
        <SkeletonRows rows={3} caption={false} />
      </SectionPage>
    );
  }

  if (load.kind === 'notFound') {
    return (
      <SectionPage eyebrow={eyebrow} title={messages.apisTitle} data-testid="api-page">
        <div className={pageStyles.section} data-testid="api-not-found">
          <EmptyState message={messages.apiNotFound} />
        </div>
      </SectionPage>
    );
  }

  if (load.kind === 'failed') {
    return (
      <SectionPage eyebrow={eyebrow} title={messages.apisTitle} data-testid="api-page">
        <Banner tone="bad" action={{ label: messages.retry, onClick: () => setAttempt((n) => n + 1) }} data-testid="api-load-failed">
          <p>{messages.loadFailed}</p>
          <ErrorReference code={load.failure.code} traceId={load.failure.traceId} />
        </Banner>
      </SectionPage>
    );
  }

  const { detail } = load;
  const saved = (next: ApiResourceDetail) => setLoad({ kind: 'ready', detail: next });
  return (
    <SectionPage
      eyebrow={eyebrow}
      title={
        <span className={pageStyles.title}>
          <bdi data-testid="api-title">{detail.api.name}</bdi>
          {detail.api.builtIn && <ProtocolBadge data-testid="api-built-in">{messages.apiBuiltIn}</ProtocolBadge>}
        </span>
      }
      data-testid="api-page"
    >
      <div className={pageStyles.section}>
        <ApiSettings request={request} tenantId={tenantId} detail={detail} canManage={canManage} onSaved={saved} />
      </div>
      <div className={pageStyles.section}>
        <ApiPermissions request={request} tenantId={tenantId} detail={detail} canManage={canManage} onChanged={saved} />
      </div>
    </SectionPage>
  );
}

/** What the settings form holds: the two switches and each lifetime's text, as typed. */
type Draft = { offlineAccess: boolean; rbac: boolean } & Record<LifetimeField, string>;

type Errors = Partial<Record<LifetimeField, string>>;

function draftOf(detail: ApiResourceDetail): Draft {
  return {
    offlineAccess: detail.api.offlineAccess,
    rbac: detail.api.rbac,
    accessTokenLifetime: String(detail.api.accessTokenLifetime),
    idTokenLifetime: String(detail.api.idTokenLifetime),
    refreshTokenAbsoluteLifetime: String(detail.api.refreshTokenAbsoluteLifetime),
    refreshTokenInactivityLifetime: String(detail.api.refreshTokenInactivityLifetime),
  };
}

/** "Maximum is 1 hour." for a limit in seconds: the Tokens tab's wording. */
function maximumText(maximum: number, messages: Messages): string {
  return formatMessage(messages.applicationTokensMaximum, { limit: durationText(maximum, messages) });
}

function serverReasonText(error: ApiProblemError, messages: Messages): string {
  if (error.reason === 'above_maximum' && typeof error.maximum === 'number') return maximumText(error.maximum, messages);
  if (error.reason === 'below_minimum') return messages.applicationTokensMinimum;
  return messages.applicationTokensNotWhole;
}

const LIFETIME_LABELS: Record<LifetimeField, (messages: Messages) => string> = {
  accessTokenLifetime: (m) => m.applicationTokensAccessLifetime,
  idTokenLifetime: (m) => m.applicationTokensIdLifetime,
  refreshTokenAbsoluteLifetime: (m) => m.applicationTokensAbsoluteLifetime,
  refreshTokenInactivityLifetime: (m) => m.applicationTokensInactivityLifetime,
};

interface ApiSettingsProps {
  request: ShellRequest;
  tenantId: string;
  detail: ApiResourceDetail;
  canManage: boolean;
  onSaved: (detail: ApiResourceDetail) => void;
}

/**
 * The API's Settings card: its identifier, locked; offline access ("Issue refresh tokens for this API"); Enable RBAC; and
 * the four token lifetimes, each checked as the Tokens tab checks an Application's, "Maximum is {limit}." over its hard
 * limit, before anything is sent. A save shows a toast. The server checks every value again.
 */
function ApiSettings({ request, tenantId, detail, canManage, onSaved }: ApiSettingsProps) {
  const messages = useMessages();
  const toast = useToast();
  const [draft, setDraft] = useState<Draft>(() => draftOf(detail));
  const [errors, setErrors] = useState<Errors>({});
  const [refusal, setRefusal] = useState<Refusal>(null);
  const [saving, setSaving] = useState(false);
  const inFlight = useRef(false);
  const inputs: Record<LifetimeField, RefObject<HTMLInputElement | null>> = {
    accessTokenLifetime: useRef<HTMLInputElement>(null),
    idTokenLifetime: useRef<HTMLInputElement>(null),
    refreshTokenAbsoluteLifetime: useRef<HTMLInputElement>(null),
    refreshTokenInactivityLifetime: useRef<HTMLInputElement>(null),
  };

  const stored = draftOf(detail);
  const dirty =
    draft.offlineAccess !== stored.offlineAccess ||
    draft.rbac !== stored.rbac ||
    LIFETIME_FIELDS.some((field) => draft[field].trim() !== stored[field]);
  useUnsavedChanges(dirty && !saving);

  function showErrors(next: Errors) {
    setErrors(next);
    const first = LIFETIME_FIELDS.find((field) => next[field]);
    if (first) inputs[first].current?.focus();
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canManage || inFlight.current) return;

    const seconds = {} as Record<LifetimeField, number>;
    const found: Errors = {};
    for (const field of LIFETIME_FIELDS) {
      const check = checkLifetime(field, draft[field]);
      if (check.kind === 'ok') seconds[field] = check.seconds;
      else if (check.kind === 'aboveMaximum') found[field] = maximumText(check.maximum, messages);
      else if (check.kind === 'belowMinimum') found[field] = messages.applicationTokensMinimum;
      else found[field] = messages.applicationTokensNotWhole;
    }
    if (Object.keys(found).length > 0) {
      showErrors(found);
      return;
    }

    inFlight.current = true;
    setSaving(true);
    setRefusal(null);
    const body: ApiSettingsRequest = {
      offlineAccess: draft.offlineAccess,
      rbac: draft.rbac,
      accessTokenLifetime: seconds.accessTokenLifetime,
      idTokenLifetime: seconds.idTokenLifetime,
      refreshTokenAbsoluteLifetime: seconds.refreshTokenAbsoluteLifetime,
      refreshTokenInactivityLifetime: seconds.refreshTokenInactivityLifetime,
    };

    let answer;
    try {
      answer = await request('put', () => api.updateApiSettings(tenantId, detail.api.id, body));
    } catch {
      answer = null;
    }
    inFlight.current = false;
    setSaving(false);

    if (answer?.ok && answer.data && typeof answer.data.api?.id === 'string') {
      setErrors({});
      setDraft(draftOf(answer.data));
      onSaved(answer.data);
      toast(messages.applicationSaved);
      return;
    }
    if (answer?.status === 401) return;
    const problem = answer && !answer.ok ? answer.problem : null;
    if (answer?.status === 400 && problem?.code === 'api_invalid' && problem.errors && problem.errors.length > 0) {
      const next: Errors = {};
      for (const error of problem.errors) {
        if ((LIFETIME_FIELDS as readonly string[]).includes(error.field)) next[error.field as LifetimeField] ??= serverReasonText(error, messages);
      }
      if (Object.keys(next).length > 0) {
        showErrors(next);
        return;
      }
    }
    if (answer?.status === 409 && problem?.code === 'tenant_mismatch') return;
    if (answer?.status === 403) {
      setRefusal({ kind: 'forbidden' });
      return;
    }
    setRefusal({ kind: 'saveFailed', code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' });
  }

  const lifetimeField = (field: LifetimeField) => {
    const check = checkLifetime(field, draft[field]);
    const unit =
      check.kind === 'ok' || check.kind === 'aboveMaximum'
        ? formatMessage(messages.applicationTokensSecondsHint, { duration: durationText(Number(draft[field].trim()), messages) })
        : messages.applicationTokensSeconds;
    return (
      <Field
        key={field}
        label={LIFETIME_LABELS[field](messages)}
        helper={formatMessage(messages.applicationTokensDefault, { duration: durationText(LIFETIME_DEFAULTS[field], messages) })}
        error={errors[field]}
      >
        <span className={cards.input}>
          <Input
            ref={inputs[field]}
            code
            inputMode="numeric"
            autoComplete="off"
            spellCheck={false}
            value={draft[field]}
            aria-describedby={`api-${field}-unit`}
            readOnly={!canManage || saving}
            onChange={(event) => {
              const value = event.target.value;
              setDraft((now) => ({ ...now, [field]: value }));
              if (errors[field]) setErrors((now) => ({ ...now, [field]: undefined }));
            }}
            data-testid={`api-${field}`}
          />
          <span id={`api-${field}-unit`} className={cards.unit}>
            {unit}
          </span>
        </span>
      </Field>
    );
  };

  return (
    <form className={cards.form} onSubmit={submit} noValidate data-testid="api-settings">
      {refusal?.kind === 'saveFailed' && (
        <Banner tone="bad" data-testid="api-settings-save-failed">
          <p>{messages.applicationSaveFailed}</p>
          <ErrorReference code={refusal.code} traceId={refusal.traceId} />
        </Banner>
      )}
      {refusal?.kind === 'forbidden' && (
        <Banner tone="bad" data-testid="api-settings-save-forbidden">
          {messages.actionForbidden}
        </Banner>
      )}

      <section className={cards.card} aria-labelledby="api-settings-heading">
        <header className={cards.cardHeader}>
          <h2 id="api-settings-heading">{messages.apiSettingsTitle}</h2>
        </header>
        <div className={styles.identifier}>
          <span id="api-identifier-label">{messages.apiIdentifier}</span>
          <code aria-labelledby="api-identifier-label" data-testid="api-identifier">
            {detail.api.identifier}
          </code>
          <span data-testid="api-identifier-locked">{messages.apiIdentifierLocked}</span>
        </div>
        <div className={styles.rows}>
          <SettingsRow label={messages.apiOfflineAccess} description={messages.apiOfflineAccessDescription}>
            <Toggle
              label={messages.apiOfflineAccess}
              hideLabel
              checked={draft.offlineAccess}
              disabled={!canManage || saving}
              onCheckedChange={(on) => setDraft((now) => ({ ...now, offlineAccess: on }))}
              data-testid="api-offline-access"
            />
          </SettingsRow>
          <SettingsRow label={messages.apiRbac} description={messages.apiRbacDescription}>
            <Toggle
              label={messages.apiRbac}
              hideLabel
              checked={draft.rbac}
              disabled={!canManage || saving}
              onCheckedChange={(on) => setDraft((now) => ({ ...now, rbac: on }))}
              data-testid="api-rbac"
            />
          </SettingsRow>
        </div>
      </section>

      <section className={cards.card} aria-labelledby="api-tokens-heading">
        <header className={cards.cardHeader}>
          <h2 id="api-tokens-heading">{messages.apiTokensTitle}</h2>
          <p>{messages.apiTokensDescription}</p>
        </header>
        <div className={cards.cardBody}>{LIFETIME_FIELDS.map(lifetimeField)}</div>
      </section>

      {canManage ? (
        <div className={cards.actions}>
          <Button type="submit" variant="primary" pending={saving} data-testid="api-settings-save">
            {messages.applicationSave}
          </Button>
        </div>
      ) : (
        <p className={cards.note} data-testid="api-settings-read-only">
          {messages.apiReadOnly}
        </p>
      )}
    </form>
  );
}

interface ApiPermissionsProps {
  request: ShellRequest;
  tenantId: string;
  detail: ApiResourceDetail;
  canManage: boolean;
  onChanged: (detail: ApiResourceDetail) => void;
}

/**
 * The API's Permissions card: each resource:action and its description, with Remove; "No permissions yet" with Add when
 * there are none. The built-in Management API's are fixed, so it has neither Add nor Remove, and neither does a caller
 * without tenant.apis.manage.
 */
function ApiPermissions({ request, tenantId, detail, canManage, onChanged }: ApiPermissionsProps) {
  const messages = useMessages();
  const toast = useToast();
  const editable = canManage && !detail.api.builtIn;
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const [failure, setFailure] = useState<Failure | { kind: 'forbidden' } | null>(null);

  async function remove(permission: ApiPermission) {
    if (removing !== null) return;
    setRemoving(permission.value);
    setFailure(null);
    let answer;
    try {
      answer = await request('delete', () => api.removeApiPermission(tenantId, detail.api.id, permission.value));
    } catch {
      answer = null;
    }
    setRemoving(null);
    // A 404 is a Permission already removed elsewhere: it is gone either way, so its row goes too.
    if (answer?.ok || answer?.status === 404) {
      onChanged({ ...detail, permissions: detail.permissions.filter((p) => p.value !== permission.value) });
      if (answer.ok) toast(messages.apiPermissionRemoved);
      return;
    }
    if (answer?.status === 401) return;
    const problem = answer && !answer.ok ? answer.problem : null;
    if (answer?.status === 409 && problem?.code === 'tenant_mismatch') return;
    if (answer?.status === 403) {
      setFailure({ kind: 'forbidden' });
      return;
    }
    setFailure({ code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' });
  }

  const columns: DataTableColumn<ApiPermission>[] = [
    {
      key: 'value',
      header: messages.apiPermissionsColumnValue,
      rowHeader: true,
      cell: (row) => (
        <code className={styles.value} data-testid="api-permission-value">
          {row.value}
        </code>
      ),
    },
    { key: 'description', header: messages.apiPermissionsColumnDescription, cell: (row) => <bdi>{row.description}</bdi> },
  ];
  if (editable) {
    columns.push({
      key: 'remove',
      header: messages.apiPermissionRemove,
      cell: (row) => (
        <Button
          variant="secondary"
          pending={removing === row.value}
          aria-label={formatMessage(messages.apiPermissionRemoveLabel, { value: row.value })}
          onClick={() => void remove(row)}
          data-testid="api-permission-remove"
        >
          {messages.apiPermissionRemove}
        </Button>
      ),
    });
  }

  const add = () => setAdding(true);
  return (
    <section className={cards.card} aria-labelledby="api-permissions-heading" data-testid="api-permissions">
      <header className={cards.cardHeader}>
        <div className={styles.headerRow}>
          <h2 id="api-permissions-heading">{messages.apiPermissionsTitle}</h2>
          {editable && detail.permissions.length > 0 && (
            <Button variant="secondary" onClick={add} data-testid="api-permission-add">
              {messages.apiPermissionAdd}
            </Button>
          )}
        </div>
        {detail.api.builtIn && <p data-testid="api-permissions-fixed">{messages.apiPermissionsBuiltIn}</p>}
      </header>
      <div className={styles.table}>
        {failure && 'kind' in failure && (
          <Banner tone="bad" data-testid="api-permission-forbidden">
            {messages.actionForbidden}
          </Banner>
        )}
        {failure && !('kind' in failure) && (
          <Banner tone="bad" data-testid="api-permission-failed">
            <p>{messages.apiPermissionFailed}</p>
            <ErrorReference code={failure.code} traceId={failure.traceId} />
          </Banner>
        )}
        <DataTable
          caption={messages.apiPermissionsTitle}
          hideCaption
          columns={columns}
          rows={detail.permissions}
          rowKey={(row) => row.value}
          pageSize={Math.max(detail.permissions.length, 1)}
          empty={
            <EmptyState
              message={messages.apiPermissionsEmpty}
              action={editable ? { label: messages.apiPermissionAdd, onClick: add } : undefined}
            />
          }
        />
      </div>
      {editable && (
        <AddPermissionModal
          open={adding}
          request={request}
          tenantId={tenantId}
          apiId={detail.api.id}
          onClose={() => setAdding(false)}
          onAdded={(next) => {
            setAdding(false);
            onChanged(next);
            toast(messages.apiPermissionAdded);
          }}
        />
      )}
    </section>
  );
}

interface AddPermissionModalProps {
  open: boolean;
  request: ShellRequest;
  tenantId: string;
  apiId: string;
  onClose: () => void;
  onAdded: (detail: ApiResourceDetail) => void;
}

/** Add permission: its resource:action value and an optional description. A duplicate shows inline under the value. */
function AddPermissionModal({ open, request, tenantId, apiId, onClose, onAdded }: AddPermissionModalProps) {
  const messages = useMessages();
  const [value, setValue] = useState('');
  const [description, setDescription] = useState('');
  const [valueError, setValueError] = useState<string | null>(null);
  const [descriptionError, setDescriptionError] = useState<string | null>(null);
  const [failure, setFailure] = useState<Failure | { kind: 'forbidden' | 'signedInAgain' } | null>(null);
  const [pending, setPending] = useState(false);
  const valueInput = useRef<HTMLInputElement>(null);
  const descriptionInput = useRef<HTMLInputElement>(null);
  const inFlight = useRef(false);

  function reset() {
    setValue('');
    setDescription('');
    setValueError(null);
    setDescriptionError(null);
    setFailure(null);
  }

  function close() {
    if (pending) return;
    reset();
    onClose();
  }

  async function submit(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    if (inFlight.current) return;
    const valueText = isPermissionValue(value) ? null : messages.apiPermissionValueInvalid;
    const descriptionText = isPermissionDescription(description) ? null : messages.apiPermissionDescriptionInvalid;
    if (valueText !== null || descriptionText !== null) {
      setValueError(valueText);
      setDescriptionError(descriptionText);
      (valueText !== null ? valueInput : descriptionInput).current?.focus();
      return;
    }

    inFlight.current = true;
    setPending(true);
    setFailure(null);
    let answer;
    try {
      answer = await request('post', () => api.addApiPermission(tenantId, apiId, { value, description: description.trim() }));
    } catch {
      answer = null;
    }
    inFlight.current = false;
    setPending(false);

    if (answer?.ok && answer.data && typeof answer.data.api?.id === 'string') {
      reset();
      onAdded(answer.data);
      return;
    }
    if (answer?.status === 401) {
      // The renewal brought the Admin back and didn't send it again: everything typed is kept.
      setFailure({ kind: 'signedInAgain' });
      return;
    }
    const problem = answer && !answer.ok ? answer.problem : null;
    if (answer?.status === 409 && problem?.code === 'tenant_mismatch') {
      close();
      return;
    }
    if (answer?.status === 409 && problem?.code === 'permission_taken') {
      setValueError(messages.apiPermissionTaken);
      valueInput.current?.focus();
      return;
    }
    if (answer?.status === 409 && problem?.code === 'permission_limit_reached') {
      setValueError(messages.apiPermissionLimit);
      valueInput.current?.focus();
      return;
    }
    if (answer?.status === 400 && problem?.code === 'api_invalid' && problem.errors && problem.errors.length > 0) {
      const valueRefused = problem.errors.some((e) => e.field === 'value');
      const descriptionRefused = problem.errors.some((e) => e.field === 'description');
      setValueError(valueRefused ? messages.apiPermissionValueInvalid : null);
      setDescriptionError(descriptionRefused ? messages.apiPermissionDescriptionInvalid : null);
      (valueRefused ? valueInput : descriptionInput).current?.focus();
      return;
    }
    if (answer?.status === 403) {
      setFailure({ kind: 'forbidden' });
      return;
    }
    setFailure({ code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' });
  }

  return (
    <Modal
      open={open}
      onClose={close}
      dismissible={!pending}
      title={messages.apiPermissionAddTitle}
      initialFocus={() => valueInput.current}
      fallbackFocus={() => document.querySelector<HTMLElement>('main h1')}
      data-testid="add-api-permission"
      footer={
        <>
          <Button aria-disabled={pending || undefined} onClick={close}>
            {messages.cancel}
          </Button>
          <Button variant="primary" pending={pending} onClick={() => void submit()} data-testid="add-api-permission-submit">
            {messages.apiPermissionAdd}
          </Button>
        </>
      }
    >
      <form className={pageStyles.form} noValidate onSubmit={(event) => void submit(event)}>
        {failure && !('kind' in failure) && (
          <Banner tone="bad" data-testid="add-api-permission-failed">
            <p>{messages.apiPermissionFailed}</p>
            <ErrorReference code={failure.code} traceId={failure.traceId} />
          </Banner>
        )}
        {failure && 'kind' in failure && failure.kind === 'signedInAgain' && (
          <Banner tone="bad" data-testid="add-api-permission-signed-in-again">
            {messages.actionRetryAfterSignIn}
          </Banner>
        )}
        {failure && 'kind' in failure && failure.kind === 'forbidden' && (
          <Banner tone="bad" data-testid="add-api-permission-forbidden">
            {messages.actionForbidden}
          </Banner>
        )}
        <Field label={messages.apiPermissionValue} helper={messages.apiPermissionValueHelper} error={valueError}>
          <Input
            ref={valueInput}
            name="value"
            value={value}
            code
            autoComplete="off"
            spellCheck={false}
            readOnly={pending}
            onChange={(event) => {
              setValue(event.currentTarget.value);
              setValueError(null);
            }}
            data-testid="add-api-permission-value"
          />
        </Field>
        <Field label={messages.apiPermissionDescription} error={descriptionError}>
          <Input
            ref={descriptionInput}
            name="description"
            value={description}
            autoComplete="off"
            readOnly={pending}
            onChange={(event) => {
              setDescription(event.currentTarget.value);
              setDescriptionError(null);
            }}
            data-testid="add-api-permission-description"
          />
        </Field>
        <button type="submit" hidden aria-hidden tabIndex={-1} />
      </form>
    </Modal>
  );
}
