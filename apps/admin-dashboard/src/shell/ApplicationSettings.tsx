import type { ApiProblemError, ApplicationResponse, ApplicationSettingsRequest } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  Checkbox,
  ErrorReference,
  Field,
  SettingsRow,
  Textarea,
  Toggle,
  formatMessage,
  useMessages,
  useToast,
} from '@gatekeep/ui/admin';
import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode, type RefObject } from 'react';
import { api } from '../session';
import {
  GRANT_TYPES,
  grantAvailable,
  hasUrls,
  hasWebOrigins,
  newCustomSchemes,
  sameList,
  urlLines,
  urlText,
  type ApplicationKind,
  type GrantType,
} from './applications';
import { kindText } from './CreateApplicationModal';
import type { ShellRequest } from './CredentialsPage';
import type { FreshAssertion } from './freshAssertion';
import styles from './ApplicationSettings.module.css';
import { confirmationText } from './TenantSettingsPage';
import { useUnsavedChanges } from './unsavedChanges';

type Messages = ReturnType<typeof useMessages>;

type UrlField = 'callbackUrls' | 'logoutUrls' | 'webOrigins';

/** What the form holds: each textarea's text, each grant's switch, and the Prod acknowledgement. */
interface Draft {
  callbackUrls: string;
  logoutUrls: string;
  webOrigins: string;
  grants: Record<GrantType, boolean>;
  acknowledged: boolean;
}

/** The server's refusals, by field, as the text each field shows. */
type Errors = Partial<Record<UrlField | 'grantTypes', string[]>>;

type Refusal = { kind: 'saveFailed'; code: string; traceId: string } | { kind: 'forbidden' } | { kind: 'unconfirmed'; text: string } | null;

function draftOf(application: ApplicationResponse): Draft {
  const held = new Set<string>(application.grantTypes);
  return {
    callbackUrls: urlText(application.callbackUrls),
    logoutUrls: urlText(application.logoutUrls),
    webOrigins: urlText(application.webOrigins),
    grants: {
      authorization_code: held.has('authorization_code'),
      client_credentials: held.has('client_credentials'),
      refresh_token: held.has('refresh_token'),
    },
    acknowledged: false,
  };
}

/** The reason's text for a line or field the server refused. */
function reasonText(error: ApiProblemError, messages: Messages): string {
  switch (error.reason) {
    case 'not_absolute':
      return error.field === 'webOrigins' ? messages.applicationOriginNotAbsolute : messages.applicationUrlNotAbsolute;
    case 'wildcard':
      return messages.applicationUrlWildcard;
    case 'scheme_not_allowed':
      return messages.applicationUrlSchemeNotAllowed;
    case 'too_long':
      return messages.applicationUrlTooLong;
    case 'too_many':
      return messages.applicationUrlTooMany;
    case 'duplicate':
      return messages.applicationUrlDuplicate;
    default:
      return error.field === 'grantTypes' ? messages.applicationGrantsNotAllowed : messages.applicationUrlNotAllowedForType;
  }
}

export interface ApplicationSettingsProps {
  request: ShellRequest;
  fresh: FreshAssertion;
  tenantId: string;
  /** Whether the path Tenant is labelled Prod, as the switcher lists it: the server decides either way. */
  prod: boolean;
  application: ApplicationResponse;
  /** Whether the caller holds tenant.application_callbacks.manage: without it every field is read-only and there is no Save. */
  canManage: boolean;
  /** The Application as the server saved it. */
  onSaved: (application: ApplicationResponse) => void;
  /** Whether the form holds unsaved changes, for the tabs' leave check. */
  onDirtyChange: (dirty: boolean) => void;
}

/**
 * An Application's Settings tab (Story 3.2; design Application detail, Settings, as the Design Delta
 * trims it): the Application URLs card, one URL per line in the code type, matched exactly with no
 * wildcard, and the Grant types card's three switches. Machine-to-machine has no URL card, and native
 * shows the system-browser guidance and no web origins. Save sends the full settings once; in a Prod
 * Tenant the server may ask for a fresh assertion, which the sheet confirms before it is sent once
 * more, and a new custom-scheme URL needs the Admin's acknowledgement. Every refused line shows on its
 * field by its line number. The server decides every rule; this form only follows its answers.
 */
export function ApplicationSettings({ request, fresh, tenantId, prod, application, canManage, onSaved, onDirtyChange }: ApplicationSettingsProps) {
  const messages = useMessages();
  const toast = useToast();
  const kind = application.type as ApplicationKind;
  const [draft, setDraft] = useState<Draft>(() => draftOf(application));
  const [errors, setErrors] = useState<Errors>({});
  const [ackError, setAckError] = useState(false);
  // The server asked for the acknowledgement, whatever the page thought the label was (a stale or unlisted Tenant).
  const [ackRequired, setAckRequired] = useState(false);
  const [focusAcknowledgement, setFocusAcknowledgement] = useState(0);
  useEffect(() => {
    if (focusAcknowledgement > 0) acknowledgement.current?.focus();
  }, [focusAcknowledgement]);
  const [refusal, setRefusal] = useState<Refusal>(null);
  const [saving, setSaving] = useState(false);
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);
  const fields: Record<UrlField, RefObject<HTMLTextAreaElement | null>> = {
    callbackUrls: useRef<HTMLTextAreaElement>(null),
    logoutUrls: useRef<HTMLTextAreaElement>(null),
    webOrigins: useRef<HTMLTextAreaElement>(null),
  };
  const acknowledgement = useRef<HTMLInputElement>(null);
  const firstGrant = useRef<HTMLButtonElement>(null);

  const lines = useMemo(
    () => ({
      callbackUrls: urlLines(draft.callbackUrls),
      logoutUrls: urlLines(draft.logoutUrls),
      webOrigins: urlLines(draft.webOrigins),
    }),
    [draft.callbackUrls, draft.logoutUrls, draft.webOrigins],
  );
  const urls = hasUrls(kind);
  const origins = hasWebOrigins(kind);
  const callbacks = urls ? lines.callbackUrls.values : [];
  const logouts = urls ? lines.logoutUrls.values : [];
  const webOrigins = origins ? lines.webOrigins.values : [];
  const grantTypes = GRANT_TYPES.filter((grant) => draft.grants[grant] && grantAvailable(kind, grant));

  const dirty =
    !sameList(callbacks, application.callbackUrls) ||
    !sameList(logouts, application.logoutUrls) ||
    !sameList(webOrigins, application.webOrigins) ||
    !sameList(grantTypes, application.grantTypes);
  useUnsavedChanges(dirty && !saving);
  useEffect(() => onDirtyChange(dirty), [dirty, onDirtyChange]);

  // A Prod Tenant's new custom-scheme callback or logout URL is acknowledged before Save (the server still decides).
  const needsAcknowledgement =
    ackRequired ||
    (prod && (newCustomSchemes(callbacks, application.callbackUrls).length > 0 || newCustomSchemes(logouts, application.logoutUrls).length > 0));

  function edit(change: Partial<Draft>) {
    setDraft((now) => ({ ...now, ...change }));
  }

  function setGrant(grant: GrantType, on: boolean) {
    setDraft((now) => {
      const grants = { ...now.grants, [grant]: on };
      // Refresh tokens come only with the code flow.
      if (grant === 'authorization_code' && !on) grants.refresh_token = false;
      return { ...now, grants };
    });
  }

  /** Shows each refused line on its field, and moves focus to the first field in error. */
  function showErrors(list: readonly ApiProblemError[]) {
    const next: Errors = {};
    for (const error of list) {
      // A settings save names only its own fields; the tokens save's (Story 3.4) never come here.
      if (error.field !== 'grantTypes' && error.field !== 'callbackUrls' && error.field !== 'logoutUrls' && error.field !== 'webOrigins') continue;
      const reason = reasonText(error, messages);
      const field = error.field;
      const line = field === 'grantTypes' || error.index === null ? undefined : lines[field as UrlField]?.lines[error.index];
      const text = line === undefined ? reason : formatMessage(messages.applicationUrlLine, { line, reason });
      (next[field] ??= []).push(text);
    }
    setErrors(next);
    const first = (['callbackUrls', 'logoutUrls', 'webOrigins'] as const).find((field) => next[field]);
    if (first) fields[first].current?.focus();
    else if (next.grantTypes) firstGrant.current?.focus();
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canManage || inFlight.current) return;
    if (needsAcknowledgement && !draft.acknowledged) {
      setAckError(true);
      acknowledgement.current?.focus();
      return;
    }

    inFlight.current = true;
    setSaving(true);
    setRefusal(null);
    setAckError(false);

    const body: ApplicationSettingsRequest = {
      callbackUrls: callbacks,
      logoutUrls: logouts,
      webOrigins,
      grantTypes,
      ...(needsAcknowledgement ? { acknowledgeCustomScheme: draft.acknowledged } : {}),
    };
    const put = () => request('put', () => api.updateApplicationSettings(tenantId, application.id, body));

    let outcome;
    try {
      outcome = await fresh.withFreshAssertion({ action: 'tenant.application_callbacks.manage', target: application.id, tenantId }, put);
    } catch {
      outcome = null;
    }
    inFlight.current = false;
    setSaving(false);

    if (outcome?.kind === 'unconfirmed') {
      setRefusal({ kind: 'unconfirmed', text: confirmationText(outcome.confirmation, messages) });
      return;
    }
    const answer = outcome?.answer ?? null;
    if (answer?.ok && answer.data && typeof answer.data.id === 'string') {
      setErrors({});
      setAckRequired(false);
      setDraft(draftOf(answer.data));
      onSaved(answer.data);
      toast(messages.applicationSaved);
      return;
    }
    if (answer?.status === 401) {
      // The renewal brought the Admin back and didn't send it again: everything typed is kept.
      return;
    }
    const problem = answer && !answer.ok ? answer.problem : null;
    if (answer?.status === 400 && problem?.code === 'application_invalid' && problem.errors && problem.errors.length > 0) {
      showErrors(problem.errors);
      return;
    }
    if (answer?.status === 400 && problem?.code === 'custom_scheme_acknowledgement_required') {
      // The checkbox shows from now on, if it didn't, and the next save carries it; focus moves once it renders.
      setAckRequired(true);
      setAckError(true);
      setFocusAcknowledgement((n) => n + 1);
      return;
    }
    if (answer?.status === 409 && problem?.code === 'tenant_mismatch') {
      // The shell's banner names both Tenants: nothing else here.
      return;
    }
    if (answer?.status === 403) {
      // access_denied, or the bodiless 403 of an earlier check: the server refuses this outright.
      setRefusal({ kind: 'forbidden' });
      return;
    }
    setRefusal({ kind: 'saveFailed', code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' });
  }

  const typeName = kindText(kind, messages).name;
  const helper = (values: readonly string[]) => (values.length === 0 ? messages.applicationUrlsEmptyHelper : messages.applicationUrlsHelper);
  const fieldError = (field: UrlField | 'grantTypes'): ReactNode =>
    errors[field] ? (
      <span className={styles.errors}>
        {errors[field]!.map((text, index) => (
          <span key={index}>{text}</span>
        ))}
      </span>
    ) : undefined;

  const urlField = (field: UrlField, label: string) => (
    <Field label={label} helper={helper(lines[field].values)} error={fieldError(field)}>
      <Textarea
        ref={fields[field]}
        value={draft[field]}
        readOnly={!canManage || saving}
        rows={4}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        onChange={(event) => {
          edit({ [field]: event.target.value } as Partial<Draft>);
          if (errors[field]) setErrors((now) => ({ ...now, [field]: undefined }));
        }}
        data-testid={`application-${field}`}
      />
    </Field>
  );

  const grantRow = (grant: GrantType, label: string, description: string, ref?: RefObject<HTMLButtonElement | null>) => {
    const available = grantAvailable(kind, grant);
    const needsCode = grant === 'refresh_token' && !draft.grants.authorization_code;
    const reason = !available ? formatMessage(messages.applicationGrantNotAvailable, { type: typeName }) : needsCode ? messages.applicationGrantNeedsCode : null;
    return (
      <SettingsRow label={label} description={reason ?? description}>
        <Toggle
          ref={ref}
          label={label}
          hideLabel
          checked={available && draft.grants[grant]}
          disabled={!canManage || !available || needsCode || saving}
          onCheckedChange={(on) => {
            setGrant(grant, on);
            if (errors.grantTypes) setErrors((now) => ({ ...now, grantTypes: undefined }));
          }}
          data-testid={`application-grant-${grant}`}
        />
      </SettingsRow>
    );
  };

  return (
    <form className={styles.form} onSubmit={submit} noValidate data-testid="application-settings">
      {refusal?.kind === 'saveFailed' && (
        <Banner tone="bad" data-testid="application-save-failed">
          <p>{messages.applicationSaveFailed}</p>
          <ErrorReference code={refusal.code} traceId={refusal.traceId} />
        </Banner>
      )}
      {refusal?.kind === 'forbidden' && (
        <Banner tone="bad" data-testid="application-save-forbidden">
          {messages.actionForbidden}
        </Banner>
      )}
      {refusal?.kind === 'unconfirmed' && (
        <Banner tone="bad" data-testid="fresh-assertion-failed">
          {refusal.text}
        </Banner>
      )}
      {kind === 'native' && (
        <Banner tone="info" live={false} data-testid="application-native-guidance">
          {messages.applicationNativeGuidance}
        </Banner>
      )}

      {urls ? (
        <section className={styles.card} aria-labelledby="application-urls-heading" data-testid="application-urls">
          <header className={styles.cardHeader}>
            <h2 id="application-urls-heading">{messages.applicationUrlsTitle}</h2>
          </header>
          <div className={styles.cardBody}>
            {urlField('callbackUrls', messages.applicationCallbackUrls)}
            {urlField('logoutUrls', messages.applicationLogoutUrls)}
            {origins && urlField('webOrigins', messages.applicationWebOrigins)}
          </div>
        </section>
      ) : (
        <p className={styles.note} data-testid="application-machine-no-urls">
          {messages.applicationMachineNoUrls}
        </p>
      )}

      <section className={styles.card} aria-labelledby="application-grants-heading" data-testid="application-grants">
        <header className={styles.cardHeader}>
          <h2 id="application-grants-heading">{messages.applicationGrantsTitle}</h2>
          <p>{messages.applicationGrantsDescription}</p>
        </header>
        <div>
          {grantRow(
            'authorization_code',
            messages.applicationGrantAuthorizationCode,
            messages.applicationGrantAuthorizationCodeDescription,
            kind === 'machine' ? undefined : firstGrant,
          )}
          {grantRow('refresh_token', messages.applicationGrantRefreshToken, messages.applicationGrantRefreshTokenDescription)}
          {grantRow(
            'client_credentials',
            messages.applicationGrantClientCredentials,
            messages.applicationGrantClientCredentialsDescription,
            kind === 'machine' ? firstGrant : undefined,
          )}
        </div>
        {errors.grantTypes && (
          <p className={styles.grantError} role="status" data-testid="application-grants-error">
            {errors.grantTypes.join(' ')}
          </p>
        )}
      </section>

      {canManage && needsAcknowledgement && (
        <div className={styles.acknowledgement} data-testid="application-custom-scheme">
          <Checkbox
            ref={acknowledgement}
            label={messages.applicationCustomSchemeAcknowledge}
            checked={draft.acknowledged}
            aria-invalid={ackError || undefined}
            aria-describedby={ackError ? 'application-custom-scheme-error' : undefined}
            onChange={(event) => {
              edit({ acknowledged: event.target.checked });
              if (event.target.checked) setAckError(false);
            }}
            data-testid="application-custom-scheme-acknowledge"
          />
          {ackError && (
            <p id="application-custom-scheme-error" className={styles.grantError} data-testid="application-custom-scheme-error">
              {messages.applicationCustomSchemeRequired}
            </p>
          )}
        </div>
      )}

      {canManage ? (
        <div className={styles.actions}>
          <Button type="submit" variant="primary" pending={saving} data-testid="application-save">
            {messages.applicationSave}
          </Button>
        </div>
      ) : (
        <p className={styles.note} data-testid="application-settings-read-only">
          {messages.applicationSettingsReadOnly}
        </p>
      )}
    </form>
  );
}
