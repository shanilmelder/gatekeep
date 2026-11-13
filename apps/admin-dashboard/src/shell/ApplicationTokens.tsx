import type { ApiProblemError, ApplicationResponse, ApplicationTokensRequest } from '@gatekeep/api-client';
import { Banner, Button, ErrorReference, Field, Input, formatMessage, useMessages, useToast } from '@gatekeep/ui/admin';
import { useEffect, useRef, useState, type FormEvent, type RefObject } from 'react';
import { api } from '../session';
import {
  LIFETIME_DEFAULTS,
  LIFETIME_FIELDS,
  checkLifetime,
  durationParts,
  lifetimeFields,
  type ApplicationKind,
  type LifetimeField,
} from './applications';
import type { ShellRequest } from './CredentialsPage';
import styles from './ApplicationTokens.module.css';
import { useUnsavedChanges } from './unsavedChanges';

type Messages = ReturnType<typeof useMessages>;

/** What the form holds: each field's text, as typed. */
type Draft = Record<LifetimeField, string>;

/** The error each field shows, from the browser's check or the server's answer. */
type Errors = Partial<Record<LifetimeField, string>>;

type Refusal = { kind: 'saveFailed'; code: string; traceId: string } | { kind: 'forbidden' } | null;

function draftOf(application: ApplicationResponse): Draft {
  return {
    accessTokenLifetime: String(application.accessTokenLifetime),
    idTokenLifetime: String(application.idTokenLifetime),
    refreshTokenAbsoluteLifetime: String(application.refreshTokenAbsoluteLifetime),
    refreshTokenInactivityLifetime: String(application.refreshTokenInactivityLifetime),
  };
}

/** A whole number of seconds as people read it, such as "15 minutes", "1 hour" or "30 days". */
export function durationText(seconds: number, messages: Messages): string {
  const words = durationParts(seconds).map(({ unit, count }) => {
    switch (unit) {
      case 'day':
        return count === 1 ? messages.durationDay : formatMessage(messages.durationDays, { count });
      case 'hour':
        return count === 1 ? messages.durationHour : formatMessage(messages.durationHours, { count });
      case 'minute':
        return count === 1 ? messages.durationMinute : formatMessage(messages.durationMinutes, { count });
      default:
        return count === 1 ? messages.durationSecond : formatMessage(messages.durationSeconds, { count });
    }
  });
  return words.reduce((first, second) => (first === '' ? second : formatMessage(messages.durationJoin, { first, second })), '');
}

/** "Maximum is 1 hour." for a limit in seconds. */
function maximumText(maximum: number, messages: Messages): string {
  return formatMessage(messages.applicationTokensMaximum, { limit: durationText(maximum, messages) });
}

/** The text a refused field shows, from the server's reason and, above the limit, its maximum. */
function serverReasonText(error: ApiProblemError, messages: Messages): string {
  if (error.reason === 'above_maximum' && typeof error.maximum === 'number') return maximumText(error.maximum, messages);
  if (error.reason === 'below_minimum') return messages.applicationTokensMinimum;
  return messages.applicationTokensNotWhole;
}

export interface ApplicationTokensProps {
  request: ShellRequest;
  tenantId: string;
  application: ApplicationResponse;
  /** Whether the caller holds tenant.applications.manage: without it every field is read-only and there is no Save. */
  canManage: boolean;
  /** The Application as the server saved it. */
  onSaved: (application: ApplicationResponse) => void;
  /** Whether the form holds unsaved changes, for the tabs' leave check. */
  onDirtyChange: (dirty: boolean) => void;
}

/**
 * An Application's Tokens tab (Story 3.4; design Application detail, Tokens, as the Design Delta trims it):
 * the Access token and ID token cards and the Refresh tokens card's absolute and inactivity lifetimes, each a
 * whole number of seconds with its duration beside it and its default below. A machine-to-machine Application
 * gets only an access token, so it shows only that, and Save sends its other lifetimes back unchanged. A value
 * over its hard limit is refused here with "Maximum is {limit}." and nothing is sent; the server checks again
 * and answers the same. There is no signing algorithm, rotation or reuse control: those are fixed.
 */
export function ApplicationTokens({ request, tenantId, application, canManage, onSaved, onDirtyChange }: ApplicationTokensProps) {
  const messages = useMessages();
  const toast = useToast();
  const kind = application.type as ApplicationKind;
  const shown = lifetimeFields(kind);
  const [draft, setDraft] = useState<Draft>(() => draftOf(application));
  const [errors, setErrors] = useState<Errors>({});
  const [refusal, setRefusal] = useState<Refusal>(null);
  const [saving, setSaving] = useState(false);
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);
  const inputs: Record<LifetimeField, RefObject<HTMLInputElement | null>> = {
    accessTokenLifetime: useRef<HTMLInputElement>(null),
    idTokenLifetime: useRef<HTMLInputElement>(null),
    refreshTokenAbsoluteLifetime: useRef<HTMLInputElement>(null),
    refreshTokenInactivityLifetime: useRef<HTMLInputElement>(null),
  };

  const stored = draftOf(application);
  const dirty = shown.some((field) => draft[field].trim() !== stored[field]);
  useUnsavedChanges(dirty && !saving);
  useEffect(() => onDirtyChange(dirty), [dirty, onDirtyChange]);

  /** Shows each error on its field, and moves focus to the first field in error. */
  function showErrors(next: Errors) {
    setErrors(next);
    const first = LIFETIME_FIELDS.find((field) => next[field] && shown.includes(field));
    if (first) inputs[first].current?.focus();
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canManage || inFlight.current) return;

    // The browser's check first: a value it refuses is never sent.
    const seconds = {} as Record<LifetimeField, number>;
    const found: Errors = {};
    for (const field of LIFETIME_FIELDS) {
      // A field the type doesn't show goes back as stored.
      const text = shown.includes(field) ? draft[field] : stored[field];
      const check = checkLifetime(field, text);
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

    const body: ApplicationTokensRequest = {
      accessTokenLifetime: seconds.accessTokenLifetime,
      idTokenLifetime: seconds.idTokenLifetime,
      refreshTokenAbsoluteLifetime: seconds.refreshTokenAbsoluteLifetime,
      refreshTokenInactivityLifetime: seconds.refreshTokenInactivityLifetime,
    };

    let answer;
    try {
      answer = await request('put', () => api.updateApplicationTokens(tenantId, application.id, body));
    } catch {
      answer = null;
    }
    inFlight.current = false;
    setSaving(false);

    if (answer?.ok && answer.data && typeof answer.data.id === 'string') {
      setErrors({});
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
      const next: Errors = {};
      for (const error of problem.errors) {
        if ((LIFETIME_FIELDS as readonly string[]).includes(error.field)) next[error.field as LifetimeField] ??= serverReasonText(error, messages);
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
    setRefusal({ kind: 'saveFailed', code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' });
  }

  const lifetimeField = (field: LifetimeField, label: string) => {
    const check = checkLifetime(field, draft[field]);
    const unit =
      check.kind === 'ok' || check.kind === 'aboveMaximum'
        ? formatMessage(messages.applicationTokensSecondsHint, { duration: durationText(Number(draft[field].trim()), messages) })
        : messages.applicationTokensSeconds;
    return (
      <Field
        label={label}
        helper={formatMessage(messages.applicationTokensDefault, { duration: durationText(LIFETIME_DEFAULTS[field], messages) })}
        error={errors[field]}
      >
        <span className={styles.input}>
          <Input
            ref={inputs[field]}
            code
            inputMode="numeric"
            autoComplete="off"
            spellCheck={false}
            value={draft[field]}
            aria-describedby={`application-${field}-unit`}
            readOnly={!canManage || saving}
            onChange={(event) => {
              const value = event.target.value;
              setDraft((now) => ({ ...now, [field]: value }));
              if (errors[field]) setErrors((now) => ({ ...now, [field]: undefined }));
            }}
            data-testid={`application-${field}`}
          />
          <span id={`application-${field}-unit`} className={styles.unit} data-testid={`application-${field}-hint`}>
            {unit}
          </span>
        </span>
      </Field>
    );
  };

  return (
    <form className={styles.form} onSubmit={submit} noValidate data-testid="application-tokens">
      {refusal?.kind === 'saveFailed' && (
        <Banner tone="bad" data-testid="application-tokens-save-failed">
          <p>{messages.applicationSaveFailed}</p>
          <ErrorReference code={refusal.code} traceId={refusal.traceId} />
        </Banner>
      )}
      {refusal?.kind === 'forbidden' && (
        <Banner tone="bad" data-testid="application-tokens-save-forbidden">
          {messages.actionForbidden}
        </Banner>
      )}

      <section className={styles.card} aria-labelledby="application-access-token-heading" data-testid="application-tokens-access">
        <header className={styles.cardHeader}>
          <h2 id="application-access-token-heading">{messages.applicationTokensAccessTitle}</h2>
        </header>
        <div className={styles.cardBody}>{lifetimeField('accessTokenLifetime', messages.applicationTokensAccessLifetime)}</div>
      </section>

      {shown.includes('idTokenLifetime') && (
        <section className={styles.card} aria-labelledby="application-id-token-heading" data-testid="application-tokens-id">
          <header className={styles.cardHeader}>
            <h2 id="application-id-token-heading">{messages.applicationTokensIdTitle}</h2>
          </header>
          <div className={styles.cardBody}>{lifetimeField('idTokenLifetime', messages.applicationTokensIdLifetime)}</div>
        </section>
      )}

      {shown.includes('refreshTokenAbsoluteLifetime') && (
        <section className={styles.card} aria-labelledby="application-refresh-tokens-heading" data-testid="application-tokens-refresh">
          <header className={styles.cardHeader}>
            <h2 id="application-refresh-tokens-heading">{messages.applicationTokensRefreshTitle}</h2>
            <p>{messages.applicationTokensRefreshDescription}</p>
          </header>
          <div className={styles.cardBody}>
            {lifetimeField('refreshTokenAbsoluteLifetime', messages.applicationTokensAbsoluteLifetime)}
            {lifetimeField('refreshTokenInactivityLifetime', messages.applicationTokensInactivityLifetime)}
          </div>
        </section>
      )}

      {canManage ? (
        <div className={styles.actions}>
          <Button type="submit" variant="primary" pending={saving} data-testid="application-tokens-save">
            {messages.applicationSave}
          </Button>
        </div>
      ) : (
        <p className={styles.note} data-testid="application-tokens-read-only">
          {messages.applicationSettingsReadOnly}
        </p>
      )}
    </form>
  );
}
