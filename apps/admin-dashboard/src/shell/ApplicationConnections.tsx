import type { ApplicationConnectionResponse, ApplicationResponse } from '@gatekeep/api-client';
import {
  Banner,
  ErrorReference,
  ProtocolBadge,
  SettingsRow,
  SkeletonRows,
  Toggle,
  formatMessage,
  useMessages,
  useToast,
} from '@gatekeep/ui/admin';
import { useEffect, useRef, useState } from 'react';
import { api } from '../session';
import type { ShellRequest } from './CredentialsPage';
import { anyUsable } from './database';
import styles from './ApplicationConnections.module.css';

type Messages = ReturnType<typeof useMessages>;

type Failure = { code: string; traceId: string };

type Load =
  | { kind: 'loading' }
  | { kind: 'ready'; connections: ApplicationConnectionResponse[] }
  | { kind: 'failed'; failure: Failure };

/** Why the last toggle didn't save, shown above the card. */
type Refusal = { kind: 'saveFailed'; failure: Failure } | { kind: 'forbidden' } | { kind: 'notActive' } | null;

function failureOf(result: { ok: boolean; problem?: { code?: string; traceId?: string } | null } | null): Failure {
  const problem = result && !result.ok ? result.problem : null;
  return { code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' };
}

/** A Connection kind as people read it. In v1 there is only the database one. */
function kindName(kind: string, messages: Messages): string {
  return kind === 'database' ? messages.applicationConnectionKindDatabase : kind;
}

/** A Connection kind's badge. In v1 there is only the database one. */
function kindBadge(kind: string, messages: Messages): string {
  return kind === 'database' ? messages.databaseBadge : kind;
}

export interface ApplicationConnectionsProps {
  request: ShellRequest;
  tenantId: string;
  application: ApplicationResponse;
  /** Whether the caller holds tenant.connections.toggle: without it every toggle is read-only. */
  canToggle: boolean;
}

/**
 * An Application's Connections tab (Story 4.12; design Application detail, Connections, as the Design Delta trims it to
 * the database Connection): "Connections enabled for this app", one row per Connection with its badge, name, kind, state
 * and switch. A switch saves at once, one at a time, with "Changes saved"; a refusal puts it back and says why. Without
 * tenant.connections.toggle the switches are read-only under the view-only banner. With no Connection both on here and
 * in the Tenant, a banner says Users can't sign in.
 */
export function ApplicationConnections({ request, tenantId, application, canToggle }: ApplicationConnectionsProps) {
  const messages = useMessages();
  const toast = useToast();
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);
  const [refusal, setRefusal] = useState<Refusal>(null);
  const [saving, setSaving] = useState<string | null>(null);
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);

  useEffect(() => {
    const controller = new AbortController();
    setLoad({ kind: 'loading' });

    void (async () => {
      let result;
      try {
        result = await request('get', () => api.listApplicationConnections(tenantId, application.id), controller.signal);
      } catch {
        result = null;
      }
      if (controller.signal.aborted) return;
      const connections = result?.ok ? result.data?.connections : undefined;
      if (Array.isArray(connections)) setLoad({ kind: 'ready', connections });
      else setLoad({ kind: 'failed', failure: failureOf(result) });
    })();

    return () => controller.abort();
  }, [request, tenantId, application.id, attempt]);

  function replace(connection: ApplicationConnectionResponse) {
    setLoad((now) =>
      now.kind === 'ready'
        ? { kind: 'ready', connections: now.connections.map((c) => (c.connectionId === connection.connectionId ? connection : c)) }
        : now,
    );
  }

  async function toggle(connection: ApplicationConnectionResponse, enabled: boolean) {
    if (!canToggle || inFlight.current) return;
    inFlight.current = true;
    setSaving(connection.connectionId);
    setRefusal(null);
    // Shown at once; put back if the server refuses it.
    replace({ ...connection, enabled });

    let answer;
    try {
      answer = await request('put', () => api.setApplicationConnection(tenantId, application.id, connection.connectionId, { enabled }));
    } catch {
      answer = null;
    }
    inFlight.current = false;
    setSaving(null);

    if (answer?.ok && answer.data && typeof answer.data.enabled === 'boolean') {
      replace(answer.data);
      toast(messages.applicationConnectionsSaved);
      return;
    }

    replace(connection);
    // The renewal brought the Admin back and didn't send it again; the shell's banner names a Tenant mismatch.
    if (answer?.status === 401) return;
    const problem = answer && !answer.ok ? (answer.problem ?? null) : null;
    if (answer?.status === 409 && problem?.code === 'tenant_mismatch') return;
    if (answer?.status === 409 && problem?.code === 'tenant_not_active') setRefusal({ kind: 'notActive' });
    else if (answer?.status === 403) setRefusal({ kind: 'forbidden' });
    else setRefusal({ kind: 'saveFailed', failure: failureOf(answer) });
  }

  if (load.kind === 'loading') return <SkeletonRows rows={1} caption={false} />;

  if (load.kind === 'failed') {
    return (
      <Banner tone="bad" action={{ label: messages.retry, onClick: () => setAttempt((n) => n + 1) }} data-testid="application-connections-load-failed">
        <p>{messages.loadFailed}</p>
        <ErrorReference code={load.failure.code} traceId={load.failure.traceId} />
      </Banner>
    );
  }

  return (
    <div className={styles.tab} data-testid="application-connections">
      {!canToggle && (
        <Banner tone="info" live={false} data-testid="tenant-view-only">
          {messages.tenantViewOnly}
        </Banner>
      )}
      {!anyUsable(load.connections) && (
        <Banner tone="warn" live={false} data-testid="application-connections-none">
          {messages.applicationConnectionsNone}
        </Banner>
      )}
      {refusal?.kind === 'saveFailed' && (
        <Banner tone="bad" data-testid="application-connections-save-failed">
          <p>{messages.applicationConnectionsSaveFailed}</p>
          <ErrorReference code={refusal.failure.code} traceId={refusal.failure.traceId} />
        </Banner>
      )}
      {refusal?.kind === 'forbidden' && (
        <Banner tone="bad" data-testid="application-connections-save-forbidden">
          {messages.actionForbidden}
        </Banner>
      )}
      {refusal?.kind === 'notActive' && (
        <Banner tone="warn" data-testid="application-connections-not-active">
          {messages.tenantNotActive}
        </Banner>
      )}

      <section className={styles.card} aria-labelledby="application-connections-heading">
        <header className={styles.cardHeader}>
          <h2 id="application-connections-heading">{messages.applicationConnectionsTitle}</h2>
          <p>{formatMessage(messages.applicationConnectionsDescription, { application: application.name })}</p>
        </header>
        <div className={styles.rows}>
          {load.connections.map((connection) => (
            <SettingsRow
              key={connection.connectionId}
              label={
                <span className={styles.connection}>
                  <ProtocolBadge>{kindBadge(connection.kind, messages)}</ProtocolBadge>
                  <bdi data-testid={`application-connection-${connection.connectionId}-name`}>{connection.name}</bdi>
                </span>
              }
              description={
                <span className={styles.meta}>
                  <span>{kindName(connection.kind, messages)}</span>
                  <span aria-hidden="true">·</span>
                  <span data-testid={`application-connection-${connection.connectionId}-state`}>
                    {connection.enabled ? messages.applicationConnectionEnabled : messages.applicationConnectionDisabled}
                  </span>
                </span>
              }
            >
              <Toggle
                label={connection.name}
                hideLabel
                checked={connection.enabled}
                disabled={!canToggle || saving !== null}
                aria-busy={saving === connection.connectionId || undefined}
                onCheckedChange={(on) => void toggle(connection, on)}
                data-testid={`application-connection-${connection.connectionId}`}
              />
            </SettingsRow>
          ))}
        </div>
      </section>
    </div>
  );
}
