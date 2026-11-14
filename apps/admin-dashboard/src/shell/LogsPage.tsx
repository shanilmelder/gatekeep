import type { TenantLogEvent, TenantLogEventDetail, TenantLogsResponse } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  CodeBadge,
  DataTable,
  EmptyState,
  ErrorReference,
  EventDrawer,
  Field,
  Input,
  SectionPage,
  Select,
  SkeletonRows,
  useMessages,
  useUrlParams,
  type DataTableColumn,
  type EventSummaryRow,
} from '@gatekeep/ui/admin';
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { api } from '../session';
import type { ShellRequest } from './CredentialsPage';
import styles from './LogsPage.module.css';
import { eventSummary } from './logEvent';
import {
  OUTCOMES,
  RANGES,
  choices,
  fieldsOf,
  initialValue,
  isChoice,
  isField,
  paramsOf,
  queryOf,
  referenceOf,
  searchOf,
  utcTime,
  type LogField,
  type LogQuery,
  type LogSearch,
} from './logs';

type Messages = ReturnType<typeof useMessages>;

/** The URL parameters the search is kept in. */
const PARAMS = ['field', 'value'] as const;

/** A read's failure: a 400 says the search itself is malformed; anything else may pass on Retry. */
interface LogsFailure {
  status: number | null;
  code: string;
  traceId: string;
}

type LogsRead = { kind: 'ready'; list: TenantLogsResponse } | { kind: 'failed'; failure: LogsFailure };

type EventRead = { kind: 'ready'; event: TenantLogEventDetail } | { kind: 'failed'; failure: LogsFailure };

/**
 * Which Log the page reads: the path Tenant's (Story 7.4), or the Deployment Log (Story 7.7),
 * which only the Deployment Owner reads.
 */
export type LogScope = { kind: 'tenant'; tenantId: string } | { kind: 'deployment' };

/** One event of the scope's Log, opened (Stories 7.5 and 7.7). A 2xx without the event's fields is a failure. */
export async function readLogEvent(request: ShellRequest, scope: LogScope, eventId: string, signal?: AbortSignal): Promise<EventRead> {
  try {
    const result = await request(
      'get',
      () => (scope.kind === 'deployment' ? api.getDeploymentLogEvent(eventId) : api.getTenantLogEvent(scope.tenantId, eventId)),
      signal,
    );
    if (result.ok) {
      const event = result.data;
      if (event && typeof event.id === 'string' && typeof event.type === 'string' && event.actor) return { kind: 'ready', event };
      return { kind: 'failed', failure: { status: null, code: '', traceId: '' } };
    }
    return { kind: 'failed', failure: { status: result.status, code: result.problem?.code ?? '', traceId: result.problem?.traceId ?? '' } };
  } catch {
    // A lost connection, or a read abandoned with its drawer: the caller checks its signal.
    return { kind: 'failed', failure: { status: null, code: '', traceId: '' } };
  }
}

/** One page of the scope's Log for `query`, after `cursor` when given. A 2xx without the list's fields is a failure. */
export async function readLogs(
  request: ShellRequest,
  scope: LogScope,
  query: LogQuery,
  cursor?: string,
  signal?: AbortSignal,
): Promise<LogsRead> {
  const sent = cursor === undefined ? query : { ...query, cursor };
  try {
    const result = await request(
      'get',
      () => (scope.kind === 'deployment' ? api.searchDeploymentLogs(sent) : api.searchTenantLogs(scope.tenantId, sent)),
      signal,
    );
    if (result.ok) {
      const list = result.data;
      if (list && Array.isArray(list.events)) return { kind: 'ready', list };
      return { kind: 'failed', failure: { status: null, code: '', traceId: '' } };
    }
    return { kind: 'failed', failure: { status: result.status, code: result.problem?.code ?? '', traceId: result.problem?.traceId ?? '' } };
  } catch {
    // A lost connection, or a read abandoned with its page: the caller checks its signal.
    return { kind: 'failed', failure: { status: null, code: '', traceId: '' } };
  }
}

function fieldLabel(field: LogField, messages: Messages): string {
  switch (field) {
    case 'type':
      return messages.logsFieldType;
    case 'user':
      return messages.logsFieldUser;
    case 'application':
      return messages.logsFieldApplication;
    case 'admin':
      return messages.logsFieldAdmin;
    case 'tenant':
      return messages.logsFieldTenant;
    case 'outcome':
      return messages.logsFieldOutcome;
    case 'range':
      return messages.logsFieldRange;
  }
}

function choiceLabel(value: string, messages: Messages): string {
  switch (value) {
    case OUTCOMES[0]:
      return messages.logsOutcomeSuccess;
    case OUTCOMES[1]:
      return messages.logsOutcomeFailure;
    case RANGES[0].value:
      return messages.logsRangeHour;
    case RANGES[1].value:
      return messages.logsRangeDay;
    case RANGES[2].value:
      return messages.logsRangeWeek;
    case RANGES[3].value:
      return messages.logsRangeMonth;
    case RANGES[4].value:
      return messages.logsRangeQuarter;
    default:
      return value;
  }
}

function helper(field: LogField, messages: Messages): string | undefined {
  if (field === 'type') return messages.logsTypeHelper;
  if (field === 'user') return messages.logsUserHelper;
  if (field === 'application') return messages.logsApplicationHelper;
  if (field === 'admin') return messages.logsAdminHelper;
  if (field === 'tenant') return messages.logsTenantHelper;
  return undefined;
}

/** The form's draft for a search: a choice field with no value shows, and so holds, its first choice. */
function draftOf(search: LogSearch): LogSearch {
  return isChoice(search.field) && search.value === '' ? { field: search.field, value: initialValue(search.field) } : search;
}

export interface LogsPageProps {
  request: ShellRequest;
  /** The Log this page reads: the path Tenant's, as the shell decoded it, or the Deployment's. */
  scope: LogScope;
}

/**
 * A Tenant's Logs (Story 7.4, FR-40, UX-DR12): one field select and a value, kept in the URL as
 * `field` and `value`, so a reload, a shared link and Back restore the search, and Search runs
 * it. The table lists the Log newest first, 50 at a time, with Load more for the next page:
 * Time (UTC), the type as a code badge toned by its outcome, the catalogue's description, and the
 * User and Application the event names. No Live view, Log streams, query bar, quick filters or
 * Location column. Each read has its own AbortController, abandoned when a newer one starts or
 * the page leaves.
 *
 * Opening a row, by click or from its Description link with the keyboard (Story 7.5, UX-DR18),
 * opens the event drawer, drawn selected, and reads that event: its code badge, its summary
 * rows and, only when the server sent `raw`, the raw JSON with Copy JSON. Esc and Close shut it;
 * the drawer isn't kept in the URL.
 *
 * The same page is the Deployment Log (Story 7.7) for the `deployment` scope: Deployment › Log,
 * searched by Admin and Tenant in place of User and Application, with Admin and Tenant columns,
 * and a drawer whose summary names no User or Application. The server always sends its `raw`.
 */
export function LogsPage({ request, scope }: LogsPageProps) {
  const messages = useMessages();
  const fields = fieldsOf(scope.kind);
  const [params, setParams] = useUrlParams(PARAMS);
  const search = searchOf(params, fields);
  const [draft, setDraft] = useState<LogSearch>(() => draftOf(search));
  const [read, setRead] = useState<LogsRead | null>(null);
  const [query, setQuery] = useState<LogQuery>({});
  const [attempt, setAttempt] = useState(0);
  const [more, setMore] = useState<'idle' | 'loading' | 'failed'>('idle');
  // The page's own life: a late Load more answer after a new search or unmount lands nowhere.
  const alive = useRef(new AbortController());
  // The open row, and its event read: each open, and each Retry, reads with its own controller.
  const [opened, setOpened] = useState<TenantLogEvent | null>(null);
  const [currentRead, setEventRead] = useState<EventRead | null>(null);
  const [eventAttempt, setEventAttempt] = useState(0);

  // The URL is the search: on a reload, Back or Forward, the form shows what the URL holds.
  useEffect(() => setDraft(draftOf(search)), [search.field, search.value]);

  // The scope as plain values, so a re-render with an equal scope reads nothing again.
  const tenantId = scope.kind === 'tenant' ? scope.tenantId : null;
  const current = useMemo<LogScope>(() => (tenantId === null ? { kind: 'deployment' } : { kind: 'tenant', tenantId }), [tenantId]);

  useEffect(() => {
    const controller = new AbortController();
    alive.current = controller;
    // A time range ends now: its start is taken as this read is sent.
    const sent = queryOf(search, Date.now(), fields);
    setQuery(sent);
    setRead(null);
    setMore('idle');
    setOpened(null);
    setEventRead(null);
    void readLogs(request, current, sent, undefined, controller.signal).then((result) => {
      if (!controller.signal.aborted) setRead(result);
    });
    return () => controller.abort();
  }, [request, current, search.field, search.value, attempt]);

  const openedId = opened?.id ?? null;
  useEffect(() => {
    if (openedId === null) return;
    const controller = new AbortController();
    setEventRead(null);
    void readLogEvent(request, current, openedId, controller.signal).then((result) => {
      if (!controller.signal.aborted) setEventRead(result);
    });
    return () => controller.abort();
  }, [request, current, openedId, eventAttempt]);

  const closeEvent = useCallback(() => {
    setOpened(null);
    setEventRead(null);
  }, []);

  const loadMore = useCallback(async () => {
    if (read?.kind !== 'ready' || read.list.nextCursor == null || more === 'loading') return;
    const signal = alive.current.signal;
    setMore('loading');
    const next = await readLogs(request, current, query, read.list.nextCursor, signal);
    if (signal.aborted) return;
    if (next.kind === 'failed') {
      setMore('failed');
      return;
    }
    setRead({ kind: 'ready', list: { events: [...read.list.events, ...next.list.events], nextCursor: next.list.nextCursor } });
    setMore('idle');
  }, [read, more, request, current, query]);

  function submit(event: FormEvent) {
    event.preventDefault();
    const wanted = paramsOf(draft);
    const current = paramsOf(search);
    // The same search again reads again: the Log may have grown since. The URL is normalised too.
    if (wanted.field === current.field && wanted.value === current.value) setAttempt((n) => n + 1);
    setParams(wanted);
  }

  function pickField(value: string) {
    if (!isField(value, fields)) return;
    setDraft({ field: value, value: initialValue(value) });
  }

  const columns: DataTableColumn<TenantLogEvent>[] = [
    { key: 'time', header: messages.logsColumnTime, cell: (row) => <span className={styles.time}>{utcTime(row.occurredAt)}</span> },
    {
      key: 'type',
      header: messages.logsColumnType,
      cell: (row) => <CodeBadge outcome={row.outcome === 'failure' ? 'failure' : 'success'}>{row.type}</CodeBadge>,
    },
    { key: 'description', header: messages.logsColumnDescription, rowHeader: true, rowLink: true, cell: (row) => row.summary ?? row.type },
    ...(scope.kind === 'deployment'
      ? [
          { key: 'admin', header: messages.logsColumnAdmin, cell: (row: TenantLogEvent) => <Reference id={referenceOf(row, 'admin')} /> },
          { key: 'tenant', header: messages.logsColumnTenant, cell: (row: TenantLogEvent) => <Reference id={referenceOf(row, 'tenant')} /> },
        ]
      : [
          { key: 'user', header: messages.logsColumnUser, cell: (row: TenantLogEvent) => <Reference id={referenceOf(row, 'user')} /> },
          {
            key: 'application',
            header: messages.logsColumnApplication,
            cell: (row: TenantLogEvent) => <Reference id={referenceOf(row, 'client')} />,
          },
        ]),
  ];
  const title = scope.kind === 'deployment' ? messages.navDeploymentLog : messages.navLogs;

  const invalid = read?.kind === 'failed' && read.failure.status === 400;

  // Only a read of the open row counts: one of a row opened before shows as loading, so nothing
  // of the earlier event paints under the new one before its read starts.
  const eventRead = currentRead?.kind === 'ready' && currentRead.event.id !== openedId ? null : currentRead;
  // The drawer's header comes from the event once read, from its row until then.
  const shown = eventRead?.kind === 'ready' ? eventRead.event : opened;
  const summary: EventSummaryRow[] =
    eventRead?.kind === 'ready'
      ? eventSummary(eventRead.event, {
          time: messages.logsColumnTime,
          actor: messages.logsEventActor,
          target: messages.logsEventTarget,
          user: messages.logsColumnUser,
          application: messages.logsColumnApplication,
          ipAddress: messages.logsEventIpAddress,
          userAgent: messages.logsEventUserAgent,
          email: messages.logsEventEmail,
        }, scope.kind).map((line) => ({
          key: line.key,
          label: line.label,
          value: line.code ? <code className={styles.reference}>{line.value}</code> : line.value,
        }))
      : [];
  const missing = eventRead?.kind === 'failed' && eventRead.failure.status === 404;
  const eventStatus =
    opened === null ? undefined : eventRead === null ? (
      <SkeletonRows rows={4} columns={2} caption={false} />
    ) : eventRead.kind === 'failed' ? (
      <Banner
        tone="bad"
        action={missing ? undefined : { label: messages.retry, onClick: () => setEventAttempt((n) => n + 1) }}
        data-testid={missing ? 'log-event-not-found' : 'log-event-failed'}
      >
        <p>
          {missing
            ? scope.kind === 'deployment'
              ? messages.logsDeploymentEventNotFound
              : messages.logsEventNotFound
            : messages.logsEventLoadFailed}
        </p>
        <ErrorReference code={eventRead.failure.code || 'unavailable'} traceId={eventRead.failure.traceId} />
      </Banner>
    ) : undefined;
  const drawer = {
    open: opened !== null,
    onClose: closeEvent,
    code: shown?.type ?? '',
    outcome: shown?.outcome === 'failure' ? ('failure' as const) : ('success' as const),
    title: shown ? (shown.summary ?? shown.type) : '',
    summary,
    status: eventStatus,
    'data-testid': 'log-event',
  };
  const raw = eventRead?.kind === 'ready' ? eventRead.event.raw : null;

  return (
    <SectionPage
      eyebrow={scope.kind === 'deployment' ? messages.navDeployment : messages.navMonitoring}
      title={title}
      data-testid={scope.kind === 'deployment' ? 'deployment-logs-page' : 'logs-page'}
    >
      <div className={styles.page}>
        <form className={styles.search} onSubmit={submit} role="search" data-testid="logs-search">
          <Field label={messages.logsField} className={styles.field}>
            <Select value={draft.field} onChange={(event) => pickField(event.target.value)} data-testid="logs-field">
              {fields.map((field) => (
                <option key={field} value={field}>
                  {fieldLabel(field, messages)}
                </option>
              ))}
            </Select>
          </Field>
          <Field label={messages.logsValue} helper={helper(draft.field, messages)} className={styles.value}>
            {isChoice(draft.field) ? (
              <Select value={draft.value} onChange={(event) => setDraft({ ...draft, value: event.target.value })} data-testid="logs-value">
                {choices(draft.field).map((choice) => (
                  <option key={choice} value={choice}>
                    {choiceLabel(choice, messages)}
                  </option>
                ))}
              </Select>
            ) : (
              <Input
                code
                value={draft.value}
                onChange={(event) => setDraft({ ...draft, value: event.target.value })}
                autoComplete="off"
                spellCheck={false}
                data-testid="logs-value"
              />
            )}
          </Field>
          <Button type="submit" variant="primary" className={styles.submit} data-testid="logs-submit">
            {messages.logsSearch}
          </Button>
        </form>
        {read === null && <SkeletonRows rows={3} columns={5} caption={false} />}
        {read?.kind === 'failed' && (
          <Banner
            tone="bad"
            action={invalid ? undefined : { label: messages.retry, onClick: () => setAttempt((n) => n + 1) }}
            data-testid={invalid ? 'logs-invalid' : 'logs-load-failed'}
          >
            <p>{invalid ? messages.logsInvalid : messages.loadFailed}</p>
            <ErrorReference code={read.failure.code || 'unavailable'} traceId={read.failure.traceId} />
          </Banner>
        )}
        {read?.kind === 'ready' && (
          <div data-testid="logs">
            <DataTable
              caption={title}
              hideCaption
              columns={columns}
              rows={read.list.events}
              rowKey={(row) => row.id}
              onRowActivate={(row) => setOpened(row)}
              selectedKey={opened?.id}
              // Every loaded row on one page: Load more reads the next 50.
              pageSize={Math.max(read.list.events.length, 1)}
              empty={<EmptyState message={messages.logsEmpty} />}
            />
            {more === 'failed' && (
              <Banner tone="bad" action={{ label: messages.retry, onClick: () => void loadMore() }} data-testid="logs-more-failed">
                {messages.loadFailed}
              </Banner>
            )}
            {read.list.nextCursor != null && more !== 'failed' && (
              <Button variant="secondary" pending={more === 'loading'} onClick={() => void loadMore()} data-testid="logs-load-more">
                {messages.logsLoadMore}
              </Button>
            )}
          </div>
        )}
      </div>
      {raw != null ? <EventDrawer {...drawer} canSeeRaw raw={raw} /> : <EventDrawer {...drawer} canSeeRaw={false} />}
    </SectionPage>
  );
}

/** A User, Application, Admin or Tenant reference in the code type, or nothing when the event names none. */
function Reference({ id }: { id: string | null }) {
  return id === null ? null : <code className={styles.reference}>{id}</code>;
}
