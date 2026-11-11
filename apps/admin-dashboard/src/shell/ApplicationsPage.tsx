import type { ApplicationListResponse, ApplicationResponse } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  CopyButton,
  DataTable,
  EmptyState,
  ErrorReference,
  SectionPage,
  SkeletonRows,
  useMessages,
  useToast,
  type DataTableColumn,
} from '@gatekeep/ui/admin';
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { navigate } from '../navigation';
import { api } from '../session';
import { applicationPath } from './applications';
import { useCapabilities } from './capabilities';
import { CreateApplicationModal, kindText } from './CreateApplicationModal';
import type { ShellRequest } from './CredentialsPage';
import { ForbiddenPage } from './ForbiddenPage';
import styles from './ApplicationsPage.module.css';

type Failure = { code: string; traceId: string };

type Load =
  | { kind: 'loading' }
  | { kind: 'ready'; list: ApplicationListResponse }
  | { kind: 'forbidden'; failure: Failure }
  | { kind: 'failed'; failure: Failure };

const DATE = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });

/** A date, in the browser's own time zone and locale. */
export function day(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : DATE.format(date);
}

/** A refusal's code and trace ID, as far as the answer carries them: a bodiless 503 has neither. */
export function failureOf(result: { ok: boolean; problem?: { code?: string; traceId?: string } | null } | null): Failure {
  const problem = result && !result.ok ? result.problem : null;
  return { code: problem?.code ?? '', traceId: problem?.traceId ?? '' };
}

/** One page read: the list, or why there is none. */
async function readPage(request: ShellRequest, tenantId: string, cursor: string | undefined, signal: AbortSignal): Promise<Exclude<Load, { kind: 'loading' }>> {
  let result;
  try {
    result = await request('get', () => api.listApplications(tenantId, cursor), signal);
  } catch {
    result = null;
  }
  const list = result?.ok ? result.data : undefined;
  if (list && Array.isArray(list.applications)) return { kind: 'ready', list };
  if (result !== null && !result.ok && result.status === 403 && result.problem?.code === 'access_denied')
    return { kind: 'forbidden', failure: failureOf(result) };
  return { kind: 'failed', failure: failureOf(result) };
}

export interface ApplicationsPageProps {
  request: ShellRequest;
  /** The path Tenant this page was mounted with: every request it sends names this one. */
  tenantId: string;
}

/**
 * Applications (Story 3.1, FR-11, FR-44; design Applications as the epic changes it): the Tenant's
 * Applications, newest first, with Name, Type, Client ID in the code type with its own Copy, and
 * Created, then Load more while an older page follows. With none, "No applications yet". Create
 * application, in the header and the empty state, shows only with tenant.applications.manage;
 * a create opens the new Application's page. A 403 is the forbidden page. The server decides
 * every request.
 */
export function ApplicationsPage({ request, tenantId }: ApplicationsPageProps) {
  const messages = useMessages();
  const toast = useToast();
  const { has } = useCapabilities();
  const canCreate = has('tenant.applications.manage');
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);
  const [more, setMore] = useState<{ kind: 'idle' | 'loading' } | { kind: 'failed'; failure: Failure }>({ kind: 'idle' });
  const [creating, setCreating] = useState(false);
  // The page's own life: a late Load more after unmount lands nowhere.
  const alive = useRef(new AbortController());

  useEffect(() => {
    const controller = new AbortController();
    alive.current = controller;
    setLoad({ kind: 'loading' });
    setMore({ kind: 'idle' });
    void readPage(request, tenantId, undefined, controller.signal).then((result) => {
      if (!controller.signal.aborted) setLoad(result);
    });
    return () => controller.abort();
  }, [request, tenantId, attempt]);

  const loadMore = useCallback(async () => {
    if (load.kind !== 'ready' || load.list.nextCursor == null || more.kind === 'loading') return;
    const controller = alive.current;
    setMore({ kind: 'loading' });
    const next = await readPage(request, tenantId, load.list.nextCursor, controller.signal);
    if (controller.signal.aborted) return;
    if (next.kind !== 'ready') {
      setMore({ kind: 'failed', failure: next.failure });
      return;
    }
    setMore({ kind: 'idle' });
    setLoad((current) =>
      current.kind === 'ready'
        ? { kind: 'ready', list: { applications: [...current.list.applications, ...next.list.applications], nextCursor: next.list.nextCursor } }
        : current,
    );
  }, [load, more, request, tenantId]);

  if (load.kind === 'forbidden') return <ForbiddenPage code={load.failure.code} traceId={load.failure.traceId} />;

  const open = (application: ApplicationResponse) => navigate(applicationPath(tenantId, application.id));

  const columns: DataTableColumn<ApplicationResponse>[] = [
    {
      key: 'name',
      header: messages.applicationsColumnName,
      rowHeader: true,
      rowLink: true,
      cell: (row) => (
        <bdi className={styles.name} data-testid="application-name">
          {row.name}
        </bdi>
      ),
    },
    { key: 'type', header: messages.applicationsColumnType, cell: (row) => kindText(row.type, messages).name },
    {
      key: 'clientId',
      header: messages.applicationsColumnClientId,
      cell: (row) => (
        <span className={styles.clientId}>
          <code data-testid="application-client-id">{row.clientId}</code>
          <CopyButton value={row.clientId} what={messages.applicationClientIdWhat} />
        </span>
      ),
    },
    { key: 'created', header: messages.applicationsColumnCreated, cell: (row) => day(row.createdAt) },
  ];

  const create = () => setCreating(true);

  let body: ReactNode;
  if (load.kind === 'loading') {
    body = <SkeletonRows rows={4} caption={false} />;
  } else if (load.kind === 'failed') {
    body = (
      <Banner tone="bad" action={{ label: messages.retry, onClick: () => setAttempt((n) => n + 1) }} data-testid="applications-load-failed">
        <p>{messages.loadFailed}</p>
        <ErrorReference code={load.failure.code} traceId={load.failure.traceId} />
      </Banner>
    );
  } else {
    const { list } = load;
    body = (
      <div className={styles.content} data-testid="applications">
        <DataTable
          caption={messages.applicationsTitle}
          hideCaption
          columns={columns}
          rows={list.applications}
          rowKey={(row) => row.id}
          onRowActivate={open}
          // Every loaded row on one page: Load more reads the next 50.
          pageSize={Math.max(list.applications.length, 1)}
          empty={
            <EmptyState message={messages.applicationsEmpty} action={canCreate ? { label: messages.createApplication, onClick: create } : undefined} />
          }
        />
        {more.kind === 'failed' && (
          <Banner tone="bad" action={{ label: messages.retry, onClick: () => void loadMore() }} data-testid="applications-more-failed">
            <p>{messages.loadFailed}</p>
            <ErrorReference code={more.failure.code} traceId={more.failure.traceId} />
          </Banner>
        )}
        {list.nextCursor != null && more.kind !== 'failed' && (
          <Button
            className={styles.more}
            variant="secondary"
            pending={more.kind === 'loading'}
            onClick={() => void loadMore()}
            data-testid="applications-load-more"
          >
            {messages.applicationsLoadMore}
          </Button>
        )}
      </div>
    );
  }

  // The header's Create application, once the list has read and isn't empty: the empty state carries its own.
  const showHeaderCreate = canCreate && load.kind === 'ready' && load.list.applications.length > 0;
  return (
    <SectionPage
      title={messages.applicationsTitle}
      description={messages.applicationsDescription}
      actions={
        showHeaderCreate ? (
          <Button variant="primary" onClick={create} data-testid="applications-create">
            {messages.createApplication}
          </Button>
        ) : undefined
      }
      data-testid="applications-page"
    >
      {body}
      {canCreate && (
        <CreateApplicationModal
          open={creating}
          request={request}
          tenantId={tenantId}
          onClose={() => setCreating(false)}
          onCreated={(application) => {
            setCreating(false);
            toast(messages.createApplicationCreated);
            open(application);
          }}
        />
      )}
    </SectionPage>
  );
}
