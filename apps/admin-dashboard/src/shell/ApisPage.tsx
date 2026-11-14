import type { ApiResource, ApiResourceDetail, ApiResourceListResponse } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  DataTable,
  ErrorReference,
  ProtocolBadge,
  SectionPage,
  SkeletonRows,
  useMessages,
  useToast,
  type DataTableColumn,
} from '@gatekeep/ui/admin';
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { navigate } from '../navigation';
import { api } from '../session';
import { apiPath } from './apis';
import { durationText } from './ApplicationTokens';
import { failureOf } from './ApplicationsPage';
import { useCapabilities } from './capabilities';
import { CreateApiModal } from './CreateApiModal';
import type { ShellRequest } from './CredentialsPage';
import { ForbiddenPage } from './ForbiddenPage';
import styles from './ApplicationsPage.module.css';

type Failure = { code: string; traceId: string };

type Load =
  | { kind: 'loading' }
  | { kind: 'ready'; list: ApiResourceListResponse }
  | { kind: 'forbidden'; failure: Failure }
  | { kind: 'failed'; failure: Failure };

/** One page read: the list, or why there is none. */
async function readPage(request: ShellRequest, tenantId: string, cursor: string | undefined, signal: AbortSignal): Promise<Exclude<Load, { kind: 'loading' }>> {
  let result;
  try {
    result = await request('get', () => api.listApis(tenantId, cursor), signal);
  } catch {
    result = null;
  }
  const list = result?.ok ? result.data : undefined;
  if (list && Array.isArray(list.apis)) return { kind: 'ready', list };
  if (result !== null && !result.ok && result.status === 403 && result.problem?.code === 'access_denied')
    return { kind: 'forbidden', failure: failureOf(result) };
  return { kind: 'failed', failure: failureOf(result) };
}

export interface ApisPageProps {
  request: ShellRequest;
  /** The path Tenant this page was mounted with: every request it sends names this one. */
  tenantId: string;
}

/**
 * APIs (Story 3.6, FR-16; design APIs as the epic changes it): the Tenant's APIs, the built-in Gatekeep Management API
 * first with its Built-in badge, then newest first, with Name, Identifier in the code type, RBAC and Access token
 * lifetime, then Load more while another page follows. Every Tenant has the built-in one, so the list is never empty.
 * Create API shows only with tenant.apis.manage; a create opens the new API's page. A 403 is the forbidden page. The
 * server decides every request.
 */
export function ApisPage({ request, tenantId }: ApisPageProps) {
  const messages = useMessages();
  const toast = useToast();
  const { has } = useCapabilities();
  const canCreate = has('tenant.apis.manage');
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
      current.kind === 'ready' ? { kind: 'ready', list: { apis: [...current.list.apis, ...next.list.apis], nextCursor: next.list.nextCursor } } : current,
    );
  }, [load, more, request, tenantId]);

  if (load.kind === 'forbidden') return <ForbiddenPage code={load.failure.code} traceId={load.failure.traceId} />;

  const open = (resource: ApiResource) => navigate(apiPath(tenantId, resource.id));

  const columns: DataTableColumn<ApiResource>[] = [
    {
      key: 'name',
      header: messages.apisColumnName,
      rowHeader: true,
      rowLink: true,
      cell: (row) => (
        <span className={styles.title}>
          <bdi className={styles.name} data-testid="api-name">
            {row.name}
          </bdi>
          {row.builtIn && <ProtocolBadge data-testid="api-built-in">{messages.apiBuiltIn}</ProtocolBadge>}
        </span>
      ),
    },
    {
      key: 'identifier',
      header: messages.apisColumnIdentifier,
      cell: (row) => (
        <span className={styles.clientId}>
          <code data-testid="api-identifier">{row.identifier}</code>
        </span>
      ),
    },
    { key: 'rbac', header: messages.apisColumnRbac, cell: (row) => (row.rbac ? messages.apisRbacOn : messages.apisRbacOff) },
    { key: 'accessToken', header: messages.apisColumnAccessToken, cell: (row) => durationText(row.accessTokenLifetime, messages) },
  ];

  const create = () => setCreating(true);

  let body: ReactNode;
  if (load.kind === 'loading') {
    body = <SkeletonRows rows={2} caption={false} />;
  } else if (load.kind === 'failed') {
    body = (
      <Banner tone="bad" action={{ label: messages.retry, onClick: () => setAttempt((n) => n + 1) }} data-testid="apis-load-failed">
        <p>{messages.loadFailed}</p>
        <ErrorReference code={load.failure.code} traceId={load.failure.traceId} />
      </Banner>
    );
  } else {
    const { list } = load;
    body = (
      <div className={styles.content} data-testid="apis">
        <DataTable
          caption={messages.apisTitle}
          hideCaption
          columns={columns}
          rows={list.apis}
          rowKey={(row) => row.id}
          onRowActivate={open}
          // Every loaded row on one page: Load more reads the next 50.
          pageSize={Math.max(list.apis.length, 1)}
        />
        {more.kind === 'failed' && (
          <Banner tone="bad" action={{ label: messages.retry, onClick: () => void loadMore() }} data-testid="apis-more-failed">
            <p>{messages.loadFailed}</p>
            <ErrorReference code={more.failure.code} traceId={more.failure.traceId} />
          </Banner>
        )}
        {list.nextCursor != null && more.kind !== 'failed' && (
          <Button className={styles.more} variant="secondary" pending={more.kind === 'loading'} onClick={() => void loadMore()} data-testid="apis-load-more">
            {messages.apisLoadMore}
          </Button>
        )}
      </div>
    );
  }

  return (
    <SectionPage
      title={messages.apisTitle}
      description={messages.apisDescription}
      actions={
        canCreate && load.kind === 'ready' ? (
          <Button variant="primary" onClick={create} data-testid="apis-create">
            {messages.createApi}
          </Button>
        ) : undefined
      }
      data-testid="apis-page"
    >
      {body}
      {canCreate && (
        <CreateApiModal
          open={creating}
          request={request}
          tenantId={tenantId}
          onClose={() => setCreating(false)}
          onCreated={(created: ApiResourceDetail) => {
            setCreating(false);
            toast(messages.createApiCreated);
            open(created.api);
          }}
        />
      )}
    </SectionPage>
  );
}
