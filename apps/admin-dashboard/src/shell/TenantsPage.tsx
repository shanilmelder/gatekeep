import type { TenantListResponse, TenantResponse } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  DataTable,
  DraftBadge,
  EmptyState,
  EnvironmentBadge,
  ErrorReference,
  SectionPage,
  StatusBadge,
  formatMessage,
  useMessages,
  type DataTableColumn,
} from '@gatekeep/ui/admin';
import { useCallback, useEffect, useRef, useState } from 'react';
import { navigate } from '../navigation';
import { api } from '../session';
import { useCapabilities } from './capabilities';
import type { ShellRequest } from './CredentialsPage';
import { TenantsReadState, environmentTag } from './CreateTenantPage';
import { NEW_TENANT_PATH, readTenants, type TenantsRead } from './tenants';

/** How often the list is read again while a Tenant on it is still being created. */
export const REFRESH_MS = 2000;

/** The most refreshes one read of the page makes, so a creation stuck running stops costing reads. */
export const REFRESH_LIMIT = 60;

const DATE = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** An absolute date and time, in the browser's own time zone and locale. */
function when(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : DATE.format(date);
}

/**
 * Tenants (Story 1.27): the Deployment's Tenants, oldest first, with each one's name, its stored
 * host, its environment tag and when it was created, and Load more for the next page. A Tenant
 * still being created says so, and one whose creation failed has its own Retry. Rows aren't links:
 * no Tenant page exists yet. Create Tenant shows only with deployment.tenants.create, and the
 * server still decides every request.
 */
export function TenantsPage({ request }: { request: ShellRequest }) {
  const messages = useMessages();
  const { has } = useCapabilities();
  const canCreate = has('deployment.tenants.create');
  const [read, setRead] = useState<TenantsRead | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [more, setMore] = useState<'idle' | 'loading' | 'failed'>('idle');
  const [retrying, setRetrying] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<{ kind: 'saveFailed'; code: string; traceId: string } | { kind: 'forbidden' } | null>(null);
  const creating = read?.kind === 'ready' && read.list.tenants.some((row) => row.status === 'creating');
  // The page's own life: a late answer after unmount lands nowhere.
  const alive = useRef(new AbortController());

  useEffect(() => {
    const controller = new AbortController();
    alive.current = controller;
    setRead(null);
    setMore('idle');
    void readTenants(request, undefined, controller.signal).then((result) => {
      if (!controller.signal.aborted) setRead(result);
    });
    return () => controller.abort();
  }, [request, attempt]);

  // While a Tenant is still being created, the first page is read again every REFRESH_MS, at most
  // REFRESH_LIMIT times, and its rows replace the same Tenants' rows. A failed refresh changes
  // nothing. Unmounting, or a new read, stops it.
  useEffect(() => {
    if (!creating) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let left = REFRESH_LIMIT;
    const tick = async () => {
      left -= 1;
      const fresh = await readTenants(request, undefined, controller.signal);
      if (controller.signal.aborted) return;
      if (fresh.kind === 'ready') {
        const byId = new Map(fresh.list.tenants.map((row) => [row.id, row] as const));
        // Once no row is creating, the effect ends with the state that says so.
        setRead((current) =>
          current?.kind === 'ready'
            ? { kind: 'ready', list: { ...current.list, tenants: current.list.tenants.map((row) => byId.get(row.id) ?? row) } }
            : current,
        );
      }
      if (left > 0) timer = setTimeout(() => void tick(), REFRESH_MS);
    };
    timer = setTimeout(() => void tick(), REFRESH_MS);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
    // Only a new read, or the page going from creating to not, restarts or ends the refreshes.
  }, [creating, request, attempt]);

  const loadMore = useCallback(async () => {
    if (read?.kind !== 'ready' || read.list.nextCursor == null || more === 'loading') return;
    const signal = alive.current.signal;
    setMore('loading');
    const next = await readTenants(request, read.list.nextCursor, signal);
    if (signal.aborted) return;
    if (next.kind === 'failed') {
      setMore('failed');
      return;
    }
    const list: TenantListResponse = { ...next.list, tenants: [...read.list.tenants, ...next.list.tenants] };
    setRead({ kind: 'ready', list });
    setMore('idle');
  }, [read, more, request]);

  async function retry(tenant: TenantResponse) {
    const operationId = tenant.creation?.operationId;
    if (!operationId || retrying !== null) return;
    setRetrying(tenant.id);
    setRefusal(null);
    let result;
    try {
      result = await request('post', () => api.retryOperation(operationId));
    } catch {
      result = null;
    }
    setRetrying(null);
    if (result?.status === 401) {
      // The renewal brought the Admin back and didn't send it again: they press Retry once more.
      return;
    }
    // 202 runs it again, and a 409 says it isn't failed any more: the list read next says where it stands.
    if (result !== null && (result.status === 202 || result.status === 409)) {
      setAttempt((n) => n + 1);
      return;
    }
    if (result?.status === 403) {
      setRefusal({ kind: 'forbidden' });
      return;
    }
    const problem = result === null || result.ok ? null : result.problem;
    setRefusal({ kind: 'saveFailed', code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' });
  }

  const create = () => navigate(NEW_TENANT_PATH);

  const columns = (rows: readonly TenantResponse[]): DataTableColumn<TenantResponse>[] => {
    const list: DataTableColumn<TenantResponse>[] = [
      {
        key: 'name',
        header: messages.tenantsColumnName,
        rowHeader: true,
        cell: (row) => (
          <>
            {row.name}
            {row.creation?.status === 'running' && (
              <>
                {' '}
                <DraftBadge data-testid="tenant-creating">{messages.tenantsCreating}</DraftBadge>
              </>
            )}
            {row.creation?.status === 'failed' && (
              <>
                {' '}
                <StatusBadge status="blocked" data-testid="tenant-creation-failed">
                  {messages.tenantsCreationFailed}
                </StatusBadge>
              </>
            )}
          </>
        ),
      },
      { key: 'host', header: messages.tenantsColumnSubdomain, cell: (row) => <code>{row.host}</code> },
      {
        key: 'environment',
        header: messages.tenantsColumnEnvironment,
        cell: (row) => <EnvironmentBadge environment={row.label}>{environmentTag(row.label, messages)}</EnvironmentBadge>,
      },
      { key: 'created', header: messages.tenantsColumnCreated, cell: (row) => when(row.createdAt) },
    ];
    if (canCreate && rows.some((row) => row.creation?.status === 'failed')) {
      list.push({
        key: 'retry',
        header: messages.retry,
        cell: (row) =>
          row.creation?.status === 'failed' ? (
            <Button
              variant="secondary"
              size="sm"
              pending={retrying === row.id}
              aria-label={formatMessage(messages.tenantsRetryNamed, { name: row.name })}
              onClick={() => void retry(row)}
            >
              {messages.retry}
            </Button>
          ) : null,
      });
    }
    return list;
  };

  return (
    <SectionPage
      eyebrow={messages.navDeployment}
      title={messages.navTenants}
      actions={
        canCreate ? (
          <Button variant="primary" onClick={create} data-testid="tenants-create">
            {messages.createTenantSubmit}
          </Button>
        ) : undefined
      }
      data-testid="tenants-page"
    >
      <TenantsReadState read={read} onRetry={() => setAttempt((n) => n + 1)}>
        {({ list }) => (
          <div data-testid="tenants">
            {refusal?.kind === 'saveFailed' && (
              <Banner tone="bad" data-testid="tenants-retry-failed">
                <p>{messages.createTenantSaveFailed}</p>
                <ErrorReference code={refusal.code} traceId={refusal.traceId} />
              </Banner>
            )}
            {refusal?.kind === 'forbidden' && (
              <Banner tone="bad" data-testid="tenants-retry-forbidden">
                {messages.actionForbidden}
              </Banner>
            )}
            <DataTable
              caption={messages.navTenants}
              hideCaption
              columns={columns(list.tenants)}
              rows={list.tenants}
              rowKey={(row) => row.id}
              // Every loaded row on one page: Load more reads the next 50.
              pageSize={Math.max(list.tenants.length, 1)}
              empty={
                <EmptyState
                  message={messages.tenantsEmpty}
                  action={canCreate ? { label: messages.createTenantSubmit, onClick: create } : undefined}
                />
              }
            />
            {more === 'failed' && (
              <Banner tone="bad" action={{ label: messages.retry, onClick: () => void loadMore() }} data-testid="tenants-more-failed">
                {messages.loadFailed}
              </Banner>
            )}
            {list.nextCursor != null && more !== 'failed' && (
              <Button variant="secondary" pending={more === 'loading'} onClick={() => void loadMore()} data-testid="tenants-load-more">
                {messages.tenantsLoadMore}
              </Button>
            )}
          </div>
        )}
      </TenantsReadState>
    </SectionPage>
  );
}
