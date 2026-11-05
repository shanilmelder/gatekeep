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
  useToast,
  type DataTableColumn,
} from '@gatekeep/ui/admin';
import { useCallback, useEffect, useRef, useState } from 'react';
import { navigate } from '../navigation';
import { api } from '../session';
import { useCapabilities } from './capabilities';
import type { ShellRequest } from './CredentialsPage';
import { TenantsReadState, environmentTag } from './CreateTenantPage';
import { DeleteTenantModal, type DeletionAction, type DeletionOutcome } from './DeleteTenantModal';
import type { FreshAssertion } from './freshAssertion';
import { inProgress, merge, reaches, refreshDelay } from './refresh';
import { NEW_TENANT_PATH, isPermanent, readTenants, type TenantsRead } from './tenants';

const DATE = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** An absolute date and time, in the browser's own time zone and locale. */
function when(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : DATE.format(date);
}


/** Whether a row may be deleted: an active Tenant, or one whose creation failed. */
function deletable(row: TenantResponse): boolean {
  return row.status === 'active' || (row.status === 'creating' && row.creation?.status === 'failed');
}

export interface TenantsPageProps {
  request: ShellRequest;
  fresh: FreshAssertion;
  /** Reads the shell's lists again, so the switcher drops a Tenant being deleted at once. */
  onTenantsChanged: () => void;
}

/**
 * Tenants (Story 1.27): the Deployment's Tenants, oldest first, with each one's name, its stored
 * host, its environment tag and when it was created, and Load more for the next page. A Tenant
 * still being created says so, and one whose creation failed has its own Retry. From Story 1.29,
 * with deployment.tenants.delete, a trailing Delete opens Delete Tenant; a Tenant being deleted
 * says so, and one whose deletion failed has its own Retry; a deleted one leaves the list. Rows
 * aren't links: no Tenant page exists yet. The actions show only with their capability, and the
 * server still decides every request.
 */
export function TenantsPage({ request, fresh, onTenantsChanged }: TenantsPageProps) {
  const messages = useMessages();
  const toast = useToast();
  const { has } = useCapabilities();
  const canCreate = has('deployment.tenants.create');
  const canDelete = has('deployment.tenants.delete');
  const [read, setRead] = useState<TenantsRead | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [more, setMore] = useState<'idle' | 'loading' | 'failed'>('idle');
  const [retrying, setRetrying] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<{ kind: 'saveFailed'; code: string; traceId: string } | { kind: 'forbidden' } | null>(null);
  const [deletion, setDeletion] = useState<DeletionAction | null>(null);
  const busy = read?.kind === 'ready' && read.list.tenants.some(inProgress);
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

  // The loaded rows, for the refresh to know how far to read without restarting on every merge.
  const loaded = useRef<readonly TenantResponse[]>([]);
  loaded.current = read?.kind === 'ready' ? read.list.tenants : [];

  // While a Tenant is still being created or deleted by a running Operation, the list is read
  // again, from the first page through every page that holds a loaded row, after refreshDelay: 2
  // seconds, backing off to 30, and never stopping, so a long deletion is never shown "Deleting"
  // for good. Its rows replace the same Tenants' rows; a Tenant deleted since leaves the list. A
  // refresh that failed for now changes nothing; one that would fail the same way every time, such
  // as a 403, stops the refreshes. A failed creation or deletion isn't in progress: it waits for
  // its Retry. Unmounting, or a new read, stops them too.
  useEffect(() => {
    if (!busy) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let done = 0;
    const tick = async () => {
      done += 1;
      let fresh: TenantResponse[] = [];
      let cursor: string | null | undefined;
      let failure = null;
      // Through the last loaded row: a busy row past the first page is read again too.
      for (;;) {
        const next = await readTenants(request, cursor ?? undefined, controller.signal);
        if (controller.signal.aborted) return;
        if (next.kind !== 'ready') {
          failure = next.failure;
          break;
        }
        fresh = [...fresh, ...next.list.tenants];
        cursor = next.list.nextCursor;
        if (reaches({ tenants: fresh, nextCursor: cursor }, loaded.current)) break;
      }

      if (failure === null) {
        // Once no row is in progress, the effect ends with the state that says so.
        setRead((current) =>
          current?.kind === 'ready'
            ? { kind: 'ready', list: { ...current.list, tenants: merge(current.list.tenants, { tenants: fresh, nextCursor: cursor }) } }
            : current,
        );
      } else if (isPermanent(failure)) {
        return;
      }
      timer = setTimeout(() => void tick(), refreshDelay(done));
    };
    timer = setTimeout(() => void tick(), refreshDelay(0));
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
    // Only a new read, or the page going from busy to not, restarts or ends the refreshes.
  }, [busy, request, attempt]);

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
    // 202 runs it again, and a 409 says it isn't failed any more, or the Tenant is being deleted
    // (Story 1.29): the list read next says where it stands.
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

  function deleted(outcome: DeletionOutcome) {
    setDeletion(null);
    setRefusal(null);
    if (outcome === 'started') toast(messages.deleteTenantStarted);
    // The list, and the shell's lists, so the switcher drops the Tenant at once.
    setAttempt((n) => n + 1);
    onTenantsChanged();
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
            {row.status === 'deleting' && row.deletion?.status !== 'failed' && (
              <>
                {' '}
                <DraftBadge data-testid="tenant-deleting">{messages.tenantsDeleting}</DraftBadge>
              </>
            )}
            {row.status === 'deleting' && row.deletion?.status === 'failed' && (
              <>
                {' '}
                <StatusBadge status="blocked" data-testid="tenant-deletion-failed">
                  {messages.tenantsDeletionFailed}
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
    const creationRetry = (row: TenantResponse) => canCreate && row.status === 'creating' && row.creation?.status === 'failed';
    const deletionRetry = (row: TenantResponse) => canDelete && row.status === 'deleting' && row.deletion?.status === 'failed';
    if (rows.some((row) => creationRetry(row) || deletionRetry(row))) {
      list.push({
        key: 'retry',
        header: messages.retry,
        cell: (row) =>
          creationRetry(row) ? (
            <Button
              variant="secondary"
              size="sm"
              pending={retrying === row.id}
              aria-label={formatMessage(messages.tenantsRetryNamed, { name: row.name })}
              onClick={() => void retry(row)}
            >
              {messages.retry}
            </Button>
          ) : deletionRetry(row) ? (
            <Button
              variant="secondary"
              size="sm"
              aria-label={formatMessage(messages.tenantsRetryDeletingNamed, { name: row.name })}
              onClick={() => setDeletion({ mode: 'retry', tenant: row })}
            >
              {messages.retry}
            </Button>
          ) : null,
      });
    }
    if (canDelete) {
      list.push({
        key: 'delete',
        header: messages.tenantsDelete,
        cell: (row) =>
          deletable(row) ? (
            <Button
              variant="destructive"
              size="sm"
              aria-label={formatMessage(messages.tenantsDeleteNamed, { name: row.name })}
              onClick={() => setDeletion({ mode: 'delete', tenant: row })}
            >
              {messages.tenantsDelete}
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
      <DeleteTenantModal action={deletion} request={request} fresh={fresh} onClose={() => setDeletion(null)} onDone={deleted} />
    </SectionPage>
  );
}
