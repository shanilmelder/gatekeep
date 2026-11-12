import type { AdminTenant, ApplicationResponse } from '@gatekeep/api-client';
import {
  Banner,
  ConfirmModal,
  CopyButton,
  EmptyState,
  ErrorReference,
  ProtocolBadge,
  SectionPage,
  SkeletonRows,
  Tabs,
  useMessages,
} from '@gatekeep/ui/admin';
import { useCallback, useEffect, useRef, useState, type MouseEvent } from 'react';
import { navigate } from '../navigation';
import { api } from '../session';
import { applicationsPath } from './applications';
import { ApplicationSettings } from './ApplicationSettings';
import { failureOf } from './ApplicationsPage';
import { useCapabilities } from './capabilities';
import { kindText } from './CreateApplicationModal';
import type { ShellRequest } from './CredentialsPage';
import { ForbiddenPage } from './ForbiddenPage';
import type { FreshAssertion } from './freshAssertion';
import styles from './ApplicationsPage.module.css';

type Failure = { code: string; traceId: string };

type Load =
  | { kind: 'loading' }
  | { kind: 'ready'; application: ApplicationResponse }
  | { kind: 'notFound' }
  | { kind: 'forbidden'; failure: Failure }
  | { kind: 'failed'; failure: Failure };

export interface ApplicationDetailPageProps {
  request: ShellRequest;
  fresh: FreshAssertion;
  /** The path Tenant this page was mounted with. */
  tenantId: string;
  /** The path Tenant as the switcher lists it, for its label, or null when unlisted. */
  tenant: AdminTenant | null;
  /** The Application the path names, as decoded: the server decides whether it is this Tenant's. */
  applicationId: string;
}

/**
 * One Application (Story 3.1; design Application detail): the breadcrumb back to Applications, the
 * name with its type badge, the client ID in the code type with Copy, then the tabs. Settings, the
 * default (Story 3.2), holds the URLs and grants; Credentials says whether the type needs a secret.
 * Regular web and machine-to-machine need one, which only a Tenant Owner creates (Story 3.3);
 * single-page and native need none. A 404 says the Tenant has no such Application, a 403 is the
 * forbidden page, and any other failure a banner with Retry.
 */
export function ApplicationDetailPage({ request, fresh, tenantId, tenant, applicationId }: ApplicationDetailPageProps) {
  const messages = useMessages();
  const { has } = useCapabilities();
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoad({ kind: 'loading' });

    void (async () => {
      let result;
      try {
        result = await request('get', () => api.getApplication(tenantId, applicationId), controller.signal);
      } catch {
        result = null;
      }
      if (controller.signal.aborted) return;
      const application = result?.ok ? result.data : undefined;
      if (application && typeof application.id === 'string') setLoad({ kind: 'ready', application });
      else if (result !== null && !result.ok && result.status === 404) setLoad({ kind: 'notFound' });
      else if (result !== null && !result.ok && result.status === 403 && result.problem?.code === 'access_denied')
        setLoad({ kind: 'forbidden', failure: failureOf(result) });
      else setLoad({ kind: 'failed', failure: failureOf(result) });
    })();

    return () => controller.abort();
  }, [request, tenantId, applicationId, attempt]);

  // Leaving Settings with unsaved changes asks first (Story 3.2): its panel goes, and its form with it.
  const dirty = useRef(false);
  const [leaving, setLeaving] = useState<((leave: boolean) => void) | null>(null);
  const onDirtyChange = useCallback((now: boolean) => {
    dirty.current = now;
  }, []);
  const canLeave = useCallback(
    (from: string) =>
      from !== 'settings' || !dirty.current
        ? true
        : new Promise<boolean>((resolve) => {
            setLeaving(() => resolve);
          }),
    [],
  );
  const settleLeave = (leave: boolean) => {
    leaving?.(leave);
    if (leave) dirty.current = false;
    setLeaving(null);
  };

  if (load.kind === 'forbidden') return <ForbiddenPage code={load.failure.code} traceId={load.failure.traceId} />;

  const listHref = applicationsPath(tenantId);
  const back = (event: MouseEvent<HTMLAnchorElement>) => {
    // A plain click stays in the dashboard; a modified one opens the link as the browser does.
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    navigate(listHref);
  };

  const application = load.kind === 'ready' ? load.application : null;
  const eyebrow = (
    <nav aria-label={messages.applicationBreadcrumb}>
      <ol className={styles.crumbs} data-testid="application-breadcrumb">
        <li>
          <a href={listHref} onClick={back}>
            {messages.applicationsTitle}
          </a>
        </li>
        {application && (
          <li aria-current="page">
            <bdi>{application.name}</bdi>
          </li>
        )}
      </ol>
    </nav>
  );

  if (load.kind === 'loading') {
    return (
      <SectionPage eyebrow={eyebrow} title={messages.applicationsTitle} data-testid="application-page">
        <SkeletonRows rows={3} caption={false} />
      </SectionPage>
    );
  }

  if (load.kind === 'notFound') {
    return (
      <SectionPage eyebrow={eyebrow} title={messages.applicationsTitle} data-testid="application-page">
        <div className={styles.section} data-testid="application-not-found">
          <EmptyState message={messages.applicationNotFound} />
        </div>
      </SectionPage>
    );
  }

  if (load.kind === 'failed') {
    return (
      <SectionPage eyebrow={eyebrow} title={messages.applicationsTitle} data-testid="application-page">
        <Banner tone="bad" action={{ label: messages.retry, onClick: () => setAttempt((n) => n + 1) }} data-testid="application-load-failed">
          <p>{messages.loadFailed}</p>
          <ErrorReference code={load.failure.code} traceId={load.failure.traceId} />
        </Banner>
      </SectionPage>
    );
  }

  const { application: ready } = load;
  const needsSecret = ready.credentialRequired;
  return (
    <SectionPage
      eyebrow={eyebrow}
      title={
        <span className={styles.title}>
          <bdi data-testid="application-title">{ready.name}</bdi>
          <ProtocolBadge data-testid="application-type">{kindText(ready.type, messages).name}</ProtocolBadge>
        </span>
      }
      data-testid="application-page"
    >
      <section className={styles.section} aria-labelledby="application-client-id-heading">
        <h2 id="application-client-id-heading">{messages.applicationClientId}</h2>
        <span className={styles.clientId}>
          <code data-testid="application-client-id">{ready.clientId}</code>
          <CopyButton value={ready.clientId} what={messages.applicationClientIdWhat} />
        </span>
      </section>
      <div className={styles.section}>
        <Tabs
          label={messages.applicationTabsLabel}
          param="tab"
          defaultSelected="settings"
          canLeave={canLeave}
          tabs={[
            {
              id: 'settings',
              label: messages.applicationTabSettings,
              panel: (
                <ApplicationSettings
                  request={request}
                  fresh={fresh}
                  tenantId={tenantId}
                  prod={tenant?.label === 'prod'}
                  application={ready}
                  canManage={has('tenant.application_callbacks.manage')}
                  onSaved={(application) => setLoad({ kind: 'ready', application })}
                  onDirtyChange={onDirtyChange}
                />
              ),
            },
            {
              id: 'credentials',
              label: messages.applicationTabCredentials,
              panel: (
                <section className={styles.section} aria-labelledby="application-credentials-heading" data-testid="application-credentials">
                  <h2 id="application-credentials-heading">{messages.applicationCredentialsTitle}</h2>
                  <p>{needsSecret ? messages.applicationCredentialsNeeded : messages.applicationCredentialsNone}</p>
                </section>
              ),
            },
          ]}
        />
      </div>
      <ConfirmModal
        open={leaving !== null}
        onCancel={() => settleLeave(false)}
        onConfirm={() => settleLeave(true)}
        tone="destructive"
        title={messages.unsavedTitle}
        confirmLabel={messages.unsavedLeave}
        cancelLabel={messages.unsavedKeep}
        data-testid="application-unsaved"
      >
        <p>{messages.unsavedBody}</p>
      </ConfirmModal>
    </SectionPage>
  );
}
