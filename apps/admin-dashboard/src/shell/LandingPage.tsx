import type { AdminTenant } from '@gatekeep/api-client';
import { Banner, EmptyState, ErrorReference, SectionPage, useMessages } from '@gatekeep/ui/admin';
import { useEffect, useState } from 'react';
import { navigate } from '../navigation';
import { useCapabilities } from './capabilities';
import type { ShellRequest } from './CredentialsPage';
import { CreateTenantForm, TenantsReadState } from './CreateTenantPage';
import { TENANTS_PATH, readTenants, type TenantsRead } from './tenants';

/**
 * The landing page (FR-44; Story 1.28). An Admin holding a Tenant Role lands on the current
 * Tenant's page: the remembered one, else the first listed, whose settings page is its landing
 * until Story 3.1's Applications list. Otherwise an Admin who can list Tenants has the first page
 * read: with none, it is the Create Tenant form, in place; with any, the URL becomes the Tenants
 * page. Anyone else has no Tenant to reach. It is one Section page throughout, so its h1 stays
 * the same node as the read answers, and focus on it stays.
 */
export function LandingPage({
  request,
  tenants,
  tenantsFailure,
  onRetry,
  current,
}: {
  request: ShellRequest;
  tenants: readonly AdminTenant[];
  /** The switcher's list failed to read: the landing can't tell where to go, so it says so. */
  tenantsFailure: { code: string; traceId: string } | null;
  onRetry: () => void;
  current: AdminTenant | null;
}) {
  const messages = useMessages();
  const { has } = useCapabilities();
  const target = tenantsFailure === null && tenants.length > 0 ? (current ?? tenants[0]!) : null;
  const canRead = tenantsFailure === null && target === null && has('deployment.tenants.read');
  const [read, setRead] = useState<TenantsRead | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (target !== null) navigate(`/tenants/${encodeURIComponent(target.id)}/settings`, { replace: true });
  }, [target]);

  useEffect(() => {
    if (!canRead) return;
    const controller = new AbortController();
    setRead(null);
    void readTenants(request, undefined, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      if (result.kind === 'ready' && result.list.tenants.length > 0) {
        navigate(TENANTS_PATH, { replace: true });
        return;
      }
      setRead(result);
    });
    return () => controller.abort();
  }, [canRead, request, attempt]);

  if (target !== null) return <SectionPage title={messages.landingTitle} data-testid="landing" />;

  if (tenantsFailure !== null) {
    return (
      <SectionPage title={messages.landingTitle} data-testid="landing">
        <Banner tone="bad" action={{ label: messages.retry, onClick: onRetry }} data-testid="landing-tenants-failed">
          <p>{messages.loadFailed}</p>
          <ErrorReference code={tenantsFailure.code} traceId={tenantsFailure.traceId} />
        </Banner>
      </SectionPage>
    );
  }

  if (!canRead) {
    return (
      <SectionPage title={messages.landingTitle} data-testid="landing">
        <EmptyState message={messages.landingNoAccess} />
      </SectionPage>
    );
  }

  const creating = read?.kind === 'ready';
  return (
    <SectionPage
      title={creating ? messages.createTenantTitle : messages.landingTitle}
      description={creating ? messages.createTenantDescription : undefined}
      data-testid="landing"
    >
      <TenantsReadState read={read} onRetry={() => setAttempt((n) => n + 1)}>
        {(ready) => <CreateTenantForm request={request} zone={ready.list.tenantZone} />}
      </TenantsReadState>
    </SectionPage>
  );
}
