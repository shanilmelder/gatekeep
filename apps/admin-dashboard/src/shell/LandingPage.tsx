import { EmptyState, SectionPage, useMessages } from '@gatekeep/ui/admin';
import { useEffect, useState } from 'react';
import { navigate } from '../navigation';
import { useCapabilities } from './capabilities';
import type { ShellRequest } from './CredentialsPage';
import { CreateTenantForm, TenantsReadState } from './CreateTenantPage';
import { TENANTS_PATH, readTenants, type TenantsRead } from './tenants';

/**
 * The landing page, interim until Stories 1.28 and 3.1 own the final rules. An Admin who can list
 * Tenants has the first page read: with none, it is the Create Tenant form, in place (FR-44); with
 * any, the URL becomes the Tenants page. Anyone else has no Tenant to reach. It is one Section
 * page throughout, so its h1 stays the same node as the read answers, and focus on it stays.
 */
export function LandingPage({ request }: { request: ShellRequest }) {
  const messages = useMessages();
  const { has } = useCapabilities();
  const canRead = has('deployment.tenants.read');
  const [read, setRead] = useState<TenantsRead | null>(null);
  const [attempt, setAttempt] = useState(0);

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
