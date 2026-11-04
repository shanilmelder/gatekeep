import { EmptyState, SectionPage, useMessages } from '@gatekeep/ui/admin';
import { useCapabilities } from './capabilities';

/**
 * The landing page, a holding page until Story 1.27's create-Tenant form: an Admin who can list
 * Tenants has none yet, and anyone else has no Tenant to reach. Story 1.28 owns the final rules.
 */
export function LandingPage() {
  const messages = useMessages();
  const { has } = useCapabilities();
  return (
    <SectionPage title={messages.landingTitle} data-testid="landing">
      <EmptyState message={has('deployment.tenants.read') ? messages.landingNoTenants : messages.landingNoAccess} />
    </SectionPage>
  );
}
