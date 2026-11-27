import { HostedCard, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';

export interface StillSignedInScreenProps {
  /** The Tenant the User stays signed in to. */
  tenant: HostedTenant;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * "Stay signed in" at the logout confirmation with no page to go back to (Story 4.13): "You're still signed in." and
 * "You can close this page.", with no action. Nothing was ended.
 */
export function StillSignedInScreen({ tenant, headingLevel, className, 'data-testid': testId }: StillSignedInScreenProps) {
  const messages = useMessages();
  return (
    <HostedCard
      tenant={tenant}
      title={messages.stillSignedInTitle}
      subtitle={messages.stillSignedInBody}
      headingLevel={headingLevel}
      className={className}
      data-testid={testId}
    />
  );
}
