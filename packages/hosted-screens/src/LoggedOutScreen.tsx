import { HostedCard, StatusIcon, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';

export interface LoggedOutScreenProps {
  /** The Tenant logged out of. */
  tenant: HostedTenant;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * A completed logout with no redirect back to an Application (Story 4.13, EXPERIENCE.md, Logout): the success status
 * icon (its ✓ glyph) and "You're logged out.", with no action.
 */
export function LoggedOutScreen({ tenant, headingLevel, className, 'data-testid': testId }: LoggedOutScreenProps) {
  const messages = useMessages();
  return (
    <HostedCard
      tenant={tenant}
      icon={<StatusIcon status="success" />}
      title={messages.loggedOutTitle}
      headingLevel={headingLevel}
      className={className}
      data-testid={testId}
    />
  );
}
