import { Button, HostedCard, formatMessage, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';

export interface LogoutScreenProps {
  /** The Tenant being logged out of. */
  tenant: HostedTenant;
  /** "Log out": the caller confirms the logout. */
  onLogOut: () => void;
  /** "Stay signed in": the caller leaves without ending anything. */
  onStay: () => void;
  /** Log out is under way. */
  pending?: boolean;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * The logout confirmation (Story 4.13, EXPERIENCE.md, Logout): "Log out of {Tenant}?", "You'll be signed out of all
 * {Tenant} apps on this browser.", then side by side the secondary "Stay signed in" and the primary "Log out",
 * stacking where the card is too narrow for both.
 */
export function LogoutScreen({ tenant, onLogOut, onStay, pending = false, headingLevel, className, 'data-testid': testId }: LogoutScreenProps) {
  const messages = useMessages();
  return (
    <HostedCard
      tenant={tenant}
      title={formatMessage(messages.logoutTitle, { tenant: tenant.name })}
      subtitle={formatMessage(messages.logoutBody, { tenant: tenant.name })}
      headingLevel={headingLevel}
      actionLayout="pair"
      action={
        <>
          <Button variant="secondary" aria-disabled={pending || undefined} onClick={onStay} data-testid="logout-stay">
            {messages.logoutStay}
          </Button>
          <Button variant="primary" pending={pending} onClick={onLogOut} data-testid="logout-confirm">
            {messages.logoutConfirm}
          </Button>
        </>
      }
      className={className}
      data-testid={testId}
    />
  );
}
