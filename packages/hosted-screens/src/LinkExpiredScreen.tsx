import { Button, HostedCard, StatusIcon, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';

export interface LinkExpiredScreenProps {
  /** The Tenant the link is for. */
  tenant: HostedTenant;
  /** "Send a new link": the caller asks for one. Without it, as for a value that was never a link, there is no action. */
  onSendNewLink?: () => void;
  /** The request is under way. */
  pending?: boolean;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * Link expired (Story 4.7, EXPERIENCE.md): the error status icon and "This link has expired or was already used.", the
 * same for an expired, used, unknown or another Tenant's link, with "Send a new link", which leads to the neutral
 * confirmation.
 */
export function LinkExpiredScreen({ tenant, onSendNewLink, pending = false, headingLevel, className, 'data-testid': testId }: LinkExpiredScreenProps) {
  const messages = useMessages();
  return (
    <HostedCard
      tenant={tenant}
      icon={<StatusIcon status="error" />}
      title={messages.linkExpiredTitle}
      headingLevel={headingLevel}
      action={
        onSendNewLink ? (
          <Button variant="primary" pending={pending} onClick={onSendNewLink} data-testid="link-send-new">
            {messages.linkExpiredSendNew}
          </Button>
        ) : undefined
      }
      className={className}
      data-testid={testId}
    />
  );
}
