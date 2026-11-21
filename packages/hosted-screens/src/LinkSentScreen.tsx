import { HostedCard, StatusIcon, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';

export interface LinkSentScreenProps {
  /** The Tenant the link is for. */
  tenant: HostedTenant;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * The neutral link confirmation (Story 4.7, EXPERIENCE.md): "If an account exists for that email, we've sent a link.",
 * the same whether a link was sent or not, so it never says whether an account exists.
 */
export function LinkSentScreen({ tenant, headingLevel, className, 'data-testid': testId }: LinkSentScreenProps) {
  const messages = useMessages();
  return (
    <HostedCard
      tenant={tenant}
      icon={<StatusIcon status="warning" />}
      title={messages.linkSentTitle}
      subtitle={messages.linkSentBody}
      headingLevel={headingLevel}
      className={className}
      data-testid={testId}
    />
  );
}
