import { HostedCard, LinkButton, StatusIcon, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';

export interface LinkSentScreenProps {
  /** The Tenant the link is for. */
  tenant: HostedTenant;
  /** Story 4.11: "Back to login", after a reset request on the sign-in itself. Without it there is no action. */
  onBack?: () => void;
  /** Back to login is under way. */
  pending?: boolean;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * The neutral link confirmation (Story 4.7, EXPERIENCE.md): "If an account exists for that email, we've sent a link.",
 * the same whether a link was sent or not, so it never says whether an account exists. After a reset request (Story 4.11)
 * it offers "Back to login".
 */
export function LinkSentScreen({ tenant, onBack, pending = false, headingLevel, className, 'data-testid': testId }: LinkSentScreenProps) {
  const messages = useMessages();
  return (
    <HostedCard
      tenant={tenant}
      icon={<StatusIcon status="warning" />}
      title={messages.linkSentTitle}
      subtitle={messages.linkSentBody}
      headingLevel={headingLevel}
      link={
        onBack ? (
          <LinkButton onClick={onBack} aria-disabled={pending || undefined} data-testid="link-sent-back">
            {messages.backToLogin}
          </LinkButton>
        ) : undefined
      }
      className={className}
      data-testid={testId}
    />
  );
}
