import { ButtonLink, HostedCard, StatusIcon, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';

export interface EmailVerifiedScreenProps {
  /** The Tenant the sign-up was for. */
  tenant: HostedTenant;
  /**
   * Where Continue goes, by a top-level GET back to the authorization request: given only when the link was opened in
   * the browser that signed up, whose Session it started. Without it the page says it can be closed, with no action.
   */
  continueHref?: string;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * Email verified (Story 4.7, EXPERIENCE.md): the success status icon (its ✓ glyph) and "Email verified", then Continue
 * when this browser signed up, or "You can close this page." with no action anywhere else.
 */
export function EmailVerifiedScreen({ tenant, continueHref, headingLevel, className, 'data-testid': testId }: EmailVerifiedScreenProps) {
  const messages = useMessages();
  const continues = continueHref !== undefined && continueHref !== '';
  return (
    <HostedCard
      tenant={tenant}
      icon={<StatusIcon status="success" />}
      title={messages.emailVerifiedTitle}
      subtitle={continues ? undefined : messages.emailVerifiedClose}
      headingLevel={headingLevel}
      action={
        continues ? (
          <ButtonLink variant="primary" href={continueHref} data-testid="verified-continue">
            {messages.emailVerifiedContinue}
          </ButtonLink>
        ) : undefined
      }
      className={className}
      data-testid={testId}
    />
  );
}
