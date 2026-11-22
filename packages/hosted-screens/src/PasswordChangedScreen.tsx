import { ButtonLink, HostedCard, StatusIcon, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';

export interface PasswordChangedScreenProps {
  /** The Tenant the reset was for. */
  tenant: HostedTenant;
  /**
   * Where "Log in" goes, by a top-level GET to Login: given only in the browser that asked for the reset, whose sign-in
   * went back to Login with the email kept. Without it the page says it can be closed, with no action.
   */
  logInHref?: string;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * Password changed (Story 4.11, EXPERIENCE.md): the success status icon (its ✓ glyph), "Password changed" and "You've
 * been signed out everywhere for your security.", then "Log in" in the browser that asked, or "You can close this page."
 * with no action anywhere else. A reset never signs anyone in.
 */
export function PasswordChangedScreen({ tenant, logInHref, headingLevel, className, 'data-testid': testId }: PasswordChangedScreenProps) {
  const messages = useMessages();
  const logsIn = logInHref !== undefined && logInHref !== '';
  return (
    <HostedCard
      tenant={tenant}
      icon={<StatusIcon status="success" />}
      title={messages.passwordChangedTitle}
      subtitle={messages.passwordChangedBody}
      headingLevel={headingLevel}
      action={
        logsIn ? (
          <ButtonLink variant="primary" href={logInHref} data-testid="password-changed-login">
            {messages.passwordChangedLogIn}
          </ButtonLink>
        ) : undefined
      }
      link={logsIn ? undefined : <span data-testid="password-changed-close">{messages.passwordChangedClose}</span>}
      className={className}
      data-testid={testId}
    />
  );
}
