import { Button, HostedCard, ResendAction, StatusIcon, formatMessage, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';

export interface VerifyEmailScreenProps {
  /** The Tenant the sign-up is for. */
  tenant: HostedTenant;
  /** The address the link went to, as entered, or null when the step doesn't name one. */
  email: string | null;
  /** "I've verified — continue": the caller asks whether the link was used. */
  onContinue: () => void;
  /** "Resend email": the caller asks for a new link. */
  onResend: () => void;
  /** "We haven't seen that yet. Check your inbox.", after Continue before the link was used. */
  error?: string;
  /** The email was just sent again: "Email sent" is announced once. */
  resent?: boolean;
  /** How many times the email was sent again on this page: each change starts the resend countdown again. */
  sends?: number;
  /** Continue is under way. */
  pending?: boolean;
  /** Resend is under way. */
  resending?: boolean;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * Email verification required (Story 4.7, EXPERIENCE.md): the warning status icon (its `@` glyph), "Verify your email to
 * continue", "We sent a link to {email}. Click it, then come back here.", the primary "I've verified — continue", and
 * "Resend email", `aria-disabled` for 30 seconds with its countdown outside any live region. The same screen answers
 * every address, so it never says whether an account exists.
 */
export function VerifyEmailScreen({
  tenant,
  email,
  onContinue,
  onResend,
  error,
  resent = false,
  sends,
  pending = false,
  resending = false,
  headingLevel,
  className,
  'data-testid': testId,
}: VerifyEmailScreenProps) {
  const messages = useMessages();
  return (
    <HostedCard
      tenant={tenant}
      icon={<StatusIcon status="warning" />}
      title={messages.verifyEmailTitle}
      subtitle={email ? formatMessage(messages.verifyEmailBody, { email }) : messages.verifyEmailBodyNoAddress}
      headingLevel={headingLevel}
      action={
        <Button variant="primary" pending={pending} onClick={onContinue} data-testid="verify-continue">
          {messages.verifyEmailContinue}
        </Button>
      }
      link={<ResendAction label={messages.resendEmail} onResend={onResend} restartKey={sends} sent={resent} pending={resending} data-testid="verify-resend" />}
      className={className}
      data-testid={testId}
    >
      {error ? (
        // Injected after a failed Continue, so it is an alert.
        <p role="alert" data-testid="verify-error">
          {error}
        </p>
      ) : undefined}
    </HostedCard>
  );
}
