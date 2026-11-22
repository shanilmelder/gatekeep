import { Button, Field, HostedCard, Input, LinkButton, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';
import { useId } from 'react';

export interface ForgotPasswordScreenProps {
  /** The Tenant the reset is for. */
  tenant: HostedTenant;
  /** The email field's value. The caller owns it: it starts as the email carried from the Password step. */
  email: string;
  onEmailChange: (email: string) => void;
  /** "Send reset link": the caller submits. The form's own submission never leaves the page. */
  onSend: () => void;
  /** "Back to login": the caller goes back to Login, the email kept. */
  onBack: () => void;
  /** The email field's error, such as "Enter a valid email address.", from the catalogue. */
  error?: string;
  /** Send reset link or Back to login is under way. */
  pending?: boolean;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * Forgot password (Story 4.11, EXPERIENCE.md, Hosted Login): "Forgot your password?", "Enter your email and we'll send a
 * reset link.", the "Email address" field (`autocomplete="email"`, filled with the email carried from the Password
 * step), "Send reset link", and "Back to login". Whatever the address, the answer is the same neutral confirmation.
 */
export function ForgotPasswordScreen({
  tenant,
  email,
  onEmailChange,
  onSend,
  onBack,
  error,
  pending = false,
  headingLevel,
  className,
  'data-testid': testId,
}: ForgotPasswordScreenProps) {
  const messages = useMessages();
  const formId = useId();
  return (
    <HostedCard
      tenant={tenant}
      title={messages.forgotPasswordTitle}
      subtitle={messages.forgotPasswordBody}
      headingLevel={headingLevel}
      action={
        <Button type="submit" form={formId} variant="primary" pending={pending} data-testid="forgot-send">
          {messages.forgotPasswordSend}
        </Button>
      }
      link={
        <LinkButton onClick={onBack} aria-disabled={pending || undefined} data-testid="forgot-back">
          {messages.backToLogin}
        </LinkButton>
      }
      className={className}
      data-testid={testId}
    >
      <form
        id={formId}
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          onSend();
        }}
      >
        <Field label={messages.loginEmailLabel} error={error}>
          <Input
            type="email"
            name="email"
            autoComplete="email"
            autoCapitalize="none"
            spellCheck={false}
            inputMode="email"
            required
            value={email}
            onChange={(event) => onEmailChange(event.currentTarget.value)}
            data-testid="forgot-email"
          />
        </Field>
      </form>
    </HostedCard>
  );
}
