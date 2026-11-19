import { Button, Field, HostedCard, Input, LinkButton, formatMessage, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';
import { useId } from 'react';

export interface LoginScreenProps {
  /** The Tenant Login speaks for. Its name, never Gatekeep's, is in the subtitle and the logo tile. */
  tenant: HostedTenant;
  /** The email field's value. The caller owns it: the email carries across steps and a restart. */
  email: string;
  /** Every change to the email field. */
  onEmailChange: (email: string) => void;
  /** Continue: the caller submits the email. The form's own submission never leaves the page. */
  onContinue: () => void;
  /** The field error to show, such as "Enter a valid email address.", from the catalogue. */
  error?: string;
  /** Continue is under way: the button shows it and ignores another submit. */
  pending?: boolean;
  /**
   * "Sign up" (Story 4.7): the caller moves to Signup, carrying the email. Shown only while the Tenant's database
   * Connection is enabled with sign-up on, which `signupEnabled` says; never a deferred control.
   */
  onSignUp?: () => void;
  /** Whether sign-up is open, so "Don't have an account? Sign up" shows. */
  signupEnabled?: boolean;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * Login's identifier step (Story 4.2, EXPERIENCE.md, Hosted Login): the Tenant's monogram, "Welcome back",
 * "Log in to {tenant} to continue", the "Email address" field and Continue, then from Story 4.7 "Don't have an account?
 * Sign up" while sign-up is open. Its content depends only on the Connections enabled, never on the identifier; there is
 * no social, passkey, SSO or recovery-code control yet (FR-33: no deferred controls). The email field is type email,
 * `autocomplete="username webauthn"` so password managers and passkeys find it, and carries
 * `data-gk-initial-focus`, so first load focuses it unless a field is invalid.
 */
export function LoginScreen({
  tenant,
  email,
  onEmailChange,
  onContinue,
  error,
  pending = false,
  onSignUp,
  signupEnabled = false,
  headingLevel,
  className,
  'data-testid': testId,
}: LoginScreenProps) {
  const messages = useMessages();
  const formId = useId();
  return (
    <HostedCard
      tenant={tenant}
      title={messages.loginTitle}
      subtitle={formatMessage(messages.loginSubtitle, { tenant: tenant.name })}
      headingLevel={headingLevel}
      action={
        <Button type="submit" form={formId} variant="primary" pending={pending}>
          {messages.continue}
        </Button>
      }
      link={
        signupEnabled && onSignUp ? (
          <>
            {messages.signupPrompt}{' '}
            <LinkButton onClick={onSignUp} data-testid="login-signup">
              {messages.signupLink}
            </LinkButton>
          </>
        ) : undefined
      }
      className={className}
      data-testid={testId}
    >
      <form
        id={formId}
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          onContinue();
        }}
      >
        <Field label={messages.loginEmailLabel} error={error}>
          <Input
            type="email"
            name="username"
            autoComplete="username webauthn"
            autoCapitalize="none"
            spellCheck={false}
            inputMode="email"
            required
            value={email}
            onChange={(event) => onEmailChange(event.currentTarget.value)}
            data-gk-initial-focus=""
          />
        </Field>
      </form>
    </HostedCard>
  );
}
