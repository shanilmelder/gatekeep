import {
  Button,
  Field,
  HostedCard,
  Input,
  LinkButton,
  PasswordField,
  StrengthMeter,
  TermsAgreement,
  formatMessage,
  useMessages,
  type HostedTenant,
  type PasswordStrengthLevel,
} from '@gatekeep/ui/hosted';
import { useId } from 'react';

export interface SignupScreenProps {
  /** The Tenant the sign-up is for. Its name, never Gatekeep's, is in the subtitle and the logo tile. */
  tenant: HostedTenant;
  /** The email field's value. The caller owns it: the email carries across steps. */
  email: string;
  onEmailChange: (email: string) => void;
  /** The password field's value. The caller owns it, and only Create account sends it. */
  password: string;
  onPasswordChange: (password: string) => void;
  /** The policy the strength meter checks in the browser, from the step. */
  minLength: number;
  strength: PasswordStrengthLevel;
  /** Create account: the caller submits. The form's own submission never leaves the page. */
  onCreate: () => void;
  /** "Already have an account? Log in": the caller goes back to Login, the email kept. */
  onLogIn: () => void;
  /** The email field's error, such as "Enter a valid email address.", from the catalogue. */
  emailError?: string;
  /** The server's refusal of the password, each failing rule's sentence from the catalogue. */
  passwordErrors?: readonly string[];
  /**
   * The Tenant's terms URL (Story 4.8), or null for none: with one, a required "I agree to the Terms of Service" row
   * shows between the strength meter and Create account.
   */
  termsUrl?: string | null;
  /** Whether the terms checkbox is ticked. The caller owns it, and Create account sends it. */
  termsAccepted?: boolean;
  onTermsChange?: (accepted: boolean) => void;
  /** The terms checkbox's error, "Accept the terms to continue.", from the catalogue. */
  termsError?: string;
  /** Create account is under way. */
  pending?: boolean;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * Signup (Story 4.7, EXPERIENCE.md, Hosted Login): "Create your account", the "Email address" field
 * (`autocomplete="username"`), the masked "Password" field (`autocomplete="new-password"`, paste and password managers
 * allowed), the strength meter and its checklist, Create account, and "Already have an account? Log in". The meter
 * follows the typing with no request; the server checks the whole policy at submit, and its refusal names each rule under
 * the password. With a terms URL (Story 4.8), a terms checkbox follows the meter, its link outside the label opening the
 * terms in a new tab; refused, its error shows under it. There is no breach tick (Design Delta).
 */
export function SignupScreen({
  tenant,
  email,
  onEmailChange,
  password,
  onPasswordChange,
  minLength,
  strength,
  onCreate,
  onLogIn,
  emailError,
  passwordErrors,
  termsUrl = null,
  termsAccepted = false,
  onTermsChange,
  termsError,
  pending = false,
  headingLevel,
  className,
  'data-testid': testId,
}: SignupScreenProps) {
  const messages = useMessages();
  const formId = useId();
  const passwordError = passwordErrors && passwordErrors.length > 0 ? passwordErrors.join(' ') : undefined;
  return (
    <HostedCard
      tenant={tenant}
      title={messages.signupTitle}
      subtitle={formatMessage(messages.signupSubtitle, { tenant: tenant.name })}
      headingLevel={headingLevel}
      action={
        <Button type="submit" form={formId} variant="primary" pending={pending} data-testid="signup-create">
          {messages.signupCreate}
        </Button>
      }
      link={
        <>
          {messages.signupHaveAccount}{' '}
          <LinkButton onClick={onLogIn} data-testid="signup-login">
            {messages.signupLogIn}
          </LinkButton>
        </>
      }
      className={className}
      data-testid={testId}
    >
      <form
        id={formId}
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          onCreate();
        }}
      >
        <Field label={messages.loginEmailLabel} error={emailError}>
          <Input
            type="email"
            name="username"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            inputMode="email"
            required
            value={email}
            onChange={(event) => onEmailChange(event.currentTarget.value)}
            data-gk-initial-focus=""
            data-testid="signup-email"
          />
        </Field>
        <PasswordField
          label={messages.signupPasswordLabel}
          name="new-password"
          autoComplete="new-password"
          required
          value={password}
          error={passwordError}
          onChange={(event) => onPasswordChange(event.currentTarget.value)}
          data-testid="signup-password"
        />
        <StrengthMeter password={password} minLength={minLength} strength={strength} data-testid="strength-meter" />
        {termsUrl !== null && (
          <TermsAgreement
            label={messages.signupTermsAgree}
            linkLabel={messages.signupTermsLink}
            href={termsUrl}
            checked={termsAccepted}
            onChange={(accepted) => onTermsChange?.(accepted)}
            error={termsError}
            data-testid="signup-terms"
          />
        )}
      </form>
    </HostedCard>
  );
}
