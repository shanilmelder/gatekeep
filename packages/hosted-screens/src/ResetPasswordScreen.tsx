import { Button, HostedCard, PasswordField, StrengthMeter, useMessages, type HostedTenant, type PasswordStrengthLevel } from '@gatekeep/ui/hosted';
import { useId } from 'react';

export interface ResetPasswordScreenProps {
  /** The Tenant the reset is for. */
  tenant: HostedTenant;
  /** The link User's email, held in a visually hidden read-only username field for password managers. */
  email?: string;
  /** The new password's value. The caller owns it, and only Reset password sends it. */
  password: string;
  onPasswordChange: (password: string) => void;
  /** The confirmation's value. The caller owns it. */
  confirm: string;
  onConfirmChange: (confirm: string) => void;
  /** The policy the strength meter checks in the browser, from the step. */
  minLength: number;
  strength: PasswordStrengthLevel;
  /** Reset password: the caller submits. The form's own submission never leaves the page. */
  onSubmit: () => void;
  /** The server's refusal of the new password, each failing rule's sentence from the catalogue, under New password. */
  passwordErrors?: readonly string[];
  /** The confirmation's error, "Passwords don't match.", from the catalogue. */
  confirmError?: string;
  /** Reset password is under way. */
  pending?: boolean;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * Reset password (Story 4.11, EXPERIENCE.md, Hosted Login): "Choose a new password", the masked "New password" field
 * (`autocomplete="new-password"`), beside a visually hidden read-only `username` field with the link User's email for
 * password managers, with the strength meter, which follows the typing with no request, the masked
 * "Confirm password" field (`autocomplete="new-password"`), and "Reset password". The server checks the whole policy at
 * submit and names each failing rule under New password; a confirmation that doesn't match shows "Passwords don't
 * match." under Confirm password.
 */
export function ResetPasswordScreen({
  tenant,
  email,
  password,
  onPasswordChange,
  confirm,
  onConfirmChange,
  minLength,
  strength,
  onSubmit,
  passwordErrors,
  confirmError,
  pending = false,
  headingLevel,
  className,
  'data-testid': testId,
}: ResetPasswordScreenProps) {
  const messages = useMessages();
  const formId = useId();
  const passwordError = passwordErrors && passwordErrors.length > 0 ? passwordErrors.join(' ') : undefined;
  return (
    <HostedCard
      tenant={tenant}
      title={messages.resetPasswordTitle}
      headingLevel={headingLevel}
      action={
        <Button type="submit" form={formId} variant="primary" pending={pending} data-testid="reset-submit">
          {messages.resetPasswordSubmit}
        </Button>
      }
      className={className}
      data-testid={testId}
    >
      <form
        id={formId}
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit();
        }}
      >
        <PasswordField
          label={messages.resetPasswordNewLabel}
          username={email}
          usernameLabel={messages.loginEmailLabel}
          name="new-password"
          autoComplete="new-password"
          required
          value={password}
          error={passwordError}
          onChange={(event) => onPasswordChange(event.currentTarget.value)}
          data-testid="reset-password"
        />
        <StrengthMeter password={password} minLength={minLength} strength={strength} data-testid="strength-meter" />
        <PasswordField
          label={messages.resetPasswordConfirmLabel}
          name="confirm-password"
          autoComplete="new-password"
          required
          value={confirm}
          error={confirmError}
          onChange={(event) => onConfirmChange(event.currentTarget.value)}
          data-testid="reset-confirm"
        />
      </form>
    </HostedCard>
  );
}
