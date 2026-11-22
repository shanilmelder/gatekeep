import { Button, HostedCard, IdentifierChip, PasswordField, formatMessage, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';
import { useId } from 'react';

export interface PasswordScreenProps {
  /** The Tenant the sign-in is for. Its name, never Gatekeep's, is in the subtitle and the logo tile. */
  tenant: HostedTenant;
  /** The email entered at Login, shown whole in the identifier chip and held in the form's read-only username field. */
  email: string;
  /** The password field's value. The caller owns it, and only Log in sends it. */
  password: string;
  onPasswordChange: (password: string) => void;
  /** Log in: the caller submits. The form's own submission never leaves the page. */
  onLogIn: () => void;
  /** The chip's "Edit": the caller goes back to Login, the email kept. */
  onEdit: () => void;
  /** The password field's error, "Incorrect email or password.", from the catalogue. */
  error?: string;
  /** Log in or Edit is under way. */
  pending?: boolean;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * The Password step (Story 4.9, EXPERIENCE.md, Hosted Login): "Enter your password", the identifier chip with the email
 * (wrapping, never truncated) and its "Edit", a visually hidden read-only `username` field holding the email in the same
 * form for password managers, the masked "Password" field (`autocomplete="current-password"`, paste and password managers
 * allowed) and the primary "Log in". A failed submit shows "Incorrect email or password." under the password, the same
 * for every account. It has no "Forgot password?" (Story 4.11), no "Use a recovery code" (Story 6.8) and no passkey hint
 * (Design Delta): no deferred controls. First load focuses the card heading, since no field is marked for it.
 */
export function PasswordScreen({
  tenant,
  email,
  password,
  onPasswordChange,
  onLogIn,
  onEdit,
  error,
  pending = false,
  headingLevel,
  className,
  'data-testid': testId,
}: PasswordScreenProps) {
  const messages = useMessages();
  const formId = useId();
  return (
    <HostedCard
      tenant={tenant}
      title={messages.passwordTitle}
      subtitle={formatMessage(messages.loginSubtitle, { tenant: tenant.name })}
      headingLevel={headingLevel}
      action={
        <Button type="submit" form={formId} variant="primary" pending={pending} data-testid="password-login">
          {messages.passwordLogIn}
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
          onLogIn();
        }}
      >
        <IdentifierChip
          identifier={email}
          editLabel={messages.identifierEdit}
          onEdit={onEdit}
          pending={pending}
          usernameLabel={messages.loginEmailLabel}
          data-testid="identifier-chip"
        />
        <PasswordField
          label={messages.passwordLabel}
          name="current-password"
          autoComplete="current-password"
          required
          value={password}
          error={error}
          onChange={(event) => onPasswordChange(event.currentTarget.value)}
          data-testid="password-input"
        />
      </form>
    </HostedCard>
  );
}
