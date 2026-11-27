import { HostedPage, PASSWORD_MAX_LENGTH, formatMessage, useMessages, type Messages } from '@gatekeep/ui/hosted';
import {
  EmailVerifiedScreen,
  ForgotPasswordScreen,
  GenericErrorScreen,
  LinkExpiredScreen,
  LinkSentScreen,
  LoggedOutScreen,
  LoginScreen,
  LogoutScreen,
  StillSignedInScreen,
  PasswordChangedScreen,
  PasswordScreen,
  ResetPasswordScreen,
  SignupScreen,
  VerifyEmailScreen,
} from '@gatekeep/hosted-screens';
import { useEffect, useLayoutEffect, type ReactNode } from 'react';
import { LOGIN_PATH } from './navigate';
import type { Step } from './step';

/** The Tenant theme scope: the server's theme stylesheet sets its tokens under [data-gk-theme]. */
export const THEME = 'tenant';

/** Login's and Signup's email field error text, by the code the server sends it as. */
const FIELD_ERRORS: Readonly<Record<string, keyof Messages>> = { email_invalid: 'emailInvalid' };

/** A refused password's rule sentences (Story 4.7), by the rule codes the server names. */
const RULE_ERRORS: Readonly<Record<string, keyof Messages>> = {
  length: 'passwordErrorLength',
  too_long: 'passwordErrorTooLong',
  classes: 'passwordErrorClasses',
  repeats: 'passwordErrorRepeats',
  dictionary: 'passwordErrorDictionary',
  personal_data: 'passwordErrorPersonalData',
  history: 'passwordErrorHistory',
};

/** Each step's screen heading, for the page title. A redirect shows no screen, and keeps Login's. */
function heading(step: Step, messages: Readonly<Messages>, stayed = false): string {
  switch (step.step) {
    case 'generic_error':
      return messages.genericErrorTitle;
    case 'login':
    case 'redirect':
      return messages.loginTitle;
    case 'signup':
      return messages.signupTitle;
    case 'password':
      return messages.passwordTitle;
    case 'verify_email':
      return messages.verifyEmailTitle;
    case 'email_verified':
      return messages.emailVerifiedTitle;
    case 'link_expired':
      return messages.linkExpiredTitle;
    case 'link_sent':
      return messages.linkSentTitle;
    case 'forgot_password':
      return messages.forgotPasswordTitle;
    case 'reset_password':
      return messages.resetPasswordTitle;
    case 'password_changed':
      return messages.passwordChangedTitle;
    case 'logout':
      if (stayed) return messages.stillSignedInTitle;
      return formatMessage(messages.logoutTitle, { tenant: step.data.tenant });
    case 'logged_out':
      return messages.loggedOutTitle;
  }
}

/** What the screens need from the page: the email and password it carries, and each step's actions. */
export interface StepControls {
  email: string;
  onEmailChange: (email: string) => void;
  password: string;
  onPasswordChange: (password: string) => void;
  /** Login's Continue. */
  onContinue: () => void;
  /** Login's "Sign up". */
  onSignUp: () => void;
  /** Signup's "Log in". */
  onLogIn: () => void;
  /** Signup's Create account. */
  onCreate: () => void;
  /** Story 4.9: the Password step's Log in. */
  onPasswordLogIn: () => void;
  /** The Password step's identifier chip "Edit". */
  onEditIdentifier: () => void;
  /** Story 4.11: Reset password's confirmation, and its change. */
  confirm: string;
  onConfirmChange: (confirm: string) => void;
  /** The Password step's "Forgot password?". */
  onForgotPassword: () => void;
  /** Forgot password's "Send reset link". */
  onSendReset: () => void;
  /** "Back to login" from Forgot password or its confirmation. */
  onResetBack: () => void;
  /** Reset password's submit. */
  onResetSubmit: () => void;
  /** Story 4.8: whether Signup's terms checkbox is ticked, and its change. */
  termsAccepted: boolean;
  onTermsChange: (accepted: boolean) => void;
  /** Email verification required's "I've verified — continue". */
  onVerified: () => void;
  /** Email verification required's "Resend email". */
  onResend: () => void;
  /** Link expired's "Send a new link". */
  onSendNewLink: () => void;
  /** Story 4.13: the logout confirmation's "Log out", and its "Stay signed in". */
  onLogOut: () => void;
  onStay: () => void;
  /** "Stay signed in" with no page to go back to: the confirmation becomes "You're still signed in.". */
  stayed: boolean;
  pending: boolean;
  resending: boolean;
  /** How many times the email was sent again on this page. */
  sends: number;
}

/** The field error's text for a known code; the readers admit only known codes, so nothing else is shown. */
function fieldError(code: string | null, messages: Readonly<Messages>): string | undefined {
  return code !== null && Object.hasOwn(FIELD_ERRORS, code) ? messages[FIELD_ERRORS[code]!] : undefined;
}

/** A refused password's rule sentences (Stories 4.7 and 4.11), or undefined when the error isn't a rule refusal. */
function ruleErrors(error: string | null, rules: readonly string[], minLength: number, messages: Readonly<Messages>): string[] | undefined {
  return error === 'password_rule'
    ? rules.filter((rule) => Object.hasOwn(RULE_ERRORS, rule)).map((rule) =>
        formatMessage(messages[RULE_ERRORS[rule]!], { count: minLength, max: PASSWORD_MAX_LENGTH }),
      )
    : undefined;
}

function screen(step: Step, controls: StepControls, messages: Readonly<Messages>): ReactNode {
  switch (step.step) {
    case 'generic_error':
      return <GenericErrorScreen tenant={{ name: step.data.tenant }} code={step.data.code} traceId={step.data.traceId} />;
    case 'login':
      return (
        <LoginScreen
          tenant={{ name: step.data.tenant }}
          email={controls.email}
          onEmailChange={controls.onEmailChange}
          onContinue={controls.onContinue}
          error={fieldError(step.data.error, messages)}
          pending={controls.pending}
          signupEnabled={step.data.signupEnabled}
          onSignUp={controls.onSignUp}
        />
      );
    case 'signup': {
      const { policy, rules, error } = step.data;
      const passwordErrors = ruleErrors(error, rules, policy.minLength, messages);
      return (
        <SignupScreen
          tenant={{ name: step.data.tenant }}
          email={controls.email}
          onEmailChange={controls.onEmailChange}
          password={controls.password}
          onPasswordChange={controls.onPasswordChange}
          minLength={policy.minLength}
          strength={policy.strength}
          onCreate={controls.onCreate}
          onLogIn={controls.onLogIn}
          emailError={fieldError(error, messages)}
          passwordErrors={passwordErrors}
          termsUrl={step.data.termsUrl}
          termsAccepted={controls.termsAccepted}
          onTermsChange={controls.onTermsChange}
          termsError={error === 'terms_required' ? messages.signupTermsRequired : undefined}
          pending={controls.pending}
        />
      );
    }
    case 'password':
      return (
        <PasswordScreen
          tenant={{ name: step.data.tenant }}
          email={step.data.email ?? controls.email}
          password={controls.password}
          onPasswordChange={controls.onPasswordChange}
          onLogIn={controls.onPasswordLogIn}
          onEdit={controls.onEditIdentifier}
          onForgotPassword={controls.onForgotPassword}
          error={step.data.error === 'incorrect' ? messages.passwordIncorrect : undefined}
          pending={controls.pending}
        />
      );
    case 'verify_email':
      return (
        <VerifyEmailScreen
          tenant={{ name: step.data.tenant }}
          email={step.data.email}
          onContinue={controls.onVerified}
          onResend={controls.onResend}
          error={step.data.error === 'not_verified_yet' ? messages.verifyEmailNotYet : undefined}
          resent={step.data.resent}
          sends={controls.sends}
          pending={controls.pending}
          resending={controls.resending}
        />
      );
    case 'email_verified':
      return (
        <EmailVerifiedScreen
          tenant={{ name: step.data.tenant }}
          continueHref={step.data.continueTo === 'app' && step.data.location !== null ? step.data.location : undefined}
        />
      );
    case 'link_expired':
      return (
        <LinkExpiredScreen
          tenant={{ name: step.data.tenant }}
          onSendNewLink={step.data.token === null ? undefined : controls.onSendNewLink}
          pending={controls.pending}
        />
      );
    case 'link_sent':
      return (
        <LinkSentScreen
          tenant={{ name: step.data.tenant }}
          onBack={step.data.back ? controls.onResetBack : undefined}
          pending={controls.pending}
        />
      );
    case 'forgot_password':
      return (
        <ForgotPasswordScreen
          tenant={{ name: step.data.tenant }}
          email={controls.email}
          onEmailChange={controls.onEmailChange}
          onSend={controls.onSendReset}
          onBack={controls.onResetBack}
          error={fieldError(step.data.error, messages)}
          pending={controls.pending}
        />
      );
    case 'reset_password': {
      const { policy, rules, error } = step.data;
      return (
        <ResetPasswordScreen
          tenant={{ name: step.data.tenant }}
          email={step.data.email ?? undefined}
          password={controls.password}
          onPasswordChange={controls.onPasswordChange}
          confirm={controls.confirm}
          onConfirmChange={controls.onConfirmChange}
          minLength={policy.minLength}
          strength={policy.strength}
          onSubmit={controls.onResetSubmit}
          passwordErrors={ruleErrors(error, rules, policy.minLength, messages)}
          confirmError={error === 'password_mismatch' ? messages.resetPasswordMismatch : undefined}
          pending={controls.pending}
        />
      );
    }
    case 'password_changed':
      return (
        <PasswordChangedScreen tenant={{ name: step.data.tenant }} logInHref={step.data.continueTo === 'login' ? LOGIN_PATH : undefined} />
      );
    case 'logout':
      if (controls.stayed) return <StillSignedInScreen tenant={{ name: step.data.tenant }} />;
      return <LogoutScreen tenant={{ name: step.data.tenant }} onLogOut={controls.onLogOut} onStay={controls.onStay} pending={controls.pending} />;
    case 'logged_out':
      // Story 4.13: with a redirect the page is leaving for the Application by a top-level GET: nothing to show meanwhile.
      return step.data.redirectTo === null ? <LoggedOutScreen tenant={{ name: step.data.tenant }} /> : null;
    case 'redirect':
      // The page is leaving by a top-level GET: nothing to show meanwhile.
      return null;
  }
}

/**
 * Where focus goes when a step is shown (EXPERIENCE.md, Focus and titles): the first invalid field, else
 * Login's or Signup's email field, which its screen marks with data-gk-initial-focus, else the card heading, which
 * takes focus without joining the tab order.
 */
function initialFocus(main: HTMLElement): HTMLElement | null {
  const invalid = main.querySelector<HTMLElement>('[aria-invalid="true"]');
  if (invalid) return invalid;
  const email = main.querySelector<HTMLElement>('input[data-gk-initial-focus]');
  if (email) return email;
  const title = main.querySelector<HTMLElement>('h1');
  title?.setAttribute('tabindex', '-1');
  return title;
}

/** Whether the step shows a failed submit: a field error, or "We haven't seen that yet". */
export function isFailed(step: Step): boolean {
  return (
    (step.step === 'login' ||
      step.step === 'signup' ||
      step.step === 'password' ||
      step.step === 'verify_email' ||
      step.step === 'forgot_password' ||
      step.step === 'reset_password') &&
    step.data.error !== null
  );
}

/**
 * One step's page: its screen in the Hosted page frame, following the device's scheme, under the
 * Tenant's theme scope. The title is "{heading} – {Tenant}", or the heading alone with no Tenant, with
 * "Error:" before it after a failed submit. `shown` changes each time the server answers with a step, so
 * focus moves again then: to the invalid field after a failed submit, else as on first load.
 */
export function StepScreen({ step, controls, failed = false, shown = 0 }: { step: Step; controls: StepControls; failed?: boolean; shown?: number }) {
  const messages = useMessages();
  const title = heading(step, messages, controls.stayed);
  const tenant = step.data.tenant.trim();

  useLayoutEffect(() => {
    const plain = tenant === '' ? title : formatMessage(messages.hostedPageTitle, { heading: title, tenant });
    document.title = failed ? formatMessage(messages.hostedErrorTitle, { title: plain }) : plain;
  }, [messages, title, tenant, failed]);

  useEffect(() => {
    const main = document.querySelector('main');
    if (main) initialFocus(main)?.focus({ preventScroll: true });
  }, [shown]);

  return (
    <HostedPage scheme="auto" theme={THEME}>
      {screen(step, controls, messages)}
    </HostedPage>
  );
}
