import { AlertDialog, useMessages } from '@gatekeep/ui/hosted';
import { useEffect, useRef, useState } from 'react';
import {
  postExtend,
  postIdentifier,
  postNewLink,
  postPassword,
  postPasswordBack,
  postResend,
  postReset,
  postResetBack,
  postResetComplete,
  postResetOpen,
  postSignup,
  postSignupBack,
  postSignupOpen,
  postVerifiedContinue,
} from './api';
import { useExpiry } from './expiry';
import { LOGIN_PATH, forgetQuery, go, queryToken } from './navigate';
import type { Step } from './step';
import { StepScreen, isFailed } from './StepScreen';

/** The steps that stand on a live sign-in transaction, whose life is counted and can be extended. */
const LIVE_STEPS: ReadonlySet<Step['step']> = new Set(['login', 'signup', 'password', 'verify_email', 'forgot_password', 'link_sent']);

/** The email a step carries, as its field starts. */
function emailOf(step: Step): string {
  return step.step === 'login' || step.step === 'signup' || step.step === 'password' || step.step === 'forgot_password' ? (step.data.email ?? '') : '';
}

/**
 * Hosted Login's page (Stories 4.1, 4.2, 4.7, 4.9 and 4.11). It shows the step the server sent and follows the next one each
 * request answers with, holding no flow logic: Continue posts the email, the Password step's Log in posts the password and
 * its Edit goes back to Login, Sign up opens Signup carrying it, Create account
 * posts the email and password, the verification step's actions ask the server again, "Forgot password?" leads to
 * Forgot password and its neutral confirmation, a reset link's page posts its new password with the link it was opened
 * with (kept in memory once the address bar drops it), a redirect step is opened with a
 * top-level GET, and while a step has a life, its expiry warning shows two minutes before the end. "Keep going" extends
 * the life without a reload; at expiry the page goes to Login, which restarts with the email kept.
 */
export function App({ initial }: { initial: Step }) {
  const messages = useMessages();
  const [step, setStep] = useState(initial);
  const [email, setEmail] = useState(emailOf(initial));
  const [password, setPassword] = useState('');
  // Story 4.11: Reset password's confirmation, and the reset link the page was opened with, kept in memory only.
  const [confirm, setConfirm] = useState('');
  const resetToken = useRef(initial.step === 'reset_password' ? queryToken() : null);
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [pending, setPending] = useState(false);
  const [resending, setResending] = useState(false);
  const [sends, setSends] = useState(0);
  const [failed, setFailed] = useState(isFailed(initial));
  const [warning, setWarning] = useState(false);
  const [shown, setShown] = useState(0);
  // Each new life restarts the countdown, even when it is the same number of seconds.
  const [life, setLife] = useState(0);
  const extending = useRef(false);
  // One step request at a time, whichever control started it (Resend and "I've verified" included), and the count of
  // steps shown, so an answer to a request made on a step since replaced is dropped rather than shown over the newer one.
  const inFlight = useRef(false);
  const shownCount = useRef(0);

  const counted = LIVE_STEPS.has(step.step) ? step.expiresInSeconds : null;
  useExpiry(
    counted,
    life,
    () => setWarning(true),
    () => go(LOGIN_PATH),
  );

  useEffect(() => {
    if (step.step === 'redirect') go(step.data.location);
  }, [step]);

  // A verification link's page: its token leaves the address bar once the page has it.
  useEffect(() => {
    if (initial.step === 'email_verified' || initial.step === 'link_expired' || initial.step === 'reset_password') forgetQuery();
  }, [initial]);

  /** A step the server answered with: shown, its life counted afresh, and focus moved to it. */
  function show(next: Step) {
    shownCount.current += 1;
    setStep(next);
    setFailed(isFailed(next));
    setWarning(false);
    setLife((n) => n + 1);
    setShown((n) => n + 1);
    // The password is kept only for a refused Create account or Reset password (Story 4.11), so it can be corrected;
    // anything else drops it, every answer to the Password step's Log in included (Story 4.9).
    if (next.step !== 'signup' && next.step !== 'reset_password') setPassword('');
    if (next.step !== 'reset_password') setConfirm('');
    if (next.step === 'login' || next.step === 'signup' || next.step === 'password' || next.step === 'forgot_password') {
      const carried = next.data.email;
      setEmail((typed) => carried ?? typed);
    }
    // Story 4.8: the terms box starts unticked on a Signup reached from another step, or asking for other terms.
    if (next.step !== 'signup' || step.step !== 'signup' || step.data.termsUrl !== next.data.termsUrl) setTermsAccepted(false);
  }

  /** Story 4.8: the terms box ticked or not; ticking it clears a terms_required error, which no longer holds. */
  function onTermsChange(accepted: boolean) {
    setTermsAccepted(accepted);
    if (accepted && step.step === 'signup' && step.data.error === 'terms_required') {
      setStep({ ...step, data: { ...step.data, error: null } });
      setFailed(false);
    }
  }

  /** Sends one request for the step on screen, at most one at a time, and shows its answer. */
  async function send(request: () => Promise<Step>, busy: (on: boolean) => void = setPending): Promise<Step | null> {
    if (inFlight.current) return null;
    inFlight.current = true;
    const sentOn = shownCount.current;
    busy(true);
    const next = await request();
    busy(false);
    inFlight.current = false;
    if (shownCount.current !== sentOn) return null;
    show(next);
    return next;
  }

  function onContinue() {
    if (step.step !== 'login' || step.csrfToken === null) return;
    const { stepVersion, csrfToken } = step;
    void send(() => postIdentifier(stepVersion, email, csrfToken, step.data.tenant));
  }

  function onSignUp() {
    if (step.step !== 'login' || step.csrfToken === null) return;
    const { stepVersion, csrfToken } = step;
    void send(() => postSignupOpen(stepVersion, email, csrfToken, step.data.tenant));
  }

  function onLogIn() {
    if (step.step !== 'signup' || step.csrfToken === null) return;
    const { stepVersion, csrfToken } = step;
    void send(() => postSignupBack(stepVersion, csrfToken, step.data.tenant));
  }

  function onCreate() {
    if (step.step !== 'signup' || step.csrfToken === null) return;
    const { stepVersion, csrfToken } = step;
    // Story 4.8: the terms unticked are refused here first, with the server's own error, and focus moves to the box. The
    // step keeps its life: nothing was asked of the server, which checks again whatever is sent.
    if (step.data.termsUrl !== null && !termsAccepted) {
      if (inFlight.current) return;
      setStep({ ...step, data: { ...step.data, error: 'terms_required', rules: [] } });
      setFailed(true);
      setShown((n) => n + 1);
      return;
    }
    void send(() => postSignup(stepVersion, email, password, termsAccepted, csrfToken, step.data.tenant));
  }

  function onPasswordLogIn() {
    if (step.step !== 'password' || step.csrfToken === null) return;
    const { stepVersion, csrfToken } = step;
    void send(() => postPassword(stepVersion, password, csrfToken, step.data.tenant));
  }

  function onEditIdentifier() {
    if (step.step !== 'password' || step.csrfToken === null) return;
    const { stepVersion, csrfToken } = step;
    void send(() => postPasswordBack(stepVersion, csrfToken, step.data.tenant));
  }

  /** Story 4.11: the Password step's "Forgot password?". */
  function onForgotPassword() {
    if (step.step !== 'password' || step.csrfToken === null) return;
    const { stepVersion, csrfToken } = step;
    void send(() => postResetOpen(stepVersion, csrfToken, step.data.tenant));
  }

  function onSendReset() {
    if (step.step !== 'forgot_password' || step.csrfToken === null) return;
    const { stepVersion, csrfToken } = step;
    void send(() => postReset(stepVersion, email, csrfToken, step.data.tenant));
  }

  /** "Back to login" from Forgot password or the reset confirmation. */
  function onResetBack() {
    if ((step.step !== 'forgot_password' && step.step !== 'link_sent') || step.csrfToken === null) return;
    const { stepVersion, csrfToken } = step;
    void send(() => postResetBack(stepVersion, csrfToken, step.data.tenant));
  }

  function onResetSubmit() {
    if (step.step !== 'reset_password' || step.csrfToken === null || resetToken.current === null) return;
    const { csrfToken } = step;
    const token = resetToken.current;
    // A confirmation that doesn't match is refused here first, with the server's own error; the server checks again.
    if (password !== confirm) {
      if (inFlight.current) return;
      setStep({ ...step, data: { ...step.data, error: 'password_mismatch', rules: [] } });
      setFailed(true);
      setShown((n) => n + 1);
      return;
    }
    void send(() => postResetComplete(token, password, confirm, csrfToken, step.data.tenant));
  }

  function onVerified() {
    if (step.step !== 'verify_email' || step.csrfToken === null) return;
    const { stepVersion, csrfToken } = step;
    void send(() => postVerifiedContinue(stepVersion, csrfToken, step.data.tenant));
  }

  async function onResend() {
    if (step.step !== 'verify_email' || step.csrfToken === null) return;
    const { stepVersion, csrfToken } = step;
    const next = await send(() => postResend(stepVersion, csrfToken, step.data.tenant), setResending);
    if (next?.step === 'verify_email' && next.data.resent) setSends((n) => n + 1);
  }

  function onSendNewLink() {
    if (step.step !== 'link_expired' || step.csrfToken === null || step.data.token === null) return;
    const { csrfToken } = step;
    const token = step.data.token;
    const reset = step.data.purpose === 'reset';
    void send(() => postNewLink(token, csrfToken, step.data.tenant, reset));
  }

  async function onKeepGoing() {
    if (!LIVE_STEPS.has(step.step) || step.csrfToken === null || extending.current) return;
    extending.current = true;
    const extended = step;
    const next = await postExtend(step.csrfToken, step.data.tenant);
    extending.current = false;
    setWarning(false);
    if (next.step === extended.step && next.stepVersion === extended.stepVersion) {
      // The same step with a new life: refresh only its life and token, and only while the page still shows that
      // version, so an answer that arrives after another request showed a newer step never overwrites it.
      setStep((current) =>
        current.step === next.step && current.stepVersion === next.stepVersion
          ? { ...current, expiresInSeconds: next.expiresInSeconds, csrfToken: next.csrfToken }
          : current,
      );
      setLife((n) => n + 1);
      return;
    }
    show(next);
  }

  const controls = {
    email,
    onEmailChange: setEmail,
    password,
    onPasswordChange: setPassword,
    confirm,
    onConfirmChange: setConfirm,
    onForgotPassword,
    onSendReset,
    onResetBack,
    onResetSubmit,
    onContinue,
    onSignUp,
    onLogIn,
    onCreate,
    onPasswordLogIn,
    onEditIdentifier,
    termsAccepted,
    onTermsChange,
    onVerified,
    onResend: () => void onResend(),
    onSendNewLink,
    pending,
    resending,
    sends,
  };

  return (
    <>
      <StepScreen step={step} controls={controls} failed={failed} shown={shown} />
      <AlertDialog
        open={warning}
        title={messages.expiryWarningTitle}
        actionLabel={messages.keepGoing}
        onAction={onKeepGoing}
        onClose={() => setWarning(false)}
        data-testid="expiry-warning"
      >
        {messages.expiryWarningBody}
      </AlertDialog>
    </>
  );
}
