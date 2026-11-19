import { AlertDialog, useMessages } from '@gatekeep/ui/hosted';
import { useEffect, useRef, useState } from 'react';
import {
  postExtend,
  postIdentifier,
  postNewLink,
  postResend,
  postSignup,
  postSignupBack,
  postSignupOpen,
  postVerifiedContinue,
} from './api';
import { useExpiry } from './expiry';
import { LOGIN_PATH, forgetQuery, go } from './navigate';
import type { Step } from './step';
import { StepScreen, isFailed } from './StepScreen';

/** The steps that stand on a live sign-in transaction, whose life is counted and can be extended. */
const LIVE_STEPS: ReadonlySet<Step['step']> = new Set(['login', 'signup', 'verify_email']);

/** The email a step carries, as its field starts. */
function emailOf(step: Step): string {
  return step.step === 'login' || step.step === 'signup' ? (step.data.email ?? '') : '';
}

/**
 * Hosted Login's page (Stories 4.1, 4.2 and 4.7). It shows the step the server sent and follows the next one each
 * request answers with, holding no flow logic: Continue posts the email, Sign up opens Signup carrying it, Create account
 * posts the email and password, the verification step's actions ask the server again, a redirect step is opened with a
 * top-level GET, and while a step has a life, its expiry warning shows two minutes before the end. "Keep going" extends
 * the life without a reload; at expiry the page goes to Login, which restarts with the email kept.
 */
export function App({ initial }: { initial: Step }) {
  const messages = useMessages();
  const [step, setStep] = useState(initial);
  const [email, setEmail] = useState(emailOf(initial));
  const [password, setPassword] = useState('');
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
    if (initial.step === 'email_verified' || initial.step === 'link_expired') forgetQuery();
  }, [initial]);

  /** A step the server answered with: shown, its life counted afresh, and focus moved to it. */
  function show(next: Step) {
    shownCount.current += 1;
    setStep(next);
    setFailed(isFailed(next));
    setWarning(false);
    setLife((n) => n + 1);
    setShown((n) => n + 1);
    // The password is kept only for a refused Create account, so it can be corrected; anything else drops it.
    if (next.step !== 'signup') setPassword('');
    if (next.step === 'login' || next.step === 'signup') setEmail((typed) => next.data.email ?? typed);
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
    void send(() => postSignup(stepVersion, email, password, csrfToken, step.data.tenant));
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
    void send(() => postNewLink(token, csrfToken, step.data.tenant));
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
    onContinue,
    onSignUp,
    onLogIn,
    onCreate,
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
