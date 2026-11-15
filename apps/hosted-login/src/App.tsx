import { AlertDialog, useMessages } from '@gatekeep/ui/hosted';
import { useEffect, useRef, useState } from 'react';
import { postExtend, postIdentifier } from './api';
import { useExpiry } from './expiry';
import { LOGIN_PATH, go } from './navigate';
import type { Step } from './step';
import { StepScreen } from './StepScreen';

/**
 * Hosted Login's page (Stories 4.1 and 4.2). It shows the step the server sent and follows the next one each
 * request answers with, holding no flow logic: Continue posts the email, a redirect step is opened with a
 * top-level GET, and while a step has a life, its expiry warning shows two minutes before the end. "Keep going"
 * extends the life without a reload; at expiry the page goes to Login, which restarts with the email kept.
 */
export function App({ initial }: { initial: Step }) {
  const messages = useMessages();
  const [step, setStep] = useState(initial);
  const [email, setEmail] = useState(initial.step === 'login' ? (initial.data.email ?? '') : '');
  const [pending, setPending] = useState(false);
  const [failed, setFailed] = useState(false);
  const [warning, setWarning] = useState(false);
  const [shown, setShown] = useState(0);
  // Each new life restarts the countdown, even when it is the same number of seconds.
  const [life, setLife] = useState(0);
  const extending = useRef(false);

  const counted = step.step === 'login' ? step.expiresInSeconds : null;
  useExpiry(
    counted,
    life,
    () => setWarning(true),
    () => go(LOGIN_PATH),
  );

  useEffect(() => {
    if (step.step === 'redirect') go(step.data.location);
  }, [step]);

  /** A step the server answered with: shown, its life counted afresh, and focus moved to it. */
  function show(next: Step) {
    setStep(next);
    setFailed(next.step === 'login' && next.data.error !== null);
    setWarning(false);
    setLife((n) => n + 1);
    setShown((n) => n + 1);
  }

  async function onContinue() {
    if (step.step !== 'login' || step.csrfToken === null || pending) return;
    setPending(true);
    const next = await postIdentifier(step.stepVersion, email, step.csrfToken, step.data.tenant);
    setPending(false);
    show(next);
  }

  async function onKeepGoing() {
    if (step.step !== 'login' || step.csrfToken === null || extending.current) return;
    extending.current = true;
    const extendedVersion = step.stepVersion;
    const next = await postExtend(step.csrfToken, step.data.tenant);
    extending.current = false;
    setWarning(false);
    if (next.step === 'login' && next.stepVersion === extendedVersion) {
      // The same step with a new life: refresh only its life and token, and only while the page still shows that
      // version, so an answer that arrives after Continue showed a newer step never overwrites it.
      setStep((current) =>
        current.step === 'login' && current.stepVersion === next.stepVersion
          ? { ...current, expiresInSeconds: next.expiresInSeconds, csrfToken: next.csrfToken }
          : current,
      );
      setLife((n) => n + 1);
      return;
    }
    show(next);
  }

  return (
    <>
      <StepScreen step={step} login={{ email, onEmailChange: setEmail, onContinue, pending }} failed={failed} shown={shown} />
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
