import { HostedPage, formatMessage, useMessages, type Messages } from '@gatekeep/ui/hosted';
import { GenericErrorScreen, LoginScreen } from '@gatekeep/hosted-screens';
import { useEffect, useLayoutEffect, type ReactNode } from 'react';
import type { Step } from './step';

/** The Tenant theme scope: the server's theme stylesheet sets its tokens under [data-gk-theme]. */
export const THEME = 'tenant';

/** Login's field error text, by the code the server sends it as. */
const FIELD_ERRORS: Readonly<Record<string, keyof Messages>> = { email_invalid: 'emailInvalid' };

/** Each step's screen heading, for the page title. A redirect shows no screen, and keeps Login's. */
function heading(step: Step, messages: Readonly<Messages>): string {
  switch (step.step) {
    case 'generic_error':
      return messages.genericErrorTitle;
    case 'login':
    case 'redirect':
      return messages.loginTitle;
  }
}

/** What Login's screen needs from the page: the email it carries, and Continue. */
export interface LoginControls {
  email: string;
  onEmailChange: (email: string) => void;
  onContinue: () => void;
  pending: boolean;
}

function screen(step: Step, login: LoginControls, messages: Readonly<Messages>): ReactNode {
  switch (step.step) {
    case 'generic_error':
      return <GenericErrorScreen tenant={{ name: step.data.tenant }} code={step.data.code} traceId={step.data.traceId} />;
    case 'login': {
      const code = step.data.error;
      // The reader admits only known codes, so an own entry is always found; nothing else is shown.
      const error = code !== null && Object.hasOwn(FIELD_ERRORS, code) ? messages[FIELD_ERRORS[code]!] : undefined;
      return (
        <LoginScreen
          tenant={{ name: step.data.tenant }}
          email={login.email}
          onEmailChange={login.onEmailChange}
          onContinue={login.onContinue}
          error={error}
          pending={login.pending}
        />
      );
    }
    case 'redirect':
      // The page is leaving by a top-level GET: nothing to show meanwhile.
      return null;
  }
}

/**
 * Where focus goes when a step is shown (EXPERIENCE.md, Focus and titles): the first invalid field, else
 * Login's email field, which its screen marks with data-gk-initial-focus, else the card heading, which
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

/**
 * One step's page: its screen in the Hosted page frame, following the device's scheme, under the
 * Tenant's theme scope. The title is "{heading} – {Tenant}", or the heading alone with no Tenant, with
 * "Error:" before it after a failed submit. `shown` changes each time the server answers with a step, so
 * focus moves again then: to the invalid field after a failed submit, else as on first load.
 */
export function StepScreen({ step, login, failed = false, shown = 0 }: { step: Step; login: LoginControls; failed?: boolean; shown?: number }) {
  const messages = useMessages();
  const title = heading(step, messages);
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
      {screen(step, login, messages)}
    </HostedPage>
  );
}
