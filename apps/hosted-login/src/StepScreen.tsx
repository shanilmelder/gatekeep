import { HostedPage, formatMessage, useMessages, type Messages } from '@gatekeep/ui/hosted';
import { GenericErrorScreen } from '@gatekeep/hosted-screens';
import { useEffect, useLayoutEffect } from 'react';
import type { Step } from './step';

/** The Tenant theme scope: the server's theme stylesheet sets its tokens under [data-gk-theme]. */
export const THEME = 'tenant';

/** Each step's screen heading, for the page title. */
function heading(step: Step, messages: Readonly<Messages>): string {
  switch (step.step) {
    case 'generic_error':
      return messages.genericErrorTitle;
  }
}

function screen(step: Step) {
  switch (step.step) {
    case 'generic_error':
      return <GenericErrorScreen tenant={{ name: step.data.tenant }} code={step.data.code} traceId={step.data.traceId} />;
  }
}

/**
 * Where focus goes on first load (EXPERIENCE.md, Focus and titles): the first invalid field, else
 * Login's email field, which its screen marks with data-gk-initial-focus, else the card heading,
 * which takes focus without joining the tab order.
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
 * Tenant's theme scope. The title is "{heading} – {Tenant}", or the heading alone with no Tenant.
 */
export function StepScreen({ step }: { step: Step }) {
  const messages = useMessages();
  const title = heading(step, messages);
  const tenant = step.data.tenant.trim();

  useLayoutEffect(() => {
    document.title = tenant === '' ? title : formatMessage(messages.hostedPageTitle, { heading: title, tenant });
  }, [messages, title, tenant]);

  useEffect(() => {
    const main = document.querySelector('main');
    if (main) initialFocus(main)?.focus({ preventScroll: true });
  }, []);

  return (
    <HostedPage scheme="auto" theme={THEME}>
      {screen(step)}
    </HostedPage>
  );
}
