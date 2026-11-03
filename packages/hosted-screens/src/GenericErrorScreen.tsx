import { ButtonLink, ErrorReference, HostedCard, StatusIcon, formatMessage, useMessages, type HostedTenant } from '@gatekeep/ui/hosted';

export interface GenericErrorScreenProps {
  /** The Tenant the error page speaks for. Its name, never Gatekeep's, is on the page. */
  tenant: HostedTenant;
  /** The error code, such as "invalid_request". */
  code: string;
  /** The trace ID support asks for. It has a Copy control (NFR-18). */
  traceId: string;
  /**
   * The Application to go back to. The server passes only a validated, registered Application
   * URL. Without one, as for an unregistered client or a mismatched callback, there is no
   * primary action: Generic error never redirects (EXPERIENCE.md, Unregistered client).
   */
  backHref?: string;
  /** The heading level: 2 inside another page, such as the theme preview. 1 otherwise. */
  headingLevel?: 1 | 2;
  className?: string;
  'data-testid'?: string;
}

/**
 * Generic error (EXPERIENCE.md, Hosted Login): an error status icon, the fixed heading
 * "Something went wrong" and a fixed subtitle from the catalogue, then the code and trace ID
 * in Geist Mono with Copy on the trace ID, and "Back to {Tenant}" when there is a validated
 * Application to go back to. The code and trace ID are the only variable detail it shows
 * (FR-33).
 */
export function GenericErrorScreen({ tenant, code, traceId, backHref, headingLevel, className, 'data-testid': testId }: GenericErrorScreenProps) {
  const messages = useMessages();
  return (
    <HostedCard
      tenant={tenant}
      icon={<StatusIcon status="error" />}
      title={messages.genericErrorTitle}
      subtitle={messages.genericErrorBody}
      headingLevel={headingLevel}
      action={
        backHref === undefined || backHref === '' ? undefined : (
          <ButtonLink variant="primary" href={backHref}>
            {formatMessage(messages.backTo, { tenant: tenant.name })}
          </ButtonLink>
        )
      }
      className={className}
      data-testid={testId}
    >
      <ErrorReference code={code} traceId={traceId} />
    </HostedCard>
  );
}
