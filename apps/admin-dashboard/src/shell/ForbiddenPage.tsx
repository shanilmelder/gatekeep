import { ErrorReference, SectionPage, useMessages } from '@gatekeep/ui/admin';

/**
 * The forbidden page (UX-DR22), shown only for the server's 403 `access_denied`, with that
 * response's code and trace ID. Nothing else: no hint whether the page or the Tenant exists.
 */
export function ForbiddenPage({ code, traceId }: { code: string; traceId: string }) {
  const messages = useMessages();
  return (
    <SectionPage title={messages.forbiddenTitle} data-testid="forbidden">
      <ErrorReference code={code} traceId={traceId} data-testid="forbidden-reference" />
    </SectionPage>
  );
}
