import { ButtonLink, SectionPage, useMessages } from '@gatekeep/ui/admin';
import type { MouseEvent } from 'react';
import { navigate } from '../navigation';

/** A path with no page, or an allowed Tenant path whose page isn't built yet. */
export function NotFoundPage() {
  const messages = useMessages();
  function onClick(event: MouseEvent<HTMLAnchorElement>) {
    // A modified click opens a tab or window: the browser's.
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    navigate('/');
  }
  return (
    <SectionPage title={messages.notFoundTitle} data-testid="not-found">
      <div>
        <ButtonLink href="/" onClick={onClick}>
          {messages.backToDashboard}
        </ButtonLink>
      </div>
    </SectionPage>
  );
}
