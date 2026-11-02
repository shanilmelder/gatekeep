// The one modal registry per document (UX-DR45): which modal is open, if any, for every
// Modal, whatever ModalProvider it sits under. Toasts read it too, so a toast shown while a
// modal is open renders inside that modal, the one part of the page that isn't inert.

interface Registry {
  token: string | null;
  element: HTMLDialogElement | null;
  listeners: Set<() => void>;
}

const registry: Registry = { token: null, element: null, listeners: new Set() };

function notify() {
  registry.listeners.forEach((listener) => listener());
}

/** Claims the registry for a modal. False when another modal holds it. */
export function claimModal(token: string, element: HTMLDialogElement): boolean {
  if (registry.token !== null && registry.token !== token) return false;
  registry.token = token;
  registry.element = element;
  notify();
  return true;
}

/** Releases the registry if `token` holds it. */
export function releaseModal(token: string) {
  if (registry.token !== token) return;
  registry.token = null;
  registry.element = null;
  notify();
}

/** The open modal's dialog element, or null. */
export function openModalElement(): HTMLDialogElement | null {
  return registry.element;
}

/** Calls `listener` whenever a modal opens or closes. Returns the unsubscribe. */
export function subscribeModal(listener: () => void): () => void {
  registry.listeners.add(listener);
  return () => registry.listeners.delete(listener);
}
