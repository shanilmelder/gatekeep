// Fresh WebAuthn assertions for sensitive actions (UX-DR17, FR-46; Story 1.26). The server decides
// that an action needs one: a request without a grant bound to its Session, action and target
// answers 403 fresh_assertion_required. The page then confirms it's the Admin (begin, the
// browser's sheet, complete) and sends the action once more. The grant stays on the server,
// bound to the Session: nothing here holds it, stores it or sends it. The UI never decides from a
// role, a capability or a timer that an action needs a confirmation, or that it has one.
//
// This module is plain TypeScript with no import, so Node runs its tests directly
// (test/freshAssertion.test.mjs). The calls are injected: the shell wraps each one in its
// Session renewal, so a 401 still renews and a state-changing request is never sent twice by it.

/** What a fresh assertion confirms: an action, and its target exactly as the action's request names it. */
export interface Binding {
  action: string;
  target?: string | null;
}

/** The parts of an API answer this module reads. */
export interface Answer {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  problem?: { code: string } | null;
  data?: unknown;
}

/** What one confirmation came to. */
export type Confirmation =
  | { kind: 'confirmed' }
  /** The Admin cancelled the sheet, or it was refused for want of user activation, or aborted. */
  | { kind: 'cancelled' }
  /** The server refused the assertion or the action (400): another credential, a used challenge. */
  | { kind: 'refused' }
  /** Begin or complete answered 429. `seconds` is Retry-After, when it gave a whole number. */
  | { kind: 'rateLimited'; seconds: number | null }
  /** Anything else: a 5xx, a lost connection, a malformed answer, a sheet that failed otherwise. */
  | { kind: 'unavailable' };

/** What an action sent with `withFreshAssertion` came to: its answer, or why it couldn't be confirmed. */
export type Guarded<R> = { kind: 'answered'; answer: R } | { kind: 'unconfirmed'; confirmation: Exclude<Confirmation, { kind: 'confirmed' }> };

export interface FreshAssertionCalls {
  /** POST /assertions with the binding, through the shell's renewal. */
  begin(binding: { action: string; target: string | null }): Promise<Answer>;
  /** POST /assertions/complete with the assertion, through the shell's renewal. */
  complete(assertion: unknown): Promise<Answer>;
  /**
   * The browser's sheet for the begin's options: navigator.credentials.get, and the assertion as
   * the complete call takes it. It throws as the browser does: a DOMException when cancelled.
   */
  assert(options: unknown, signal?: AbortSignal): Promise<unknown>;
}

/** Retry-After as whole seconds, or null when it isn't one. */
function seconds(value: string | null): number | null {
  if (value === null || !/^\s*\d+\s*$/.test(value)) return null;
  const parsed = Number.parseInt(value, 10);
  return parsed > 0 ? parsed : null;
}

/** A refused begin or complete: 400 refused, 429 rate-limited, anything else unavailable. */
function refusal(answer: Answer | null): Exclude<Confirmation, { kind: 'confirmed' }> {
  if (answer === null || answer.ok) return { kind: 'unavailable' };
  if (answer.status === 400) return { kind: 'refused' };
  if (answer.status === 429) return { kind: 'rateLimited', seconds: seconds(answer.headers.get('Retry-After')) };
  return { kind: 'unavailable' };
}

/** Whether an action's answer is the server's 403 asking for a fresh assertion. */
export function needsFreshAssertion(answer: { status: number; problem?: { code: string } | null } | null | undefined): boolean {
  return answer?.status === 403 && answer.problem?.code === 'fresh_assertion_required';
}

export function createFreshAssertion(calls: FreshAssertionCalls) {
  /** Begin, the sheet, complete. A 204 leaves the grant on the server; nothing comes back here. */
  async function confirmItsYou(binding: Binding, signal?: AbortSignal): Promise<Confirmation> {
    try {
      if (signal?.aborted) return { kind: 'cancelled' };
      const begin = await calls.begin({ action: binding.action, target: binding.target ?? null });
      if (!begin.ok || begin.data === undefined || begin.data === null) return refusal(begin.ok ? null : begin);
      if (signal?.aborted) return { kind: 'cancelled' };

      let assertion: unknown;
      try {
        assertion = await calls.assert(begin.data, signal);
      } catch (error) {
        const name = (error as { name?: unknown } | null)?.name;
        if (name === 'NotAllowedError' || name === 'AbortError') return { kind: 'cancelled' };
        return { kind: 'unavailable' };
      }
      if (assertion === null || assertion === undefined) return { kind: 'unavailable' };
      if (signal?.aborted) return { kind: 'cancelled' };

      const complete = await calls.complete(assertion);
      if (complete.ok && complete.status === 204) return { kind: 'confirmed' };
      return refusal(complete.ok ? null : complete);
    } catch {
      return { kind: 'unavailable' };
    }
  }

  /**
   * Sends the action. Only on the server's 403 fresh_assertion_required does it confirm, then send
   * it once more; a second fresh_assertion_required is refused, and nothing is sent a third time.
   */
  async function withFreshAssertion<R extends { status: number; problem?: { code: string } | null }>(
    binding: Binding,
    send: () => Promise<R>,
    signal?: AbortSignal,
  ): Promise<Guarded<R>> {
    const first = await send();
    if (!needsFreshAssertion(first)) return { kind: 'answered', answer: first };

    const confirmation = await confirmItsYou(binding, signal);
    if (confirmation.kind !== 'confirmed') return { kind: 'unconfirmed', confirmation };

    const second = await send();
    if (needsFreshAssertion(second)) return { kind: 'unconfirmed', confirmation: { kind: 'refused' } };
    return { kind: 'answered', answer: second };
  }

  return { confirmItsYou, withFreshAssertion };
}

export type FreshAssertion = ReturnType<typeof createFreshAssertion>;
