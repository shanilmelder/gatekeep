// Session renewal inside the shell (UX-DR22; Story 1.25). Every request the shell and its pages
// make goes through `request`. A 401 there means the Admin Session ended while the page was
// open: the page stays mounted with its values, a banner says why, and the browser's WebAuthn
// sheet opens through the existing sign-in endpoints. One renewal runs at a time, so concurrent
// 401s wait on the same one.
//
// Once the same Admin is signed in again, an interrupted read (GET or HEAD) is sent once more: a
// 401 is refused before any handler runs, so nothing was read or changed, and the page gets its
// data. Any other method, a state-changing one or one this module doesn't know, is never sent
// again: it resolves with its own 401 once the Admin is back, the page keeps what was typed, and
// the Admin repeats the action. A different Admin's sign-in, or one still without both
// credentials, leaves the page: the values belong to the other context.
//
// The sheet opens by itself once per expiry, for the first 401. After it is cancelled, refused,
// rate-limited or unavailable, only the banner's Sign in opens it again, and never during a
// rate limit's Retry-After window. A 401 for a request sent before the latest renewal is not a
// new expiry. A request whose caller has moved on (its AbortSignal fired) leaves the waiting list
// and is never sent again.
//
// This module is plain TypeScript with no import, so Node runs its tests directly
// (test/renewal.test.mjs). The sign-in itself (begin, the sheet, complete) is passed in.

/** The HTTP methods the shell sends. Only `get` and `head` are ever sent again. */
export type Method = 'get' | 'head' | 'post' | 'put' | 'patch' | 'delete';

/** What one try at signing in again came to. */
export type SignInOutcome =
  | { kind: 'signedIn'; adminId: string; csrfToken: string; setupComplete: boolean }
  /** The Admin cancelled the sheet, the browser refused it without user activation, or it was aborted. */
  | { kind: 'cancelled' }
  /** The server refused the credential (400). */
  | { kind: 'refused' }
  /** Begin or complete answered 429. `seconds` is Retry-After, when it gave a whole number. */
  | { kind: 'rateLimited'; seconds: number | null }
  /** A 5xx, a lost connection, a malformed answer, or a sheet that failed for another reason. */
  | { kind: 'unavailable' };

/** The banner the shell shows: none while the Session is live. */
export type RenewalState =
  | { kind: 'live' }
  /** Expired: the sheet is open, or is one Sign in away. */
  | { kind: 'expired'; signingIn: boolean }
  | { kind: 'refused'; signingIn: boolean }
  /** `cooling` while the Retry-After window lasts: Sign in can't start a sheet until it ends. */
  | { kind: 'rateLimited'; seconds: number | null; signingIn: boolean; cooling: boolean }
  | { kind: 'unavailable'; signingIn: boolean };

export interface RenewalOptions {
  /** The Admin the shell booted for, from the Session read. */
  adminId: string;
  /** One sign-in: begin, the browser's sheet, complete. It stops early once `signal` fires. */
  signIn: (signal: AbortSignal) => Promise<SignInOutcome>;
  /** Keeps the new Session's CSRF token, in memory only. */
  setCsrfToken: (token: string) => void;
  /** The banner to show. */
  onChange: (state: RenewalState) => void;
  /**
   * Leaves the page after a sign-in the shell can't continue: `another-admin` is a full load of
   * the root, and `setup` goes to credential setup.
   */
  leave: (reason: 'another-admin' | 'setup') => void;
}

export interface Renewal {
  /**
   * Sends `call`. A 401 starts a renewal (or joins the one under way) and waits for it. Then a
   * read is sent once more, and any other request resolves with its 401, unsent. A request
   * whose Session never comes back stays pending, so its page stays read-only. When `signal`
   * fires, a waiting request rejects with an AbortError and is never sent again.
   */
  request<R extends { status: number }>(method: Method, call: () => Promise<R>, signal?: AbortSignal): Promise<R>;
  /** Opens the sheet again, as the banner's Sign in does. Nothing happens while one is open, the Session is live, or a rate limit is cooling. */
  signIn(): void;
  /**
   * Stops the sign-in under way, if any, and resolves once it has settled, so nothing it
   * answers lands afterwards. A Session it had already created keeps its CSRF token, so a
   * sign-out that follows ends that Session. The banner stays.
   */
  cancel(): Promise<void>;
  /** Ends the renewal for good, as on sign-out or unmount: nothing it answers lands afterwards. */
  dispose(): void;
  /** The banner now. */
  state(): RenewalState;
}

const RESENT: ReadonlySet<string> = new Set(['get', 'head']);

function abortError(): DOMException {
  return new DOMException('The request was abandoned.', 'AbortError');
}

export function createRenewal(options: RenewalOptions): Renewal {
  let state: RenewalState = { kind: 'live' };
  // Counts successful renewals: a 401 for a request sent under an earlier one isn't an expiry.
  let generation = 0;
  // Whether this expiry's sheet has opened by itself already.
  let autoOpened = false;
  let attempt: { controller: AbortController; done: Promise<void> } | null = null;
  let cooling: ReturnType<typeof setTimeout> | undefined;
  let disposed = false;
  // Resolved together once the same Admin is signed in again.
  const waiting = new Set<() => void>();

  const set = (next: RenewalState) => {
    if (disposed) return;
    state = next;
    options.onChange(next);
  };

  const withSigningIn = (signingIn: boolean): RenewalState => (state.kind === 'live' ? state : { ...state, signingIn });

  function stopCooling() {
    if (cooling !== undefined) clearTimeout(cooling);
    cooling = undefined;
  }

  function renewed(signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        waiting.delete(entry);
        reject(abortError());
      };
      const entry = () => {
        signal?.removeEventListener('abort', onAbort);
        resolve();
      };
      if (signal?.aborted) {
        reject(abortError());
        return;
      }
      waiting.add(entry);
      signal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  /** Marks the Session expired, once, and opens the sheet by itself at most once per expiry. */
  function expire(openSheet: boolean) {
    if (disposed) return;
    if (state.kind === 'live') set({ kind: 'expired', signingIn: false });
    if (openSheet && !autoOpened) {
      autoOpened = true;
      signIn();
    }
  }

  function settle(outcome: SignInOutcome) {
    switch (outcome.kind) {
      case 'signedIn': {
        options.setCsrfToken(outcome.csrfToken);
        // Another Admin's context: nothing waiting belongs to them, so nothing is sent.
        if (outcome.adminId !== options.adminId) {
          options.leave('another-admin');
          return;
        }
        if (!outcome.setupComplete) {
          options.leave('setup');
          return;
        }
        generation += 1;
        autoOpened = false;
        set({ kind: 'live' });
        const resume = [...waiting];
        waiting.clear();
        for (const resolve of resume) resolve();
        return;
      }
      case 'cancelled':
        set({ kind: 'expired', signingIn: false });
        return;
      case 'refused':
        set({ kind: 'refused', signingIn: false });
        return;
      case 'rateLimited': {
        const { seconds } = outcome;
        set({ kind: 'rateLimited', seconds, signingIn: false, cooling: seconds !== null });
        if (seconds !== null) {
          cooling = setTimeout(() => {
            cooling = undefined;
            if (state.kind === 'rateLimited') set({ ...state, cooling: false });
          }, seconds * 1000);
        }
        return;
      }
      default:
        set({ kind: 'unavailable', signingIn: false });
    }
  }

  function signIn() {
    if (disposed || attempt || state.kind === 'live') return;
    if (state.kind === 'rateLimited' && state.cooling) return;
    stopCooling();
    const controller = new AbortController();
    set(withSigningIn(true));
    const done = options
      .signIn(controller.signal)
      .catch((): SignInOutcome => ({ kind: 'unavailable' }))
      .then((outcome) => {
        attempt = null;
        if (disposed) return;
        if (controller.signal.aborted) {
          // Stopped for a sign-out: a Session the server created anyway keeps its token, so
          // the sign-out ends it. Nothing else lands.
          if (outcome.kind === 'signedIn') options.setCsrfToken(outcome.csrfToken);
          set(withSigningIn(false));
          return;
        }
        settle(outcome);
      });
    attempt = { controller, done };
  }

  async function request<R extends { status: number }>(method: Method, call: () => Promise<R>, signal?: AbortSignal): Promise<R> {
    // Anything but a known read, an unknown or empty method included, is never sent twice.
    const resend = RESENT.has(String(method ?? '').trim().toLowerCase());
    // The sheet may open by itself only for a request's first 401. A resent read refused again
    // shows the banner and waits for the Admin's own Sign in, so nothing loops on its own.
    let mayOpen = true;
    for (;;) {
      if (signal?.aborted) throw abortError();
      const sentUnder = generation;
      const result = await call();
      if (result.status !== 401) return result;
      if (signal?.aborted) throw abortError();
      if (sentUnder !== generation) {
        // Refused under a Session renewed since it was sent: not a new expiry.
        if (!resend) return result;
        continue;
      }
      const back = renewed(signal);
      expire(mayOpen);
      await back;
      if (!resend) return result;
      mayOpen = false;
    }
  }

  function cancel(): Promise<void> {
    if (!attempt) return Promise.resolve();
    attempt.controller.abort();
    return attempt.done;
  }

  function dispose() {
    disposed = true;
    stopCooling();
    attempt?.controller.abort();
    waiting.clear();
  }

  return { request, signIn, cancel, dispose, state: () => state };
}

/** Retry-After as whole seconds, or null when it isn't one. */
export function retryAfterSeconds(value: string | null): number | null {
  if (value === null || !/^\s*\d+\s*$/.test(value)) return null;
  const seconds = Number.parseInt(value, 10);
  return seconds > 0 ? seconds : null;
}
