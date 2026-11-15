// The sign-in transaction's expiry, as the client keeps time for it (Story 4.2, UX-DR33): the warning
// shows EXPIRY_WARNING_SECONDS before the step's expiresInSeconds runs out, and at expiry the page goes
// to Login, which restarts the sign-in with the email kept. The server decides both times: this only
// counts down what the last step said.

import { useEffect } from 'react';

/** How long before expiry the warning shows: SecurityLimits.SignInExpiryWarning, 2 minutes. */
export const EXPIRY_WARNING_SECONDS = 120;

/**
 * Runs `onWarn` when `expiresInSeconds` is down to EXPIRY_WARNING_SECONDS, at once if it already is, and `onExpire`
 * when it runs out. `restart` changes each time the life is reset, so the same seconds count again. Null counts nothing.
 */
export function useExpiry(expiresInSeconds: number | null, restart: number, onWarn: () => void, onExpire: () => void): void {
  useEffect(() => {
    if (expiresInSeconds === null) return;
    const warn = setTimeout(onWarn, Math.max(0, expiresInSeconds - EXPIRY_WARNING_SECONDS) * 1000);
    const expire = setTimeout(onExpire, expiresInSeconds * 1000);
    return () => {
      clearTimeout(warn);
      clearTimeout(expire);
    };
    // onWarn and onExpire are read when the timers start: a new life restarts them.
  }, [expiresInSeconds, restart]);
}
