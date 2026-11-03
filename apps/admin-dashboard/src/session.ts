// The Admin Session's CSRF token, in memory only: never in web storage, a cookie or a URL.
// A reload loses it, and GET /api/v1/deployment/session issues a fresh one (Story 1.21).

import { createApiClient } from '@gatekeep/api-client';

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

/** The one client the dashboard calls the Admin API with, on its own origin. */
export const api = createApiClient({ csrfToken: () => csrfToken });
