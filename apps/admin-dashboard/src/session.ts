// The Admin Session's CSRF token, in memory only: never in web storage, a cookie or a URL.
// A reload loses it, and GET /api/v1/deployment/session issues a fresh one (Story 1.21).

import { createApiClient } from '@gatekeep/api-client';
import { pageTenant } from './shell/currentTenant';

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

/**
 * The one client the dashboard calls the Admin API with, on its own origin. A state-changing
 * Tenant-surface call carries the page's Tenant, read from the URL the shell shows at send time
 * (Story 1.28): the server compares it with the path's and refuses a mismatch.
 */
export const api = createApiClient({
  csrfToken: () => csrfToken,
  pageTenant: () => pageTenant(window.location.pathname),
});
