// The Tenants list read (Story 1.27), shared by the landing, Create Tenant and the Tenants page.
// It goes through the shell's Session renewal, so a 401 renews and the read is sent once more.

import type { TenantListResponse } from '@gatekeep/api-client';
import { api } from '../session';
import type { ShellRequest } from './CredentialsPage';

/** The Deployment's Tenants page, as the dashboard shows it. */
export const TENANTS_PATH = '/deployment/tenants';

/** Create Tenant, reached from the Tenants page. The landing shows the same form in place. */
export const NEW_TENANT_PATH = '/deployment/tenants/new';

/** A failed read's code and trace ID, either empty when the answer had none. */
export interface TenantsFailure {
  code: string;
  traceId: string;
  /** The answer's HTTP status, or null for a lost connection or a malformed 2xx (Story 1.29). */
  status?: number | null;
}

/**
 * Whether a failed read will fail the same way however often it is sent again: a 4xx, other than
 * 408 and 429. A refresh loop stops on one (Story 1.29); a 5xx or a lost connection may pass.
 */
export function isPermanent(failure: TenantsFailure): boolean {
  const status = failure.status ?? null;
  return status !== null && status >= 400 && status < 500 && status !== 408 && status !== 429;
}

/**
 * A Tenant's lifecycle as the Tenants list shows it (Story 1.29): `creating` until its creation
 * succeeds, `active`, then `deleting` while its deletion runs. A deleted Tenant is never listed.
 */
export type TenantStatus = 'creating' | 'active' | 'deleting';

/** Whether a row is still changing on its own, so the list is read again: see refresh.ts. */
export { inProgress } from './refresh';

export type TenantsRead = { kind: 'ready'; list: TenantListResponse } | { kind: 'failed'; failure: TenantsFailure };

/** One page of Tenants: the first, or the one after `cursor`. A 2xx without the list's fields is a failure. */
export async function readTenants(request: ShellRequest, cursor?: string, signal?: AbortSignal): Promise<TenantsRead> {
  try {
    const result = await request('get', () => api.listTenants(cursor), signal);
    if (result.ok) {
      const list = result.data;
      if (list && typeof list.tenantZone === 'string' && Array.isArray(list.tenants)) return { kind: 'ready', list };
      return { kind: 'failed', failure: { code: '', traceId: '', status: null } };
    }
    return { kind: 'failed', failure: { code: result.problem?.code ?? '', traceId: result.problem?.traceId ?? '', status: result.status } };
  } catch {
    // A lost connection, or a read abandoned with its page: the caller checks its signal.
    return { kind: 'failed', failure: { code: '', traceId: '', status: null } };
  }
}
