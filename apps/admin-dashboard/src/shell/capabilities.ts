// What the current Admin holds, as the server says (UX-DR23). The shell reads the Deployment
// capabilities on every in-shell navigation, and on a /tenants/{tenantId}/… path the path
// Tenant's too. Nothing is cached across navigations or stored, so a Tenant Role removed
// mid-session counts on the next navigation (Story 8.4). Pages ask `has(capability)`; the UI
// never names, compares or infers a role (AD-20), and hiding is never the control: the server
// refuses everything on its own (Story 1.24).

import type { ApiProblem, ApiResult, CapabilitiesResponse } from '@gatekeep/api-client';
import { createContext, createElement, useContext, useEffect, useState, type ReactNode } from 'react';
import { api } from '../session';

/** A capability name, from the generated contract: never a hand-written string. */
export type Capability = CapabilitiesResponse['capabilities'][number];

/** Sends one read through the shell's renewal (renewal.ts). `signal` abandons it, as when the route changes. */
export type ShellRead = <R extends { status: number }>(call: () => Promise<R>, signal: AbortSignal) => Promise<R>;

/** A failed read's code and trace ID, either empty when the answer had none. */
export interface ReadFailure {
  code: string;
  traceId: string;
}

/** The two lists the current route read: Deployment, and the path Tenant's or none. */
export interface Held {
  deployment: ReadonlySet<Capability>;
  tenantId: string | null;
  tenant: ReadonlySet<Capability> | null;
}

export type Reads =
  | { kind: 'pending' }
  | { kind: 'ready' }
  /** The server's one 403 `access_denied` for the path Tenant, with its trace ID. */
  | { kind: 'forbidden'; failure: ReadFailure; also: ReadFailure | null }
  /** A 5xx, a lost connection, another refusal or a 2xx with no list. */
  | { kind: 'failed'; failure: ReadFailure };

const NONE: Held = { deployment: new Set(), tenantId: null, tenant: null };

/**
 * The path Tenant: the segment after /tenants/, decoded once, so the client's own encoding puts
 * it back into the API path exactly as the Admin wrote it. The dashboard never validates it:
 * only the server decides. A segment whose escapes don't decode is `malformed`: no Tenant can
 * have that ID, so the route is not found and nothing is asked.
 */
export function pathTenant(path: string): { tenantId: string } | 'malformed' | null {
  const match = /^\/tenants\/([^/]+)(?:\/|$)/.exec(path);
  if (!match) return null;
  try {
    return { tenantId: decodeURIComponent(match[1]!) };
  } catch {
    return 'malformed';
  }
}

type Outcome = { list: ReadonlySet<Capability> } | { denied: ReadFailure } | { failed: ReadFailure };

function failureOf(problem: ApiProblem | null): ReadFailure {
  return { code: problem?.code ?? '', traceId: problem?.traceId ?? '' };
}

function outcome(result: ApiResult<CapabilitiesResponse> | null): Outcome {
  if (result === null) return { failed: { code: '', traceId: '' } };
  if (result.ok) {
    const list = result.data?.capabilities;
    if (!Array.isArray(list)) return { failed: { code: '', traceId: '' } };
    return { list: new Set(list.filter((name): name is Capability => typeof name === 'string')) };
  }
  if (result.status === 403 && result.problem?.code === 'access_denied') return { denied: failureOf(result.problem) };
  return { failed: failureOf(result.problem) };
}

async function readOne(read: ShellRead, call: () => Promise<ApiResult<CapabilitiesResponse>>, signal: AbortSignal): Promise<Outcome> {
  try {
    return outcome(await read(call, signal));
  } catch {
    return outcome(null);
  }
}

/** The reads that last answered: the path and navigation they were for, and what they said. */
export interface Answered {
  /** The navigation they were read for. A Retry reads again for the same one. */
  navigation: number;
  path: string;
  reads: Exclude<Reads, { kind: 'pending' }>;
}

/**
 * Reads both lists for `path` whenever `navigation` or `attempt` changes, abandoning the
 * previous route's reads (so a Session renewal never sends them again). Until they answer,
 * `reads` is pending and `answered` is still the previous route's, so the shell keeps that page
 * in place, mounted, rather than blank it. `held` is what the last answer read, for the sidebar:
 * a list that failed to read holds nothing, and a forbidden Tenant holds nothing.
 */
export function useCapabilityReads(
  path: string,
  navigation: number,
  attempt: number,
  read: ShellRead,
): { reads: Reads; answered: Answered | null; held: Held } {
  const key = `${navigation}:${attempt}`;
  const [answered, setAnswered] = useState<(Answered & { key: string }) | null>(null);
  const [held, setHeld] = useState<Held>(NONE);

  useEffect(() => {
    const controller = new AbortController();
    const tenant = pathTenant(path);
    const tenantId = tenant === null || tenant === 'malformed' ? null : tenant.tenantId;
    void Promise.all([
      readOne(read, () => api.getCapabilities(), controller.signal),
      tenantId === null ? Promise.resolve(null) : readOne(read, () => api.getTenantCapabilities(tenantId), controller.signal),
    ]).then(([deployment, tenantOutcome]) => {
      if (controller.signal.aborted) return;
      const deploymentFailure = 'list' in deployment ? null : 'denied' in deployment ? deployment.denied : deployment.failed;
      setHeld({
        deployment: 'list' in deployment ? deployment.list : NONE.deployment,
        tenantId,
        tenant: tenantOutcome && 'list' in tenantOutcome ? tenantOutcome.list : null,
      });
      let reads: Answered['reads'];
      if (tenantOutcome && 'denied' in tenantOutcome) reads = { kind: 'forbidden', failure: tenantOutcome.denied, also: deploymentFailure };
      else if (tenantOutcome && 'failed' in tenantOutcome) reads = { kind: 'failed', failure: tenantOutcome.failed };
      else if (deploymentFailure) reads = { kind: 'failed', failure: deploymentFailure };
      else reads = { kind: 'ready' };
      setAnswered({ key, navigation, path, reads });
    });
    return () => controller.abort();
    // `read` is the shell's one renewal, stable for its life.
  }, [key]);

  return { reads: answered?.key === key ? answered.reads : { kind: 'pending' }, answered, held };
}

export interface CapabilitiesValue {
  /** Whether the current route's reads say the Admin holds `capability`. */
  has: (capability: Capability) => boolean;
  /** The path Tenant those reads were for, or null. */
  tenantId: string | null;
}

const CapabilitiesContext = createContext<CapabilitiesValue>({ has: () => false, tenantId: null });

/** `has` over the held lists: a `deployment.*` name in the Deployment list, a `tenant.*` one in the path Tenant's. */
export function capabilitiesOf(held: Held): CapabilitiesValue {
  return {
    has: (capability) => (capability.startsWith('deployment.') ? held.deployment.has(capability) : (held.tenant?.has(capability) ?? false)),
    tenantId: held.tenantId,
  };
}

export function CapabilitiesProvider({ value, children }: { value: CapabilitiesValue; children?: ReactNode }) {
  return createElement(CapabilitiesContext.Provider, { value }, children);
}

export function useCapabilities(): CapabilitiesValue {
  return useContext(CapabilitiesContext);
}
