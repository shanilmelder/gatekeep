// One Log event, opened (Story 7.5, FR-39, UX-DR18): the summary rows the event drawer lists.
// The server decides what an Admin may see: `raw` is null for a role without raw detail, so
// the detail rows (IP address, User-Agent, email) come only from `raw` and never appear without it.
//
// This module is plain TypeScript with type-only imports, so Node runs its tests directly
// (test/logs.test.mjs).

import type { LogReference, TenantLogEventDetail } from '@gatekeep/api-client';

/** The labels the summary rows use, from the page's messages. */
export interface EventSummaryLabels {
  time: string;
  actor: string;
  target: string;
  user: string;
  application: string;
  ipAddress: string;
  userAgent: string;
  email: string;
}

/** One summary row: a stable key, its label and its text. */
export interface EventSummaryLine {
  key: 'time' | 'actor' | 'target' | 'user' | 'application' | 'ipAddress' | 'userAgent' | 'email';
  label: string;
  value: string;
  /** Whether the value is an ID or address, shown in the code type. */
  code: boolean;
}

/** An instant as the Time (UTC) column shows it: `YYYY-MM-DD HH:MM:SS`, or the text as sent when it doesn't parse. */
function utc(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toISOString().slice(0, 19).replace('T', ' ');
}

/** A reference as the drawer shows it: its kind, then its ID when it has one. */
export function referenceText(reference: LogReference): string {
  return reference.id == null ? reference.kind : `${reference.kind} ${reference.id}`;
}

/** The ID an event names for `kind`: its Actor's, else its target's, else none. */
function named(event: Pick<TenantLogEventDetail, 'actor' | 'target'>, kind: 'user' | 'client'): string | null {
  if (event.actor.kind === kind) return event.actor.id ?? null;
  if (event.target?.kind === kind) return event.target.id ?? null;
  return null;
}

/**
 * The drawer's summary rows for an event, in order: Time (UTC) and Actor always; Target, User and
 * Application when the envelope names one; then IP address, User-Agent and Email, each only when
 * `raw.detail` holds it. Without `raw`, no detail row.
 */
export function eventSummary(event: TenantLogEventDetail, labels: EventSummaryLabels): EventSummaryLine[] {
  const rows: EventSummaryLine[] = [
    { key: 'time', label: labels.time, value: utc(event.occurredAt), code: false },
    { key: 'actor', label: labels.actor, value: referenceText(event.actor), code: true },
  ];
  if (event.target != null) rows.push({ key: 'target', label: labels.target, value: referenceText(event.target), code: true });
  const user = named(event, 'user');
  if (user !== null) rows.push({ key: 'user', label: labels.user, value: user, code: true });
  const application = named(event, 'client');
  if (application !== null) rows.push({ key: 'application', label: labels.application, value: application, code: true });

  const detail = event.raw?.detail;
  if (detail != null) {
    if (detail.ipAddress) rows.push({ key: 'ipAddress', label: labels.ipAddress, value: detail.ipAddress, code: true });
    if (detail.userAgent) rows.push({ key: 'userAgent', label: labels.userAgent, value: detail.userAgent, code: true });
    if (detail.email) rows.push({ key: 'email', label: labels.email, value: detail.email, code: false });
  }
  return rows;
}
