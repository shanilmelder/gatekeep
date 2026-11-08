// A Tenant's Logs field search (Story 7.4, UX-DR12, UX-DR44): one field and one value, kept in
// the URL as `field` and `value`, and the API query they stand for. No query bar, quick filters
// or Live view: those are v2. The server validates every value again and answers anything
// malformed with 400 invalid_request.
//
// This module is plain TypeScript with type-only imports, so Node runs its tests directly
// (test/logs.test.mjs).

import type { TenantLogEvent, TenantLogsQuery } from '@gatekeep/api-client';

/** The fields a Log is searched by, in the select's order. */
export const LOG_FIELDS = ['type', 'user', 'application', 'outcome', 'range'] as const;

export type LogField = (typeof LOG_FIELDS)[number];

/** The outcome choices, as the API spells them. */
export const OUTCOMES = ['success', 'failure'] as const;

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

/** The time range choices, each ending now, by how far back it starts. */
export const RANGES = [
  { value: '1h', ms: HOUR },
  { value: '24h', ms: DAY },
  { value: '7d', ms: 7 * DAY },
  { value: '30d', ms: 30 * DAY },
  { value: '90d', ms: 90 * DAY },
] as const;

/** A search: its field and its value, which is empty for no filter. */
export interface LogSearch {
  field: LogField;
  value: string;
}

/** The field the search starts on when the URL names none. */
export const DEFAULT_FIELD: LogField = 'type';

export function isField(value: unknown): value is LogField {
  return typeof value === 'string' && (LOG_FIELDS as readonly string[]).includes(value);
}

/** Whether a field's value is picked from a list rather than typed. */
export function isChoice(field: LogField): boolean {
  return field === 'outcome' || field === 'range';
}

/** The values a choice field offers, or none for a typed field. */
export function choices(field: LogField): readonly string[] {
  if (field === 'outcome') return OUTCOMES;
  if (field === 'range') return RANGES.map((range) => range.value);
  return [];
}

/** The value a field starts with when the Admin picks it: a choice field's first choice, else empty. */
export function initialValue(field: LogField): string {
  return choices(field)[0] ?? '';
}

/**
 * The search the URL's `field` and `value` hold. An unknown field is the default one; a value is
 * trimmed, and a choice field's value outside its choices is no value. With no value there is no
 * filter, whatever the field.
 */
export function searchOf(params: { field: string | null; value: string | null }): LogSearch {
  const field = isField(params.field) ? params.field : DEFAULT_FIELD;
  let value = (params.value ?? '').trim();
  if (isChoice(field) && !choices(field).includes(value)) value = '';
  return { field, value };
}

/** The URL parameters for a search: its field and value, or neither when it has no value. */
export function paramsOf(search: LogSearch): { field: string | null; value: string | null } {
  const value = search.value.trim();
  return value === '' ? { field: null, value: null } : { field: search.field, value };
}

/**
 * The API query a search stands for at `now` (milliseconds since the epoch): one parameter, or
 * none for no filter. A time range becomes `from`, its start, as an ISO 8601 instant in UTC.
 */
export function queryOf(search: LogSearch, now: number): TenantLogsQuery {
  const { field, value } = searchOf(search);
  if (value === '') return {};
  switch (field) {
    case 'type':
      return { type: value };
    case 'user':
      return { user: value };
    case 'application':
      return { application: value };
    case 'outcome':
      return { outcome: value };
    case 'range': {
      const range = RANGES.find((choice) => choice.value === value);
      return range ? { from: new Date(now - range.ms).toISOString() } : {};
    }
  }
}

/** The ID an event names for `kind` (`user`, or `client` for an Application): its Actor's, else its target's, else none. */
export function referenceOf(event: Pick<TenantLogEvent, 'actor' | 'target'>, kind: 'user' | 'client'): string | null {
  if (event.actor.kind === kind) return event.actor.id;
  if (event.target?.kind === kind) return event.target.id;
  return null;
}

/** An instant as the Time (UTC) column shows it: `YYYY-MM-DD HH:MM:SS`, or the text as sent when it doesn't parse. */
export function utcTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toISOString().slice(0, 19).replace('T', ' ');
}
