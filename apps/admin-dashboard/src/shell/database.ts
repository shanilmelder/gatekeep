// The Database page (Story 4.6): its path, the password policy's limits and form, the "what users see" preview's minimum,
// and the Tenant settings card's form. The limits mirror SecurityLimits; the server holds the same rules and decides
// every request: this is feedback only. The preview's sample is checked here and never sent.
//
// Plain TypeScript with no import, so Node runs its tests directly (test/database.test.mjs).

/** The shortest minimum a policy may set: 12 characters (SecurityLimits.PasswordMinimumLengthFloor). */
export const PASSWORD_MIN_LENGTH_FLOOR = 12;
/** The longest minimum a policy may set: 64 characters (SecurityLimits.PasswordMinimumLengthCeiling). */
export const PASSWORD_MIN_LENGTH_CEILING = 64;
/** The most earlier passwords the history rule may remember: 24 (SecurityLimits.PasswordHistoryMaximum). */
export const PASSWORD_HISTORY_MAX = 24;
/** The count the history rule starts on when it is turned on: the default policy's. */
export const PASSWORD_HISTORY_DEFAULT = 5;
/** The longest terms URL: 2048 characters (SecurityLimits.MaxTermsUrlLength). */
export const TERMS_URL_MAX_LENGTH = 2048;

export type PasswordStrength = 'good' | 'excellent';

export const PASSWORD_STRENGTHS: readonly PasswordStrength[] = ['good', 'excellent'];

/** A policy as the server gives it. */
export interface PasswordPolicy {
  minLength: number;
  strength: string;
  historyCount: number;
  dictionary: boolean;
  personalData: boolean;
}

/** What the policy form holds: the numbers as typed, and the history rule's switch apart from its count. */
export interface PolicyDraft {
  minLength: string;
  strength: PasswordStrength;
  historyOn: boolean;
  historyCount: string;
  dictionary: boolean;
  personalData: boolean;
}

/** The policy save's body. */
export interface PolicyRequest {
  minLength: number;
  strength: PasswordStrength;
  historyCount: number;
  dictionary: boolean;
  personalData: boolean;
}

export type PolicyField = 'minLength' | 'strength' | 'historyCount' | 'dictionary' | 'personalData';

/** A refused field: why, and the server's own rule text when it gave one, which the page shows as it is. */
export interface FieldError {
  reason: string;
  detail?: string;
}

export type PolicyErrors = Partial<Record<PolicyField, FieldError>>;

/** One Connection as an Application sees it (Story 4.12), as far as the no-Connection banner needs it. */
export interface ApplicationConnectionState {
  enabled: boolean;
  tenantEnabled: boolean;
}

/**
 * Whether Users can sign in to the Application through any Connection (Story 4.12): one both on for it and enabled in the
 * Tenant. False with none, which Application · Connections warns of.
 */
export function anyUsable(connections: readonly ApplicationConnectionState[]): boolean {
  return connections.some((connection) => connection.enabled && connection.tenantEnabled);
}

/** An Application's Connections tab (Story 4.12), which Database · Applications links each Application to. */
export function applicationConnectionsPath(tenantId: string, applicationId: string): string {
  return `/tenants/${encodeURIComponent(tenantId)}/applications/${encodeURIComponent(applicationId)}?tab=connections`;
}

/** The Database page's path for a Tenant. */
export function databasePath(tenantId: string): string {
  return `/tenants/${encodeURIComponent(tenantId)}/database`;
}

export function isStrength(value: unknown): value is PasswordStrength {
  return typeof value === 'string' && (PASSWORD_STRENGTHS as readonly string[]).includes(value);
}

/** The form for a stored policy. A history count of 0 is the rule turned off, with the default count ready. */
export function policyDraftOf(policy: PasswordPolicy): PolicyDraft {
  return {
    minLength: String(policy.minLength),
    strength: isStrength(policy.strength) ? policy.strength : 'good',
    historyOn: policy.historyCount > 0,
    historyCount: String(policy.historyCount > 0 ? policy.historyCount : PASSWORD_HISTORY_DEFAULT),
    dictionary: policy.dictionary,
    personalData: policy.personalData,
  };
}

const WHOLE = /^\d{1,3}$/;

/** A whole number as typed, or NaN. */
function whole(text: string): number {
  const trimmed = text.trim();
  return WHOLE.test(trimmed) ? Number(trimmed) : Number.NaN;
}

/** The request for a draft: the history rule off sends 0. Only for a draft {@link checkPolicyDraft} passes. */
export function policyRequestOf(draft: PolicyDraft): PolicyRequest {
  return {
    minLength: whole(draft.minLength),
    strength: draft.strength,
    historyCount: draft.historyOn ? whole(draft.historyCount) : 0,
    dictionary: draft.dictionary,
    personalData: draft.personalData,
  };
}

/** The browser's checks on a policy draft: the numbers whole and in range. The server checks every rule again. */
export function checkPolicyDraft(draft: PolicyDraft): PolicyErrors {
  const errors: PolicyErrors = {};
  const minLength = whole(draft.minLength);
  if (draft.minLength.trim() === '') errors.minLength = { reason: 'required' };
  else if (Number.isNaN(minLength)) errors.minLength = { reason: 'invalid' };
  else if (minLength < PASSWORD_MIN_LENGTH_FLOOR) errors.minLength = { reason: 'below_minimum' };
  else if (minLength > PASSWORD_MIN_LENGTH_CEILING) errors.minLength = { reason: 'above_maximum' };

  if (draft.historyOn) {
    const count = whole(draft.historyCount);
    if (draft.historyCount.trim() === '') errors.historyCount = { reason: 'required' };
    else if (Number.isNaN(count)) errors.historyCount = { reason: 'invalid' };
    else if (count < 1) errors.historyCount = { reason: 'below_minimum' };
    else if (count > PASSWORD_HISTORY_MAX) errors.historyCount = { reason: 'above_maximum' };
  }
  return errors;
}

/** Whether the draft would save something other than `stored`. */
export function isPolicyDirty(draft: PolicyDraft, stored: PasswordPolicy | null): boolean {
  if (stored === null) return false;
  const baseline = policyDraftOf(stored);
  if (draft.strength !== baseline.strength || draft.dictionary !== stored.dictionary || draft.personalData !== stored.personalData) return true;
  if (draft.historyOn !== baseline.historyOn) return true;
  if (draft.minLength.trim() !== baseline.minLength) return true;
  return draft.historyOn && draft.historyCount.trim() !== baseline.historyCount;
}

const POLICY_FIELDS: ReadonlySet<string> = new Set<PolicyField>(['minLength', 'strength', 'historyCount', 'dictionary', 'personalData']);

/** The server's field errors as the policy form's, the first per field, each with its rule text; unknown fields are left out. */
export function serverPolicyErrors(
  errors: readonly { field: string; reason: string; detail?: string | null }[] | null | undefined,
): PolicyErrors {
  const found: PolicyErrors = {};
  for (const error of errors ?? []) {
    if (!POLICY_FIELDS.has(error.field)) continue;
    found[error.field as PolicyField] ??= typeof error.detail === 'string' && error.detail !== ''
      ? { reason: error.reason, detail: error.detail }
      : { reason: error.reason };
  }
  return found;
}

// The preview's rules themselves (characterClasses, hasLongRun and passwordRules) are @gatekeep/ui's (Story 4.7), shared
// with Hosted Login's strength meter.

/** The minimum the preview shows while the typed one isn't usable: the floor. */
export function previewMinLength(draft: PolicyDraft): number {
  const typed = whole(draft.minLength);
  return Number.isNaN(typed) ? PASSWORD_MIN_LENGTH_FLOOR : Math.min(Math.max(typed, PASSWORD_MIN_LENGTH_FLOOR), PASSWORD_MIN_LENGTH_CEILING);
}

// The Tenant settings card (Story 4.6).

/** The settings as the server gives them. */
export interface StoredSettings {
  termsUrl: string | null;
  emailVerificationOff: boolean;
  emailVerificationOffAvailable: boolean;
  defaultAudience: string | null;
}

/** What the card's form holds: the URL as typed, the audience's identifier or '' for none, and the switch. */
export interface SettingsDraft {
  termsUrl: string;
  defaultAudience: string;
  emailVerificationOff: boolean;
}

export interface SettingsRequest {
  termsUrl: string | null;
  emailVerificationOff: boolean;
  defaultAudience: string | null;
}

export type SettingsField = 'termsUrl' | 'emailVerificationOff' | 'defaultAudience';

export type SettingsErrors = Partial<Record<SettingsField, FieldError>>;

export function settingsDraftOf(settings: StoredSettings): SettingsDraft {
  return {
    termsUrl: settings.termsUrl ?? '',
    defaultAudience: settings.defaultAudience ?? '',
    emailVerificationOff: settings.emailVerificationOff,
  };
}

/** The request for a draft: an empty URL or no audience is null; verification off only where it is available. */
export function settingsRequestOf(draft: SettingsDraft, available: boolean): SettingsRequest {
  const termsUrl = draft.termsUrl.trim();
  return {
    termsUrl: termsUrl === '' ? null : termsUrl,
    emailVerificationOff: available && draft.emailVerificationOff,
    defaultAudience: draft.defaultAudience === '' ? null : draft.defaultAudience,
  };
}

/** An absolute https URL with a host, and no userinfo, white space or control character. */
export function isTermsUrl(text: string): boolean {
  if (text.length === 0 || text.length > TERMS_URL_MAX_LENGTH || /[\s\p{Cc}]/u.test(text) || !text.startsWith('https://')) return false;
  const authority = text.slice('https://'.length).split(/[/?#\\]/u, 1)[0] ?? '';
  if (authority === '' || authority.includes('@')) return false;
  try {
    return new URL(text).protocol === 'https:';
  } catch {
    return false;
  }
}

/** The browser's checks on the card: the URL's form and length. The server checks every rule again, the audience's too. */
export function checkSettingsDraft(draft: SettingsDraft): SettingsErrors {
  const errors: SettingsErrors = {};
  const termsUrl = draft.termsUrl.trim();
  if (termsUrl.length > TERMS_URL_MAX_LENGTH) errors.termsUrl = { reason: 'too_long' };
  else if (termsUrl !== '' && !isTermsUrl(termsUrl)) errors.termsUrl = { reason: 'invalid' };
  return errors;
}

export function isSettingsDirty(draft: SettingsDraft, stored: StoredSettings | null, available: boolean): boolean {
  if (stored === null) return false;
  const request = settingsRequestOf(draft, available);
  return (
    request.termsUrl !== stored.termsUrl ||
    request.defaultAudience !== stored.defaultAudience ||
    request.emailVerificationOff !== stored.emailVerificationOff
  );
}

const SETTINGS_FIELDS: ReadonlySet<string> = new Set<SettingsField>(['termsUrl', 'emailVerificationOff', 'defaultAudience']);

/** The server's field errors as the card's, the first per field, each with its rule text. */
export function serverSettingsErrors(
  errors: readonly { field: string; reason: string; detail?: string | null }[] | null | undefined,
): SettingsErrors {
  const found: SettingsErrors = {};
  for (const error of errors ?? []) {
    if (!SETTINGS_FIELDS.has(error.field)) continue;
    found[error.field as SettingsField] ??= typeof error.detail === 'string' && error.detail !== ''
      ? { reason: error.reason, detail: error.detail }
      : { reason: error.reason };
  }
  return found;
}
