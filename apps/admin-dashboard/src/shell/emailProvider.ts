// The Email provider page (Story 4.4): its path, each provider kind's fields, the form's draft and the request it
// sends, and the browser's checks before a save. The server's rules are the same and decide every request: this is
// feedback only. The secret is write-only: the draft never holds a stored one, and an empty field sends none, so
// the server keeps what it stores.
//
// Plain TypeScript with no import, so Node runs its tests directly (test/emailProvider.test.mjs).

export type EmailProviderKind = 'smtp' | 'sendgrid' | 'postmark' | 'mailgun' | 'ses' | 'custom_http';

/** Every kind, in the order the page's cards show them. */
export const EMAIL_PROVIDER_KINDS: readonly EmailProviderKind[] = ['smtp', 'sendgrid', 'postmark', 'mailgun', 'ses', 'custom_http'];

/** A settings member a kind's card shows. */
export type SettingName = 'host' | 'port' | 'tls' | 'username' | 'region' | 'messageStream' | 'domain' | 'accessKeyId' | 'endpoint' | 'authHeaderName';

/** One field of a kind's card: a text box, or a choice from fixed values. */
export interface SettingField {
  name: SettingName;
  required: boolean;
  maxLength: number;
  /** The values a choice offers, in order; a text box has none. */
  options?: readonly string[];
  /** Whether the value is a whole number (the SMTP port). */
  numeric?: boolean;
}

/** Each kind's settings, in the order its card shows them. */
export const KIND_FIELDS: Readonly<Record<EmailProviderKind, readonly SettingField[]>> = {
  smtp: [
    { name: 'host', required: true, maxLength: 253 },
    { name: 'port', required: true, maxLength: 5, numeric: true },
    { name: 'tls', required: true, maxLength: 16, options: ['starttls', 'implicit'] },
    { name: 'username', required: false, maxLength: 256 },
  ],
  sendgrid: [{ name: 'region', required: true, maxLength: 64, options: ['global', 'eu'] }],
  postmark: [{ name: 'messageStream', required: false, maxLength: 64 }],
  mailgun: [
    { name: 'domain', required: true, maxLength: 253 },
    { name: 'region', required: true, maxLength: 64, options: ['us', 'eu'] },
  ],
  ses: [
    { name: 'region', required: true, maxLength: 64 },
    { name: 'accessKeyId', required: true, maxLength: 128 },
  ],
  custom_http: [
    { name: 'endpoint', required: true, maxLength: 2048 },
    { name: 'authHeaderName', required: false, maxLength: 64 },
  ],
};

export const FROM_ADDRESS_MAX_LENGTH = 254;
export const FROM_NAME_MAX_LENGTH = 128;
export const SECRET_MAX_LENGTH = 4096;

/** A new SMTP card's port and TLS, and each choice's first value. */
const DEFAULTS: Partial<Record<SettingName, string>> = { port: '587', tls: 'starttls' };

/** What the form holds: the kind, every kind's settings as typed, the From parts and a new secret, if one is typed. */
export interface EmailProviderDraft {
  kind: EmailProviderKind;
  settings: Record<SettingName, string>;
  fromAddress: string;
  fromName: string;
  secret: string;
}

/** The provider as the server gives it, in the parts this module reads. */
export interface StoredProvider {
  configured: boolean;
  kind?: string | null;
  settings?: Partial<Record<SettingName, string | number | null>> | null;
  fromAddress?: string | null;
  fromName?: string | null;
  secretSet?: boolean | null;
}

/** The request a save sends. */
export interface EmailProviderRequest {
  kind: EmailProviderKind;
  settings: Partial<Record<SettingName, string | number>>;
  fromAddress: string;
  fromName?: string;
  secret?: string;
}

/** A field the server or the browser names: `kind`, `settings.{name}`, `fromAddress`, `fromName` or `secret`. */
export type DraftField = 'kind' | 'settings' | `settings.${SettingName}` | 'fromAddress' | 'fromName' | 'secret';

/** Why a field is refused, as the server says it. */
export type FieldReason = 'required' | 'invalid' | 'too_long';

export type DraftErrors = Partial<Record<DraftField, FieldReason>>;

const CONTROL = /\p{Cc}/u;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;

/** The Email provider page's path for a Tenant. */
export function emailProviderPath(tenantId: string): string {
  return `/tenants/${encodeURIComponent(tenantId)}/email-provider`;
}

export function isKind(value: unknown): value is EmailProviderKind {
  return typeof value === 'string' && (EMAIL_PROVIDER_KINDS as readonly string[]).includes(value);
}

function emptySettings(): Record<SettingName, string> {
  return {
    host: '',
    port: DEFAULTS.port ?? '',
    tls: DEFAULTS.tls ?? '',
    username: '',
    region: '',
    messageStream: '',
    domain: '',
    accessKeyId: '',
    endpoint: '',
    authHeaderName: '',
  };
}

/** The form for a stored provider, or a new SMTP one; never a secret. */
export function draftOf(provider: StoredProvider | null): EmailProviderDraft {
  const settings = emptySettings();
  const kind: EmailProviderKind = provider?.configured && isKind(provider.kind) ? provider.kind : 'smtp';
  for (const [name, value] of Object.entries(provider?.configured ? (provider.settings ?? {}) : {})) {
    if (name in settings && (typeof value === 'string' || typeof value === 'number')) settings[name as SettingName] = String(value);
  }
  // A choice starts on its first value, so a new card never shows an empty one.
  for (const field of KIND_FIELDS[kind]) {
    if (field.options && settings[field.name] === '') settings[field.name] = field.options[0] ?? '';
  }
  return {
    kind,
    settings,
    fromAddress: provider?.configured ? (provider.fromAddress ?? '') : '',
    fromName: provider?.configured ? (provider.fromName ?? '') : '',
    secret: '',
  };
}

/** Every choice's values, of any kind: a value from one of these is never carried into another kind's text box. */
const OPTION_VALUES: ReadonlySet<string> = new Set(
  Object.values(KIND_FIELDS).flatMap((fields) => fields.flatMap((field) => field.options ?? [])),
);

/**
 * The draft moved to another kind: its settings are kept as typed, but a choice's value carried into a field that
 * doesn't offer it starts empty, and the new kind's choices start on their first value. A typed secret is cleared:
 * one kind's secret is never sent as another's.
 */
export function withKind(draft: EmailProviderDraft, kind: EmailProviderKind): EmailProviderDraft {
  if (kind === draft.kind) return draft;
  const settings = { ...draft.settings };
  for (const field of KIND_FIELDS[kind]) {
    const value = settings[field.name];
    if (field.options) {
      if (!field.options.includes(value)) settings[field.name] = field.options[0] ?? '';
    } else if (OPTION_VALUES.has(value)) {
      settings[field.name] = '';
    }
  }
  return { ...draft, kind, settings, secret: '' };
}

/** Whether the kind, with these settings, sends with a secret: every kind but SMTP with no username. */
export function usesSecret(kind: EmailProviderKind, settings: Readonly<Record<SettingName, string>>): boolean {
  return kind !== 'smtp' || settings.username.trim() !== '';
}

/** A setting as the save sends it and the server stores it: trimmed, and the auth header's default when left empty. */
function sent(name: SettingName, value: string): string {
  const trimmed = value.trim();
  return name === 'authHeaderName' && trimmed === '' ? 'Authorization' : trimmed;
}

/**
 * Whether a save must carry a new secret: the kind uses one, and none is stored for exactly this destination (a first
 * save, a change of kind, an SMTP username where there was none, or any change of settings but Postmark's message
 * stream). The server holds the same rule, so a stored secret is never sent anywhere new.
 */
export function secretRequired(draft: EmailProviderDraft, stored: StoredProvider | null): boolean {
  if (!usesSecret(draft.kind, draft.settings)) return false;
  if (!(stored?.configured && stored.kind === draft.kind && stored.secretSet === true)) return true;
  const baseline = draftOf(stored).settings;
  return KIND_FIELDS[draft.kind].some(
    (field) => field.name !== 'messageStream' && sent(field.name, draft.settings[field.name]) !== sent(field.name, baseline[field.name]),
  );
}

/** The request for a draft: only its kind's settings, trimmed, the optional ones left out when empty, and the secret only when typed. */
export function requestOf(draft: EmailProviderDraft): EmailProviderRequest {
  const settings: Partial<Record<SettingName, string | number>> = {};
  for (const field of KIND_FIELDS[draft.kind]) {
    const value = draft.settings[field.name].trim();
    if (value === '' && !field.required) continue;
    settings[field.name] = field.numeric && /^\d+$/.test(value) ? Number(value) : value;
  }
  const request: EmailProviderRequest = { kind: draft.kind, settings, fromAddress: draft.fromAddress.trim() };
  const fromName = draft.fromName.trim();
  if (fromName !== '') request.fromName = fromName;
  if (draft.secret !== '' && usesSecret(draft.kind, draft.settings)) request.secret = draft.secret;
  return request;
}

/** The browser's checks on a draft: what is missing, too long or plainly malformed. The server checks every rule again. */
export function checkDraft(draft: EmailProviderDraft, stored: StoredProvider | null): DraftErrors {
  const errors: DraftErrors = {};
  for (const field of KIND_FIELDS[draft.kind]) {
    const value = draft.settings[field.name].trim();
    const key = `settings.${field.name}` as const;
    if (value === '') {
      if (field.required) errors[key] = 'required';
    } else if (value.length > field.maxLength) {
      errors[key] = 'too_long';
    } else if (CONTROL.test(value) || (field.numeric && !/^\d+$/.test(value)) || (field.options && !field.options.includes(value))) {
      errors[key] = 'invalid';
    } else if (field.numeric && (Number(value) < 1 || Number(value) > 65535)) {
      errors[key] = 'invalid';
    } else if (field.name === 'endpoint' && !value.toLowerCase().startsWith('https://')) {
      errors[key] = 'invalid';
    }
  }

  const fromAddress = draft.fromAddress.trim();
  if (fromAddress === '') errors.fromAddress = 'required';
  else if (fromAddress.length > FROM_ADDRESS_MAX_LENGTH) errors.fromAddress = 'too_long';
  else if (!EMAIL.test(fromAddress) || CONTROL.test(fromAddress)) errors.fromAddress = 'invalid';

  const fromName = draft.fromName.trim();
  if (fromName.length > FROM_NAME_MAX_LENGTH) errors.fromName = 'too_long';
  else if (CONTROL.test(fromName)) errors.fromName = 'invalid';

  if (draft.secret === '') {
    if (secretRequired(draft, stored)) errors.secret = 'required';
  } else if (draft.secret.length > SECRET_MAX_LENGTH) {
    errors.secret = 'too_long';
  } else if (draft.secret.includes('\u0000')) {
    errors.secret = 'invalid';
  }
  return errors;
}

/** The server's field errors as the draft's, the first reason per field; a field the page doesn't know is left out. */
export function serverErrors(errors: readonly { field: string; reason: string }[] | null | undefined): DraftErrors {
  const found: DraftErrors = {};
  for (const error of errors ?? []) {
    const known =
      error.field === 'kind' ||
      error.field === 'settings' ||
      error.field === 'fromAddress' ||
      error.field === 'fromName' ||
      error.field === 'secret' ||
      (error.field.startsWith('settings.') && error.field.slice('settings.'.length) in emptySettings());
    const reason = error.reason === 'required' || error.reason === 'too_long' ? error.reason : 'invalid';
    if (known) found[error.field as DraftField] ??= reason;
  }
  return found;
}

/** Whether the draft differs from what is stored, or from a new card when none is: its kind, a setting of its kind, the From parts, or a typed secret. */
export function isDirty(draft: EmailProviderDraft, stored: StoredProvider | null): boolean {
  if (draft.secret !== '') return true;
  const baseline = draftOf(stored);
  if (draft.kind !== baseline.kind) return true;
  if (draft.fromAddress.trim() !== baseline.fromAddress || draft.fromName.trim() !== baseline.fromName) return true;
  return KIND_FIELDS[draft.kind].some((field) => draft.settings[field.name].trim() !== baseline.settings[field.name]);
}
