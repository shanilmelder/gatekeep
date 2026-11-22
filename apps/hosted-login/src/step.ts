// The steps the server sends (AD-21, Stories 4.1 and 4.2): Host.Hosted embeds the first in the page,
// in <script type="application/json" id="gk-step">, and Hosted Login's two API requests answer with the
// next. The client reads each the same way and renders the matching props-only screen: it holds no flow
// logic, only follows what the server says comes next.

/** The element the server's step JSON is in. */
export const STEP_ELEMENT_ID = 'gk-step';

/** The code Generic error shows when a step is missing, unreadable or unknown. */
export const INVALID_STEP = 'invalid_step';

/** The server's StepResponse, as sent: `data` is the step's props, checked by its screen's reader. */
export interface StepResponse {
  step: string;
  stepVersion: number;
  expiresInSeconds: number | null;
  data: Record<string, unknown>;
  csrfToken: string | null;
}

/** Generic error's props, which every unreadable step falls back to. */
export interface GenericErrorData {
  tenant: string;
  code: string;
  traceId: string;
}

/** Login's props (Story 4.2): the email to fill in, if kept, a field error's code, and whether "Sign up" shows (Story 4.7). */
export interface LoginData {
  tenant: string;
  email: string | null;
  error: string | null;
  signupEnabled: boolean;
}

/** The password policy the strength meter checks (Story 4.7). */
export interface SignupPolicy {
  minLength: number;
  strength: 'good' | 'excellent';
}

/**
 * Signup's props (Story 4.7): the email carried from Login, the policy, a field error's code and the failing rules; from
 * Story 4.8 the Tenant's terms URL, or null, which shows the terms row.
 */
export interface SignupData {
  tenant: string;
  email: string | null;
  policy: SignupPolicy;
  error: string | null;
  rules: string[];
  termsUrl: string | null;
}

/** Email verification required's props (Story 4.7). */
export interface VerifyEmailData {
  tenant: string;
  email: string | null;
  resent: boolean;
  error: string | null;
}

/** Email verified's props (Story 4.7): back to the Application by `location`, or "You can close this page.". */
export interface EmailVerifiedData {
  tenant: string;
  continueTo: 'app' | 'close';
  location: string | null;
}

/** Link expired's props (Story 4.7): the link's own value for "Send a new link", when it had a link's shape. */
export interface LinkExpiredData {
  tenant: string;
  token: string | null;
}

/** The neutral link confirmation's props (Story 4.7). */
export interface LinkSentData {
  tenant: string;
}

/** A redirect's props (Story 4.2): the same-origin path the client opens with a top-level GET. */
export interface RedirectData {
  tenant: string;
  location: string;
}

/** What every step carries besides its props: its version, its remaining life and its CSRF token. */
export interface StepMeta {
  stepVersion: number;
  expiresInSeconds: number | null;
  csrfToken: string | null;
}

/** A readable step, by name, with its checked props. */
export type Step = StepMeta &
  (
    | { step: 'generic_error'; data: GenericErrorData }
    | { step: 'login'; data: LoginData }
    | { step: 'redirect'; data: RedirectData }
    | { step: 'signup'; data: SignupData }
    | { step: 'verify_email'; data: VerifyEmailData }
    | { step: 'email_verified'; data: EmailVerifiedData }
    | { step: 'link_expired'; data: LinkExpiredData }
    | { step: 'link_sent'; data: LinkSentData }
  );

type StepName = Step['step'];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const text = (value: unknown): string | undefined => (typeof value === 'string' ? value : undefined);

/** A string or null; undefined when it is neither. */
const optionalText = (value: unknown): string | null | undefined => (value === null ? null : text(value));

/** The origin a location is resolved against to check it stays on the page's own: a name no real host has. */
const PROBE_ORIGIN = 'https://origin.invalid';

/**
 * A path on this origin: no ASCII control character or whitespace anywhere (a browser strips tabs and newlines,
 * so "/\t/evil.example" would become "//evil.example"), and it starts with one slash, never two or a backslash,
 * and still resolves to the page's own origin.
 */
export function isSameOriginPath(path: string): boolean {
  for (const character of path) {
    const code = character.charCodeAt(0);
    if (code <= 0x20 || code === 0x7f) return false;
  }
  if (!path.startsWith('/') || path.startsWith('//') || path.startsWith('/\\')) return false;
  try {
    return new URL(path, PROBE_ORIGIN).origin === PROBE_ORIGIN;
  } catch {
    return false;
  }
}

/** An absolute https URL with no userinfo, as a Tenant's terms URL is saved (Story 4.8); anything else is never linked. */
export function isHttpsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '';
  } catch {
    return false;
  }
}

/** The Login field error codes the server sends, each shown as its catalogue text. */
export const LOGIN_ERRORS: readonly string[] = Object.freeze(['email_invalid']);

/** Signup's error codes (Story 4.7): the email field's, the password's, whose rules the step names, or (Story 4.8) the terms'. */
export const SIGNUP_ERRORS: readonly string[] = Object.freeze(['email_invalid', 'password_rule', 'terms_required']);

/** The password rule codes the server names (Story 4.7), each shown as its catalogue sentence. */
export const PASSWORD_RULES: readonly string[] = Object.freeze(['length', 'too_long', 'classes', 'repeats', 'dictionary', 'personal_data', 'history']);

/** Email verification required's error codes (Story 4.7). */
export const VERIFY_EMAIL_ERRORS: readonly string[] = Object.freeze(['not_verified_yet']);

/** A code, or null; undefined when it is neither or isn't one of `known`, so an unknown code never shows as another. */
const knownCode = (value: unknown, known: readonly string[]): string | null | undefined => {
  const code = optionalText(value);
  return code === null || (code !== undefined && known.includes(code)) ? code : undefined;
};

/** A step that needs its transaction's CSRF token and remaining life. */
const live = (meta: StepMeta): boolean => meta.csrfToken !== null && meta.expiresInSeconds !== null;

/** Each step's props reader: undefined when the data, or the step's meta, doesn't fit the screen. */
const readers: { [name in StepName]: (data: Record<string, unknown>, meta: StepMeta) => Extract<Step, { step: name }>['data'] | undefined } = {
  generic_error: (data) => {
    const tenant = text(data.tenant);
    const code = text(data.code);
    const traceId = text(data.traceId);
    return tenant === undefined || code === undefined || traceId === undefined ? undefined : { tenant, code, traceId };
  },
  login: (data, meta) => {
    const tenant = text(data.tenant);
    const email = optionalText(data.email);
    const error = optionalText(data.error);
    // An unknown field error code is an unreadable step, never shown as some other error.
    const known = error === null || (error !== undefined && LOGIN_ERRORS.includes(error));
    const signupEnabled = data.signupEnabled === true;
    return tenant === undefined || email === undefined || error === undefined || !known || meta.csrfToken === null || meta.expiresInSeconds === null
      ? undefined
      : { tenant, email, error, signupEnabled };
  },
  redirect: (data) => {
    const tenant = text(data.tenant);
    const location = text(data.location);
    return tenant === undefined || location === undefined || !isSameOriginPath(location) ? undefined : { tenant, location };
  },
  signup: (data, meta) => {
    const tenant = text(data.tenant);
    const email = optionalText(data.email);
    const error = knownCode(data.error, SIGNUP_ERRORS);
    const policy = isRecord(data.policy) ? data.policy : {};
    const minLength = typeof policy.minLength === 'number' && Number.isInteger(policy.minLength) && policy.minLength > 0 ? policy.minLength : undefined;
    const strength = policy.strength === 'good' || policy.strength === 'excellent' ? policy.strength : undefined;
    const rules = Array.isArray(data.rules) && data.rules.every((rule) => typeof rule === 'string' && PASSWORD_RULES.includes(rule)) ? (data.rules as string[]) : undefined;
    // Story 4.8: only an https URL is linked; a missing field is no terms.
    const terms = data.termsUrl === undefined ? null : optionalText(data.termsUrl);
    const termsUrl = terms === null || (terms !== undefined && isHttpsUrl(terms)) ? terms : undefined;
    return tenant === undefined || email === undefined || error === undefined || minLength === undefined || strength === undefined || rules === undefined || termsUrl === undefined || !live(meta)
      ? undefined
      : { tenant, email, policy: { minLength, strength }, error, rules, termsUrl };
  },
  verify_email: (data, meta) => {
    const tenant = text(data.tenant);
    const email = optionalText(data.email);
    const error = knownCode(data.error, VERIFY_EMAIL_ERRORS);
    const resent = data.resent === true;
    return tenant === undefined || email === undefined || error === undefined || !live(meta) ? undefined : { tenant, email, resent, error };
  },
  email_verified: (data) => {
    const tenant = text(data.tenant);
    const location = optionalText(data.location);
    if (tenant === undefined || location === undefined) return undefined;
    if (data.continueTo === 'app') return location !== null && isSameOriginPath(location) ? { tenant, continueTo: 'app', location } : undefined;
    return data.continueTo === 'close' ? { tenant, continueTo: 'close', location: null } : undefined;
  },
  link_expired: (data, meta) => {
    const tenant = text(data.tenant);
    const token = optionalText(data.token);
    // A link to send again needs its link-bound CSRF token.
    return tenant === undefined || token === undefined || (token !== null && meta.csrfToken === null) ? undefined : { tenant, token };
  },
  link_sent: (data) => {
    const tenant = text(data.tenant);
    return tenant === undefined ? undefined : { tenant };
  },
};

/** Generic error for a step that couldn't be read, keeping the Tenant's name when one was given. */
export function invalidStep(tenant: string, code: string = INVALID_STEP): Step {
  return { step: 'generic_error', stepVersion: 1, expiresInSeconds: null, csrfToken: null, data: { tenant, code, traceId: '' } };
}

/**
 * A step from its parsed JSON. An unknown step name, data that doesn't fit its screen or anything that isn't a
 * StepResponse is Generic error with the code `invalid_step` and no trace ID, keeping the Tenant's name when the
 * data names one, else `fallbackTenant`.
 */
export function parseStep(parsed: unknown, fallbackTenant = ''): Step {
  const response = isRecord(parsed) ? parsed : {};
  const data = isRecord(response.data) ? response.data : {};
  const meta: StepMeta = {
    stepVersion: typeof response.stepVersion === 'number' && Number.isInteger(response.stepVersion) ? response.stepVersion : 1,
    expiresInSeconds: typeof response.expiresInSeconds === 'number' && response.expiresInSeconds >= 0 ? response.expiresInSeconds : null,
    csrfToken: text(response.csrfToken) ?? null,
  };
  const name = text(response.step);
  if (name !== undefined && Object.hasOwn(readers, name)) {
    const props = readers[name as StepName](data, meta);
    if (props !== undefined) return { ...meta, step: name, data: props } as Step;
  }
  return invalidStep(text(data.tenant) ?? fallbackTenant);
}

/** The page's step, embedded by the server: Generic error with `invalid_step` when it is missing or unparsable. */
export function readStep(document: Document): Step {
  let parsed: unknown;
  try {
    parsed = JSON.parse(document.getElementById(STEP_ELEMENT_ID)?.textContent ?? '');
  } catch {
    parsed = undefined;
  }
  return parseStep(parsed);
}
