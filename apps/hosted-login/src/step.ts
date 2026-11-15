// The step the server embedded in the page (AD-21, Story 4.1): Host.Hosted puts the step's
// StepResponse in <script type="application/json" id="gk-step">. The client reads it once, maps its
// step name to a props-only screen and renders it, with no fetch: it holds no flow logic.

/** The element the server's step JSON is in. */
export const STEP_ELEMENT_ID = 'gk-step';

/** The code Generic error shows when the page's step is missing, unreadable or unknown. */
export const INVALID_STEP = 'invalid_step';

/** The server's StepResponse, as embedded: `data` is the step's props, checked by its screen's reader. */
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

/** A readable step, by name, with its checked props. */
export type Step = { step: 'generic_error'; data: GenericErrorData };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const text = (value: unknown): string | undefined => (typeof value === 'string' ? value : undefined);

/** Each step's props reader: undefined when the data doesn't fit the screen. */
const readers: { [name in Step['step']]: (data: Record<string, unknown>) => Extract<Step, { step: name }>['data'] | undefined } = {
  generic_error: (data) => {
    const tenant = text(data.tenant);
    const code = text(data.code);
    const traceId = text(data.traceId);
    return tenant === undefined || code === undefined || traceId === undefined ? undefined : { tenant, code, traceId };
  },
};

/**
 * The page's step. A missing or unparsable block, an unknown step name or data that doesn't fit its
 * screen is Generic error with the code `invalid_step` and no trace ID, keeping the Tenant's name
 * when the data names one.
 */
export function readStep(document: Document): Step {
  let parsed: unknown;
  try {
    parsed = JSON.parse(document.getElementById(STEP_ELEMENT_ID)?.textContent ?? '');
  } catch {
    parsed = undefined;
  }

  const response = isRecord(parsed) ? parsed : {};
  const data = isRecord(response.data) ? response.data : {};
  const name = text(response.step);
  if (name !== undefined && Object.hasOwn(readers, name)) {
    const props = readers[name as Step['step']](data);
    if (props !== undefined) return { step: name as Step['step'], data: props };
  }
  return { step: 'generic_error', data: { tenant: text(data.tenant) ?? '', code: INVALID_STEP, traceId: '' } };
}
