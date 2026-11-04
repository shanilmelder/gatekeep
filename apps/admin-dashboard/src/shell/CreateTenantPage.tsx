import type { OperationResponse } from '@gatekeep/api-client';
import {
  Banner,
  Button,
  EnvironmentBadge,
  ErrorReference,
  Field,
  Input,
  Radio,
  RadioGroup,
  SectionPage,
  SkeletonRows,
  formatMessage,
  useMessages,
  useToast,
  type Environment,
} from '@gatekeep/ui/admin';
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { navigate } from '../navigation';
import { api } from '../session';
import type { ShellRequest } from './CredentialsPage';
import styles from './CreateTenantPage.module.css';
import { TENANTS_PATH, readTenants, type TenantsRead } from './tenants';
import { NAME_MAX_LENGTH, checkTenantName } from './tenantName';
import { isTenantSubdomain } from './tenantSubdomain';

/** How often a creation Operation is read while it runs. */
export const POLL_MS = 1000;

/** The longest wait between reads after failed ones, which back off from POLL_MS. */
export const POLL_MAX_BACKOFF_MS = 10_000;

/** Failed reads in a row before the page says it can't check, while it keeps trying. */
export const POLL_FAILURES_SHOWN = 3;

type Messages = ReturnType<typeof useMessages>;

/** The environments, in the design's order (wiz.s0), with each one's option text and tag. */
const ENVIRONMENTS: readonly { value: Environment; option: keyof Messages; tag: keyof Messages }[] = [
  { value: 'dev', option: 'environmentDevelopment', tag: 'environmentTagDev' },
  { value: 'staging', option: 'environmentStagingOption', tag: 'environmentTagStaging' },
  { value: 'prod', option: 'environmentProduction', tag: 'environmentTagProd' },
];

/** The tag for a stored label, such as DEV, on its environment's tone. */
export function environmentTag(label: Environment, messages: Messages): string {
  return messages[ENVIRONMENTS.find((environment) => environment.value === label)?.tag ?? 'environmentTagDev'] as string;
}

type Creation = { tenantId: string; operationId: string; name: string };

type Phase =
  | { kind: 'editing' }
  /** The POST is in flight, through a Session renewal too: the form is read-only, never resent. */
  | { kind: 'submitting' }
  /** 202: the Operation runs, and is read every POLL_MS. */
  | ({ kind: 'creating' } & Creation)
  /** The Operation failed: its failed step's code, and Retry. */
  | ({ kind: 'failed'; code: string } & Creation)
  /**
   * Reading the Operation was refused (403) or it isn't there (404): reads stop. The form stays
   * read-only, since the Tenant was created and a second create would only be refused.
   */
  | ({ kind: 'stopped'; reason: 'forbidden' | 'loadFailed'; code: string; traceId: string } & Creation);

/** The last failed read, once POLL_FAILURES_SHOWN have failed in a row. */
type PollTrouble = { code: string; traceId: string } | null;

type Refusal = { kind: 'saveFailed'; code: string; traceId: string } | { kind: 'forbidden' } | null;

/** The code of the first failed step, the only detail an Operation carries (AD-30). */
function failedCode(operation: OperationResponse): string {
  return operation.steps.find((step) => step.status === 'failed')?.resultCode ?? '';
}

/**
 * The Create Tenant form (Story 1.27; wiz.s0 without Region): Name, Tenant Subdomain with the
 * zone beside it, and Environment. The browser checks the name and the subdomain rule first, as
 * feedback only. A 202 keeps the form read-only and reads the creation Operation every second
 * until it isn't running: success is a toast and the Tenants page, failure a banner with the
 * failed step's code and Retry. A 401 on the POST is Story 1.25's renewal: the page stays as it
 * is, every value, node and focus kept, and the POST is never sent again; the Admin presses
 * Create Tenant once signed in. Nothing here decides access: the server decides every request.
 */
export function CreateTenantForm({ request, zone, onCancel }: { request: ShellRequest; zone: string; onCancel?: () => void }) {
  const messages = useMessages();
  const toast = useToast();
  const [name, setName] = useState('');
  const [subdomain, setSubdomain] = useState('');
  const [label, setLabel] = useState<Environment>('dev');
  const [nameError, setNameError] = useState<string | null>(null);
  const [subdomainError, setSubdomainError] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>({ kind: 'editing' });
  const [refusal, setRefusal] = useState<Refusal>(null);
  const [retrying, setRetrying] = useState(false);
  const [trouble, setTrouble] = useState<PollTrouble>(null);
  const nameInput = useRef<HTMLInputElement>(null);
  const subdomainInput = useRef<HTMLInputElement>(null);
  // Set at once, before React re-renders, so a second press sends nothing.
  const inFlight = useRef(false);

  const locked = phase.kind !== 'editing';

  // The Operation, read every POLL_MS while it runs, through the renewal. A 403 or 404 stops the
  // reads; a 5xx or a lost connection backs off, and after POLL_FAILURES_SHOWN in a row says so
  // while it keeps trying. Unmounting stops it.
  useEffect(() => {
    if (phase.kind !== 'creating') return;
    const creation: Creation = { tenantId: phase.tenantId, operationId: phase.operationId, name: phase.name };
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;
    const tick = async () => {
      let status: number | null = null;
      let operation: OperationResponse | undefined;
      let code = 'unavailable';
      let traceId = '';
      try {
        const result = await request('get', () => api.getTenantOperation(creation.tenantId, creation.operationId), controller.signal);
        status = result.status;
        if (result.ok) {
          operation = result.data;
        } else {
          code = result.problem?.code ?? code;
          traceId = result.problem?.traceId ?? '';
        }
      } catch {
        status = null;
      }
      if (controller.signal.aborted) return;
      if (operation?.status === 'succeeded') {
        toast(messages.createTenantCreated);
        navigate(TENANTS_PATH);
        return;
      }
      if (operation?.status === 'failed') {
        setTrouble(null);
        setPhase({ ...creation, kind: 'failed', code: failedCode(operation) });
        return;
      }
      if (status === 403 || status === 404) {
        setTrouble(null);
        setPhase({
          ...creation,
          kind: 'stopped',
          reason: status === 403 ? 'forbidden' : 'loadFailed',
          code: status === 404 ? 'not_found' : code,
          traceId,
        });
        return;
      }
      if (operation?.status === 'running') {
        failures = 0;
        setTrouble(null);
        timer = setTimeout(() => void tick(), POLL_MS);
        return;
      }
      // A 5xx, a lost connection or an answer that isn't an Operation: back off, and read again.
      failures += 1;
      if (failures >= POLL_FAILURES_SHOWN) setTrouble({ code, traceId });
      timer = setTimeout(() => void tick(), Math.min(POLL_MS * 2 ** (failures - 1), POLL_MAX_BACKOFF_MS));
    };
    timer = setTimeout(() => void tick(), POLL_MS);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [phase, request, toast, messages]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (locked || inFlight.current) return;

    const checked = checkTenantName(name);
    const trimmed = checked.kind === 'ok' ? checked.name : '';
    const nameProblem =
      checked.kind === 'empty' ? messages.createTenantNameRequired : checked.kind === 'invalid' ? messages.createTenantNameInvalid : null;
    const subdomainProblem = isTenantSubdomain(subdomain, zone) ? null : messages.createTenantSubdomainRule;
    setNameError(nameProblem);
    setSubdomainError(subdomainProblem);
    if (nameProblem) {
      nameInput.current?.focus();
      return;
    }
    if (subdomainProblem) {
      subdomainInput.current?.focus();
      return;
    }

    inFlight.current = true;
    setRefusal(null);
    setPhase({ kind: 'submitting' });

    let result;
    try {
      result = await request('post', () => api.createTenant({ name: trimmed, subdomain, label }));
    } catch {
      result = null;
    }
    inFlight.current = false;

    if (result?.ok && result.status === 202 && result.data?.tenant && result.data.operation) {
      setPhase({ kind: 'creating', tenantId: result.data.tenant.id, operationId: result.data.operation.id, name: result.data.tenant.name });
      return;
    }

    setPhase({ kind: 'editing' });
    if (result === null) {
      setRefusal({ kind: 'saveFailed', code: 'unavailable', traceId: '' });
    } else if (result.status === 401) {
      // The renewal brought the Admin back and didn't send it again: everything typed is kept.
    } else if (!result.ok && result.status === 400 && result.problem?.code === 'subdomain_refused') {
      setSubdomainError(messages.createTenantSubdomainRefused);
      subdomainInput.current?.focus();
    } else if (result.status === 403) {
      setRefusal({ kind: 'forbidden' });
    } else {
      const problem = result.ok ? null : result.problem;
      setRefusal({ kind: 'saveFailed', code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' });
    }
  }

  async function retry() {
    if (phase.kind !== 'failed' || retrying) return;
    setRetrying(true);
    setRefusal(null);
    let result;
    try {
      result = await request('post', () => api.retryOperation(phase.operationId));
    } catch {
      result = null;
    }
    setRetrying(false);
    // 202 runs it again; a 409 says it isn't failed any more, so it is read again to see what it is.
    if (result !== null && (result.status === 202 || result.status === 409)) {
      setPhase({ kind: 'creating', tenantId: phase.tenantId, operationId: phase.operationId, name: phase.name });
      return;
    }
    if (result?.status === 401) {
      // The renewal brought the Admin back and didn't send it again: they press Retry once more.
      return;
    }
    if (result?.status === 403) {
      setRefusal({ kind: 'forbidden' });
      return;
    }
    const problem = result === null || result.ok ? null : result.problem;
    setRefusal({ kind: 'saveFailed', code: problem?.code ?? 'unavailable', traceId: problem?.traceId ?? '' });
  }

  /** Reads the Operation again after a stopped read, from the load-failed banner. */
  function resume() {
    if (phase.kind !== 'stopped') return;
    setPhase({ kind: 'creating', tenantId: phase.tenantId, operationId: phase.operationId, name: phase.name });
  }

  const host = subdomain === '' ? null : `${subdomain}.${zone}`;

  return (
    <form className={styles.form} onSubmit={(event) => void submit(event)} noValidate data-testid="create-tenant">
      {refusal?.kind === 'saveFailed' && (
        <Banner tone="bad" data-testid="create-tenant-save-failed">
          <p>{messages.createTenantSaveFailed}</p>
          <ErrorReference code={refusal.code} traceId={refusal.traceId} />
        </Banner>
      )}
      {refusal?.kind === 'forbidden' && (
        <Banner tone="bad" data-testid="create-tenant-forbidden">
          {messages.actionForbidden}
        </Banner>
      )}
      {phase.kind === 'stopped' && phase.reason === 'forbidden' && (
        <Banner tone="bad" data-testid="create-tenant-poll-forbidden">
          {messages.actionForbidden}
        </Banner>
      )}
      {phase.kind === 'stopped' && phase.reason === 'loadFailed' && (
        <Banner tone="bad" action={{ label: messages.retry, onClick: resume }} data-testid="create-tenant-poll-load-failed">
          <p>{messages.loadFailed}</p>
          <ErrorReference code={phase.code} traceId={phase.traceId} />
        </Banner>
      )}
      {phase.kind === 'creating' && trouble !== null && (
        <Banner tone="warn" data-testid="create-tenant-poll-trouble">
          <p>{messages.createTenantPollFailed}</p>
          <ErrorReference code={trouble.code} traceId={trouble.traceId} />
        </Banner>
      )}
      {phase.kind === 'failed' && (
        <Banner
          tone="bad"
          action={{ label: messages.retry, onClick: () => void retry(), pending: retrying }}
          data-testid="create-tenant-failed"
        >
          <p>{messages.createTenantFailed}</p>
          <ErrorReference code={phase.code} traceId="" data-testid="create-tenant-failed-reference" />
        </Banner>
      )}
      <Field label={messages.createTenantName} error={nameError}>
        <Input
          ref={nameInput}
          name="name"
          value={name}
          maxLength={NAME_MAX_LENGTH}
          autoComplete="off"
          readOnly={locked}
          onChange={(event) => {
            setName(event.currentTarget.value);
            setNameError(null);
          }}
        />
      </Field>
      <Field label={messages.createTenantSubdomain} helper={messages.createTenantSubdomainHelper} error={subdomainError}>
        <div className={styles.subdomain}>
          <Input
            ref={subdomainInput}
            name="subdomain"
            code
            value={subdomain}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            autoComplete="off"
            readOnly={locked}
            onChange={(event) => {
              setSubdomain(event.currentTarget.value);
              setSubdomainError(null);
            }}
          />
          <span className={styles.zone} data-testid="create-tenant-zone">
            .{zone}
          </span>
        </div>
        {host !== null && (
          <p className={styles.host} data-testid="create-tenant-host">
            {host}
          </p>
        )}
      </Field>
      <RadioGroup legend={messages.createTenantEnvironment} value={label} onChange={(value) => !locked && setLabel(value as Environment)}>
        {ENVIRONMENTS.map((environment) => (
          <Radio
            key={environment.value}
            value={environment.value}
            disabled={locked}
            label={
              <span className={styles.option}>
                {messages[environment.option] as string}
                <EnvironmentBadge environment={environment.value}>{messages[environment.tag] as string}</EnvironmentBadge>
              </span>
            }
          />
        ))}
      </RadioGroup>
      <p role="status" className={styles.status} data-testid="create-tenant-progress">
        {phase.kind === 'creating' ? formatMessage(messages.createTenantCreating, { name: phase.name }) : ''}
      </p>
      <div className={styles.actions}>
        <Button
          type="submit"
          variant="primary"
          pending={phase.kind === 'submitting' || phase.kind === 'creating'}
          aria-disabled={phase.kind === 'failed' || phase.kind === 'stopped' ? true : undefined}
          data-testid="create-tenant-submit"
        >
          {messages.createTenantSubmit}
        </Button>
        {onCancel && (
          <Button type="button" variant="secondary" onClick={onCancel} data-testid="create-tenant-cancel">
            {messages.cancel}
          </Button>
        )}
      </div>
    </form>
  );
}

/** The body a Tenants read leaves before its form or table: a skeleton, or the load-failed banner with Retry. */
export function TenantsReadState({ read, onRetry, children }: { read: TenantsRead | null; onRetry: () => void; children: (ready: Extract<TenantsRead, { kind: 'ready' }>) => ReactNode }) {
  const messages = useMessages();
  if (read === null) return <SkeletonRows rows={3} caption={false} />;
  if (read.kind === 'failed') {
    return (
      <Banner tone="bad" action={{ label: messages.retry, onClick: onRetry }} data-testid="tenants-load-failed">
        <p>{messages.loadFailed}</p>
        <ErrorReference code={read.failure.code} traceId={read.failure.traceId} />
      </Banner>
    );
  }
  return <>{children(read)}</>;
}

/**
 * Create Tenant at /deployment/tenants/new, from the Tenants page: the first page of Tenants is
 * read for the zone, then the form, with Cancel back to Tenants.
 */
export function CreateTenantPage({ request }: { request: ShellRequest }) {
  const messages = useMessages();
  const [read, setRead] = useState<TenantsRead | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setRead(null);
    void readTenants(request, undefined, controller.signal).then((result) => {
      if (!controller.signal.aborted) setRead(result);
    });
    return () => controller.abort();
  }, [request, attempt]);

  return (
    <SectionPage title={messages.createTenantTitle} description={messages.createTenantDescription} data-testid="create-tenant-page">
      <TenantsReadState read={read} onRetry={() => setAttempt((n) => n + 1)}>
        {(ready) => <CreateTenantForm request={request} zone={ready.list.tenantZone} onCancel={() => navigate(TENANTS_PATH)} />}
      </TenantsReadState>
    </SectionPage>
  );
}
