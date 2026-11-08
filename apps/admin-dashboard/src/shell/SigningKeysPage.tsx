import type { SigningKey, SigningKeysJwksResponse } from '@gatekeep/api-client';
import {
  Banner,
  CodeBlock,
  CopyButton,
  DataTable,
  ErrorReference,
  KeyStateBadge,
  SectionPage,
  SkeletonRows,
  formatMessage,
  useMessages,
  type DataTableColumn,
  type KeyState,
} from '@gatekeep/ui/admin';
import { useEffect, useState, type ReactNode } from 'react';
import { api } from '../session';
import type { ShellRequest } from './CredentialsPage';
import { ForbiddenPage } from './ForbiddenPage';
import styles from './SigningKeysPage.module.css';

type Failure = { code: string; traceId: string };

type ListLoad =
  | { kind: 'loading' }
  | { kind: 'ready'; keys: readonly SigningKey[] }
  | { kind: 'forbidden'; failure: Failure }
  | { kind: 'failed'; failure: Failure };

type JwksLoad = { kind: 'loading' } | { kind: 'ready'; sample: SigningKeysJwksResponse } | { kind: 'failed'; failure: Failure };

const DATE = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });

/** A date, in the browser's own time zone and locale. */
function day(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : DATE.format(date);
}

/** A refusal's code and trace ID, as far as the answer carries them: a bodiless 503 has neither. */
function failureOf(result: { ok: boolean; problem?: { code?: string; traceId?: string } | null } | null): Failure {
  const problem = result && !result.ok ? result.problem : null;
  return { code: problem?.code ?? '', traceId: problem?.traceId ?? '' };
}

export interface SigningKeysPageProps {
  request: ShellRequest;
  /** The path Tenant this page was mounted with: every request it sends names this one. */
  tenantId: string;
}

/**
 * Signing keys (Story 9.1; GEN.keys as the epic changes it): the Tenant's Signing Keys in every
 * state, each key ID in the code type with its own Copy, and below them the public JWKS sample
 * its Tenant host serves, with its URI and its own Copy. The two are read apart: the table is the
 * database's and the sample needs key custody, so a sample that can't be read says so in its
 * place and the table stays. A 403 on the list is the forbidden page. It only reads: Rotate and
 * Revoke arrive with Stories 9.2 and 9.3, and the server decides every request.
 */
export function SigningKeysPage({ request, tenantId }: SigningKeysPageProps) {
  const messages = useMessages();
  const [list, setList] = useState<ListLoad>({ kind: 'loading' });
  const [jwks, setJwks] = useState<JwksLoad>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);
  const [jwksAttempt, setJwksAttempt] = useState(0);
  const listed = list.kind === 'ready';

  useEffect(() => {
    const controller = new AbortController();
    setList({ kind: 'loading' });

    void (async () => {
      let result;
      try {
        result = await request('get', () => api.listSigningKeys(tenantId), controller.signal);
      } catch {
        result = null;
      }
      if (controller.signal.aborted) return;
      const keys = result?.ok ? result.data?.keys : undefined;
      if (Array.isArray(keys)) setList({ kind: 'ready', keys });
      else if (result !== null && !result.ok && result.status === 403 && result.problem?.code === 'access_denied')
        setList({ kind: 'forbidden', failure: failureOf(result) });
      else setList({ kind: 'failed', failure: failureOf(result) });
    })();

    return () => controller.abort();
  }, [request, tenantId, attempt]);

  // The sample only once the list has read: a refused page asks custody nothing, and is denied once.
  useEffect(() => {
    if (!listed) return;
    const controller = new AbortController();
    setJwks({ kind: 'loading' });

    void (async () => {
      let result;
      try {
        result = await request('get', () => api.getSigningKeysJwks(tenantId), controller.signal);
      } catch {
        result = null;
      }
      if (controller.signal.aborted) return;
      const sample = result?.ok ? result.data : undefined;
      if (sample && typeof sample.jwksUri === 'string' && Array.isArray(sample.keys)) setJwks({ kind: 'ready', sample });
      else setJwks({ kind: 'failed', failure: failureOf(result) });
    })();

    return () => controller.abort();
  }, [request, tenantId, listed, jwksAttempt]);

  if (list.kind === 'forbidden') return <ForbiddenPage code={list.failure.code} traceId={list.failure.traceId} />;

  const columns: DataTableColumn<SigningKey>[] = [
    {
      key: 'keyId',
      header: messages.signingKeysColumnKeyId,
      rowHeader: true,
      cell: (row) => (
        <span className={styles.keyId}>
          <code data-testid="signing-key-id">{row.keyId}</code>
          <CopyButton value={row.keyId} what={messages.signingKeyIdWhat} />
        </span>
      ),
    },
    { key: 'algorithm', header: messages.signingKeysColumnAlgorithm, cell: (row) => row.algorithm },
    { key: 'state', header: messages.signingKeysColumnStatus, cell: (row) => <KeyStateBadge state={row.state as KeyState} /> },
    { key: 'created', header: messages.signingKeysColumnCreated, cell: (row) => day(row.createdAt) },
  ];

  let body: ReactNode;
  if (list.kind === 'loading') {
    body = <SkeletonRows rows={4} caption={false} />;
  } else if (list.kind === 'failed') {
    body = (
      <Banner tone="bad" action={{ label: messages.retry, onClick: () => setAttempt((n) => n + 1) }} data-testid="signing-keys-load-failed">
        <p>{messages.loadFailed}</p>
        <ErrorReference code={list.failure.code} traceId={list.failure.traceId} />
      </Banner>
    );
  } else {
    let sample: ReactNode;
    if (jwks.kind === 'loading') {
      sample = <SkeletonRows rows={1} columns={1} caption={false} />;
    } else if (jwks.kind === 'failed') {
      sample = (
        <Banner
          tone="bad"
          live={false}
          action={{ label: messages.retry, onClick: () => setJwksAttempt((n) => n + 1) }}
          data-testid="signing-keys-jwks-failed"
        >
          <p>{messages.signingKeysJwksFailed}</p>
          <ErrorReference code={jwks.failure.code} traceId={jwks.failure.traceId} />
        </Banner>
      );
    } else {
      sample = (
        <div data-testid="signing-keys-jwks">
          {/* The whole public key set, every modulus in full, so Copy gives a usable JWKS. */}
          <CodeBlock
            filename={formatMessage(messages.signingKeysJwksTitle, { uri: jwks.sample.jwksUri })}
            code={JSON.stringify({ keys: jwks.sample.keys }, null, 2)}
          />
        </div>
      );
    }

    body = (
      <div className={styles.content} data-testid="signing-keys">
        <DataTable
          caption={messages.signingKeysTitle}
          hideCaption
          columns={columns}
          rows={list.keys}
          rowKey={(row) => row.keyId}
          // A Tenant has a handful of keys: every one on one page.
          pageSize={Math.max(list.keys.length, 1)}
        />
        {sample}
      </div>
    );
  }

  return (
    <SectionPage title={messages.signingKeysTitle} description={messages.signingKeysDescription} data-testid="signing-keys-page">
      {body}
    </SectionPage>
  );
}
