// The data display fixture (Story 1.15), at `?page=data`. Hosted renders the shared pieces
// from @gatekeep/ui/hosted: badges, Copy and the code block. Admin renders those from
// @gatekeep/ui/admin, then everything only the Admin Dashboard uses.

import type * as Admin from '@gatekeep/ui/admin';
import type * as UI from '@gatekeep/ui/hosted';
import { useState, type CSSProperties, type ReactNode } from 'react';

interface User {
  id: string;
  name: string;
  clientId: string;
  logins: number;
}

// 120 rows: two full pages of 50 and a last page of 20.
const USERS: readonly User[] = Array.from({ length: 120 }, (_, index) => {
  const n = String(index + 1).padStart(3, '0');
  return { id: `user_${n}`, name: `User ${n}`, clientId: `app_${n}k3m9q`, logins: (index + 1) * 37 };
});

const RAW_EVENT = {
  type: 'login.failure',
  user_id: 'user_007',
  attempts: 3,
  success: false,
  ip: null,
  scopes: ['openid', 'profile'],
};

const QUICKSTART = `import { Issuer } from 'openid-client';

const issuer = await Issuer.discover('https://northwind.example');
const client = new issuer.Client({ client_id: 'app_8f2k3m9q' });`;

const PERMISSIONS = [
  { id: 'read:users', label: 'read:users' },
  { id: 'write:users', label: 'write:users' },
  { id: 'delete:users', label: 'delete:users' },
];
const ROLES = [
  { id: 'viewer', label: 'Viewer' },
  { id: 'editor', label: 'Editor' },
  { id: 'owner', label: 'Owner' },
];
const GRANTS: Record<string, readonly string[]> = {
  viewer: ['read:users'],
  editor: ['read:users', 'write:users'],
  owner: ['read:users', 'write:users', 'delete:users'],
};

// A module constant, so the provider's messages stay stable across renders.
const GERMAN: Partial<UI.Messages> = {
  copy: 'Kopieren',
  copied: 'Kopiert',
  // The word order is the catalogue's, not the code's.
  copyNamed: '{what} kopieren',
  copiedNamed: '{what} kopiert',
};

const TAB_ITEMS = [
  { id: 'settings', label: 'Settings', panel: <p>Settings panel</p> },
  { id: 'credentials', label: 'Credentials', panel: <p>Credentials panel</p> },
  { id: 'connections', label: 'Connections', panel: <p>Connections panel</p> },
  { id: 'quickstart', label: 'Quickstart', panel: <p>Quickstart panel</p> },
];

const column: CSSProperties = { display: 'flex', flexDirection: 'column', gap: 'var(--gk-space-16)' };
const row: CSSProperties = { display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--gk-space-8)' };

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section aria-labelledby={id} style={column}>
      <h2 id={id} style={{ font: 'var(--gk-font-section)', margin: 0 }}>
        {title}
      </h2>
      {children}
    </section>
  );
}

export function DataFixture({ surface, ui, admin }: { surface: UI.Surface; ui: typeof UI; admin: typeof Admin | null }) {
  const { CodeBadge, CodeBlock, CopyButton, DraftBadge, EnvironmentBadge, MessagesProvider, ProtocolBadge, StatusBadge } = ui;
  return (
    <main style={{ ...column, padding: 'var(--gk-space-page-padding)', gap: 'var(--gk-space-32)' }}>
      <h1 style={{ font: 'var(--gk-font-page-title)', margin: 0 }}>Data display on {surface}</h1>

      <Section id="badges" title="Badges">
        <div style={row}>
          <StatusBadge status="active" data-testid="badge-active" />
          <StatusBadge status="pending" data-testid="badge-pending" />
          <StatusBadge status="blocked" data-testid="badge-blocked" />
          <ProtocolBadge data-testid="badge-protocol">OIDC</ProtocolBadge>
          <DraftBadge data-testid="badge-draft" />
        </div>
        <div style={row}>
          <EnvironmentBadge environment="prod" data-testid="badge-prod" />
          <EnvironmentBadge environment="staging" data-testid="badge-staging" />
          <EnvironmentBadge environment="dev" data-testid="badge-dev" />
          <CodeBadge data-testid="badge-success">s</CodeBadge>
          <CodeBadge outcome="failure" data-testid="badge-failure">
            fp
          </CodeBadge>
        </div>
      </Section>

      <Section id="copy" title="Copy">
        <div style={row}>
          <code style={{ font: 'var(--gk-font-code)' }}>app_8f2k3m9q</code>
          <CopyButton value="app_8f2k3m9q" what="client ID" data-testid="copy-client-id" />
          <CopyButton value={() => 'computed-at-click'} what="setup key" variant="secondary" data-testid="copy-setup-key" />
          <MessagesProvider messages={GERMAN}>
            <CopyButton value="geheim" what="Schlüssel" data-testid="copy-german" />
          </MessagesProvider>
        </div>
      </Section>

      <Section id="code" title="Code">
        <CodeBlock filename="auth.ts" code={QUICKSTART} />
      </Section>

      {admin && <AdminOnly admin={admin} />}
    </main>
  );
}

function AdminOnly({ admin }: { admin: typeof Admin }) {
  const { Checkbox, CopyButton, DataTable, EmptyState, JsonViewer, RbacMatrix, SettingsRow, SkeletonRows, StatTile, Tabs, Toggle, UsageBar } =
    admin;
  const [activated, setActivated] = useState<string[]>([]);
  const [dirty, setDirty] = useState(false);
  const [asyncGuard, setAsyncGuard] = useState(false);
  const [guardCalls, setGuardCalls] = useState(0);
  const [created, setCreated] = useState(0);
  const [loading, setLoading] = useState(false);
  const [controlledTab, setControlledTab] = useState('one');
  const [requestedTab, setRequestedTab] = useState('');
  const [controlledPage, setControlledPage] = useState(0);
  const [pageRequests, setPageRequests] = useState<number[]>([]);

  return (
    <>
      <Section id="tabs" title="Tabs">
        <div style={row}>
          <Checkbox label="Unsaved changes" checked={dirty} onChange={(event) => setDirty(event.currentTarget.checked)} data-testid="dirty" />
          <Checkbox
            label="Guard answers later"
            checked={asyncGuard}
            onChange={(event) => setAsyncGuard(event.currentTarget.checked)}
            data-testid="async-guard"
          />
          <output data-testid="guard-calls">{guardCalls}</output>
        </div>
        <Tabs
          label="Application"
          param="tab"
          canLeave={() => {
            setGuardCalls((n) => n + 1);
            return asyncGuard ? new Promise((resolve) => setTimeout(() => resolve(!dirty), 50)) : !dirty;
          }}
          tabs={TAB_ITEMS}
        />
        {/* Controlled without a URL: a selection waits for the caller. Ids hold spaces. */}
        <Tabs
          label="Controlled"
          selected={controlledTab}
          onSelect={setRequestedTab}
          tabs={[
            { id: 'one', label: 'One', panel: <p>One panel</p> },
            { id: 'two words', label: 'Two', panel: <button type="button">Inside two</button> },
          ]}
        />
        <div style={row}>
          <output data-testid="requested-tab">{requestedTab}</output>
          <button type="button" data-testid="apply-tab" onClick={() => setControlledTab(requestedTab || controlledTab)}>
            Apply requested tab
          </button>
        </div>
        <div dir="rtl">
          <Tabs
            label="Right to left"
            tabs={[
              { id: 'a', label: 'Alpha', panel: <p>Alpha panel</p> },
              { id: 'b', label: 'Beta', panel: <p>Beta panel</p> },
              { id: 'c', label: 'Gamma', panel: <p>Gamma panel</p> },
            ]}
          />
        </div>
      </Section>

      <Section id="table" title="Table">
        <DataTable<User>
          caption="Users"
          rows={USERS}
          rowKey={(user) => user.id}
          onRowActivate={(user) => setActivated((list) => [...list, user.id])}
          columns={[
            { key: 'name', header: 'Name', cell: (user) => user.name, rowHeader: true, rowLink: true },
            {
              key: 'client',
              header: 'Client ID',
              cell: (user) => (
                <span style={row}>
                  <code style={{ font: 'var(--gk-font-code)' }}>{user.clientId}</code>
                  <CopyButton value={user.clientId} what={`client ID of ${user.name}`} />
                </span>
              ),
            },
            { key: 'logins', header: 'Logins', cell: (user) => user.logins.toLocaleString('en'), numeric: true },
          ]}
        />
        <output data-testid="activated">{activated.join(' ')}</output>

        {/* Controlled paging, a hidden caption and a selected row. */}
        <DataTable<User>
          caption="Controlled users"
          hideCaption
          rows={USERS}
          rowKey={(user) => user.id}
          selectedKey="user_002"
          page={controlledPage}
          onPageChange={(to) => setPageRequests((list) => [...list, to])}
          columns={[
            { key: 'name', header: 'Name', cell: (user) => user.name, rowHeader: true },
            { key: 'logins', header: 'Logins', cell: (user) => String(user.logins), numeric: true },
          ]}
        />
        <div style={row}>
          <output data-testid="page-requests">{pageRequests.join(' ')}</output>
          <button type="button" data-testid="page-past-end" onClick={() => setControlledPage(99)}>
            Go past the end
          </button>
        </div>

        <DataTable<User>
          caption="No users"
          rows={[]}
          rowKey={(user) => user.id}
          columns={[{ key: 'name', header: 'Name', cell: (user) => user.name, rowHeader: true }]}
          empty={<EmptyState message="No users yet" />}
        />
      </Section>

      <Section id="json" title="JSON">
        <JsonViewer label="Raw event" value={RAW_EVENT} />
        <JsonViewer label="Big number" value={{ id: BigInt(1) }} />
      </Section>

      <Section id="empty" title="Empty states">
        <div data-testid="empty-with-action">
          <EmptyState icon="+" message="No applications yet" action={{ label: 'Create application', onClick: () => setCreated((n) => n + 1) }} />
        </div>
        <output data-testid="created">{created}</output>
        <div data-testid="empty-without-action">
          <EmptyState message="No applications yet" />
        </div>
      </Section>

      <Section id="loading" title="Loading">
        <div style={row}>
          <Checkbox label="Loading" checked={loading} onChange={(event) => setLoading(event.currentTarget.checked)} data-testid="loading" />
        </div>
        {/* The Users table's stand-in: 50 rows, the caption and the paging footer. */}
        <div data-testid="loading-area">{loading && <SkeletonRows rows={50} columns={3} footer />}</div>
      </Section>

      <Section id="blocks" title="Section blocks">
        <div style={row}>
          <StatTile label="Users" value="1,204" />
          <StatTile label="Logins today" value="318" />
        </div>
        <div>
          <SettingsRow label="Allow sign-up" description="New Users can create an account on Hosted Login.">
            <Toggle label="Allow sign-up" hideLabel defaultChecked data-testid="settings-toggle" />
          </SettingsRow>
          <SettingsRow label="Breached password detection" description="Always on.">
            <span>On</span>
          </SettingsRow>
        </div>
        <UsageBar label="Sign-ins this minute" value={30} max={100} />
        <UsageBar label="Emails this hour" value={150} max={100} />
        <RbacMatrix
          caption="Permissions by role"
          rows={PERMISSIONS}
          columns={ROLES}
          allowed={(permission, role) => GRANTS[role]?.includes(permission) ?? false}
        />
      </Section>
    </>
  );
}
