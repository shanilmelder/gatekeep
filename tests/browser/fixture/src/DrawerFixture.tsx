// The drawer and menu fixture (Story 1.17), at `?page=drawer`. Both components are Admin
// only, so this page always renders them from @gatekeep/ui/admin.

import type * as Admin from '@gatekeep/ui/admin';
import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';

// `&dir=rtl` lays the page out right to left, for the drawer's and menu's inline edges.
if (new URLSearchParams(location.search).get('dir') === 'rtl') document.documentElement.dir = 'rtl';

const column: CSSProperties = { display: 'flex', flexDirection: 'column', gap: 'var(--gk-space-16)' };
const row: CSSProperties = { display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--gk-space-8)' };

/** A value no Viewer's DOM may ever hold: the event drawer gets it even when it can't show it. */
export const RAW_CANARY = 'raw-canary-7f3a91';

const RAW = {
  id: 'evt_01J9Z6Q',
  type: 'user.login.failed',
  outcome: 'failure',
  user: 'ada@northwind.test',
  reason: 'wrong_password',
  attempts: 3,
  trace: RAW_CANARY,
};

const SUMMARY = [
  { label: 'Time', value: '2026-11-03 09:41:07 UTC' },
  { label: 'User', value: 'ada@northwind.test' },
  { label: 'Application', value: 'Northwind web' },
  { label: 'Outcome', value: 'Failure' },
];

const LONG_SUMMARY = Array.from({ length: 40 }, (_, index) => ({ label: `Field ${index + 1}`, value: `Value ${index + 1}` }));

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

const ROWS = ['Event A', 'Event B', 'Event C'];
const LIVE: Admin.MenuItem[] = [
  { label: 'Alpha', key: 'alpha' },
  { label: 'Beta', key: 'beta' },
  { label: 'Gamma', key: 'gamma' },
];

/** Hooks the tests call to change a menu while it's open, which no user input could do. */
declare global {
  interface Window {
    gkLive?: (change: 'remove-beta' | 'disable-beta' | 'empty' | 'align') => void;
  }
}

type EventCase = 'raw' | 'viewer' | 'untyped' | 'broken' | 'missing' | 'long';

/** The raw props for each case. "untyped" is a caller bypassing the types: raw with canSeeRaw false. */
function rawProps(event: EventCase | null): { canSeeRaw: true; raw: unknown } | { canSeeRaw: false } {
  if (event === 'viewer') return { canSeeRaw: false };
  if (event === 'untyped') return { canSeeRaw: false, raw: RAW } as unknown as { canSeeRaw: false };
  if (event === 'broken') return { canSeeRaw: true, raw: { attempts: 3n } };
  if (event === 'missing') return { canSeeRaw: true, raw: undefined };
  return { canSeeRaw: true, raw: RAW };
}

function Notify({ admin }: { admin: typeof Admin }) {
  const toast = admin.useToast();
  return (
    <admin.Button data-testid="drawer-notify" onClick={() => toast('Filter saved')}>
      Notify
    </admin.Button>
  );
}

export function DrawerFixture({ admin }: { admin: typeof Admin }) {
  return (
    <admin.ToastProvider>
      <Page admin={admin} />
    </admin.ToastProvider>
  );
}

function Page({ admin }: { admin: typeof Admin }) {
  const { Button, ConfirmModal, Drawer, EventDrawer, Menu, Modal } = admin;
  const [event, setEvent] = useState<EventCase | null>(null);
  const [live, setLive] = useState(LIVE);
  const [liveAlign, setLiveAlign] = useState<'start' | 'end'>('start');
  const [modal, setModal] = useState(false);
  const [modalDrawer, setModalDrawer] = useState(false);
  const [drawerModal, setDrawerModal] = useState(false);
  const [rows, setRows] = useState(ROWS);
  const [viewing, setViewing] = useState<string | null>(null);
  const fallback = useRef<string | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [outside, setOutside] = useState(0);
  const [deleting, setDeleting] = useState(false);
  const [hash, setHash] = useState(location.hash);
  const notes = useRef<HTMLInputElement>(null);
  const pick = (name: string) => () => setSelected((list) => [...list, name]);

  useEffect(() => {
    window.gkLive = (change) => {
      if (change === 'align') setLiveAlign((align) => (align === 'start' ? 'end' : 'start'));
      else if (change === 'empty') setLive([]);
      else if (change === 'remove-beta') setLive((items) => items.filter((item) => item.key !== 'beta'));
      else setLive((items) => items.map((item) => (item.key === 'beta' ? { ...item, disabled: true } : item)));
    };
    return () => {
      delete window.gkLive;
    };
  }, []);

  useEffect(() => {
    const onHash = () => setHash(location.hash);
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  return (
    <main style={{ ...column, padding: 'var(--gk-space-page-padding)', gap: 'var(--gk-space-32)' }}>
      <div style={{ ...row, justifyContent: 'space-between' }}>
        <h1 style={{ font: 'var(--gk-font-page-title)', margin: 0 }}>Drawer and menu</h1>
        {/* At the far inline end, so its popup has to move in to stay in the viewport. */}
        <Menu
          // The name starts with the visible initials (WCAG 2.5.3), then says what it opens.
          label="AL"
          aria-label="AL, account"
          align="start"
          data-testid="avatar-menu"
          items={[
            { label: 'Your credentials', href: '#own-credentials' },
            { label: 'Sign out', onSelect: pick('sign-out') },
          ]}
        />
      </div>

      <Section id="drawer" title="Drawer">
        <div style={row}>
          <Button data-testid="open-event" onClick={() => setEvent('raw')}>
            View event
          </Button>
          <Button data-testid="open-viewer" onClick={() => setEvent('viewer')}>
            View as Viewer
          </Button>
          <Button data-testid="open-untyped" onClick={() => setEvent('untyped')}>
            View as untyped Viewer
          </Button>
          <Button data-testid="open-broken" onClick={() => setEvent('broken')}>
            View unserialisable event
          </Button>
          <Button data-testid="open-missing" onClick={() => setEvent('missing')}>
            View event without raw
          </Button>
          <Button data-testid="open-long" onClick={() => setEvent('long')}>
            View long event
          </Button>
          <Button data-testid="open-modal" onClick={() => setModal(true)}>
            Open modal
          </Button>
        </div>
        <EventDrawer
          open={event !== null}
          onClose={() => setEvent(null)}
          code="user.login.failed"
          outcome="failure"
          title="Failed sign-in"
          summary={event === 'long' ? LONG_SUMMARY : SUMMARY}
          {...rawProps(event)}
          data-testid="event-drawer"
          footer={
            <>
              <Menu
                label="More"
                variant="secondary"
                size="sm"
                data-testid="drawer-menu"
                items={[{ label: 'Filter by this user', onSelect: pick('filter') }]}
              />
              <Button data-testid="drawer-open-modal" onClick={() => setDrawerModal(true)}>
                Open a modal
              </Button>
              <Notify admin={admin} />
            </>
          }
        />
        <Modal
          open={drawerModal}
          onClose={() => setDrawerModal(false)}
          title="Modal over the drawer"
          data-testid="drawer-modal"
          footer={<Button onClick={() => setDrawerModal(false)}>Cancel</Button>}
        >
          <p>This should never show over the drawer.</p>
        </Modal>
        <Modal
          open={modal}
          onClose={() => setModal(false)}
          title="Page modal"
          data-testid="page-modal"
          footer={
            <>
              <Button data-testid="modal-open-drawer" onClick={() => setModalDrawer(true)}>
                Open a drawer
              </Button>
              <Button onClick={() => setModal(false)}>Cancel</Button>
            </>
          }
        >
          <p>A drawer can't open over this.</p>
        </Modal>
        <Drawer open={modalDrawer} onClose={() => setModalDrawer(false)} title="Drawer over the modal" data-testid="modal-drawer">
          <p>This should never show over the modal.</p>
        </Drawer>
      </Section>

      <Section id="rows" title="Rows">
        <ul style={{ ...column, margin: 0, padding: 0, listStyle: 'none' }}>
          {rows.map((name) => (
            <li key={name} style={row} data-row={name}>
              <span>{name}</span>
              <Button size="sm" data-testid={`view-${name}`} onClick={() => setViewing(name)}>
                View {name}
              </Button>
            </li>
          ))}
        </ul>
        <Drawer
          open={viewing !== null}
          onClose={() => setViewing(null)}
          title={viewing ?? ''}
          describedBy="row-drawer-note"
          data-testid="row-drawer"
          fallbackFocus={() =>
            fallback.current === null ? null : document.querySelector<HTMLElement>(`[data-row="${fallback.current}"] button`)
          }
          footer={
            <>
              <Button data-testid="row-open-drawer" onClick={() => setEvent('raw')}>
                Open the event drawer
              </Button>
              <Button
                variant="destructive"
                data-testid="remove-row"
                onClick={() => {
                  const index = rows.indexOf(viewing!);
                  fallback.current = rows[index + 1] ?? null;
                  setRows(rows.filter((name) => name !== viewing));
                  setViewing(null);
                }}
              >
                Remove row
              </Button>
            </>
          }
        >
          <p id="row-drawer-note">Removing the row also removes the button that opened this drawer.</p>
        </Drawer>
      </Section>

      <Section id="menu" title="Menu">
        <div style={row}>
          <Menu
            label="Actions"
            variant="secondary"
            data-testid="user-menu"
            items={[
              { label: 'Block user', onSelect: pick('block') },
              { label: 'Bulk export', onSelect: pick('export') },
              { label: 'Reset MFA', onSelect: pick('reset'), disabled: true },
              { label: 'Rename', onSelect: pick('rename') },
              { type: 'separator' },
              { label: 'Open credentials', href: '#credentials' },
              { label: 'Focus notes', onSelect: () => notes.current?.focus() },
              { label: 'Delete user', tone: 'destructive', onSelect: () => setDeleting(true) },
              { label: 'Archive', onSelect: pick('archive'), disabled: true },
            ]}
          />
          <Button data-testid="outside" onClick={() => setOutside((n) => n + 1)}>
            Outside
          </Button>
          <label>
            Notes <input ref={notes} data-testid="notes" />
          </label>
          {/* Changed while open through window.gkLive. */}
          <Menu label="Live" variant="secondary" align={liveAlign} data-testid="live-menu" items={live} />
          <Menu label="Nothing" variant="secondary" data-testid="empty-menu" items={[]} />
          <Menu
            label="All disabled"
            variant="secondary"
            data-testid="disabled-menu"
            items={[{ label: 'Unavailable', disabled: true }]}
          />
        </div>
        <p>
          Selected: <span data-testid="selected">{selected.join(' ')}</span>
        </p>
        <p>
          Outside clicks: <span data-testid="outside-count">{outside}</span>
        </p>
        <p>
          Location: <span data-testid="hash">{hash}</span>
        </p>
        <ConfirmModal
          open={deleting}
          tone="destructive"
          title="Delete user ada?"
          confirmLabel="Delete"
          onCancel={() => setDeleting(false)}
          onConfirm={() => setDeleting(false)}
          data-testid="delete-modal"
        >
          <p>Their Sessions end and their data is deleted.</p>
        </ConfirmModal>
      </Section>
      {/* Room below, so the page can scroll under an open menu. */}
      <div style={{ minHeight: '100vh' }} aria-hidden="true" />
      {/* Pinned to the bottom edge, so its popup has to open above. */}
      <div style={{ position: 'fixed', insetBlockEnd: 'var(--gk-space-8)', insetInlineStart: 'var(--gk-space-8)' }}>
        <Menu
          label="Bottom"
          variant="secondary"
          data-testid="bottom-menu"
          items={[
            { label: 'First', onSelect: pick('first') },
            { label: 'Second', onSelect: pick('second') },
            { label: 'Third', onSelect: pick('third') },
          ]}
        />
      </div>
    </main>
  );
}
