// The overlays and feedback fixture (Story 1.16), at `?page=overlay`. Both surfaces render
// the shared toast and banner from their own entry; Admin also renders the modals, which
// only @gatekeep/ui/admin exports.

import type * as Admin from '@gatekeep/ui/admin';
import type * as UI from '@gatekeep/ui/hosted';
import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';

// Opt-in cases, so they don't disturb the others: `&mounttoast` sends a toast from a child's
// mount effect, `&span` puts a control over the whole viewport, and `&timerbanner` mounts a
// warn banner 1.5 seconds after load with no interaction.
const params = new URLSearchParams(location.search);

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

export function OverlayFixture({ surface, ui, admin }: { surface: UI.Surface; ui: typeof UI; admin: typeof Admin | null }) {
  const { ToastProvider } = ui;
  // Opened from inside the confirm modal, to show neither stacks over it.
  const [sibling, setSibling] = useState(false);
  const [loose, setLoose] = useState(false);
  const page = (
    <main style={{ ...column, padding: 'var(--gk-space-page-padding)', gap: 'var(--gk-space-32)' }}>
      <h1 style={{ font: 'var(--gk-font-page-title)', margin: 0 }}>Overlays on {surface}</h1>
      {params.has('span') && <Span ui={ui} />}
      {params.has('mounttoast') && <MountToast ui={ui} />}
      <Feedback ui={ui} />
      {admin && <Modals admin={admin} openSibling={() => setSibling(true)} openLoose={() => setLoose(true)} />}
      {/* Room to scroll a control to the bottom edge, where the toast would sit. */}
      <div style={{ minHeight: '100vh' }} aria-hidden="true" />
      <Toasts ui={ui} where="bottom" />
    </main>
  );
  if (!admin) return <ToastProvider>{page}</ToastProvider>;
  const { Button, Modal, ModalProvider } = admin;
  return (
    <ToastProvider>
      <ModalProvider>{page}</ModalProvider>
      {/* A sibling provider, and a modal under no provider at all: one registry still rules. */}
      <ModalProvider>
        <Modal
          open={sibling}
          onClose={() => setSibling(false)}
          title="Sibling modal"
          data-testid="sibling-modal"
          footer={<Button onClick={() => setSibling(false)}>Cancel</Button>}
        >
          <p>This should never show over another modal.</p>
        </Modal>
      </ModalProvider>
      <Modal
        open={loose}
        onClose={() => setLoose(false)}
        title="Loose modal"
        data-testid="loose-modal"
        footer={<Button onClick={() => setLoose(false)}>Cancel</Button>}
      >
        <p>This should never show over another modal.</p>
      </Modal>
    </ToastProvider>
  );
}

function MountToast({ ui }: { ui: typeof UI }) {
  const toast = ui.useToast();
  // Runs before the provider's own mount effect.
  useEffect(() => toast('Welcome back'), [toast]);
  return null;
}

function Span({ ui }: { ui: typeof UI }) {
  const toast = ui.useToast();
  return (
    <textarea
      aria-label="Notes"
      data-testid="span"
      style={{ boxSizing: 'border-box', width: '100%', height: '100vh' }}
      onKeyDown={(event) => {
        if (event.key === 'Enter' && event.ctrlKey) toast('Saved');
      }}
    />
  );
}

function Toasts({ ui, where }: { ui: typeof UI; where: string }) {
  const { Button, useToast } = ui;
  const toast = useToast();
  const [rich, setRich] = useState('');
  // The bottom row is one Save, centred, right where the toast would sit.
  if (where === 'bottom') {
    return (
      <div style={{ ...row, justifyContent: 'center' }}>
        <Button data-testid="save-bottom" onClick={() => toast('Saved')}>
          Save
        </Button>
      </div>
    );
  }
  return (
    <div style={row}>
      <Button data-testid={`save-${where}`} onClick={() => toast('Saved')}>
        Save
      </Button>
      <Button data-testid={`update-${where}`} onClick={() => toast('Profile updated')}>
        Update profile
      </Button>
      <Button
        data-testid={`rich-${where}`}
        onClick={() => {
          // What a caller bypassing the types could pass: refused, never rendered.
          (toast as unknown as (value: unknown) => void)(<a href="/x">Undo</a>);
          setRich('refused');
        }}
      >
        Rich toast
      </Button>
      <span data-testid={`rich-result-${where}`}>{rich}</span>
    </div>
  );
}

function Feedback({ ui }: { ui: typeof UI }) {
  const { Banner, Button } = ui;
  const [later, setLater] = useState(false);
  const [timed, setTimed] = useState(false);
  const [retries, setRetries] = useState(0);
  const [submits, setSubmits] = useState(0);
  useEffect(() => {
    if (!params.has('timerbanner')) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const start = () => (timer = setTimeout(() => setTimed(true), 1500));
    if (document.readyState === 'complete') start();
    else window.addEventListener('load', start, { once: true });
    return () => {
      clearTimeout(timer);
      window.removeEventListener('load', start);
    };
  }, []);
  return (
    <Section id="feedback" title="Feedback">
      <Toasts ui={ui} where="top" />
      <form
        style={row}
        onSubmit={(event) => {
          event.preventDefault();
          setSubmits((n) => n + 1);
        }}
      >
        <label>
          Display name <input data-testid="form-input" defaultValue="Esm" />
        </label>
        <span data-testid="submits">{submits}</span>
      </form>
      {timed && (
        <Banner tone="warn" data-testid="banner-timed">
          Your session ends in 2 minutes.
        </Banner>
      )}
      <Banner tone="info" data-testid="banner-load-info">
        You have view-only access to this Tenant.
      </Banner>
      <Banner tone="warn" data-testid="banner-load-warn">
        Email provider not set.
      </Banner>
      <Banner tone="bad" data-testid="banner-load-bad" action={{ label: 'Retry', onClick: () => setRetries((n) => n + 1) }}>
        Service unavailable. Trace ID 4bf92f35.
      </Banner>
      <span data-testid="retries">{retries}</span>
      <div style={row}>
        <Button data-testid="show-banners" onClick={() => setLater(true)}>
          Show banners
        </Button>
      </div>
      {later && (
        <>
          <Banner tone="info" data-testid="banner-later-info">
            Draft kept until published.
          </Banner>
          <Banner tone="warn" data-testid="banner-later-warn">
            Your session ends in 2 minutes.
          </Banner>
          <Banner tone="bad" data-testid="banner-later-bad">
            Couldn't save. Your values are kept.
          </Banner>
        </>
      )}
    </Section>
  );
}

const ROWS = ['Row A', 'Row B', 'Row C'];

function Modals({ admin, openSibling, openLoose }: { admin: typeof Admin; openSibling: () => void; openLoose: () => void }) {
  const { Button, ConfirmModal, Field, Input, Modal, OneTimeReveal, useToast } = admin;
  const toast = useToast();
  const description = useRef<HTMLInputElement>(null);
  const [sticky, setSticky] = useState(false);
  const [long, setLong] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [pending, setPending] = useState(false);
  const [revokes, setRevokes] = useState(0);
  const [plain, setPlain] = useState(false);
  const [second, setSecond] = useState(false);
  const [confirms, setConfirms] = useState(0);
  const [rows, setRows] = useState(ROWS);
  const [deleting, setDeleting] = useState<string | null>(null);
  const fallback = useRef<string | null>(null);
  const [typed, setTyped] = useState(false);
  const [typedConfirms, setTypedConfirms] = useState(0);
  const [form, setForm] = useState(false);
  const [reveal, setReveal] = useState(false);
  const [secret, setSecret] = useState<string | null>(null);
  const issued = useRef(0);

  return (
    <>
      <Section id="modal" title="Modal">
        <div style={row}>
          <Button data-testid="open-confirm" onClick={() => setPlain(true)}>
            Block user
          </Button>
          <Button data-testid="open-form" onClick={() => setForm(true)}>
            Rename
          </Button>
          <Button data-testid="open-sticky" onClick={() => setSticky(true)}>
            Sticky
          </Button>
          <Button data-testid="open-long" onClick={() => setLong(true)}>
            Terms
          </Button>
          <Button data-testid="open-pending" onClick={() => setRevoking(true)}>
            Revoke key
          </Button>
          <span>
            Revoked: <span data-testid="revokes">{revokes}</span>
          </span>
          <span>
            Confirmed: <span data-testid="confirms">{confirms}</span>
          </span>
        </div>
        <ConfirmModal
          open={plain}
          title="Block user_007?"
          confirmLabel="Block"
          onCancel={() => setPlain(false)}
          onConfirm={() => {
            setConfirms((n) => n + 1);
            setPlain(false);
          }}
          reauthentication={<p data-testid="reauth-slot">Re-authentication goes here.</p>}
          data-testid="confirm-modal"
        >
          <p>They can't sign in until they're unblocked. Their Sessions end now.</p>
          <div style={row}>
            <Button data-testid="open-second" onClick={() => setSecond(true)}>
              Open another
            </Button>
            <Button data-testid="open-sibling" onClick={openSibling}>
              Open sibling
            </Button>
            <Button data-testid="open-loose" onClick={openLoose}>
              Open loose
            </Button>
            <Button data-testid="notify" onClick={() => toast('Saved')}>
              Notify
            </Button>
          </div>
        </ConfirmModal>
        <Modal
          open={second}
          onClose={() => setSecond(false)}
          title="Second modal"
          data-testid="second-modal"
          footer={<Button onClick={() => setSecond(false)}>Cancel</Button>}
        >
          <p>This should never show.</p>
        </Modal>
        <Modal
          open={form}
          onClose={() => setForm(false)}
          title="Rename application"
          data-testid="form-modal"
          initialFocus={() => description.current}
          footer={
            <>
              <Button onClick={() => setForm(false)}>Cancel</Button>
              <Button variant="primary" onClick={() => setForm(false)}>
                Save
              </Button>
            </>
          }
        >
          <Field label="Name">
            <Input defaultValue="Northwind web" />
          </Field>
          <Field label="Description">
            {/* Handles Esc itself, as an open listbox would: the modal stays open. */}
            <Input
              ref={description}
              onKeyDown={(event) => {
                if (event.key === 'Escape') event.preventDefault();
              }}
            />
          </Field>
        </Modal>
        {/* Its caller ignores onClose, so only Done closes it: a native close must still free the registry. */}
        <Modal
          open={sticky}
          onClose={() => {}}
          title="Sticky modal"
          data-testid="sticky-modal"
          footer={<Button onClick={() => setSticky(false)}>Done</Button>}
        >
          <p>Its caller keeps it open.</p>
        </Modal>
        <Modal
          open={long}
          onClose={() => setLong(false)}
          title="Terms of service"
          data-testid="long-modal"
          footer={
            <Button variant="primary" onClick={() => setLong(false)}>
              Accept
            </Button>
          }
        >
          {Array.from({ length: 30 }, (_, index) => (
            <p key={index}>Clause {index + 1}. The service is provided as is, and its operator keeps it running.</p>
          ))}
        </Modal>
        <ConfirmModal
          open={revoking}
          title="Revoke signing key?"
          confirmLabel="Revoke"
          tone="destructive"
          pending={pending}
          onCancel={() => setRevoking(false)}
          onConfirm={() => {
            setRevokes((n) => n + 1);
            setPending(true);
          }}
          data-testid="pending-modal"
        >
          <p>Tokens it signed stop working.</p>
          <Button
            data-testid="finish"
            onClick={() => {
              setPending(false);
              setRevoking(false);
            }}
          >
            Finish
          </Button>
        </ConfirmModal>
      </Section>

      <Section id="rows" title="Rows">
        <ul style={{ ...column, margin: 0, padding: 0, listStyle: 'none' }}>
          {rows.map((name) => (
            <li key={name} style={row} data-row={name}>
              <span>{name}</span>
              <Button variant="destructive" size="sm" data-testid={`delete-${name}`} onClick={() => setDeleting(name)}>
                Delete {name}
              </Button>
            </li>
          ))}
        </ul>
        <ConfirmModal
          open={deleting !== null}
          tone="destructive"
          title={`Delete ${deleting ?? ''}?`}
          confirmLabel="Delete"
          onCancel={() => setDeleting(null)}
          fallbackFocus={() =>
            fallback.current === null ? null : document.querySelector<HTMLElement>(`[data-row="${fallback.current}"] button`)
          }
          onConfirm={() => {
            const index = rows.indexOf(deleting!);
            fallback.current = rows[index + 1] ?? null;
            setRows(rows.filter((name) => name !== deleting));
            setDeleting(null);
          }}
          data-testid="delete-modal"
        >
          <p>Its tokens stop working at once. This can't be undone.</p>
        </ConfirmModal>
      </Section>

      <Section id="typed" title="Typed confirmation">
        <div style={row}>
          <Button variant="destructive" data-testid="open-typed" onClick={() => setTyped(true)}>
            Delete Tenant
          </Button>
          <span>
            Deleted: <span data-testid="typed-confirms">{typedConfirms}</span>
          </span>
        </div>
        <ConfirmModal
          open={typed}
          tone="destructive"
          title="Delete Tenant northwind?"
          confirmLabel="Delete Tenant"
          confirmText="northwind"
          confirmTextLabel="Tenant subdomain"
          onCancel={() => setTyped(false)}
          onConfirm={() => {
            setTypedConfirms((n) => n + 1);
            setTyped(false);
          }}
          data-testid="typed-modal"
        >
          <p>Every User, Application and key in northwind is deleted.</p>
        </ConfirmModal>
      </Section>

      <Section id="reveal" title="One-time reveal">
        <div style={row}>
          <Button
            data-testid="create-secret"
            onClick={() => {
              issued.current += 1;
              setSecret(`gks_${issued.current}_7Hq2xV9pLm4R`);
              setReveal(true);
            }}
          >
            Create secret
          </Button>
          <Button data-testid="reopen-reveal" onClick={() => setReveal(true)}>
            Show again
          </Button>
        </div>
        <OneTimeReveal
          open={reveal}
          onClose={() => setReveal(false)}
          title="Client secret"
          what="client secret"
          value={secret}
          data-testid="reveal-modal"
        >
          <p>Use it in your server's configuration.</p>
        </OneTimeReveal>
      </Section>
    </>
  );
}
