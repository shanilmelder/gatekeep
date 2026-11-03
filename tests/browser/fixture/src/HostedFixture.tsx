// The Hosted building blocks and screens fixture (Story 1.18), at `?page=hosted`. Every
// component comes from @gatekeep/ui/hosted, and the screen from @gatekeep/hosted-screens;
// only the registry checks take Modal and Drawer from @gatekeep/ui/admin.
//
//   &screen=error (the default)  Generic error, as Hosted Login serves it. &back=none leaves
//                                out the Application to go back to.
//   &screen=kit                  A card with the social row, an input, a password field and
//                                the session-expiry alert dialog. &providers=N (0 to 4) or
//                                &providers=dupe sets the row. &alertFocus=secondary,
//                                &dismissible=false and &fallback=email set the dialog up.
//   &screen=status               The four status icons, and one with an unknown status.
//   &scheme=auto|light|dark      The page's scheme. Left out, HostedPage's own default.
//   &theme=custom|plain          The test-only Tenant themes in hosted-theme.css.
//   &logo=image|broken           The Tenant's logo image, or one that fails to load.
//   &tenant=blank|bidi|emoji     An unusual Tenant name. &initial=X sets the initial.
//   &frame=preview               The screen inside an Admin page, in a forced-scheme preview
//                                scope, as the theme preview (Story 15.2) will place it.
//   &root=admin                  <html> left on the Admin surface and light, as an app that
//                                forgot to set it would, with a HostedPage inside.

import { GenericErrorScreen } from '@gatekeep/hosted-screens';
import type * as Admin from '@gatekeep/ui/admin';
import type * as UI from '@gatekeep/ui/hosted';
import { useEffect, useRef, useState } from 'react';
import './hosted-theme.css';
import logoUrl from './logo.svg';

/** The fixture's trace ID and code, which tests compare the clipboard and the page against. */
export const TRACE_ID = '7f2c9a1e4b3d';
export const ERROR_CODE = 'invalid_request';

const PROVIDERS: UI.SocialProvider[] = [
  { id: 'google', name: 'Google' },
  { id: 'github', name: 'GitHub' },
  { id: 'microsoft', name: 'Microsoft' },
];
/** A fourth, only for the more-than-three case. */
const FOURTH: UI.SocialProvider = { id: 'gitlab', name: 'GitLab' };

const NAMES: Record<string, string> = { blank: '   ', bidi: '‮acme', emoji: '👩‍💻 Labs' };

export type HostedScheme = 'auto' | 'light' | 'dark';

export interface HostedFixtureProps {
  ui: typeof UI;
  admin: typeof Admin;
  /** The page's scheme, or undefined for HostedPage's own default. */
  scheme: HostedScheme | undefined;
  /** Whether the screen sits in an Admin page's preview scope instead of a HostedPage. */
  preview: boolean;
}

/** Hooks the tests call to open dialogs while another holds the registry, which no click can do. */
declare global {
  interface Window {
    gkHosted?: { openAlert: () => void; openModal: () => void; openDrawer: () => void };
  }
}

function providersFor(param: string | null): UI.SocialProvider[] {
  if (param === 'dupe') return [PROVIDERS[0]!, PROVIDERS[1]!, PROVIDERS[0]!];
  const count = Math.min(4, Math.max(0, Number(param ?? '3') || 0));
  return [...PROVIDERS, FOURTH].slice(0, count);
}

function Kit({ ui, admin, tenant, headingLevel }: { ui: typeof UI; admin: typeof Admin; tenant: UI.HostedTenant; headingLevel: 1 | 2 }) {
  const params = new URLSearchParams(location.search);
  const [open, setOpen] = useState(false);
  const [modal, setModal] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const [once, setOnce] = useState(true);
  const [selected, setSelected] = useState('');
  const [pending, setPending] = useState<string | undefined>(undefined);
  const [selects, setSelects] = useState(0);
  const [actions, setActions] = useState(0);
  const secondary = useRef<HTMLButtonElement>(null);
  const email = useRef<HTMLInputElement>(null);
  const close = () => setOpen(false);

  useEffect(() => {
    window.gkHosted = { openAlert: () => setOpen(true), openModal: () => setModal(true), openDrawer: () => setDrawer(true) };
    return () => {
      delete window.gkHosted;
    };
  }, []);

  return (
    <ui.HostedCard
      tenant={tenant}
      headingLevel={headingLevel}
      title={`Sign in to ${tenant.name}`}
      subtitle="Use your work email address."
      data-testid="kit"
      action={
        <ui.Button variant="primary" type="submit" form="kit-form" data-testid="continue">
          Continue
        </ui.Button>
      }
      link={
        <a href="#help" data-testid="help">
          Need help signing in?
        </a>
      }
    >
      <ui.SocialButtons
        providers={providersFor(params.get('providers'))}
        pendingId={pending}
        onSelect={(id) => {
          setSelects((count) => count + 1);
          setSelected(id);
          // Pending on press: the redirect is under way.
          setPending(id);
        }}
        data-testid="social"
      />
      <form id="kit-form" noValidate onSubmit={(event) => event.preventDefault()} style={{ display: 'contents' }}>
        <ui.Field label="Email address">
          <ui.Input ref={email} type="email" autoComplete="email" placeholder="you@example.com" data-testid="email" />
        </ui.Field>
        <ui.PasswordField label="Password" data-testid="password" />
      </form>
      <ui.Button data-testid="open-alert" onClick={() => setOpen(true)}>
        Show expiry warning
      </ui.Button>
      {once && (
        <ui.Button
          data-testid="open-alert-once"
          onClick={() => {
            setOpen(true);
            setOnce(false);
          }}
        >
          Warn once
        </ui.Button>
      )}
      <ui.Button data-testid="long">Continue with a one-time code sent to your email address</ui.Button>
      <p data-testid="selected" style={{ margin: 0 }} hidden={selected === ''}>
        {selected}
      </p>
      <p data-testid="selects" hidden>
        {selects}
      </p>
      <p data-testid="actions" hidden>
        {actions}
      </p>
      <p data-testid="dialogs" hidden>
        {`alert:${open ? 'open' : 'closed'} modal:${modal ? 'open' : 'closed'} drawer:${drawer ? 'open' : 'closed'}`}
      </p>
      <ui.AlertDialog
        open={open}
        title="Your session is about to end"
        actionLabel="Keep going"
        onAction={() => {
          setActions((count) => count + 1);
          close();
        }}
        onClose={close}
        dismissible={params.get('dismissible') !== 'false'}
        initialFocus={params.get('alertFocus') === 'secondary' ? () => secondary.current : undefined}
        fallbackFocus={params.get('fallback') === 'email' ? () => email.current : undefined}
        secondary={
          <ui.Button ref={secondary} onClick={close}>
            Start over
          </ui.Button>
        }
        data-testid="alert"
      >
        <p>For your security, this sign-in ends in 2 minutes. Keep going to stay on this step.</p>
      </ui.AlertDialog>
      <admin.Modal open={modal} onClose={() => setModal(false)} title="Registry modal" data-testid="registry-modal" footer={<ui.Button onClick={() => setModal(false)}>Close modal</ui.Button>}>
        <p>A modal holding the registry.</p>
      </admin.Modal>
      <admin.Drawer open={drawer} onClose={() => setDrawer(false)} title="Registry drawer" data-testid="registry-drawer">
        <p>A drawer holding the registry.</p>
      </admin.Drawer>
    </ui.HostedCard>
  );
}

function Statuses({ ui, tenant, headingLevel }: { ui: typeof UI; tenant: UI.HostedTenant; headingLevel: 1 | 2 }) {
  const statuses = ['success', 'warning', 'error', 'blocked'] as const;
  return (
    <ui.HostedCard tenant={tenant} headingLevel={headingLevel} title="Status icons" data-testid="statuses">
      <div style={{ display: 'flex', gap: 'var(--gk-space-8)', justifyContent: 'center' }}>
        {statuses.map((status) => (
          <ui.StatusIcon key={status} status={status} data-testid={`status-${status}`} />
        ))}
        {/* An untyped caller's unknown status, named after an Object.prototype key. */}
        <ui.StatusIcon status={'toString' as UI.StatusIconStatus} data-testid="status-unknown" />
      </div>
    </ui.HostedCard>
  );
}

export function HostedFixture({ ui, admin, scheme, preview }: HostedFixtureProps) {
  const params = new URLSearchParams(location.search);
  const themeParam = params.get('theme');
  const theme = themeParam === 'custom' || themeParam === 'plain' ? themeParam : undefined;
  const name = NAMES[params.get('tenant') ?? ''] ?? 'Northwind';
  const logo = params.get('logo');
  const tenant: UI.HostedTenant = {
    name,
    ...(logo === 'image' ? { logo: logoUrl } : logo === 'broken' ? { logo: '/no-such-logo.png' } : {}),
    ...(params.has('initial') ? { initial: params.get('initial') ?? '' } : {}),
  };
  // Inside the preview the Admin page holds the h1, so the card's heading is an h2.
  const headingLevel = preview ? 2 : 1;

  const screenParam = params.get('screen');
  const screen =
    screenParam === 'kit' ? (
      <Kit ui={ui} admin={admin} tenant={tenant} headingLevel={headingLevel} />
    ) : screenParam === 'status' ? (
      <Statuses ui={ui} tenant={tenant} headingLevel={headingLevel} />
    ) : (
      <GenericErrorScreen
        tenant={tenant}
        code={ERROR_CODE}
        traceId={TRACE_ID}
        backHref={params.get('back') === 'none' ? undefined : '/?page=hosted&back=1'}
        headingLevel={headingLevel}
        data-testid="generic-error"
      />
    );

  if (preview) {
    // An Admin page holding the preview: its own light Admin frame, and a Hosted scope with a
    // forced scheme inside it. No HostedPage: the preview is the frame.
    return (
      <main style={{ display: 'flex', flexDirection: 'column', gap: 'var(--gk-space-16)', padding: 'var(--gk-space-page-padding)' }}>
        <h1 style={{ font: 'var(--gk-font-page-title)', margin: 0 }}>Theme preview</h1>
        <div
          data-gk-surface="hosted"
          data-gk-scheme={scheme ?? 'light'}
          data-gk-theme={theme}
          data-testid="preview"
          style={{ display: 'flex', justifyContent: 'center', padding: 'var(--gk-space-32) var(--gk-space-16)', background: 'var(--gk-color-bg)' }}
        >
          {screen}
        </div>
      </main>
    );
  }

  return (
    <ui.HostedPage scheme={scheme} theme={theme} data-testid="hosted-page">
      {screen}
    </ui.HostedPage>
  );
}
