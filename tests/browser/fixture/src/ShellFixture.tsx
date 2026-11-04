// The Admin shell fixture (Story 1.25), at `?page=shell`: AdminShell with its TopBar, a Sidebar
// holding sample items in every group, and a SectionPage with long content and an input, so
// shell.spec.ts can drive the layout, the sidebar's gating and semantics, the top bar, focus on
// navigation and the banner slot. Admin only, so it always renders from @gatekeep/ui/admin.
// `&omit=branding` leaves a group with no item.

import type * as Admin from '@gatekeep/ui/admin';
import { useState, type CSSProperties } from 'react';

const params = new URLSearchParams(location.search);
const omit = params.get('omit');

const SAMPLE: Admin.AdminNavItem[] = [
  { group: 'deployment', label: 'Tenants', href: '/deployment/tenants' },
  { group: 'deployment', label: 'Admins', href: '/deployment/admins' },
  { group: 'applications', label: 'Applications', href: '/tenants/ten_a/applications' },
  { group: 'applications', label: 'APIs', href: '/tenants/ten_a/apis' },
  { group: 'authentication', label: 'Database', href: '/tenants/ten_a/connections/database' },
  { group: 'users', label: 'Users', href: '/tenants/ten_a/users' },
  { group: 'authorization', label: 'Roles', href: '/tenants/ten_a/roles' },
  { group: 'security', label: 'Multi-factor auth', href: '/tenants/ten_a/mfa' },
  { group: 'branding', label: 'Universal Login', href: '/tenants/ten_a/branding' },
  { group: 'monitoring', label: 'Logs', href: '/tenants/ten_a/logs' },
  { group: 'settings', label: 'Tenant', href: '/tenants/ten_a/settings' },
];

const column: CSSProperties = { display: 'flex', flexDirection: 'column', gap: 'var(--gk-space-12)' };

/** What the fixture records for the tests to read. */
declare global {
  interface Window {
    gkShell?: { navigated: string[]; toggles: number; signOuts: number };
    /** Sets or clears the banner slot without moving focus, as a Session expiry would. */
    gkShellBanner?: (shown: boolean) => void;
  }
}

export function ShellFixture({ admin }: { admin: typeof Admin }) {
  const record = (window.gkShell ??= { navigated: [], toggles: 0, signOuts: 0 });
  const items = SAMPLE.filter((item) => item.group !== omit);
  const [current, setCurrent] = useState('/tenants/ten_a/users');
  const [dark, setDark] = useState(document.documentElement.dataset.gkScheme === 'dark');
  const [banner, setBanner] = useState(false);
  const title = SAMPLE.find((item) => item.href === current)?.label ?? 'Page';
  window.gkShellBanner = setBanner;

  function navigate(href: string) {
    record.navigated.push(href);
    setCurrent(href);
  }

  function toggle() {
    record.toggles += 1;
    const next = !dark;
    setDark(next);
    document.documentElement.dataset.gkScheme = next ? 'dark' : 'light';
  }

  return (
    <admin.AdminShell
      data-testid="shell"
      pageKey={current}
      topBar={
        <admin.TopBar
          onBrandNavigate={navigate}
          dark={dark}
          onToggleTheme={toggle}
          accountItems={[{ label: 'Sign out', onSelect: () => (record.signOuts += 1) }]}
        />
      }
      sidebar={<admin.Sidebar items={items} currentHref={current} onNavigate={navigate} data-testid="sidebar" />}
      banner={
        banner ? (
          <admin.Banner tone="warn" live data-testid="fixture-banner">
            Your session expired. Sign in to continue. Nothing you entered has been lost.
          </admin.Banner>
        ) : null
      }
    >
      <admin.SectionPage
        eyebrow="User management"
        title={title}
        description="Everyone who can sign in to this Tenant's Applications."
        actions={<admin.Button variant="primary">Create user</admin.Button>}
        data-testid="section"
      >
        <div style={column}>
          <admin.Field label="Unsaved value">
            <admin.Input data-testid="unsaved" />
          </admin.Field>
          <div style={{ display: 'flex', gap: 'var(--gk-space-8)' }}>
            <admin.Button data-testid="set-banner" onClick={() => setBanner(true)}>
              Set banner
            </admin.Button>
            <admin.Button data-testid="clear-banner" onClick={() => setBanner(false)}>
              Clear banner
            </admin.Button>
          </div>
        </div>
        <div style={column} data-testid="long">
          {Array.from({ length: 60 }, (_, index) => (
            <p key={index} style={{ margin: 0 }}>
              Line {index + 1} of long content, so the main area scrolls while the window doesn't.
            </p>
          ))}
        </div>
      </admin.SectionPage>
    </admin.AdminShell>
  );
}
