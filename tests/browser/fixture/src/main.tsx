// Renders the @gatekeep/ui fixture on one surface: `?surface=admin` (the default) or
// `?surface=hosted`, and `?scheme=light` (the default) or `?scheme=dark`. `?page=data` shows
// the data display (Story 1.15), `?page=overlay` the overlays and feedback (Story 1.16) and
// `?page=drawer` the drawer and menu (Story 1.17) instead of the controls (Story 1.14). The
// surface and scheme go on <html>, as an app sets them, and the components come from that
// surface's own entry point; the drawer page is Admin only, as its components are.
// `?page=hosted` shows the Hosted building blocks and screens (Story 1.18), always from the
// hosted entry; its scheme may also be `auto`, its default, and HostedFixture reads the rest.
// `?page=shell` shows the Admin shell (Story 1.25), Admin only like the drawer page.

import '@gatekeep/ui/styles.css';
import * as admin from '@gatekeep/ui/admin';
import * as hosted from '@gatekeep/ui/hosted';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { DataFixture } from './DataFixture';
import { DrawerFixture } from './DrawerFixture';
import { Fixture } from './Fixture';
import { HostedFixture } from './HostedFixture';
import { OverlayFixture } from './OverlayFixture';
import { ShellFixture } from './ShellFixture';

const params = new URLSearchParams(location.search);
const pages = ['data', 'overlay', 'drawer', 'hosted', 'shell'] as const;
const page = pages.find((name) => name === params.get('page')) ?? 'controls';
const asked = params.get('scheme');
const scheme = asked === 'dark' ? 'dark' : page === 'hosted' && asked !== 'light' ? 'auto' : 'light';
// The hosted page passes the scheme it was asked for, or none, so HostedPage's own default runs.
const hostedScheme = asked === 'dark' || asked === 'light' || asked === 'auto' ? asked : undefined;
// The hosted page's preview frame is an Admin page holding a Hosted scope, and &root=admin
// leaves <html> on the Admin surface and light around a HostedPage.
const preview = page === 'hosted' && params.get('frame') === 'preview';
const adminRoot = preview || (page === 'hosted' && params.get('root') === 'admin');
// The drawer page's components are Admin only, so it's always on the Admin surface, and the
// hosted page's are on the Hosted surface, except with an Admin root.
const surface =
  page === 'hosted'
    ? adminRoot
      ? 'admin'
      : 'hosted'
    : page !== 'drawer' && page !== 'shell' && params.get('surface') === 'hosted'
      ? 'hosted'
      : 'admin';

document.documentElement.dataset.gkSurface = surface;
// An Admin root stays light: only the Hosted scope inside it takes the scheme.
document.documentElement.dataset.gkScheme = adminRoot ? 'light' : scheme;
// The toast's duration, for the tests to read rather than repeat.
document.documentElement.dataset.toastMs = String(hosted.TOAST_MS);

// One component serves both surfaces: everything the hosted entry exports, the admin entry
// exports as the very same module. The admin entry adds only its own data display and modals.
const hostedExports = hosted as unknown as Record<string, unknown>;
const adminExports = admin as unknown as Record<string, unknown>;
const names = Object.keys(hostedExports);
// The hosted entry's exports, exactly: anything it gains or loses fails the check.
const HOSTED = [
  'AlertDialog',
  'Banner',
  'Button',
  'ButtonLink',
  'COPIED_MS',
  'Checkbox',
  'CodeBadge',
  'CodeBlock',
  'CopyButton',
  'DraftBadge',
  'EnvironmentBadge',
  'ErrorReference',
  'Field',
  'HostedCard',
  'HostedPage',
  'Input',
  'MessagesProvider',
  'PasswordField',
  'ProtocolBadge',
  'Radio',
  'RadioGroup',
  'SOCIAL_MAX',
  'Segmented',
  'Select',
  'SocialButtons',
  'StatusBadge',
  'StatusIcon',
  'TOAST_MS',
  'Textarea',
  'ToastProvider',
  'Toggle',
  'defaultMessages',
  'formatMessage',
  'useFieldControl',
  'useMessages',
  'useToast',
];
// The admin entry's own exports, exactly: anything else it gains fails the check.
const ADMIN_ONLY = [
  'ADMIN_NAV_GROUPS',
  'AdminShell',
  'ConfirmModal',
  'DataTable',
  'Drawer',
  'EmptyState',
  'EventDrawer',
  'JsonViewer',
  'KeyStateBadge',
  'Menu',
  'Modal',
  'ModalProvider',
  'OneTimeReveal',
  'PAGE_SIZE',
  'RbacMatrix',
  'SectionPage',
  'SKELETON_DELAY_MS',
  'SettingsRow',
  'Sidebar',
  'SkeletonRows',
  'StatTile',
  'Tabs',
  'ThemeToggle',
  'TopBar',
  'UsageBar',
  'useMediaQuery',
  'useUrlTab',
];
const expected = [...names, ...ADMIN_ONLY].sort();
const actual = Object.keys(adminExports).sort();
const hostedSorted = [...names].sort();
const same =
  hostedSorted.length === HOSTED.length &&
  [...HOSTED].sort().every((name, index) => name === hostedSorted[index]) &&
  names.every((name) => name in adminExports && adminExports[name] === hostedExports[name]) &&
  actual.length === expected.length &&
  actual.every((name, index) => name === expected[index]);
document.documentElement.dataset.sameModules = String(same);
document.documentElement.dataset.hostedExports = [...names].sort().join(' ');
document.documentElement.dataset.adminOnlyExports = Object.keys(adminExports)
  .filter((name) => !(name in hostedExports))
  .sort()
  .join(' ');

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {page === 'shell' ? (
      <ShellFixture admin={admin} />
    ) : page === 'hosted' ? (
      <HostedFixture ui={hosted} admin={admin} scheme={hostedScheme} preview={preview} />
    ) : page === 'drawer' ? (
      <DrawerFixture admin={admin} />
    ) : page === 'overlay' ? (
      <OverlayFixture surface={surface} ui={surface === 'hosted' ? hosted : admin} admin={surface === 'admin' ? admin : null} />
    ) : page === 'data' ? (
      <DataFixture surface={surface} ui={surface === 'hosted' ? hosted : admin} admin={surface === 'admin' ? admin : null} />
    ) : (
      <Fixture surface={surface} scheme={scheme === 'dark' ? 'dark' : 'light'} ui={surface === 'hosted' ? hosted : admin} />
    )}
  </StrictMode>,
);
