// Renders the @gatekeep/ui fixture on one surface: `?surface=admin` (the default) or
// `?surface=hosted`, and `?scheme=light` (the default) or `?scheme=dark`. `?page=data` shows
// the data display (Story 1.15), `?page=overlay` the overlays and feedback (Story 1.16) and
// `?page=drawer` the drawer and menu (Story 1.17) instead of the controls (Story 1.14). The
// surface and scheme go on <html>, as an app sets them, and the components come from that
// surface's own entry point; the drawer page is Admin only, as its components are.

import '@gatekeep/ui/styles.css';
import * as admin from '@gatekeep/ui/admin';
import * as hosted from '@gatekeep/ui/hosted';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { DataFixture } from './DataFixture';
import { DrawerFixture } from './DrawerFixture';
import { Fixture } from './Fixture';
import { OverlayFixture } from './OverlayFixture';

const params = new URLSearchParams(location.search);
const scheme = params.get('scheme') === 'dark' ? 'dark' : 'light';
const pages = ['data', 'overlay', 'drawer'] as const;
const page = pages.find((name) => name === params.get('page')) ?? 'controls';
// The drawer page's components are Admin only, so it's always on the Admin surface.
const surface = page !== 'drawer' && params.get('surface') === 'hosted' ? 'hosted' : 'admin';

document.documentElement.dataset.gkSurface = surface;
document.documentElement.dataset.gkScheme = scheme;
// The toast's duration, for the tests to read rather than repeat.
document.documentElement.dataset.toastMs = String(hosted.TOAST_MS);

// One component serves both surfaces: everything the hosted entry exports, the admin entry
// exports as the very same module. The admin entry adds only its own data display and modals.
const hostedExports = hosted as unknown as Record<string, unknown>;
const adminExports = admin as unknown as Record<string, unknown>;
const names = Object.keys(hostedExports);
// The admin entry's own exports, exactly: anything else it gains fails the check.
const ADMIN_ONLY = [
  'ConfirmModal',
  'DataTable',
  'Drawer',
  'EmptyState',
  'EventDrawer',
  'JsonViewer',
  'Menu',
  'Modal',
  'ModalProvider',
  'OneTimeReveal',
  'PAGE_SIZE',
  'RbacMatrix',
  'SKELETON_DELAY_MS',
  'SettingsRow',
  'SkeletonRows',
  'StatTile',
  'Tabs',
  'UsageBar',
  'useUrlTab',
];
const expected = [...names, ...ADMIN_ONLY].sort();
const actual = Object.keys(adminExports).sort();
const same =
  names.length > 0 &&
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
    {page === 'drawer' ? (
      <DrawerFixture admin={admin} />
    ) : page === 'overlay' ? (
      <OverlayFixture surface={surface} ui={surface === 'hosted' ? hosted : admin} admin={surface === 'admin' ? admin : null} />
    ) : page === 'data' ? (
      <DataFixture surface={surface} ui={surface === 'hosted' ? hosted : admin} admin={surface === 'admin' ? admin : null} />
    ) : (
      <Fixture surface={surface} scheme={scheme} ui={surface === 'hosted' ? hosted : admin} />
    )}
  </StrictMode>,
);
