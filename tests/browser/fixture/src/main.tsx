// Renders every @gatekeep/ui control on one surface: `?surface=admin` (the default) or
// `?surface=hosted`, and `?scheme=light` (the default) or `?scheme=dark`. The surface and
// scheme go on <html>, as an app sets them, and the controls come from that surface's own
// entry point.

import '@gatekeep/ui/styles.css';
import * as admin from '@gatekeep/ui/admin';
import * as hosted from '@gatekeep/ui/hosted';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Fixture } from './Fixture';

const params = new URLSearchParams(location.search);
const surface = params.get('surface') === 'hosted' ? 'hosted' : 'admin';
const scheme = params.get('scheme') === 'dark' ? 'dark' : 'light';

document.documentElement.dataset.gkSurface = surface;
document.documentElement.dataset.gkScheme = scheme;

// One component serves both surfaces: the two entry points export the same modules.
const hostedExports = hosted as unknown as Record<string, unknown>;
const adminExports = admin as unknown as Record<string, unknown>;
const names = Object.keys(hostedExports);
const same =
  names.length === Object.keys(adminExports).length &&
  names.every((name) => name in adminExports && adminExports[name] === hostedExports[name]);
document.documentElement.dataset.sameModules = String(same);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Fixture surface={surface} scheme={scheme} ui={surface === 'hosted' ? hosted : admin} />
  </StrictMode>,
);
