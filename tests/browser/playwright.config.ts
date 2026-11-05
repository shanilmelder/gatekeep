// Browser tests for the built surfaces, run in the tests container. Chromium is the one the
// tests image installed at build time, at the version the catalog pins, so nothing is
// downloaded here.
//
// Story 1.13: each app's built dist is served by `vite preview` on a local port, the way the
// Deployment serves it: from its own origin (surfaces.spec.ts).
// Story 1.14: the shared controls fixture's dist is served the same way (controls.spec.ts).
// Story 1.15: the data display is served from the same fixture build at ?page=data (data.spec.ts).
// Story 1.16: the overlays and feedback, from the same build at ?page=overlay (overlay.spec.ts).
// Story 1.17: the drawer and menu, from the same build at ?page=drawer (drawer.spec.ts).
// Story 1.18: the Hosted building blocks and screens, from the same build at ?page=hosted
// (hosted.spec.ts).
// Story 1.20: the built Admin Dashboard is also served by the built Host.Admin itself, because
// the CSP and the other AD-21 headers under test are the host's own (admin-csp.spec.ts).
// Story 1.21: the Bootstrap screen on that same host, with its API intercepted (bootstrap.spec.ts).
// Story 1.22: credential setup on that same host, with a virtual authenticator (credential-setup.spec.ts).
// Story 1.23: Admin sign-in and sign-out on that same host, with a virtual authenticator (signin.spec.ts).
// Story 1.25: the Admin shell's parts, from the fixture build at ?page=shell (shell.spec.ts), and
// the shell itself on that same host, with its API intercepted and a virtual authenticator for
// Session renewal (admin-shell.spec.ts).
// Story 1.26: Your credentials and the re-authentication gate (admin-credentials.spec.ts), and
// Admin Recovery Codes (admin-recovery.spec.ts), on that same host.
// Story 1.27: creating and listing Tenants, with Session renewal on a real form (admin-tenants.spec.ts), on that same host.
// Story 1.28: the Tenant switcher, the landing rules, Tenant settings' environment and the mismatch banner (admin-tenant-switcher.spec.ts), on that same host.
// Story 1.29: deleting a Tenant, retrying its deletion and the lost-Tenant banner (admin-tenant-delete.spec.ts), on that same host.

import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from '@playwright/test';

const here = path.dirname(fileURLToPath(import.meta.url));

const surfaces = [
  { name: 'hosted-login', port: 4310 },
  { name: 'admin-dashboard', port: 4311 },
];
const fixture = { name: 'controls', port: 4312 };

const adminHost = { port: 4313, healthPort: 4314 };

const built = [
  ...surfaces.map(({ name }) => `../../apps/${name}/dist/index.html`),
  'fixture/dist/index.html',
];
for (const file of built) {
  if (!existsSync(path.join(here, file))) {
    throw new Error(`${path.relative(path.join(here, '../..'), path.join(here, file))} is missing: build first (pnpm -r build).`);
  }
}

export default defineConfig({
  testDir: '.',
  forbidOnly: true,
  retries: 0,
  reporter: [['list']],
  use: { browserName: 'chromium', headless: true },
  projects: [
    ...surfaces.map(({ name, port }) => ({
      name,
      // Every spec that isn't another project's own, so a new spec runs by default.
      testMatch: '*.spec.ts',
      testIgnore: ['admin-csp.spec.ts', 'bootstrap.spec.ts', 'credential-setup.spec.ts', 'signin.spec.ts', 'controls.spec.ts', 'data.spec.ts', 'overlay.spec.ts', 'drawer.spec.ts', 'hosted.spec.ts', 'shell.spec.ts', 'admin-shell.spec.ts', 'admin-credentials.spec.ts', 'admin-recovery.spec.ts', 'admin-tenants.spec.ts', 'admin-tenant-switcher.spec.ts', 'admin-tenant-delete.spec.ts'],
      use: { baseURL: `http://127.0.0.1:${port}` },
    })),
    { name: fixture.name, testMatch: 'controls.spec.ts', use: { baseURL: `http://127.0.0.1:${fixture.port}` } },
    // The data display (Story 1.15), on the same fixture build at ?page=data.
    { name: 'data', testMatch: 'data.spec.ts', use: { baseURL: `http://127.0.0.1:${fixture.port}` } },
    // The overlays and feedback (Story 1.16), on the same fixture build at ?page=overlay.
    { name: 'overlay', testMatch: 'overlay.spec.ts', use: { baseURL: `http://127.0.0.1:${fixture.port}` } },
    // The drawer and menu (Story 1.17), on the same fixture build at ?page=drawer.
    { name: 'drawer', testMatch: 'drawer.spec.ts', use: { baseURL: `http://127.0.0.1:${fixture.port}` } },
    // The Hosted building blocks and screens (Story 1.18), on the same fixture build at ?page=hosted.
    { name: 'hosted', testMatch: 'hosted.spec.ts', use: { baseURL: `http://127.0.0.1:${fixture.port}` } },
    // The Admin shell's parts (Story 1.25), on the same fixture build at ?page=shell.
    { name: 'shell', testMatch: 'shell.spec.ts', use: { baseURL: `http://127.0.0.1:${fixture.port}` } },
    {
      name: 'admin-host',
      testMatch: 'admin-csp.spec.ts',
      use: { baseURL: `http://127.0.0.1:${adminHost.port}` },
    },
    // The Bootstrap screen (Story 1.21), on the same built Host.Admin, its API answered by route interception.
    {
      name: 'bootstrap',
      testMatch: 'bootstrap.spec.ts',
      use: { baseURL: `http://127.0.0.1:${adminHost.port}` },
    },
    // Admin credential setup (Story 1.22), on the same host with its API intercepted, from
    // localhost: WebAuthn takes no IP address as an RP ID. A Chromium virtual authenticator
    // answers the browser's own passkey sheet.
    {
      name: 'credential-setup',
      testMatch: 'credential-setup.spec.ts',
      use: { baseURL: `http://localhost:${adminHost.port}` },
    },
    // Admin sign-in and sign-out (Story 1.23), the same way: from localhost, with a virtual
    // authenticator holding a resident credential.
    {
      name: 'signin',
      testMatch: 'signin.spec.ts',
      use: { baseURL: `http://localhost:${adminHost.port}` },
    },
    // The Admin shell (Story 1.25), the same way: from localhost, with a virtual authenticator
    // answering Session renewal's sheet.
    {
      name: 'admin-shell',
      testMatch: 'admin-shell.spec.ts',
      use: { baseURL: `http://localhost:${adminHost.port}` },
    },
    // Your credentials and the re-authentication gate (Story 1.26), the same way: from localhost,
    // with a virtual authenticator answering both sheets.
    {
      name: 'admin-credentials',
      testMatch: 'admin-credentials.spec.ts',
      use: { baseURL: `http://localhost:${adminHost.port}` },
    },
    // Admin Recovery Codes (Story 1.26): the entry on sign-in and the display at setup, from localhost.
    {
      name: 'admin-recovery',
      testMatch: 'admin-recovery.spec.ts',
      use: { baseURL: `http://localhost:${adminHost.port}` },
    },
    // Creating and listing Tenants (Story 1.27), from localhost, with a virtual authenticator
    // answering the Session renewal a real form's POST meets.
    {
      name: 'admin-tenants',
      testMatch: 'admin-tenants.spec.ts',
      use: { baseURL: `http://localhost:${adminHost.port}` },
    },
    // Switching Tenants and the environment label (Story 1.28), from localhost, with a virtual
    // authenticator answering the Prod removal's sheet.
    {
      name: 'admin-tenant-switcher',
      testMatch: 'admin-tenant-switcher.spec.ts',
      use: { baseURL: `http://localhost:${adminHost.port}` },
    },
    // Deleting a Tenant and the lost-Tenant banner (Story 1.29), from localhost, with a virtual
    // authenticator answering the deletion's sheet.
    {
      name: 'admin-tenant-delete',
      testMatch: 'admin-tenant-delete.spec.ts',
      use: { baseURL: `http://localhost:${adminHost.port}` },
    },
  ],
  webServer: [
    ...surfaces.map(({ name, port }) => ({
      command: `pnpm --dir ../../apps/${name} exec vite preview --host 127.0.0.1 --port ${port} --strictPort`,
      url: `http://127.0.0.1:${port}/`,
      reuseExistingServer: false,
      timeout: 60_000,
    })),
    {
      command: `pnpm exec vite preview --config fixture/vite.config.ts --host 127.0.0.1 --port ${fixture.port} --strictPort`,
      url: `http://127.0.0.1:${fixture.port}/`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: `node admin-host.mjs ${adminHost.port} ${adminHost.healthPort}`,
      url: `http://127.0.0.1:${adminHost.port}/`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});
