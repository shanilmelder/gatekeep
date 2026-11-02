// Browser tests for the built surfaces, run in the tests container. Chromium is the one the
// tests image installed at build time, at the version the catalog pins, so nothing is
// downloaded here.
//
// Story 1.13: each app's built dist is served by `vite preview` on a local port, the way the
// Deployment serves it: from its own origin (surfaces.spec.ts).
// Story 1.14: the shared controls fixture's dist is served the same way (controls.spec.ts).
// Story 1.20: the built Admin Dashboard is also served by the built Host.Admin itself, because
// the CSP and the other AD-21 headers under test are the host's own (admin-csp.spec.ts).

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
      testIgnore: ['admin-csp.spec.ts', 'controls.spec.ts'],
      use: { baseURL: `http://127.0.0.1:${port}` },
    })),
    { name: fixture.name, testMatch: 'controls.spec.ts', use: { baseURL: `http://127.0.0.1:${fixture.port}` } },
    {
      name: 'admin-host',
      testMatch: 'admin-csp.spec.ts',
      use: { baseURL: `http://127.0.0.1:${adminHost.port}` },
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
