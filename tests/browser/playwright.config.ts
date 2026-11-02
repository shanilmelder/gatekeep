// Browser tests for the built surfaces (Story 1.13) and the shared controls (Story 1.14),
// run in the tests container. Chromium is the one the tests image installed at build time,
// at the version the catalog pins, so nothing is downloaded here. Each app's built dist,
// and the controls fixture's, is served by `vite preview` on a local port, the way the
// Deployment serves it: from its own origin.

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
  testMatch: '*.spec.ts',
  forbidOnly: true,
  retries: 0,
  reporter: [['list']],
  use: { browserName: 'chromium', headless: true },
  projects: [
    ...surfaces.map(({ name, port }) => ({
      name,
      testMatch: 'surfaces.spec.ts',
      use: { baseURL: `http://127.0.0.1:${port}` },
    })),
    { name: fixture.name, testMatch: 'controls.spec.ts', use: { baseURL: `http://127.0.0.1:${fixture.port}` } },
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
  ],
});
