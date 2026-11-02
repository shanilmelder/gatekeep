// Browser tests for the built surfaces (Story 1.13), run in the tests container. Chromium is
// the one the tests image installed at build time, at the version the catalog pins, so
// nothing is downloaded here. Each app's built dist is served by `vite preview` on a local
// port, the way the Deployment serves it: from its own origin.

import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from '@playwright/test';

const surfaces = [
  { name: 'hosted-login', port: 4310 },
  { name: 'admin-dashboard', port: 4311 },
];

const apps = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../apps');
for (const { name } of surfaces) {
  if (!existsSync(path.join(apps, name, 'dist', 'index.html'))) {
    throw new Error(`apps/${name}/dist/index.html is missing: build the apps first (pnpm -r build).`);
  }
}

export default defineConfig({
  testDir: '.',
  testMatch: '*.spec.ts',
  forbidOnly: true,
  retries: 0,
  reporter: [['list']],
  use: { browserName: 'chromium', headless: true },
  projects: surfaces.map(({ name, port }) => ({
    name,
    use: { baseURL: `http://127.0.0.1:${port}` },
  })),
  webServer: surfaces.map(({ name, port }) => ({
    command: `pnpm --dir ../../apps/${name} exec vite preview --host 127.0.0.1 --port ${port} --strictPort`,
    url: `http://127.0.0.1:${port}/`,
    reuseExistingServer: false,
    timeout: 60_000,
  })),
});
