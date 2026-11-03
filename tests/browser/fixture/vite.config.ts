// The controls fixture (Story 1.14): one page rendering every @gatekeep/ui control, built
// and served like the apps so tests/browser/controls.spec.ts drives the real build.

import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  plugins: [react()],
  // Nothing inlined as a data: URL, so every asset, the Hosted logo image included, is a
  // same-origin request as an app serves it (hosted.spec.ts, No third party).
  build: { outDir: 'dist', emptyOutDir: true, assetsInlineLimit: 0 },
});
