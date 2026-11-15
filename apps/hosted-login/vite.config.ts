import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';
import { catalogueHtml } from '../../packages/ui/vite/catalogue-html.ts';

// Hosted Login (Story 4.1). Host.Hosted serves this bundle under /login/, and every step page is
// this index.html with the step's JSON and the Tenant's theme link put in place of its two marker
// comments (<!--gk-head--> and <!--gk-step-->), under the AD-21 CSP: files from its own origin only,
// no data: URI, inline script or inline style. So no asset is ever inlined, however small, and the
// page's fixed text (its fallback <title> and <noscript>) comes from the message catalogue at build.
export default defineConfig({
  base: '/login/',
  plugins: [react(), catalogueHtml()],
  build: {
    assetsInlineLimit: 0,
  },
});
