import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// Host.Admin serves this bundle under the AD-21 CSP, which allows only files from its own
// origin: no data: URI, inline script or inline style. So no asset is ever inlined, however
// small. If the bundle breaks the CSP, the fix belongs here, never in the CSP.
export default defineConfig({
  plugins: [react()],
  build: {
    assetsInlineLimit: 0,
  },
});
