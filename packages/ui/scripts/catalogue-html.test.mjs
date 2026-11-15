// Story 4.1: the build-time plugin that fills an app's index.html from the message catalogue
// (vite/catalogue-html.ts). It fills and HTML-escapes a known key and fails the build on an
// unknown one. The plugin is TypeScript over the TSX catalogue, so it's loaded through Vite's own
// module runner, as an app's vite.config.ts loads it.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { runnerImport } from 'vite';

const { module: plugin } = await runnerImport(fileURLToPath(new URL('../vite/catalogue-html.ts', import.meta.url)));
const { defaultMessages } = await runnerImport(fileURLToPath(new URL('../src/messages.tsx', import.meta.url))).then((m) => m.module);

describe('Catalogue HTML', () => {
  it('fills each %gk:key% from the catalogue', () => {
    const html = '<title>%gk:hostedFallbackTitle%</title><p>%gk:hostedNoScript%</p>';
    assert.equal(
      plugin.fillFromCatalogue(html),
      `<title>${defaultMessages.hostedFallbackTitle}</title><p>${defaultMessages.hostedNoScript}</p>`,
    );
  });

  it('HTML-escapes what it fills', () => {
    const messages = { ...defaultMessages, hostedFallbackTitle: `<b>"Tom" & 'Jerry'</b>` };
    assert.equal(
      plugin.fillFromCatalogue('<title>%gk:hostedFallbackTitle%</title>', messages),
      '<title>&lt;b&gt;&quot;Tom&quot; &amp; &#39;Jerry&#39;&lt;/b&gt;</title>',
    );
  });

  it('throws on a key the catalogue lacks, naming it', () => {
    assert.throws(() => plugin.fillFromCatalogue('<title>%gk:noSuchMessage%</title>'), /%gk:noSuchMessage%/);
  });

  it('runs before Vite reads the page', () => {
    const vite = plugin.catalogueHtml();
    assert.equal(vite.transformIndexHtml.order, 'pre');
    assert.equal(vite.transformIndexHtml.handler('<title>%gk:adminDocumentTitle%</title>'), `<title>${defaultMessages.adminDocumentTitle}</title>`);
  });
});
