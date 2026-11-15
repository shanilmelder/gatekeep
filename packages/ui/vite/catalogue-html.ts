// Fills an app's index.html from the message catalogue at build (Story 4.1, UX-DR41): each
// %gk:key% placeholder becomes that catalogue entry, HTML-escaped, so the page's fixed text, such as
// its fallback <title> and <noscript>, has one source and index.html holds no literal user-facing
// text (packages/ui/scripts/check-no-hardcoded-strings.mjs). An unknown key fails the build.
//
// An app's vite.config.ts imports this file by its relative path, so Vite bundles it, and the
// catalogue's TypeScript with it, into the config it runs. Its imports name their extensions, as
// Vite's native config loader asks (allowImportingTsExtensions, in each tsconfig that reads it).

import type { Plugin } from 'vite';
import { defaultMessages, type Messages } from '../src/messages.tsx';

const PLACEHOLDER = /%gk:([A-Za-z0-9]+)%/g;

/** `text` safe as HTML text or a quoted attribute value. */
export function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** `html` with every %gk:key% placeholder replaced by the catalogue's `key`, escaped. */
export function fillFromCatalogue(html: string, messages: Readonly<Messages> = defaultMessages): string {
  return html.replace(PLACEHOLDER, (_placeholder, key: string) => {
    const value = (messages as unknown as Record<string, unknown>)[key];
    if (!Object.hasOwn(messages, key) || typeof value !== 'string') {
      throw new Error(`index.html names %gk:${key}%, which the message catalogue doesn't have.`);
    }
    return escapeHtml(value);
  });
}

/** The Vite plugin: fills index.html from the catalogue, in dev and build alike. */
export function catalogueHtml(messages: Readonly<Messages> = defaultMessages): Plugin {
  return {
    name: 'gatekeep-catalogue-html',
    transformIndexHtml: {
      order: 'pre',
      handler: (html) => fillFromCatalogue(html, messages),
    },
  };
}
