// @gatekeep/hosted-screens: the Hosted Login screens, one props-only component each (Story
// 1.18). A screen shows only what its props and the @gatekeep/ui message catalogue give it:
// no fetch, router, storage or global state, and every callback and href comes in as a prop.
// Serving the steps is Story 4.1's. Pages wrap a screen in HostedPage; screens leave it out,
// so the theme preview (Story 15.2) can place them in a frame of its own. Its runtime
// dependencies are React and @gatekeep/ui's hosted entry only, which
// packages/ui/scripts/check-dependencies.mjs enforces.

export { GenericErrorScreen, type GenericErrorScreenProps } from './GenericErrorScreen';
