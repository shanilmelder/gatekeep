// @gatekeep/ui/hosted: the components Hosted Login can reach, which are the shared ones in
// ./index: the form and action controls, badges, Copy, the code block, toast and banner, and
// the Hosted building blocks (page, card, status icon, social row, error reference and alert
// dialog). React is its only third-party runtime dependency (AD-22), which
// scripts/check-dependencies.mjs enforces. There's no QR encoder: the server encodes TOTP QR
// codes and returns SVG path data (architecture review R-8).
export * from './index';
