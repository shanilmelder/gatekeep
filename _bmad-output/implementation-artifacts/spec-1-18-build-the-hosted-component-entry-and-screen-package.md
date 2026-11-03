---
title: 'Story 1.18: Build the Hosted component entry and screen package'
type: 'feature'
created: '2026-11-03'
status: 'done'
baseline_revision: 'd8f6ee581a1d0198e077c22548fc72bae2465cbf'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-17-build-the-drawer-and-menu.md'
warnings: []
deferred:
  - summary: >-
      Session-expiry alert refused while another dialog is open
    evidence: |-
      Story 1.18 review: AlertDialog joins the one-per-document registry, so a time-limit warning would be refused while a Modal or Drawer is open (WCAG 2.2.1).
    location: >-
      packages/ui/src/components/AlertDialog.tsx
    severity: medium
  - summary: >-
      Tenant font needs a family token
    evidence: |-
      Story 1.18 review: heading and body type use composite --gk-font-* tokens with the family baked in.
    location: >-
      packages/design-tokens/generator
    severity: low
  - summary: >-
      Bidi isolation for Tenant names in templates
    evidence: |-
      Story 1.18 review: RTL names are inserted into LTR catalogue templates without <bdi> or dir=auto.
    location: >-
      packages/ui/src/messages.tsx
    severity: low
---

<intent-contract>

## Intent

**Problem:** Hosted Login, the Admin pre-session pages (Bootstrap, invite acceptance, sign-in) and the theme preview (Story 15.2) must all draw the same cards. Today `@gatekeep/ui/hosted` holds only the shared controls, and `packages/hosted-screens` is an empty shell. Nothing yet does any of the following:
- draws a `hosted-card`;
- follows the device colour scheme;
- provides a Hosted `role="alertdialog"`;
- proves that the screens restyle under a Tenant theme.

**Approach:**
- Add the Hosted building blocks to `packages/ui`'s shared entry: page frame, card, status icon, social button row and alert dialog.
- Add a CSS-only "follow the device" scheme scope to the token generator.
- Make `packages/hosted-screens` a React package whose first screen is Generic error, as a props-only component.
- Test it all in Chromium through a new fixture view, in both schemes and under a theme override.

## Boundaries & Constraints

**Always:**
- **Conventions from Stories 1.14 to 1.17:**
  - Token variables only, and every built-in text from the catalogue (`messages.tsx`).
  - Native elements and the focus ring.
  - The reduced-motion rule.
  - The exact export lists in the fixture's `main.tsx`.
- **Where the components go:** the new components go in the shared `index.ts`. `@gatekeep/ui/hosted` and `@gatekeep/ui/admin` both export them, so the Admin pre-session pages and the preview can render them, and the admin entry stays a superset of the hosted one.
- **Dependencies (AC 1):** the Hosted entry's third-party runtime dependencies stay React and React DOM.
  - The QR code follows architecture review R-8: the server encodes the QR and returns SVG path data, and the TOTP enrolment story renders it. So the Hosted entry needs no client QR encoder, and the `hosted` allowlist in `scripts/check-dependencies.mjs` stays empty. Update that file's comment to say so.
  - `check-dependencies.mjs` also checks `packages/hosted-screens`. Its runtime dependencies may be only React and the `@gatekeep/*` workspace packages.
- **`HostedPage`:** the page frame.
  - Sets `data-gk-surface="hosted"`.
  - Centres one card on `bg` with `min-height: 100dvh`, so a tall card makes the page scroll and nothing is clipped.
  - Has a `main` landmark.
- **`HostedCard`** (UX-DR24). Its contents, in this order:
  1. A 42px logo tile, showing either the Tenant initial on `ac` with `on-ac` text, or an image with `alt` "{Tenant} logo".
  2. A heading (`h1`) in the theme font and `page-title` type.
  3. An optional subtitle in `tx2`.
  4. The content.
  5. One primary action slot.
  6. An optional quiet text link.

  Its sizing:
  - `hosted-card` tokens: `sf`, `bd` border, `rounded.modal`, 32px padding and `sh` shadow, with `sh-dark` in dark.
  - 384px wide. Below 416px of viewport, it takes the full width less a 16px gutter on each side.
- **Controls** (UX-DR25):
  - Buttons and inputs use the existing Hosted surface sizing. Every control height is a `min-height` (44px), so text at 200% wraps instead of clipping.
  - A new `SocialButtons` row holds up to three secondary-style buttons, each named "Continue with {provider}" from the catalogue. More than three is a development error (`console.error`), and only the first three are rendered.
  - The existing `PasswordField` toggle is named "Show password" or "Hide password". Keep it.
- **Hosted text** (AC 4): all text is `tx` or `tx2`, in both schemes. `tx3` appears only on disabled controls and control edges, which overrides the export's `tx3` code line and `OR` divider.
- **`StatusIcon`:**
  - A 52px circle (DESIGN.md `status-icon.size`; the export draws 46px) on a status `-sf` surface: success ✓, warning @, error !, blocked ⊘.
  - The glyph is `aria-hidden`, because the heading carries the meaning.
- **`AlertDialog`** (AC 5): the Hosted `role="alertdialog"`, used by the session-expiry warning (EXPERIENCE L380).
  - Built on Story 1.16's native `<dialog>` and `useModalDialog`, not copied.
  - It is named by its title and described by its body.
  - On open, focus moves to its primary action, or to the caller's `initialFocus`. Focus is trapped inside it, and on close it returns as it does for `Modal`.
  - It takes part in the one-per-document registry.
  - No third-party dependency.
- **Colour scheme:** Hosted Login follows `prefers-color-scheme` (DESIGN.md L579), with no toggle and no script.
  - The token generator emits `[data-gk-scheme="auto"]`, which takes the light values, and `@media (prefers-color-scheme: dark) { [data-gk-scheme="auto"] { …dark values } }`.
  - `surface.css` adds the same scope to its scheme selectors.
  - `HostedPage` defaults to `scheme="auto"`. A caller such as the preview can force `light` or `dark`.
  - Regenerate `tokens.css`, and keep the generator's CI check passing.
- **`packages/hosted-screens`:**
  - Builds with `tsc`, and depends at runtime only on `@gatekeep/ui` and React.
  - Each screen is a props-only component: everything it shows comes from props or the catalogue. No fetch, router, storage or global state. Callbacks and hrefs are passed in.
  - **`GenericErrorScreen`** (EXPERIENCE L214, the export's L409):
    - Props: the Tenant (name, plus an optional logo or initial), `code`, `traceId`, and `backHref`, the Application to return to.
    - Inside a `HostedCard` it shows, in order: an error `StatusIcon`, the fixed heading "Something went wrong", a fixed subtitle from the catalogue, and the code and trace ID in Geist Mono with Copy on the trace ID (NFR-18). The primary action is "Back to {Tenant}".
    - It shows no other variable detail (FR-33), and it uses the Tenant's name, never "Gatekeep".
    - Pages wrap screens in `HostedPage`. Screens don't include it, so the preview can place them in its own frame.
- **Theme variants:** a Tenant theme is a stylesheet that overrides tokens (Story 15.1), so screens must read only tokens.
  - The fixture proves this with a test-only theme scope. It overrides `ac`, `on-ac`, `ac-sf`, `ac-tx`, the control and card radius tokens, and the logo, while the font stays the bundled Geist.
  - The same screen markup then renders with that primary colour and those radii.
- **Tests:**
  - A fixture view at `?page=hosted` with `?scheme=light|dark|auto` and `?theme=custom`.
  - A new `tests/browser/hosted.spec.ts` with its own project, added to the surface projects' `testIgnore`.
  - A test for every matrix row below, and axe on the Generic error screen and the alert dialog in light, dark, auto with an emulated dark scheme, and the custom theme.

**Ask First:** none. This runs unattended, so decide and record the decision in the spec.

**Never:**
- No client-side QR library, and no other third-party runtime package reachable from `@gatekeep/ui/hosted` or `packages/hosted-screens`.
- No `tx3` text on Hosted, including placeholders and the error code line.
- No fetch, routing or step logic in screens. Serving the steps is Story 4.1, and the theme pipeline and preview are Stories 15.1 and 15.2.
- No Hosted toast, modal or banner work: that is Story 16.1.
- No new screens beyond Generic error. The others arrive with their stories.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Card order | Generic error rendered | Logo tile, status icon, `h1`, subtitle, code line, primary action, in DOM order | — |
| Card sizing | 1280px viewport; 360px viewport | Card is 384px wide; at 360px it is 360 − 32 = 328px | — |
| Control min-height | Root font size 200% | Button and input are at least 44px, text not clipped, card scrolls inside the page | — |
| Logo | Tenant with an initial; with an image | Initial on `ac`; image with `alt` "{Tenant} logo" | — |
| Text contrast | Every text node on the screen, light and dark | Computed colour is `tx` or `tx2` (or `on-ac` on the primary button); none is `tx3` | Test fails otherwise |
| Scheme auto | `scheme=auto` with emulated dark, then light | Dark tokens apply under dark, light under light, with no script | — |
| Scheme forced | `scheme=dark` under emulated light | Dark tokens apply | — |
| Theme variant | `theme=custom` | Primary button uses the override `ac`; card and control radii use the overrides; markup identical | — |
| Social row | 2 providers; 4 providers | 2 buttons named "Continue with {provider}"; 3 rendered and `console.error` | — |
| Alert dialog open | Open the dialog | `role="alertdialog"`, named and described; focus on its primary action | — |
| Alert dialog trap | Tab and Shift+Tab repeatedly | Focus stays inside | — |
| Alert dialog close | Activate the primary action | Closes; focus returns to the trigger | — |
| Copy trace | Activate Copy on the trace ID | Clipboard holds the trace ID exactly | — |
| No third party | Load the hosted fixture | Every request is same-origin | Test fails otherwise |
| Dependency check | `check-dependencies` | Passes; a third-party runtime dependency added to `hosted-screens` fails it (unit test) | — |
| Accessibility | axe on light, dark, auto with dark, and custom | No violations | Test fails otherwise |

</intent-contract>

## Code Map

- `packages/ui/src/index.ts`, `hosted.ts`, `admin.ts`: the entry points. Update the exact export lists in `tests/browser/fixture/src/main.tsx` to match.
- `packages/ui/src/surface.css`: Hosted sizing and its scheme selectors. Add the `auto` scheme here.
- `packages/ui/src/components/Button.tsx`, `Input.tsx`, `PasswordField.tsx`, `Field.tsx`, `CopyButton.tsx`, `Badge.tsx`, `messages.tsx`, `util.ts`: reuse these.
- `packages/ui/src/components/Modal.tsx`, `useModalDialog.ts`, `modalRegistry.ts`: the base for `AlertDialog`.
- `packages/ui/scripts/check-dependencies.mjs` with its tests, and `check-no-raw-hex.mjs`: the QR exception path stays as it is.
- `packages/design-tokens/generator` and `css/tokens.css`: the scheme scopes.
- `packages/hosted-screens/` (`package.json`, `tsconfig.json`, `src/index.ts`): the workspace root and the fixture's Vite config may need it wired in.
- `tests/browser/fixture/src/*`, `tests/browser/playwright.config.ts`, and the existing specs: a new spec needs its own project, plus an entry in the surface projects' `testIgnore`.
- The export at `design/Gatekeep Hosted Login.dc.html`, L34 (theme variants) and L409 (Generic error), is reference only. DESIGN.md wins over it.
- Verification runs only in Docker: `docker compose -f deploy/compose.test.yaml run --rm --build tests`. Database timeouts in Isolation under parallel load pass on rerun.

## Tasks & Acceptance

**Execution:**
- [x] `packages/design-tokens`: the `auto` scheme scope, plus regenerating `tokens.css`.
- [x] `packages/ui`: `HostedPage`, `HostedCard`, `StatusIcon`, `SocialButtons` and `AlertDialog`, with their CSS Modules, catalogue strings, exports, the `surface.css` auto scope and the dependency-check change.
- [x] `packages/hosted-screens`: the React package and `GenericErrorScreen`.
- [x] `tests/browser`: the hosted fixture view, `hosted.spec.ts` and the config, covering every matrix row plus axe.

**Acceptance Criteria:**
- Given the Hosted entry, when it builds, then its only third-party runtime dependencies are React and React DOM (no client QR encoder, per R-8), and the check enforces that for `hosted-screens` too.
- Given `hosted-card`, the Hosted button, the input and the error components, when they render, then they follow DESIGN.md order and sizing, and control heights are `min-height`.
- Given `packages/hosted-screens`, when a screen is added, then it is a props-only component that renders inside `HostedPage`, inside an Admin page, and in a forced-scheme preview scope.
- Given Hosted text, when contrast is tested in both schemes, then all text uses `tx` or `tx2`, and `tx3` appears only on disabled controls and control edges.
- Given a Hosted `role="alertdialog"`, when it opens, then focus moves into it and it uses no third-party dependency.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 46 findings — high 4, medium 18, low 23, false 1, maybe-false 0
- findings:
  - `[medium]` `[patch]` Intent: the social row has no pending state (EXPERIENCE L130) — `pendingId` added, tested.
  - `[medium]` `[patch]` Intent: Generic error always needs a back link, but some cases must never redirect — `backHref` optional; no action without it.
  - `[low]` `[patch]` Intent: decisions not recorded and the spec says 46px — Design Notes updated; DESIGN.md sets 52px.
  - `[low]` `[patch]` Intent: the `HostedPage` `theme` prop goes beyond the spec — kept, noted as Story 15.1's to replace.
  - `[low]` `[patch]` Intent: the dependency check reads ui's whole manifest — now follows what the import graph reaches.
  - `[low]` `[defer]` Intent: composite font tokens make a Tenant font hard to apply — Story 15.1.
  - `[low]` `[patch]` Intent: the fixture uses Apple as a provider — Google, GitHub and Microsoft only.
  - `[high]` `[patch]` Gap: the fixture root repeats HostedPage's surface and scheme, hiding a missing attribute — `root=admin` mode tested.
  - `[high]` `[patch]` Gap: HostedPage's default `auto` scheme is never used — omitted-prop case tested.
  - `[high]` `[patch]` Gap: AlertDialog's place in the one-per-document registry is untested — both directions tested.
  - `[high]` `[patch]` Gap: the 200% text checks can't fail — real height and line counts asserted.
  - `[medium]` `[patch]` Gap: only the error StatusIcon is tested — all four, both schemes.
  - `[low]` `[reject]` Gap: assert the status icon at 46px — DESIGN.md sets 52px and wins over the export.
  - `[medium]` `[patch]` Gap: AlertDialog `initialFocus`, `dismissible={false}` and focus fallback untested — tested.
  - `[medium]` `[patch]` Gap: the theme test relies on a doubled selector and light only — plain-selector theme added, dark and auto tested.
  - `[medium]` `[patch]` Gap: the hosted export list isn't exact — frozen list.
  - `[medium]` `[patch]` Gap: the hosted allowlist isn't pinned empty — pinned.
  - `[medium]` `[patch]` Gap: props-only screens aren't enforced — source scan test.
  - `[low]` `[patch]` Gap: deep and relative imports, missing nested manifest, explicit initial, link order, 0 or 1 providers, width boundaries, reduced motion, focus ring and accessible-name checks — tested.
  - `[medium]` `[patch]` Blind: the screens rule is a denylist with gaps — only `@gatekeep/ui/hosted`; relative imports must stay in the package.
  - `[medium]` `[patch]` Blind: the 200% test is vacuous — same fix as the Gap row.
  - `[medium]` `[patch]` Blind: scheme set on a `div` leaves the canvas light — documented that the app's `<html>` carries it (Story 4.1), tested without it.
  - `[false]` `[reject]` Blind: the `@` warning glyph is a typo — DESIGN.md specifies `@`.
  - `[low]` `[patch]` Blind: prototype keys pass the StatusIcon fallback — `Object.hasOwn`.
  - `[low]` `[patch]` Blind: an empty `initial` gives a blank tile — trimmed fallback.
  - `[low]` `[patch]` Blind: two `h1`s in the preview frame — `headingLevel`, axe on the preview.
  - `[low]` `[patch]` Blind: `.link a` overrides a styled link — `:where`.
  - `[low]` `[patch]` Blind: provider names split mid-word in a narrow row — the row reflows; labels wrap only at spaces.
  - `[low]` `[patch]` Blind: `100vw` includes the scrollbar — `100%`.
  - `[low]` `[reject]` Blind: `var()` inside `::backdrop` needs a recent engine — the same as Modal; supported engines are the target.
  - `[low]` `[patch]` Blind: "with no script" unproven — no inline `--gk-*` styles asserted.
  - `[low]` `[patch]` Blind: the custom theme is tested in light only — same fix as the Gap row.
  - `[medium]` `[patch]` Edge: relative imports reach the admin graph — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: three providers at 320px break letter by letter — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: duplicate provider ids — de-duplicated with an error.
  - `[medium]` `[patch]` Edge: a broken logo shows a broken image — falls back to the initial.
  - `[medium]` `[patch]` Edge: Generic error with no Application — same fix as the Intent row.
  - `[medium]` `[defer]` Edge: a session-expiry alert refused while a modal is open would never show — the session-expiry story decides precedence.
  - `[low]` `[patch]` Edge: `initialFocus` returning null skips the primary action — falls back to it.
  - `[low]` `[patch]` Edge: StatusIcon prototype keys — same fix as the Blind row.
  - `[low]` `[patch]` Edge: empty or long `initial`, bidi marks and multi-code-point names — one grapheme, format characters stripped.
  - `[low]` `[patch]` Edge: an empty Tenant name — development error.
  - `[low]` `[defer]` Edge: RTL Tenant names in LTR templates — the bidi pass with translation (NFR-19).
  - `[low]` `[patch]` Edge: an empty code or trace ID shows an empty row — hidden.
  - `[low]` `[patch]` Edge: `brought` ignores the entry allowlist — same fix as the Intent dependency row.
  - `[medium]` `[patch]` Other: `overlay.spec.ts` axe test fails when an animation is cancelled (`AbortError`) — the animation wait tolerates cancellation.

## Design Notes

- **QR (R-8):** AD-22 permits one reviewed encoder in the Hosted entry. R-8 moved encoding to the server, because a client `data:` image breaks the AD-21 CSP, and the server path also keeps the seed out of any client library. The client will render `<svg><path d=…>` on `#fff` in `packages/ui/src/qr/qr-code.tsx`, the raw-hex exception path that already exists. That arrives with TOTP enrolment, so this story only keeps the allowlist empty and says why.
- **Generic error subtitle:** EXPERIENCE requires fixed text. The export's "This link has expired or was already used." is case-specific. `[ASSUMPTION]` The catalogue uses "We couldn't complete this request. Go back and try again." and keeps the case-specific copy out.
- **Decisions made while building:**
  - **Status icon:** 52px, from the DESIGN.md token.
  - **`ButtonLink`:** an `<a href>` drawn as a button, for actions that navigate, such as "Back to {Tenant}".
  - **`ErrorReference`:** shows the code and trace ID, with Copy. It lives in `packages/ui` because `hosted-screens` builds with plain `tsc` and ships no CSS. It hides a row whose value is empty.
  - **Hosted buttons:** they wrap long labels and get 8px of vertical padding. Admin buttons are unchanged.
  - **Dependency check:** it follows first-party packages through what the import graph actually reaches. `hosted-screens` may reach `@gatekeep/ui` only through `@gatekeep/ui/hosted`.
  - **Raw-colour lint:** it now covers `packages/hosted-screens/src`.
  - **`GenericErrorScreen`:** `backHref` is optional. Without it, the screen has no primary action, because Generic error never redirects to an unvalidated target (EXPERIENCE L590, L696).
  - **`HostedCard`:** a `headingLevel` prop lets the preview frame sit inside an Admin page, which already has its own `h1`.
- **`HostedPage` `theme` prop:** sets `data-gk-theme` for a Tenant theme stylesheet. Story 15.1 owns how theme CSS is scoped, and may replace this.
- **Story 15.1 note:** heading and body type use composite `--gk-font-*` tokens, with the family baked in. A Tenant font needs a family token to override.

## Auto Run Result

Status: done

**Summary:** `packages/ui` gains `HostedPage`, `HostedCard`, `StatusIcon`, `SocialButtons`, `AlertDialog`, `ButtonLink` and `ErrorReference` in the shared entry. The token generator adds a CSS-only `data-gk-scheme="auto"` scope that follows `prefers-color-scheme`. `packages/hosted-screens` becomes a React package whose first props-only screen is `GenericErrorScreen`. The dependency check keeps the Hosted entry at React only (R-8 moves QR encoding to the server) and now covers `hosted-screens`. A `?page=hosted` fixture and Playwright tests cover every behaviour in light, dark, auto and a custom theme, with axe.

**Files:** `packages/design-tokens/generator/` and `css/tokens.css`; `packages/ui/src/components/` (HostedPage, HostedCard, StatusIcon, SocialButtons, AlertDialog, ErrorReference, Button), `surface.css`, `messages.tsx`, the entry points, `scripts/check-dependencies.mjs`, `scripts/check-no-raw-hex.mjs`; `packages/hosted-screens/`; `tests/browser/` (HostedFixture, themes, `hosted.spec.ts`, `overlay.spec.ts`, config); `pnpm-lock.yaml`.

**Review:** 46 findings across four layers: 40 patched, 3 deferred, 3 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. Four high verification gaps and several medium patches changed the dependency check and the tests, and only the new tests prove them.

**Verification:** see the PR screenshot; the full suite passes in the `tests` container.

**Residual risks:** tested in Chromium only. Hosted Login's `<html>` must carry the surface and scheme, which Story 4.1 serves.
