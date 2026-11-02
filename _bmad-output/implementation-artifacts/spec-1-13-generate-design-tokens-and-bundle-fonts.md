---
title: 'Story 1.13: Generate design tokens and bundle fonts'
type: 'feature'
created: '2026-11-02'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/design-consistency.md'
warnings: [oversized]
deferred: []
---

<intent-contract>

## Intent

**Problem:** The interface has no design tokens or fonts. AD-22 makes the `DESIGN.md` frontmatter the single token source, generating CSS, TypeScript and C#. CI must fail on drift, raw hex values in `packages/ui` must fail lint, Geist fonts must ship from the Deployment, and every interactive element needs a visible `focus-ring` outside the control.

**Approach:** Build a generator in `packages/design-tokens` that reads the frontmatter and writes the three outputs, with a check mode CI runs. Bundle Geist and Geist Mono in `packages/ui` with a global focus rule. Add a lint for raw hex values, and a browser test in the `tests` container proving the fonts load from the Deployment, no third-party request occurs, and focus shows outside the control.

## Boundaries & Constraints

**Always:**
- **Token source:** the generator reads only the frontmatter of `_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md`. DESIGN.md wins over the `design/*.dc.html` exports, which no build imports.
- **What it emits:**
  - all 24 colour tokens in both schemes (light and dark);
  - the extensions the frontmatter marks;
  - typography, spacing, radius and elevation.
- **Output files** (all generated and committed):
  - `packages/design-tokens/dist/tokens.css`: custom properties against a scope selector (for example `[data-gk-theme]` with `[data-gk-scheme="dark"]`), so a preview can theme a subtree. Also `:root` defaults.
  - `packages/design-tokens/src/tokens.generated.ts`: a typed map.
  - `src/Modules/Tenancy/Core/Theme/DesignTokens.g.cs`: internal C# constants for the default theme.
- **Values that aren't CSS** (references, shorthand) are mapped in the generator, never hand-edited in output.
- **Drift check:** `pnpm --filter @gatekeep/design-tokens check` regenerates in memory and fails, naming the file and token, when any committed output differs. The `tests` container and CI run it.
- **Raw hex lint:** a check run by the `tests` container fails on any raw hex colour in `packages/ui/src`, outside one named QR-encoder exception file. It is a small script in the repo, not a new lint framework.
- **Fonts:** Geist and Geist Mono (OFL) come from a pinned npm package. Their `woff2` files are copied into `packages/ui` and served by each app from its own origin through `@font-face`. There are no CDN, Google Fonts or other external URLs, and the licence file ships beside the fonts.
- **Focus:** `packages/ui` has one global `:focus-visible` rule drawing the `focus-ring` token outside the control (`outline` with a positive `outline-offset`, or an outer ring), applying to every interactive element.
- **Browser test:** Playwright with a Chromium pinned in the `tests` image, downloaded at image build only. It builds and serves `apps/hosted-login` and `apps/admin-dashboard`, then asserts:
  - every network request goes to the serving origin;
  - `document.fonts` reports Geist and Geist Mono loaded;
  - after `Tab`, the focused element's ring sits outside its box.
- **No network at test time:** the tests still pass with no egress beyond the local origin.

**Never:**
- No hand-written token values in CSS, TypeScript or C# outside the generated files.
- No `@import` or `<link>` to an external font or style host.
- No change to DESIGN.md's values.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Generate | Current DESIGN.md | Three outputs with all 24 colours in both schemes, extensions, type, space, radius, elevation | No error |
| Drift | Committed output edited by hand, or DESIGN.md changed without regenerating | `check` fails naming file and token | Build fails |
| Bad source | Frontmatter missing a colour or with an unparseable value | Generator fails naming the key | Non-zero exit |
| Raw hex | `#1a2b3c` in a `packages/ui` file | Lint fails naming file and line | Build fails |
| QR exception | Hex in the named QR file | Allowed | — |
| Fonts local | Built surface loaded in Chromium | Geist and Geist Mono loaded from the same origin | — |
| No third party | Same | Zero requests to any other origin | Test fails otherwise |
| Focus | `Tab` onto an interactive element | `focus-ring` visible outside the element box | Test fails otherwise |
| Scope | Element under `[data-gk-scheme="dark"]` | Dark values apply to that subtree only | — |

</intent-contract>

## Code Map

- `_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md` -- frontmatter keys `colors` (light, dark and extension comments around line 61), `typography` (with extensions), `rounded`, `spacing`, `elevation`, `components`. 444 frontmatter lines.
- `packages/design-tokens/` -- placeholder `src/index.ts`, `tsc` build, catalog TypeScript.
- `packages/ui/` -- placeholder `src/index.ts`.
- `apps/hosted-login`, `apps/admin-dashboard` -- Vite apps with `index.html`.
- `pnpm-workspace.yaml` -- `catalog:` pins, `ignoreScripts: true`, `engineStrict: true`. Pin any new package (YAML parser, Geist, Playwright) in the catalog.
- `deploy/docker/tests.Dockerfile`, `deploy/compose.test.yaml` -- the `tests` image and its command. Add Playwright Chromium at build, and the token check, lint and browser test to the test run.
- `src/Modules/Tenancy/` -- home for the generated C# constants (`Core/Theme/`, internal).
- `tests/Architecture/BuildEnforcementTests.cs` -- existing pnpm build and audit checks.
- Verification runs only in Docker.

## Tasks & Acceptance

**Execution:**
- [ ] `packages/design-tokens/` -- generator, `generate` and `check` scripts, committed outputs, a unit test per matrix row on the generator.
- [ ] `src/Modules/Tenancy/Core/Theme/DesignTokens.g.cs` -- generated.
- [ ] `packages/ui/` -- fonts, licence, `@font-face`, global `:focus-visible` rule, token import, and the QR exception file name constant for the lint.
- [ ] `scripts/check-no-raw-hex.mjs` (or in `packages/ui`) -- the lint.
- [ ] Browser test (Playwright) and its place in the `tests` image and run.
- [ ] `deploy/docker/tests.Dockerfile`, `deploy/compose.test.yaml`, `.github/workflows/ci.yml` if needed -- run check, lint and browser test.

**Acceptance Criteria:**
- Given the DESIGN.md frontmatter, when the generator runs, then it emits `tokens.css`, a TypeScript map and C# constants for all 24 colour tokens in both schemes, plus extensions, against a scope selector.
- Given generated output that differs from DESIGN.md, when CI runs, then the build fails.
- Given a raw hex value in `packages/ui` other than the QR exception, when lint runs, then it fails.
- Given a built surface, when it loads in a browser test, then Geist and Geist Mono load from the Deployment and no third-party request occurs.
- Given any interactive element, when it receives keyboard focus, then `focus-ring` shows outside the control.

## Spec Change Log

## Review Triage Log

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; Architecture and Isolation pass; token check, raw-hex lint and browser test pass.
