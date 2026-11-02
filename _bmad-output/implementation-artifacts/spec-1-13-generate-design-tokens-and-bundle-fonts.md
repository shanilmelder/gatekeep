---
title: 'Story 1.13: Generate design tokens and bundle fonts'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_revision: '36fbac9ef94658025fb1dfa35306a5ea84651bb2'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/design-consistency.md'
warnings: [oversized]
deferred:
  - summary: >-
      Fonts and same-origin requests are proven on vite preview, not the deployed serving path.
    evidence: |-
      No host serves the apps yet. Prove it through Caddy when Stories 1.18 and 1.25 serve them.
    location: >-
      tests/browser/playwright.config.ts
    severity: medium
  - summary: >-
      Hosted Login does not follow prefers-color-scheme.
    evidence: |-
      The token CSS supports dark scopes; the surface stories choose the scheme.
    location: >-
      packages/design-tokens/css/tokens.css
    severity: medium
  - summary: >-
      No prefers-reduced-motion override for the motion tokens.
    evidence: |-
      Belongs with the first animated components (Story 1.16).
    location: >-
      packages/ui/src/styles.css
    severity: medium
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
- [x] `packages/design-tokens/` -- generator, `generate` and `check` scripts, committed outputs, a unit test per matrix row on the generator.
- [x] `src/Modules/Tenancy/Core/Theme/DesignTokens.g.cs` -- generated.
- [x] `packages/ui/` -- fonts, licence, `@font-face`, global `:focus-visible` rule, token import, and the QR exception file name constant for the lint.
- [x] `scripts/check-no-raw-hex.mjs` (or in `packages/ui`) -- the lint.
- [x] Browser test (Playwright) and its place in the `tests` image and run.
- [x] `deploy/docker/tests.Dockerfile`, `deploy/compose.test.yaml`, `.github/workflows/ci.yml` if needed -- run check, lint and browser test.

**Acceptance Criteria:**
- Given the DESIGN.md frontmatter, when the generator runs, then it emits `tokens.css`, a TypeScript map and C# constants for all 24 colour tokens in both schemes, plus extensions, against a scope selector.
- Given generated output that differs from DESIGN.md, when CI runs, then the build fails.
- Given a raw hex value in `packages/ui` other than the QR exception, when lint runs, then it fails.
- Given a built surface, when it loads in a browser test, then Geist and Geist Mono load from the Deployment and no third-party request occurs.
- Given any interactive element, when it receives keyboard focus, then `focus-ring` shows outside the control.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 51 findings — high 0, medium 18, low 29, false 4, maybe-false 0
- findings:
  - `[medium]` `[defer]` Intent: fonts and requests are proven on `vite preview`, not the deployed serving path — no host serves the apps yet; prove it through Caddy when Stories 1.18 and 1.25 serve them.
  - `[false]` `[reject]` Intent: focus is checked on injected controls — the apps have no controls yet; the global rule applies to every element.
  - `[low]` `[reject]` Intent: the ring is checked from computed style, not geometry — a positive offset with a positive width is outside the box by construction.
  - `[medium]` `[patch]` Intent: the font loads are forced by the test — the body's computed font, size, spacing and colours are asserted.
  - `[low]` `[reject]` Intent: the licence isn't copied into each app's output — it ships beside the fonts in the package, as AD-22 places them; the built apps carry no other notices yet.
  - `[low]` `[reject]` Intent: no network isolation at test time — the browser asserts every request is same-origin, which is the property; the .NET tests need the Docker host.
  - `[false]` `[reject]` Intent: 23 colours plus `sh` — DESIGN.md has 23 scheme colours, and the design-consistency audit (DS-2) counts `sh` as the 24th token.
  - `[false]` `[reject]` Intent: the scope selector reading — a dark attribute flips its subtree and a nested theme root resets to light; both are tested.
  - `[low]` `[reject]` Intent: fallback font stacks live in the generator — the intent allows non-CSS mapping in the generator.
  - `[medium]` `[defer]` Blind: Hosted Login never follows `prefers-color-scheme` — the token CSS supports dark scopes; choosing the scheme belongs to the surface stories (1.18, 1.25).
  - `[medium]` `[defer]` Blind: no reduced-motion override — motion tokens exist; reduced motion belongs with the first animated components (Story 1.16).
  - `[medium]` `[patch]` Blind: the font shorthand drops letter spacing — emitted and applied.
  - `[medium]` `[patch]` Blind: component values bypass validation (unitless numbers, named colours) — validated.
  - `[medium]` `[patch]` Blind: C# output can fail to compile on digit-leading names or collisions — refused with a named error.
  - `[low]` `[patch]` Blind: a BOM or a final `---` breaks frontmatter parsing — handled.
  - `[medium]` `[patch]` Blind: committed `tokens.css` sits in `dist/` — moved to `css/`.
  - `[medium]` `[patch]` Blind: the raw-colour lint is narrow — apps, every file type, `rgb()`/`hsl()`, `url(#id)` skipped.
  - `[low]` `[patch]` Blind: browser tests miss forced colours, the body font and scope cases — added.
  - `[low]` `[patch]` Blind: the Playwright version `sed` is brittle — parsed with node and validated.
  - `[low]` `[reject]` Blind: the IPv4 fix is unrelated — it fixes the test run this story's verification depends on, in the same file as the story's new steps; the silent case now prints a line.
  - `[low]` `[patch]` Blind: `fonts.mjs --check` writes, crashes on a missing package, and is untested — fixed and tested.
  - `[low]` `[patch]` Blind: browser tests need built apps without saying so — fails early with a clear message.
  - `[low]` `[patch]` Blind: a test repeats the drift check — replaced with `generate` and exit-code tests.
  - `[medium]` `[patch]` Edge: `{colors.sh}` emits an undeclared variable — mapped to elevation.
  - `[medium]` `[patch]` Edge: trailing text after a reference is injected into CSS — refused.
  - `[low]` `[patch]` Edge: invalid property names — refused.
  - `[low]` `[patch]` Edge: `size` and explicit width/height overwrite — refused.
  - `[medium]` `[patch]` Edge: variable names collide across groups — tracked and refused.
  - `[medium]` `[patch]` Edge: digit-leading names give invalid C# — refused.
  - `[medium]` `[patch]` Edge: a name matching its C# class breaks the build — refused.
  - `[low]` `[patch]` Edge: unitless or infinite numbers — refused.
  - `[low]` `[patch]` Edge: motion min above max — refused.
  - `[low]` `[patch]` Edge: BOM or final `---` — same fix as the Blind row.
  - `[low]` `[patch]` Edge: missing DESIGN.md prints a raw stack — named failure.
  - `[medium]` `[patch]` Edge: renaming `body` or `focus-ring` silently breaks the UI — generation fails.
  - `[medium]` `[patch]` Edge: the lint skips itself when paths differ — real paths compared.
  - `[low]` `[patch]` Edge: unlisted extensions skip the lint — every text file.
  - `[low]` `[patch]` Edge: `url(#id)` flagged — skipped.
  - `[low]` `[patch]` Edge: symlinked directories skipped — followed.
  - `[low]` `[patch]` Edge: any font read error reported as missing — real error reported.
  - `[low]` `[patch]` Edge: `--check` creates a directory — no write in check mode.
  - `[low]` `[patch]` Edge: CRLF or quoted catalog version breaks the image build — same fix as the Blind row.
  - `[low]` `[patch]` Edge: a second catalog-like match — parsed from `catalog:` only.
  - `[low]` `[patch]` Edge: tabbing can start from an autofocused element — focus reset first.
  - `[low]` `[reject]` Edge: unknown `data-gk-scheme` values inherit silently — only `light` and `dark` are defined, and the surface stories set them.
  - `[false]` `[reject]` Edge (claim): 24 colour tokens — same as the Intent row.
  - `[low]` `[patch]` Edge (claim): the lint covers only `src` and some extensions — widened.
  - `[low]` `[reject]` Edge (claim): only `/` is tested for third-party requests — each app has one route today.
  - `[medium]` `[patch]` Gap: the body font shorthand is never checked where it's used — computed style asserted, and the generated line tested.
  - `[medium]` `[patch]` Gap: nothing shows the font check can fail — `checkFonts` exported and tested.
  - `[low]` `[patch]` Gap: the forced-colours focus rule is untested — emulated and asserted.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; Architecture and Isolation pass; token check, raw-hex lint and browser test pass.

## Auto Run Result

Status: done

**Summary:** `packages/design-tokens` generates `tokens.css`, a TypeScript map and C# constants from the DESIGN.md frontmatter, validating its input and failing CI on drift. `packages/ui` ships Geist and Geist Mono from the Deployment with a global focus ring. A raw-colour lint covers `packages/ui` and the apps. A Playwright test in the `tests` image checks fonts, same-origin requests, body styles, scopes and focus.

**Files:** `packages/design-tokens/` (generator, CLI, tests, outputs); `src/Modules/Tenancy/Core/Theme/DesignTokens.g.cs`; `packages/ui/` (fonts, licence, styles, scripts and tests); `tests/browser/`; the apps' entry points; `deploy/docker/tests.Dockerfile`, `run-tests.sh`, `compose.test.yaml`; `pnpm-workspace.yaml`, `pnpm-lock.yaml`; `.gitattributes`, `.gitignore`.

**Review:** 51 findings across four layers: 37 patched, 3 deferred, 11 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. Many medium patches harden the generator's validation and widen the lint, and new tests are their only proof.

**Verification:** see the PR screenshot; the full suite passes in the `tests` container.

**Residual risks:** the browser test uses `vite preview`, not the deployed path. Hosted Login doesn't yet follow the OS colour scheme, and motion has no reduced-motion override.
