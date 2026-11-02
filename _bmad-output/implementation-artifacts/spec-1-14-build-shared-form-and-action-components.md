---
title: 'Story 1.14: Build shared form and action components'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_revision: '26b120e08742c5d750166da998cefc880c6d58c7'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-13-generate-design-tokens-and-bundle-fonts.md'
warnings: [oversized]
deferred:
  - summary: >-
      Controlled values and callbacks of Toggle, Segmented and RadioGroup are untested.
    evidence: |-
      Pin them in the first story wiring a controlled control into a Save form.
    location: >-
      packages/ui/src/components
    severity: medium
  - summary: >-
      Checkbox and RadioGroup have no helper, error, required or group-disabled support.
    evidence: |-
      Add with the first form needing a required choice, such as a consent checkbox.
    location: >-
      packages/ui/src/components/Choice.tsx
    severity: medium
  - summary: >-
      No submit-time validation or first-invalid-field focus.
    evidence: |-
      Form-level behaviour belongs to the first form story.
    location: >-
      packages/ui/src/components/Field.tsx
    severity: medium
---

<intent-contract>

## Intent

**Problem:** Admin and Hosted screens have no shared form controls. AD-22 wants one React component per control in `packages/ui`, sized by a surface attribute. Controls reachable from Hosted Login may use no third-party headless primitive. Each control must behave as `EXPERIENCE.md` specifies when driven by mouse or keyboard alone.

**Approach:** Build `Button`, `Input`, `Select`, `Textarea`, `Field` (label, helper, error), `PasswordField`, `Toggle`, `Checkbox`, `Radio`/`RadioGroup` and `Segmented` in `packages/ui` as React components with CSS Modules. They use token variables only, and a `data-gk-surface="admin" | "hosted"` attribute selects the sizing. Test them in Chromium through a fixture page.

## Boundaries & Constraints

**Always:**
- **Native elements and dependencies:**
  - Every control is a native element (`button`, `input`, `select`, `textarea`), not a clickable `div`.
  - Only React and React DOM are runtime dependencies of these controls, with no headless or third-party primitive.
  - The package keeps the `@gatekeep/ui/hosted` and `@gatekeep/ui/admin` entry points from AD-22. Both export the same component modules, so one component serves both surfaces.
- **Styling:**
  - Values come only from `--gk-*` custom properties from `@gatekeep/design-tokens` (the raw-colour lint must pass).
  - Admin or Hosted sizing is chosen by `data-gk-surface` on an ancestor or the component, using DESIGN.md's `button*`, `hosted-button*`, `input`, `hosted-input`, `toggle` and `segmented` component tokens.
  - The global `:focus-visible` ring from Story 1.13 shows on every control.
- **Buttons:**
  - Variants: `primary`, `secondary`, `ghost`, `destructive` (outlined), plus `disabled` and `small` (`size="sm"`).
  - There is no filled warn or filled destructive variant.
  - `pending` keeps the button's rendered width and accessible name, sets `aria-busy="true"` and `aria-disabled="true"`, shows a spinner, and ignores clicks and Enter. It stays focusable and is not the HTML `disabled` attribute.
- **Inputs (`Input`, `Select`, `Textarea` through `Field`):**
  - A visible label is tied to the control.
  - Validation is supplied by the caller and runs on blur. Once the field is in error it runs again on every change.
  - The error is written into the helper, which is linked by `aria-describedby`, and the control sets `aria-invalid="true"`. The helper keeps its id whether or not there is an error.
  - Focus never moves on validation.
  - Identifier fields can opt into the code type (Geist Mono).
- **`PasswordField`:**
  - A `type="button"` toggle named "Show password" or "Hide password".
  - It re-masks when its form submits, allows paste, and doesn't block password managers (no `autocomplete="off"`).
- **Selection controls:**
  - `Toggle` is a `button` with `role="switch"` and `aria-checked`. It changes form state only and saves nothing.
  - `Checkbox` and `Radio` are native inputs drawn at 15px with 24px hit areas. `RadioGroup` uses a `fieldset` and `legend`.
  - `Segmented` is a radio group: one tab stop, arrow keys move and select immediately, and Home and End go to the ends.
- **Strings:** all built-in strings (the "Show password" and "Hide password" names, the pending spinner's label) come from one message catalogue in `packages/ui` that callers can override (UX-DR41, NFR-19).
- **Testing:**
  - A fixture page built with Vite renders every control on both surfaces.
  - `tests/browser` drives it in Chromium for each matrix row and runs `@axe-core/playwright` with no violations.
  - Component behaviour is tested by keyboard and pointer in the browser, not by snapshot.

**Never:**
- No third-party headless or UI library in `@gatekeep/ui/hosted` or in any control from this story.
- No raw colour, size or font value outside token variables.
- No filled warn or destructive button. A destructive button never acts on its own; the modal that confirms it is Story 1.16's.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Variants | Render each button variant on both surfaces | primary, secondary, ghost, outlined destructive, disabled, small exist; sizes follow the surface | No filled warn |
| Pending | Click a pending button, press Enter on it | No action; same width and name; `aria-busy` and `aria-disabled` true; still focusable | — |
| Invalid on blur | Type an invalid value, Tab away | Helper shows the error, `aria-describedby` points to it, `aria-invalid="true"`; focus stays where Tab put it | — |
| Revalidate | Field in error, type a valid value | Error clears on change without blur | — |
| Valid first blur | Valid value, Tab away | No error, no `aria-invalid` | — |
| Password | Toggle show then submit | Name flips Show and Hide; masked again after submit | — |
| Toggle | Space and Enter on a toggle | `aria-checked` flips; nothing saved | — |
| Checkbox and radio | Space on checkbox; arrows within a radio group | Checked state changes as native controls do | — |
| Segmented | Tab in, Right, Left, Home, End | One tab stop; arrows move and select immediately; Home and End reach the ends | — |
| Accessibility | axe-core over the fixture on both surfaces | No violations | Test fails otherwise |
| No third party | Dependency check of `packages/ui` | Only React and React DOM at runtime | Test fails otherwise |

</intent-contract>

## Code Map

- `packages/ui/` -- `src/index.ts` (placeholder), `src/styles.css` (fonts, global focus ring, body), `tsconfig.json` (tsc build to `dist`), `scripts/check-no-raw-hex.mjs` (lint over `packages/ui/src` and `apps/*/src`). It needs to build React with CSS Modules: use Vite library mode or keep `tsc` with CSS Modules consumed by the apps' Vite, and make whichever choice work for both apps and the fixture.
- `packages/design-tokens/css/tokens.css`, `src/tokens.generated.ts` -- component variables such as `--gk-button-primary-*`, `--gk-hosted-button-primary-*`, `--gk-input-*`, `--gk-toggle-*`, `--gk-segmented-*`, and typography variables.
- `apps/hosted-login`, `apps/admin-dashboard` -- Vite plus React; import `@gatekeep/ui/styles.css`.
- `tests/browser/` -- Playwright config serving built apps with `vite preview`, plus `surfaces.spec.ts`. Add a fixture app (for example `tests/browser/fixture`) served the same way.
- `pnpm-workspace.yaml` -- the catalog pins `react` 19.3.1 and `@vitejs/plugin-react`. Add `@axe-core/playwright` pinned.
- `deploy/docker/run-tests.sh` -- runs the UI checks and browser tests in the `tests` container.
- `EXPERIENCE.md` "Component Patterns" table -- the behaviour rules.
- Verification runs only in Docker.

## Tasks & Acceptance

**Execution:**
- [x] `packages/ui/src/` -- the components, their CSS Modules, the message catalogue, and the `hosted` and `admin` entry points.
- [x] `packages/ui` build -- React and CSS Modules output usable by both apps.
- [x] `tests/browser/fixture/` -- a fixture page rendering every control on both surfaces.
- [x] `tests/browser/controls.spec.ts` -- every matrix row, plus axe-core.
- [x] A dependency test that fails if `packages/ui` gains a runtime dependency other than React and React DOM.

**Acceptance Criteria:**
- Given the button variants, when rendered, then primary, secondary, ghost, outlined destructive, disabled and small exist, and no filled warn button exists.
- Given a pending button, when it's clicked again, then it ignores the click and keeps its width and accessible name, with `aria-busy` and `aria-disabled` set.
- Given an invalid input, when it blurs, then the helper shows the error, linked by `aria-describedby`, with `aria-invalid` set, and it revalidates on change.
- Given toggle, checkbox, radio and segmented controls, when driven by keyboard only, then each works as EXPERIENCE specifies, and segmented responds to arrow keys.
- Given the shared controls, when dependencies are reviewed, then Hosted-reachable controls use no third-party headless primitive, and one component serves both surfaces.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 45 findings — high 0, medium 14, low 29, false 2, maybe-false 0
- findings:
  - `[medium]` `[patch]` Gap: a Field's external `error` is untested — fixture and tests for helper text, `aria-invalid`, description, and precedence over `validate`.
  - `[medium]` `[defer]` Gap: controlled values and change callbacks of Toggle, Segmented and RadioGroup are untested — pin them in the first story that wires a controlled control into a Save form.
  - `[medium]` `[patch]` Blind: a disabled checked checkbox or toggle looks unchecked — disabled-and-checked rules added.
  - `[medium]` `[patch]` Blind: a caller's `aria-disabled` doesn't block clicks or submit — blocked and styled.
  - `[medium]` `[patch]` Blind: ghost, destructive, small and disabled buttons ignore the surface; missing hovers — routed through per-surface variables.
  - `[low]` `[patch]` Blind: spinner ignores the label colour and can overflow small buttons — `currentColor`, kept inside.
  - `[medium]` `[patch]` Blind: tabbing through an untouched field shows an error — blur validation waits for a change; submit-time validation belongs to the form stories.
  - `[low]` `[patch]` Blind: `aria-invalid` grammar and spelling dropped; external error never clears — passed through, and clearing documented as the caller's.
  - `[medium]` `[defer]` Blind: Checkbox and RadioGroup can't show helper or error text, or be disabled as a group — add with the first form that needs a required choice.
  - `[low]` `[patch]` Blind: radios size from the checkbox hit-area token — radio token used.
  - `[low]` `[patch]` Blind: Segmented arrows don't mirror in RTL; rejected controlled change misplaces focus — fixed; group `disabled` deferred with the Checkbox row.
  - `[medium]` `[patch]` Blind: PasswordField binds its form once, rebuilds its ref, keeps reveal enabled when disabled — fixed.
  - `[low]` `[patch]` Blind: nearest-surface claim false when an Admin island holds a scope — Admin selectors added.
  - `[low]` `[patch]` Blind: dependency check misses `composes` and counts comments — matched and stripped.
  - `[low]` `[patch]` Blind: `react-dom` not a peer; Messages memo defeated by inline objects — declared, and documented.
  - `[low]` `[patch]` Blind: test gaps (dark, forced colours, reduced motion, disabled, error, pending override, duplicate text in the tab walk) — added.
  - `[medium]` `[patch]` Edge: `aria-disabled` without `pending` still acts — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: a control's own id breaks the label — label follows the control's id.
  - `[low]` `[patch]` Edge: `aria-invalid` values dropped — same fix as the Blind row.
  - `[low]` `[patch]` Edge: external error stays after a fix — documented as the caller's to clear.
  - `[medium]` `[patch]` Edge: password stays revealed when native validation blocks submit — masks on `invalid` too.
  - `[medium]` `[patch]` Edge: password listener stays on an old form — follows the current form.
  - `[low]` `[patch]` Edge: a disabled toggle submits its value — omitted when disabled.
  - `[low]` `[patch]` Edge: toggle's hidden input ignores `form` — passed through.
  - `[low]` `[patch]` Edge: an unmatched Segmented value submits what nothing shows — falls back to the first option.
  - `[low]` `[patch]` Edge: duplicate Segmented values — asserted in development.
  - `[low]` `[patch]` Edge: RTL arrows — same fix as the Blind row.
  - `[low]` `[patch]` Edge: an `undefined` message override wipes the default — ignored.
  - `[low]` `[patch]` Edge: React 19 ref cleanups dropped — collected and returned.
  - `[low]` `[patch]` Edge: `composes` imports pass the dependency check — same fix as the Blind row.
  - `[low]` `[patch]` Edge: a malformed manifest crashes the check — reported as a problem.
  - `[low]` `[patch]` Edge: unresolvable `argv[1]` breaks importers — guarded.
  - `[low]` `[patch]` Edge: Admin island under Hosted scope — same fix as the Blind row.
  - `[medium]` `[patch]` Intent: the "no third party" rule is checked package-wide, not on what Hosted Login reaches, and would wrongly block AD-22's admin primitives and Hosted QR encoder — the strict rule now walks the `hosted` entry's import graph.
  - `[false]` `[reject]` Intent: EXPERIENCE.md conformance beyond the matrix can't be measured from the diff — the matrix rows are the contract; each row is tested.
  - `[medium]` `[patch]` Intent: button variants read Admin tokens on Hosted — same fix as the Blind row.
  - `[low]` `[patch]` Intent: `Select` validation untested — added.
  - `[low]` `[reject]` Intent: paste is checked by a synthetic event — it proves no handler blocks paste, which is the rule; a real clipboard needs permissions the test runner lacks.
  - `[low]` `[reject]` Intent: a caller can pass `autoComplete="off"` — the default is right, and the caller owns that choice.
  - `[low]` `[patch]` Intent: pending message override untested — added.
  - `[low]` `[patch]` Intent: a named toggle is never shown submitting in a form — test added.
  - `[low]` `[patch]` Intent: focus ring untested in the error state — added.
  - `[low]` `[reject]` Intent: other handlers run while pending — pending blocks activation and submit, which is the rule.
  - `[low]` `[reject]` Intent: the `.` export and the `dist` build were removed — nothing imports the bare package, and the apps compile the source.
  - `[false]` `[reject]` Intent: the destructive rule is a doc comment — the confirming modal is Story 1.16's, as the spec says.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; token, font and colour checks pass; browser tests (surfaces and controls) pass; Architecture and Isolation pass.

## Auto Run Result

Status: done

**Summary:** `packages/ui` gains Button, Field, Input, Select, Textarea, PasswordField, Toggle, Checkbox, Radio and RadioGroup, and Segmented. They are React and CSS Modules over token variables, sized per surface by `data-gk-surface`, with strings from one catalogue. A dependency check keeps what Hosted Login reaches to React and React DOM. A fixture page and Playwright tests drive every control by keyboard and pointer on both surfaces, with axe in light and dark.

**Files:** `packages/ui/src/` (components, CSS Modules, `surface.css`, `messages.tsx`, `util.ts`, entry points), `packages/ui/scripts/check-dependencies.mjs` and its test, `packages/ui/package.json`; `tests/browser/fixture/`, `tests/browser/controls.spec.ts`, `playwright.config.ts`; the apps' `index.html`; `pnpm-workspace.yaml`, `pnpm-lock.yaml`.

**Review:** 45 findings across four layers: 37 patched, 2 deferred, 6 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. Many medium patches change component behaviour and styling, with new browser tests as their only proof.

**Verification:** see the PR screenshot; the full suite passes in the `tests` container.

**Residual risks:** submit-time validation, choice-control errors and the controlled APIs are deferred to the first form stories. The 5px label gap is 4px because no 5px token exists.
