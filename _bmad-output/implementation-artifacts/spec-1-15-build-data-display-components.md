---
title: 'Story 1.15: Build data display components'
type: 'feature'
created: '2026-11-03'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-14-build-shared-form-and-action-components.md'
warnings: [oversized]
deferred: []
---

<intent-contract>

## Intent

**Problem:** Admin pages have nothing to display data with. They need tables, tabs, badges, code blocks, a JSON viewer, a Copy control, empty states, skeleton rows and the Section blocks (stat tile, settings row, usage bar, RBAC matrix). Each must look and behave the same way everywhere, as DESIGN.md and EXPERIENCE.md specify.

**Approach:** Add these as React and CSS Modules components in `packages/ui`, built the same way as Story 1.14. Export them from the `admin` entry, and from `hosted` only where Hosted needs them (badges, Copy, code block). Test them in Chromium through the existing fixture.

## Boundaries & Constraints

**Always:**
- **Build rules, as in Story 1.14:**
  - Use token variables only, and message-catalogue strings for every built-in text ("Copy", "Copied", paging labels, skeleton label).
  - Native semantic elements, the global focus ring, and the dependency check.
  - Admin components may use no third-party library either, because none is needed here.
- **Badges** (UX-DR9):
  - Status badges have a 6px dot: Active, Pending, Blocked.
  - Protocol badges; an outlined Draft badge.
  - Mono badges for environment and Log codes.
  - Environment colours: Prod uses `bad`, Staging `warn`, Dev `info`.
  - The badge text carries the meaning; the dot is `aria-hidden`.
- **Tabs** (UX-DR10):
  - A 2px `tx` underline under the selected tab, following the ARIA tab pattern: `tablist`, `tab` and `tabpanel`, a single tab stop, arrow keys, and Home and End.
  - Activation is manual, with Enter or Space, so moving focus doesn't navigate.
  - The selected tab is URL-addressable through a small `useUrlTab(param)` hook that reads and writes `URLSearchParams` with `history.pushState`. Back and Forward restore the tab.
  - An optional `canLeave()` guard (sync or async) runs before switching. When it returns false, the switch and the URL change don't happen. The confirm modal itself is Story 1.16's.
- **Data table** (UX-DR11):
  - A real `table`, `thead`, `th` (with `scope`) and `td` structure.
  - Rows are 38px and the header row 32px, from tokens.
  - Numeric columns are right-aligned and mono.
  - Row activation opens detail through an `onRowActivate` callback. A pointer click and Enter on a row-level link or button both activate it.
  - Copy controls or other interactive cells inside a row don't trigger row activation.
  - The table pages at 50 rows, with Previous and Next controls and a "{from}–{to} of {total}" status.
- **Code** (UX-DR13):
  - The code block has a filename header and Copy.
  - The JSON viewer is read-only, with line numbers that screen readers don't read.
  - The Copy control writes to the clipboard and shows "Copied" for 2 seconds, announced through a `role="status"` region. A failed copy is announced neutrally and shows no value.
- **Empty and loading states** (UX-DR14):
  - `EmptyState` shows exactly one line and at most one action. With no permitted action (`action` absent), it shows no button.
  - `SkeletonRows` appear only after 300ms of loading. They hold the table's height for its row count and are hidden from assistive tech, while one polite status says loading.
- **Section blocks** (UX-DR21):
  - `StatTile` (label and value).
  - `SettingsRow` (label, description and control slot).
  - `UsageBar` (a native `meter`, or `role="meter"` with min, max and value, plus visible text).
  - `RbacMatrix`: a real table whose `ok` ticks have accessible text.
- **Tests:** the fixture renders every component. `tests/browser` drives every matrix row in Chromium on the Admin surface (and Hosted for the shared ones), with axe in light and dark.

**Never:**
- No router dependency; `useUrlTab` uses the History API only.
- No virtualised or third-party grid.
- No raw colour, size or font value outside token variables.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Table semantics | Render a table with data | `table` with `th scope`, 38px rows, 32px head, numeric cells right-aligned mono | — |
| Paging | 120 rows | Shows rows 1–50; Next shows 51–100; status "51–100 of 120"; Previous disabled on page 1 | — |
| Row activation | Click a row; Enter on its link | `onRowActivate` called once with the row | — |
| Copy in row | Click Copy inside a row | Clipboard written; "Copied" announced; row not activated | — |
| Tabs keyboard | Tab in, arrows, Home/End, Enter | One tab stop; arrows move focus; Enter selects; panel switches | — |
| Tabs URL | Select a tab; press Back | URL param changes; Back restores the previous tab | — |
| Unsaved changes | `canLeave` returns false | Tab and URL unchanged | — |
| Copy feedback | Copy in a code block | "Copied" shown and announced, gone after 2s | Failure announced without the value |
| JSON viewer | Render JSON | Line numbers visible, not read by assistive tech; text read in order | — |
| Empty state | No action given | One line, no button | — |
| Skeleton | Loading for 200ms, then 400ms | No skeleton at 200ms; at 400ms skeleton rows at full table height, one polite status | — |
| Badges | Each badge kind and environment | Correct token colours; dot hidden from assistive tech | — |
| Usage bar | value 30 of 100 | Meter with min, max, value and visible text | — |
| RBAC matrix | Ticks | Table with accessible "allowed" text per tick | — |
| Accessibility | axe over the fixture, light and dark | No violations | Test fails otherwise |

</intent-contract>

## Code Map

- `packages/ui/src/components/` -- the Story 1.14 patterns: `Button.tsx`, `Field.tsx`, CSS Modules over `--gk-ui-*` and `--gk-*` variables, `util.ts` (`mergeRefs`), and `messages.tsx` (catalogue plus `MessagesProvider`).
- `packages/ui/src/index.ts`, `hosted.ts`, `admin.ts` -- entry points. The dependency check walks the imports reachable from `hosted.ts` and from `admin.ts`.
- `packages/ui/src/surface.css` -- per-surface variables.
- `packages/design-tokens/css/tokens.css` -- component tokens for `badge*`, `tabs`, `table*`, `code-block`, `json-viewer`, `empty-state`, `skeleton` and section blocks, as DESIGN.md defines them.
- `tests/browser/fixture/src/Fixture.tsx`, `tests/browser/controls.spec.ts`, `playwright.config.ts` -- the fixture page (`?surface=&scheme=`) and its tests. Add a data fixture section, or a `?page=data` view, and a `data.spec.ts`.
- EXPERIENCE.md "Component Patterns": `table`, `tabs`, Copy control, `code-block`, `empty-state`. DESIGN.md frontmatter `components`.
- Verification runs only in Docker.

## Tasks & Acceptance

**Execution:**
- [ ] `packages/ui/src/components/` -- Badge, Tabs and `useUrlTab`, DataTable with paging, CodeBlock, JsonViewer, CopyButton, EmptyState, SkeletonRows, StatTile, SettingsRow, UsageBar, RbacMatrix; catalogue strings; exports.
- [ ] `tests/browser/fixture/` and `tests/browser/data.spec.ts` -- every matrix row, plus axe.

**Acceptance Criteria:**
- Given a table, when rendered, then it uses real table semantics, 38px rows, 32px heads and 50-row paging, and a Copy control in a row doesn't open the row.
- Given tabs, when one is selected, then the URL changes, the ARIA tab pattern applies, and unsaved changes prompt first.
- Given an empty list or slow page, when it renders, then `empty-state` has one action, and skeleton rows appear after 300ms and hold height.

## Spec Change Log

## Review Triage Log

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; all checks and browser tests pass; Architecture and Isolation pass.
