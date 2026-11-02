---
title: 'Story 1.15: Build data display components'
type: 'feature'
created: '2026-11-03'
status: 'done'
baseline_revision: '7ab15848ec2d7b8f5eb74fa6386aaee2b6e7b62c'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-14-build-shared-form-and-action-components.md'
warnings: [oversized]
deferred:
  - summary: >-
      UsageBar has no warn or bad colouring near or over its limit.
    evidence: |-
      Belongs with the health and rate-limit usage view (Story 11.4).
    location: >-
      packages/ui/src/components/Section.tsx
    severity: low
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
- [x] `packages/ui/src/components/` -- Badge, Tabs and `useUrlTab`, DataTable with paging, CodeBlock, JsonViewer, CopyButton, EmptyState, SkeletonRows, StatTile, SettingsRow, UsageBar, RbacMatrix; catalogue strings; exports.
- [x] `tests/browser/fixture/` and `tests/browser/data.spec.ts` -- every matrix row, plus axe.

**Acceptance Criteria:**
- Given a table, when rendered, then it uses real table semantics, 38px rows, 32px heads and 50-row paging, and a Copy control in a row doesn't open the row.
- Given tabs, when one is selected, then the URL changes, the ARIA tab pattern applies, and unsaved changes prompt first.
- Given an empty list or slow page, when it renders, then `empty-state` has one action, and skeleton rows appear after 300ms and hold height.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 51 findings — high 0, medium 12, low 38, false 1, maybe-false 0
- findings:
  - `[false]` `[reject]` Intent: no Admin page uses the components yet — the story builds the components; pages adopt them in Stories 1.25 onward.
  - `[low]` `[reject]` Intent: nothing checks the Hosted Login bundle — the dependency check walks the `hosted` entry's imports, which is what the bundle can reach.
  - `[medium]` `[patch]` Intent: the skeleton is measured against a formula, not the real table — compared with a `DataTable`.
  - `[low]` `[reject]` Intent: the skeleton is hidden, not absent, before 300ms — it must hold height from the start, which an absent element can't.
  - `[low]` `[reject]` Intent: Previous uses `aria-disabled` — it stays focusable so focus isn't lost, and a forced click does nothing; tested.
  - `[low]` `[reject]` Intent: axe skips contrast on table heads — DESIGN.md documents `tx3` on `sf2` there as a known exception; every other rule and cell is checked.
  - `[medium]` `[patch]` Intent: Back and Forward skip `canLeave` — guarded, URL restored on refusal, tested.
  - `[low]` `[reject]` Intent: a failed copy only changes the announcement — the button returns to "Copy" and the failure is announced; no value is shown either way.
  - `[low]` `[patch]` Intent: "Copy {what}" word order isn't in the catalogue — template added.
  - `[low]` `[reject]` Intent: nothing scans for raw sizes — hairline `1px` borders and the tab underline offset are structural, as in Story 1.14.
  - `[low]` `[reject]` Intent: the new spec doesn't cover the dependency check or focus ring — the existing checks run over every component.
  - `[low]` `[reject]` Intent: the Button hover hook changes a 1.14 file — existing buttons are unchanged and the 1.14 tests still pass; hover tests added.
  - `[medium]` `[patch]` Blind: Back and Forward skip `canLeave`, and an async guard can apply a stale target — same fix as the Intent row, with a re-check after the await.
  - `[medium]` `[patch]` Blind: a second copy failure isn't announced — each copy announces freshly, tested.
  - `[medium]` `[patch]` Blind: JsonViewer crashes on circular or BigInt values and never scrolls vertically — caught, with max height.
  - `[medium]` `[patch]` Blind: skeleton ignores caption and footer — options added and height tested against the table.
  - `[low]` `[patch]` Blind: DataTable misuse unflagged (no row link, several, duplicate keys) — reported in every build.
  - `[medium]` `[patch]` Blind: no empty case and untested props — `empty` slot added; `selectedKey`, controlled page, `hideCaption` and drag-select tested.
  - `[medium]` `[patch]` Blind: UsageBar hides overage — real value announced and shown; near-limit colouring deferred to Story 11.4.
  - `[low]` `[patch]` Blind: RbacMatrix corner has no column header — `th scope="col"` with hidden text.
  - `[low]` `[patch]` Blind: undefined CSS module classes — defined or removed.
  - `[low]` `[patch]` Blind: every panel is a tab stop — only panels without focusable content.
  - `[low]` `[patch]` Blind: mono badges checked against the wrong height — their own tokens.
  - `[low]` `[patch]` Blind: RTL tab arrows untested — added; forced colours and 200% text left as low value.
  - `[low]` `[patch]` Blind: async-guard test uses a fixed sleep — paused clock.
  - `[low]` `[patch]` Blind: duplicate region landmarks in CodeBlock — removed from the `pre`.
  - `[low]` `[patch]` Blind: entry-point identity check weakened — exact admin list restored.
  - `[medium]` `[patch]` Edge: JsonViewer throws on BigInt or circular values — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: stale target after an async guard — same fix.
  - `[low]` `[patch]` Edge: a rejecting `canLeave` leaves an unhandled rejection — treated as stay.
  - `[low]` `[patch]` Edge: tab ids with spaces break IDREFs — encoded.
  - `[low]` `[patch]` Edge: duplicate tab ids unflagged outside DEV — reported in every build.
  - `[low]` `[patch]` Edge: skeleton `delay` turning ≤ 0 never shows — shows at once.
  - `[low]` `[patch]` Edge: `NaN` columns — guarded.
  - `[low]` `[patch]` Edge: `NaN` meter values — guarded.
  - `[low]` `[patch]` Edge: `max < min` meter — guarded.
  - `[low]` `[patch]` Edge: `SettingsRow` description `null` — treated as absent.
  - `[low]` `[patch]` Edge: `EmptyState` icon `null` — treated as absent.
  - `[low]` `[patch]` Edge: `NaN` page size or page — guarded.
  - `[low]` `[patch]` Edge: stale page after rows shrink and grow — clamped.
  - `[low]` `[patch]` Edge: `closest()` matches outside the row — limited to the row.
  - `[low]` `[patch]` Edge: no `rowLink` makes rows pointer-only — reported.
  - `[low]` `[patch]` Edge: focus lost when the pager unmounts — moved to the table.
  - `[low]` `[patch]` Edge: timer leak after unmount — ignored and cleared.
  - `[low]` `[patch]` Edge: inherited placeholders in `formatMessage` — `Object.hasOwn`.
  - `[low]` `[patch]` Edge: unknown badge value renders nothing — falls back to its text.
  - `[medium]` `[patch]` Gap: button hover changes never hovered — hover tests added.
  - `[medium]` `[patch]` Gap: skeleton height checked against a formula — compared with the real table.
  - `[low]` `[patch]` Gap: DataTable selection, controlled page and drag-select untested — tested.
  - `[low]` `[patch]` Gap: Tabs RTL, controlled selection and re-entrancy untested — tested.
  - `[low]` `[patch]` Gap: Copy twice and UsageBar clamping untested — tested.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; all checks and browser tests pass; Architecture and Isolation pass.

## Auto Run Result

Status: done

**Summary:** `packages/ui` gains Badge (status, protocol, Draft, environment, Log code), CopyButton, CodeBlock and JsonViewer, Tabs with `useUrlTab`, DataTable with 50-row paging and an empty slot, EmptyState, SkeletonRows, and the Section blocks (StatTile, SettingsRow, UsageBar, RbacMatrix). Badges, Copy and the code block are shared with Hosted; the rest are in the `admin` entry. A data fixture and Playwright tests cover every behaviour, with axe in light and dark.

**Files:** `packages/ui/src/components/` (the new components and CSS Modules, a Button hover hook), `messages.tsx`, the `index`, `hosted` and `admin` entries; `tests/browser/fixture/src/DataFixture.tsx`, `main.tsx`, `tests/browser/data.spec.ts`, `playwright.config.ts`.

**Review:** 51 findings across four layers: 42 patched, 0 deferred, 9 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. Many medium patches change Tabs history handling, Copy announcements and DataTable state, which only the new browser tests exercise.

**Verification:** see the PR screenshot; the full suite passes in the `tests` container.

**Residual risks:** table heads keep DESIGN.md's documented low-contrast `tx3`, excluded from axe's contrast check. No Admin page uses these components yet.
