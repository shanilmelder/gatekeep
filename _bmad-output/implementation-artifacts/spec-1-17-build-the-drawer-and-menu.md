---
title: 'Story 1.17: Build the drawer and menu'
type: 'feature'
created: '2026-11-03'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-16-build-overlay-and-feedback-components.md'
warnings: [oversized]
deferred: []
---

<intent-contract>

## Intent

**Problem:** Admin needs two more components that behave the same everywhere.
- **Drawer:** a side panel for Log event detail. It shows a code badge, summary rows and raw JSON, and Viewers see no raw detail.
- **Menu:** used for the Tenant switcher, the avatar menu and the User actions menu.

Neither exists yet.

**Approach:** Add `Drawer`, `EventDrawer` and `Menu` to the `admin` entry of `packages/ui`, built the same way as Stories 1.14 to 1.16, and test them in Chromium through the fixture.

## Boundaries & Constraints

**Always:**
- **Conventions from Stories 1.14 to 1.16:**
  - Token variables only, and every built-in text from the catalogue.
  - Native elements, the focus ring and the dependency check.
  - No third-party library.
  - The reduced-motion rule.
  - The exact export lists in the fixture's `main.tsx`.
- **Drawer:**
  - A side panel from the inline end, 440px wide (`drawer-w`), using the `drawer` tokens.
  - Built on a native `<dialog>` opened with `showModal()`, so it takes part in Story 1.16's one-per-document modal registry: while a modal is open, a drawer can't open, and the reverse.
  - Esc and its Close button close it, and focus returns to the trigger, or to the caller's fallback if the trigger is gone, as for `Modal`.
  - Esc already handled by a child is ignored, as in Story 1.16.
  - It has a title and a body that scrolls on its own.
- **EventDrawer:** a drawer laid out for one Log event.
  - A code badge (Story 1.15's mono Log code badge) beside the event title.
  - Summary rows: label and value pairs as a description list.
  - The raw JSON in Story 1.15's `JsonViewer`, with Copy JSON.
  - A `canSeeRaw` prop. When it's false, the JSON section and its Copy are not rendered at all, not merely hidden, and a catalogue note says raw detail is limited to the caller's role (FR-39).
- **Menu:**
  - A trigger button (`aria-haspopup="menu"`, `aria-expanded`) and a popup (`role="menu"` with `menuitem`s) following the ARIA menu button pattern. A click, Enter, Space or ArrowDown opens it on the first item, and ArrowUp opens it on the last.
  - Arrow keys move between items and wrap. Home and End jump to the ends. Typing a character moves to the next item starting with it.
  - Enter or Space activates an item and closes the menu. Esc closes it and returns focus to the trigger, and so does Tab, which also lets focus move on.
  - A click outside closes it. Disabled items are skipped by the arrow keys and can't be activated.
  - The popup is positioned below the trigger and stays inside the viewport. It is not a modal, and the page stays interactive.
  - An item can be a link (`href`) or an action (`onSelect`).
  - A `separator` item is drawn as a divider.
  - The menu has no checkbox or radio items in v1.
- **Tests:** a fixture view at `?page=drawer`, Chromium tests for every row of the matrix below, and axe in light and dark with the drawer open and the menu open.

**Never:**
- No nested submenus. No drawer stacked over a modal, or a modal over a drawer.
- Never render raw event JSON for a caller without `canSeeRaw`.
- No Tenant switcher logic or route changes: those are the shell's (Story 1.25). The menu only renders the items it's given.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Drawer Esc | Open drawer, press Esc | Closes; focus on the trigger | — |
| Drawer close button | Click Close | Same as Esc | — |
| Drawer trigger gone | Trigger removed while open | Focus on the caller's fallback, or the page heading | — |
| Drawer and modal | Open a modal while the drawer is open, and the reverse | Second refused; `console.error` | — |
| Drawer focus | Tab and Shift+Tab many times | Focus stays in the drawer | — |
| Event drawer raw | `canSeeRaw` true | Code badge, summary rows, JSON viewer, Copy JSON | — |
| Event drawer viewer | `canSeeRaw` false | Badge and summary only; DOM has no JSON or Copy; note shown | — |
| Menu open | Enter, Space or ArrowDown on the trigger; ArrowUp | Opens on the first item; ArrowUp opens on the last | — |
| Menu move | ArrowDown, ArrowUp, Home, End, typed letter | Focus moves, wraps, and skips disabled items | — |
| Menu activate | Enter on an item | `onSelect` called; menu closes; focus on the trigger, unless the action moved it | — |
| Menu close | Esc; Tab; outside click | Closes; Esc returns focus to the trigger | — |
| Menu link item | Activate an `href` item | Navigates (fixture records it) | — |
| Accessibility | axe with drawer open and menu open, light and dark | No violations | Test fails otherwise |

</intent-contract>

## Code Map

- `packages/ui/src/components/Modal.tsx`, `modalRegistry.ts` (one per document), `Modal.module.css` -- dialog, focus trap, trigger recording, fallback focus, Esc handling (`defaultPrevented`, `isComposing`). Reuse them; don't copy.
- `packages/ui/src/components/Badge.tsx` (`LogCodeBadge`, mono badge), `JsonViewer.tsx`, `CopyButton.tsx`, `messages.tsx`, `util.ts`, `present.ts`.
- `packages/ui/src/admin.ts`, `hosted.ts`, `index.ts` -- entry points, plus the exact export lists in `tests/browser/fixture/src/main.tsx`.
- `packages/design-tokens/css/tokens.css` -- the `--gk-drawer-*` and `--gk-menu-*` tokens, `--gk-spacing-drawer-w`, elevation and motion.
- `tests/browser/fixture/src/OverlayFixture.tsx`, `tests/browser/overlay.spec.ts`, `playwright.config.ts`. A new spec needs its own project, and an entry in the surface projects' `testIgnore`.
- EXPERIENCE.md `drawer` and `menu` rows, and the "Logs · Event drawer" row.
- Verification runs only in Docker. Database timeouts in Isolation under parallel load pass on rerun.

## Tasks & Acceptance

**Execution:**
- [ ] `packages/ui/src/components/` -- `Drawer`, `EventDrawer`, `Menu`, their CSS Modules, catalogue strings, `admin` exports.
- [ ] `tests/browser/fixture/` and `tests/browser/drawer.spec.ts` -- every matrix row, plus axe.

**Acceptance Criteria:**
- Given a drawer, when Esc is pressed, then it closes and focus returns.
- Given a menu, when it is driven by keyboard, then Enter opens it, arrow keys move, and Esc closes it.

## Spec Change Log

## Review Triage Log

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; all checks and browser tests pass; Architecture and Isolation pass.
