---
title: 'Story 1.16: Build overlay and feedback components'
type: 'feature'
created: '2026-11-03'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-15-build-data-display-components.md'
warnings: [oversized]
deferred: []
---

<intent-contract>

## Intent

**Problem:** Admin pages have no way to confirm an action or report its outcome. They need:
- a modal that is one level deep, traps focus and returns focus correctly;
- typed confirmation;
- a one-time reveal for secrets;
- a toast that never carries an error or a value to copy;
- a persistent status banner.

Story 1.13 also deferred a reduced-motion override for the motion tokens to this story.

**Approach:** Add `Modal`, `ConfirmModal` (including typed confirmation), `OneTimeReveal`, `Toast` (with a provider) and `Banner` to `packages/ui`, built the same way as Stories 1.14 and 1.15. Add a `prefers-reduced-motion` override for every animation. Test it all in Chromium through the fixture.

## Boundaries & Constraints

**Always:**
- **Story 1.14 and 1.15 rules apply:** token variables only, catalogue strings for every built-in text, native elements, the focus ring, the dependency check, no third-party library.
- **Exports:** all of these go in the `admin` entry. Toast and Banner also go in `hosted`, because the Account Portal uses them.
- **Modal:**
  - Built on the native `<dialog>` opened with `showModal()`, so the rest of the page is inert and focus stays inside.
  - It has a title, a body and a footer, drawn from the DESIGN.md `modal` tokens (460px width, `sf`, `sf2` footer, radius `modal`, shadow `sh`) over the `scrim`.
  - Esc and Cancel both close it, and neither confirms anything.
  - On close, focus returns to the element that opened it. If that element is gone, focus goes to a caller-supplied fallback (the next row or the section heading), otherwise to the page's main heading.
  - **One level deep:** a single `ModalProvider` allows one open modal at a time. Opening a second while one is open is refused with a `console.error` in every build, and the first stays open (UX-DR45).
- **Destructive confirm:**
  - `ConfirmModal` with a `destructive` tone uses the outlined destructive button from Story 1.14 as its Confirm.
  - Its body states the impact; the caller supplies the copy.
- **Typed confirmation:**
  - A `confirmText` prop.
  - Confirm stays disabled (`aria-disabled`, with the helper explaining) until the field matches exactly: case-sensitive, no trimming.
  - The helper names what to type.
- **One-time reveal:**
  - `OneTimeReveal` shows a secret once, in a modal with a Copy control (Story 1.15's CopyButton).
  - Close stays disabled until "I've copied this" is ticked. Esc does nothing until then.
  - After closing, the component drops the value from its state and never renders it again, even if re-opened with the same instance. The caller has to pass a new value.
- **Toast:**
  - Admin: a `ToastProvider` with `toast(message: string)` shows one toast for 2.4 seconds, announced through a polite `role="status"`.
  - Portal (Hosted surface): the toast stays in a `role="status"` region until the next call or action, and never covers the focused control.
  - The API accepts only a plain string. It has no error variant, no action, no Copy, and no rich content.
  - A test checks that a toast never contains a button or a link.
- **Banner:** a persistent page-level `Banner` with tones `info`, `warn` and `bad`, drawn from the `banner` tokens. `bad` and `warn` use `role="alert"` only when shown after the page loads; otherwise the banner is plain text. It can have one optional action.
- **Motion:**
  - The modal and toast animate with DESIGN.md's motion: 150–200ms, a 6px rise and a fade.
  - Under `prefers-reduced-motion: reduce`, every animation and transition in `packages/ui` is removed, through one shared rule.
- **Tests:** the fixture gets a `?page=overlay` view. Every matrix row is tested in Chromium, with axe in light and dark, with a modal open and with a banner and a toast shown.

**Never:**
- No stacked or nested modals, and no modal library.
- No error, value to copy, or action in a toast.
- No re-authentication gate. The WebAuthn sheet inside the confirm modal is Story 1.26's job, and this story leaves a slot for it.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Focus trap | Open modal, Tab and Shift+Tab many times | Focus never leaves the modal; the page behind is inert | — |
| Esc and Cancel | Press Esc; click Cancel | Modal closes; confirm callback not called | — |
| Focus return | Close a modal opened from a button | Focus on that button | — |
| Trigger gone | The trigger row is deleted by the action | Focus on the caller's fallback (next row) | Page heading if no fallback |
| One level | Try to open a second modal while one is open | Refused; first stays; `console.error` | — |
| Typed confirm | Type a near-match (wrong case, extra space), then the exact value | Confirm disabled until exact; then enabled | — |
| Reveal close | Untick, press Esc, click Close | Nothing closes until ticked; then Close works | — |
| Reveal gone | Close, then reopen the same instance | Value not rendered; DOM holds no copy of it | — |
| Toast admin | `toast("Saved")` | Shown and announced; gone after 2.4s | — |
| Toast portal | On Hosted, `toast(...)`, then another action | Stays until the next action; never over the focused control | — |
| Toast content | Inspect toast | No button, link or copy control | Test fails otherwise |
| Banner | Each tone, shown at load and after load | Token colours; `role="alert"` only when added after load | — |
| Reduced motion | `prefers-reduced-motion: reduce`, open modal | No animation or transition durations | — |
| Accessibility | axe with modal open, toast and banner shown, light and dark | No violations | Test fails otherwise |

</intent-contract>

## Code Map

- `packages/ui/src/components/` -- the Story 1.14 and 1.15 patterns:
  - `Button.tsx` (variants, `destructive`, `aria-disabled`), `Field.tsx`, `Checkbox` in `Choice.tsx`.
  - `CopyButton.tsx`, `messages.tsx` (catalogue, `formatMessage`, `MessagesProvider`), `util.ts`, `present.ts`.
- `packages/ui/src/index.ts`, `hosted.ts`, `admin.ts` -- entry points. The fixture's `main.tsx` checks the exact admin and hosted export lists, so update both lists.
- `packages/design-tokens/css/tokens.css` -- the variables for `--gk-modal-*`, `--gk-toast-*`, `--gk-banner-*`, `--gk-elevation-scrim`, the motion durations, easing and rise.
- `tests/browser/fixture/src/` (`Fixture.tsx`, `DataFixture.tsx`, `main.tsx`), `tests/browser/data.spec.ts`, `playwright.config.ts`. A new spec file needs its own project, and must be added to the surface projects' `testIgnore` list next to `data.spec.ts`.
- The EXPERIENCE.md "Component Patterns" rows for `modal`, `toast`, `banner`, typed confirmation and one-time reveal.
- Verification runs only in Docker. Parallel sessions can cause database timeouts in the Isolation tests; rerun those tests on their own.

## Tasks & Acceptance

**Execution:**
- [ ] `packages/ui/src/components/` -- `Modal`, `ModalProvider`, `ConfirmModal`, `OneTimeReveal`, `ToastProvider` with `useToast`, `Banner`; the shared reduced-motion rule; catalogue strings; exports.
- [ ] `tests/browser/fixture/` and `tests/browser/overlay.spec.ts` -- every matrix row, plus axe.

**Acceptance Criteria:**
- Given a modal, when it opens, then focus is trapped, Esc and Cancel close it, focus returns to the trigger or next row, and no second modal can open over it.
- Given typed confirmation, when the value doesn't match exactly, then Confirm stays disabled.
- Given a one-time reveal, when "I've copied this" isn't ticked, then Close stays disabled, and the value is never rendered again after closing.
- Given a toast, when it's used, then it never carries an error or a value to copy.

## Spec Change Log

## Review Triage Log

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; all checks and browser tests pass; Architecture and Isolation pass.
