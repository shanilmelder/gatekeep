---
title: 'Story 1.25: Open the Admin shell'
type: 'feature'
created: '2026-11-04'
status: 'ready-for-dev'
baseline_revision: '7136f28a48545722b4efcf3960a80fd53aad1572'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md'
  - '{project-root}/design/Gatekeep Admin.dc.html'
warnings: []
deferred: []
---

<intent-contract>

## Intent

**Problem:** After sign-in the Admin Dashboard shows a placeholder: `RootPage` in `apps/admin-dashboard/src/main.tsx` renders "Admin Dashboard" and a Sign out button, and any other path renders the same text. FR-44, UX-DR19, UX-DR20 and UX-DR40 require a shell:
- a 48px top bar with the brand, a theme toggle and an avatar menu, and no global search or alerts bell;
- a sidebar of the nine v1 groups that becomes an icon rail below 1100px, with the Deployment group shown only to Deployment Owners;
- a main area that scrolls while the window never does.

UX-DR22 adds two global states: the forbidden page ("You don't have access to this page." with the trace ID) and session expiry (a WebAuthn sheet and a `banner`, with unsaved values kept). UX-DR23 says the capabilities endpoint drives what shows, and hiding is never the control. Story 1.24 built both capability endpoints and the one 403 `access_denied` body with its `traceId`, but nothing in the dashboard reads them. NFR-17 makes the dashboard desktop-first and responsive to tablet, and EXPERIENCE marks widths below 768px as unsupported. Nothing documents that yet.

No shell page exists yet. Bootstrap, sign-in and credential setup are pre-Session Hosted cards and stay outside the shell. The Design Delta removes the export's Overview group and its Get started and Home pages ("Create Tenant replaces them", Story 1.27). Every Tenant page and every Deployment page belongs to a later story. Two items in `deferred-work.md` name Story 1.25:
- "Audit Admin Session expiry, and show the expiry banner (Epic 7, and Story 1.25's shell)": this story shows the banner, and the audit stays with Epic 7.
- "Make Hosted Login follow prefers-color-scheme … surface stories 1.18 and 1.25": the Admin part is settled here. The pre-Session cards keep following the device, and only the shell takes the manual toggle. The Hosted Login app's own `index.html` stays with Story 4.1.

**Approach:**
- **Presentational shell in `@gatekeep/ui/admin`:** `AdminShell`, `TopBar`, `Sidebar`, `ThemeToggle`, `SectionPage` and `ADMIN_NAV_GROUPS` (the nine v1 groups in EXPERIENCE order, with labels from the catalogue and icons). They are props-only, use CSS Modules and tokens, and are tested in the browser fixture at `?page=shell`, where sample items are available.
- **Wiring in `apps/admin-dashboard`:**
  - the route table;
  - the item registry, which is empty in this story;
  - the capability reads;
  - the scheme choice;
  - Session renewal;
  - the landing, forbidden and not-found pages.
- **Capabilities:** the shell reads `GET /api/v1/deployment/capabilities` when it mounts and on every in-shell navigation. On a `/tenants/{tenantId}/…` path it also reads `GET /api/v1/tenants/{tenantId}/capabilities`. Nothing is cached across navigations or stored. A sidebar item is listed only when its declared capability is held, and a group with no listed item isn't rendered. The server still refuses everything on its own (Story 1.24).
- **Forbidden page:** it is shown only for a server 403 `access_denied`, and uses that response's `traceId`. A direct URL to a Tenant path where the Admin holds no role reaches it through the Tenant capabilities read. Later pages reach it through their own load requests by the same path.
- **Session renewal:** a 401 on any shell request after the shell has mounted keeps the page mounted. It shows a `warn` `banner` explaining why, opens the browser's WebAuthn sheet through the existing sign-in endpoints, and then sends the interrupted request once more.
- **No server change:** the API contract, `packages/api-client` and the Admin CSP are unchanged.

## Boundaries & Constraints

**Always:**
- **Routes (`apps/admin-dashboard/src/main.tsx`), with no router library (the existing `navigation.ts`):**

  | Path | Renders |
  | --- | --- |
  | `/bootstrap`, `/signin`, `/setup/credentials` | Unchanged: the pre-Session Hosted cards, outside the shell |
  | `/` | The shell, with the landing page |
  | `/tenants/{tenantId}` and `/tenants/{tenantId}/…` | The shell. It reads the path Tenant's capabilities first. `access_denied` gives the forbidden page. 200 gives the matching Tenant page, and since none is built yet, the not-found page. |
  | Anything else | The shell, with the not-found page |

  - The `{tenantId}` segment goes to `api.getTenantCapabilities` exactly as it appears in the URL (the client already `encodeURIComponent`s it). The dashboard never parses or validates it. Only the server decides.
  - No Tenant is held anywhere but the URL: no web storage, cookie or module variable (AD-19).
- **Shell boot (replaces `RootPage`):**
  - The Session read keeps its Story 1.23 behaviour. A 401 goes to `/signin`. `setupComplete: false` goes to `/setup/credentials`. Any other failure shows the Hosted Generic error, whose action reloads the path. Until the read answers, nothing renders, as on credential setup.
  - When the read succeeds, the shell renders. The CSRF token stays in memory only (`session.ts`).
  - The Admin ID from the Session is kept in memory for the renewal check (below).
  - The Deployment capabilities read then fills the sidebar. While it is pending, the content area shows `SkeletonRows` after the 300ms delay, and the top bar and sidebar stay visible.
- **Capabilities (`apps/admin-dashboard/src/shell/capabilities.ts`):**
  - A `CapabilitiesProvider` holds the two lists the current route read: Deployment, and the path Tenant's, or none. Pages ask it `has(capability)`. Capability names are the generated `CapabilitiesResponse` union, never a hand-written string.
  - Both lists are read again on every in-shell navigation, by the brand link, a sidebar item or a browser back or forward. Nothing is cached across navigations, so a Tenant Role removed mid-session counts on the next navigation (Story 8.4).
  - The UI never names a role, compares roles or reads `deploymentOwner` to decide what shows. Only capability names decide (AD-20: the table is the only encoding of FR-39).
- **Sidebar items (`apps/admin-dashboard/src/shell/nav.ts`):**
  - Each item is `{ group, label, href, requires }`:
    - `group` is one of the nine group IDs;
    - `label` is a message key;
    - `requires` is the capability its page reads. A `deployment` group item must require a `deployment.*` capability, and every other group a `tenant.*` one, which the types enforce. A Tenant item's `href` is built from the current path Tenant.
  - In this story the registry has **no items**, because no shell page exists. Later stories each add their own item with their page.
  - Visible items are the registry filtered by `has(requires)`. Tenant items are also filtered by there being a path Tenant.
  - The Deployment group is therefore shown only to an Admin holding Deployment capabilities, that is the Deployment Owner. Every Tenant group shows to every role, because every Tenant Role holds `tenant.configuration.read` (EXPERIENCE: "visible to every role").
- **`ADMIN_NAV_GROUPS` (`packages/ui`):** exactly these nine, in this order, with these labels, which come from the message catalogue:
  1. Applications
  2. Authentication
  3. User management
  4. Authorization
  5. Security
  6. Branding
  7. Monitoring
  8. Settings
  9. Deployment

  There is no Overview group. Icons are the export's `NAV` SVG paths (`design/Gatekeep Admin.dc.html` L1252–1261) for the eight groups it draws. Deployment has no icon in the export, so it takes a stacked-layers path `[ASSUMPTION]`. Icons are inline SVG elements with `aria-hidden="true"`, never `data:` URIs.
- **`Sidebar` (`packages/ui`):**
  - It takes `items` (`{ group, label, href }`), `currentHref` and `onNavigate(href)`. It renders the groups in `ADMIN_NAV_GROUPS` order, leaves out any group with no item, and lays out nothing for an item it isn't given.
  - It is one `<nav>` named "Main" (catalogue). With no items it is still rendered, empty, at its width.
  - **Wide (≥ 1100px), 236px:**
    - Each group is a disclosure: a `<button aria-expanded aria-controls>` with its icon, label and chevron, over a list of item links.
    - The group holding the current page starts open, and the open state lives in memory only.
    - The current item has `aria-current="page"`, and DESIGN's active style: `tx`, `sf2`, weight 500 and a 2px left rule.
  - **Rail (< 1100px), 52px:**
    - Each group is one link to its first listed item. Its name is the group label, in a visually hidden span that is kept translatable, with `title` set to the same label.
    - The link has `aria-current="true"` when the current page is in that group. No item list renders.
  - The width comes from `useMediaQuery('(min-width: 1100px)')`, built on `useSyncExternalStore` over `matchMedia`, so the first render is already correct. The CSS styles a `data-rail` attribute and has no second media query that could disagree.
  - Plain left clicks call `onNavigate`. Modified clicks (new tab or window) fall through to the browser.
- **`TopBar` (`packages/ui`), 48px (`--gk-top-bar-height`), `sf` with a `bd` bottom border, a `<header>` landmark:**
  - **Brand:** an `<a href="/">` holding the mark (the export's two bars, built in CSS) and the wordmark "gatekeep". The wordmark is visually hidden below 1100px but stays the link's name. At ≥ 1100px the brand is 208px wide.
  - **Right side, in order:** `ThemeToggle`, then the avatar `Menu` (Story 1.17) with `align="end"`.
  - **Not rendered:**
    - global search, ⌘K, the alerts bell and any badge on it (v2);
    - the Tenant switcher (Story 1.28);
    - Help, which opens an API reference that doesn't exist until Story 17.5. FR-44 says deferred features don't appear in any form.
- **Avatar menu:**
  - The trigger is a 28px circle showing a generic person glyph, because the Session carries no name or email. It is named "Account" `[ASSUMPTION]`.
  - Items: **Sign out** only. Your credentials arrives with Story 1.26.
  - Sign out moves here from the root placeholder and keeps its Story 1.23 behaviour:
    - `DELETE /api/v1/deployment/session` with the CSRF token;
    - 204 or 401 clears the token and goes to `/signin`;
    - anything else shows the existing `signOutFailed` `banner` at the top of the content area;
    - a second activation sends nothing.
  - Sign out never triggers Session renewal.
- **Theme (`apps/admin-dashboard/src/shell/theme.ts`, `ThemeToggle` in `packages/ui`):**
  - `index.html` sets `<html data-gk-surface="admin" data-gk-scheme="auto">`, so CSS alone follows the device before any script runs.
  - **Shell routes:** `<html>` takes the stored choice (`light` or `dark`) or stays `auto`.
  - **Pre-Session routes:** `<html>` is set back to `auto`, matching `HostedPage`'s own `auto` scope, so the canvas and the card agree. The cards never take the manual choice.
  - `ThemeToggle` is a `button` named "Dark theme" with `aria-pressed`, which is true when the current scheme is dark, whether chosen or resolved from the device. Activating it flips the scheme, sets `data-gk-scheme` and stores the choice under the `localStorage` key `gatekeep.admin.scheme`.
  - Every storage read and write is in `try`/`catch`. A failure leaves the choice in memory and still applies it.
  - The scheme is the only thing the dashboard ever writes to web storage.
- **`AdminShell` layout (`packages/ui`):**
  - It is a grid: the top bar row over a `sidebar | main` row, at `100dvh` with `overflow: hidden`. Only `<main>` scrolls (`overflow: auto`), so the window never scrolls at any width.
  - Its `banner` slot sits at the top of `<main>`, above the page. Its `children` (the page) are never unmounted or re-keyed when the banner changes.
  - On an in-shell navigation, focus moves to the new page's `h1` (`tabIndex={-1}`). It doesn't move on the first load.
- **`SectionPage` (`packages/ui`), the Section page template (export L1143):**
  - Props:
    - `eyebrow`: the crumb, in `--gk-font-label`, uppercase, `tx3`;
    - `title`: one `h1`, in `--gk-font-page-title`;
    - `description`: `tx2`;
    - `actions`: at most one primary;
    - optional `tabs`, which take the Story 1.15 `Tabs`;
    - `children`: the blocks grid.
  - Spacing follows the export: header padding 20px and `--gk-space-page-padding`. The blocks grid uses `repeat(auto-fit, minmax(min(100%, 440px), 1fr))` with a 16px gap and a maximum width of 1440px.
  - Every page in this story is a `SectionPage`.
- **Pages (exact copy, from `messages.tsx`):**
  - **Landing (`/`):**
    - `SectionPage` with the title "Admin Dashboard" `[ASSUMPTION]` and an `EmptyState` with no action.
    - With `deployment.tenants.read` held, the message is "No Tenants yet." `[ASSUMPTION]`. Story 1.27 replaces this with the create-Tenant form.
    - Otherwise it is "You don't have access to a Tenant yet. Ask a Deployment Owner." (EXPERIENCE; Story 1.28 owns the final landing rules).
  - **Forbidden:**
    - `SectionPage` with the title "You don't have access to this page."
    - An `ErrorReference` showing the code `access_denied` and the response's `traceId`, with its Copy.
    - No other text, and no hint whether the Tenant exists.
  - **Not found:** `SectionPage` with the title "This no longer exists." `[ASSUMPTION]` and a link, "Back to Admin Dashboard" `[ASSUMPTION]`, to `/`.
  - **Service failure:** a capabilities read that fails with a 5xx, a network error or a 2xx with no list shows a `bad` `banner`, "We couldn't load this page." `[ASSUMPTION]`, with an `ErrorReference` holding the trace ID when there is one and a **Retry** action that reads again. The sidebar shows only what was already read.
- **Session renewal (`apps/admin-dashboard/src/shell/renewal.ts`):**
  - Every request the shell and its pages make goes through one `shellRequest(call)` wrapper. Before the shell has mounted, the boot read keeps its plain 401 → `/signin`.
  - **On a 401:**
    1. The shell sets its banner: `warn`, `live`, "Your session expired. Sign in to continue. Nothing you entered has been lost." `[ASSUMPTION]`, with the action **Sign in**.
    2. It then starts the sheet at once: `beginSignIn`, then `navigator.credentials.get` with the `webauthn.ts` helpers, then `completeSignIn`.
    3. If the browser refuses for lack of user activation, or the Admin cancels, the banner stays, and its **Sign in** action opens the sheet again.
  - **One renewal at a time:** concurrent 401s wait on the same promise.
  - **On success:**
    - The new CSRF token replaces the old one.
    - If the signed-in `adminId` equals the shell's, the banner clears and each waiting request is sent **once** more. A 401 refuses before any handler runs, so nothing was applied.
    - If it is another Admin, `window.location.assign('/')`. The values belonged to the other Admin's context and aren't carried over.
    - If `setupComplete` is false, go to `/setup/credentials`.
  - **On failure:** a refused sign-in (400) keeps the banner with "That credential wasn't recognised." A 429 shows "Too many sign-in attempts. Try again in {seconds} seconds." `[ASSUMPTION]`, taken from `Retry-After`. A 5xx or network error shows the service-failure text. In every case the page stays mounted with its values, and **Sign in** retries.
  - A waiting request that never renews stays pending. The page's own pending state holds its form read-only, per EXPERIENCE's action pending state.
- **Copy:** every string above goes in the `@gatekeep/ui` catalogue (`messages.tsx`, NFR-19): the nine group labels, "Main", "Account", "Dark theme", the landing, forbidden, not-found, session-expired, rate-limit and service-failure texts, "Retry", and "Back to Admin Dashboard". Existing keys are reused where they exist (`signOut`, `signOutFailed`, `signInAction`, `signInRefused`, `productName`).
- **CSP (AD-21; `tests/browser/admin-csp.spec.ts`):**
  - Nothing inline: no `style` prop, `<style>` element, inline script, `data:` or `blob:` URI, or `on*` attribute in markup.
  - Styles are CSS Modules, and values come from tokens only (the raw-hex lint).
  - The default Vite build keeps `assetsInlineLimit: 0`.
  - Every new browser test watches for `securitypolicyviolation` and fails on any.
- **Tests (Playwright with axe, all in Docker):**
  - **Fixture (`tests/browser/fixture`, `?page=shell`, new project `shell`, `shell.spec.ts`):** `AdminShell` with sample items in every group and long content.
    - Layout at 1280, 1100, 1099, 768 and 767px:
      - full sidebar (236px) at 1100 and above, and a rail (52px) below;
      - the brand wordmark visible only at 1100 and above, with its name kept;
      - the window never scrolls (`scrollingElement.scrollHeight === innerHeight`) while `<main>` does.
    - Sidebar:
      - groups render in the `ADMIN_NAV_GROUPS` order, with the nine EXPERIENCE labels written literally in the test;
      - a group with no item isn't rendered;
      - wide disclosure: `aria-expanded`, the current group open, `aria-current="page"`;
      - rail: each group is a link named by its label, pointing to its first item, with `aria-current="true"`;
      - Tab order and Enter or Space on disclosures;
      - plain clicks call `onNavigate`, and modified clicks don't.
    - Top bar: a `banner` landmark with the brand link, `ThemeToggle` and the avatar menu, and no `searchbox`, textbox or "Alerts" or "Help" control.
    - `ThemeToggle`: `aria-pressed` and the callback.
    - `SectionPage`: one `h1`, eyebrow, description and actions.
    - Values kept: an input inside the shell keeps a typed value, its focus and its DOM node when the `banner` slot is set and cleared.
    - axe has no violations in light and dark, at 1100 and 768, with a group open and with the avatar menu open.
  - **Dashboard (built Host.Admin via `admin-host.mjs`, from `localhost`, with the API intercepted and a Chromium virtual authenticator; new project `admin-shell`, `admin-shell.spec.ts`):** every row of the I/O matrix below except the fixture-only rows.
    - axe has no violations on the landing, forbidden, not-found, session-expired and service-failure states, in light and dark (the toggle, and `emulateMedia` for `auto`), at 1100 and 768.
  - **Existing specs:** `signin.spec.ts` and `credential-setup.spec.ts` now expect the shell's landing (the "Admin Dashboard" `h1`) after sign-in or setup, and reach Sign out through the avatar menu. Their assertions are otherwise unchanged. `admin-csp.spec.ts` is unchanged and must still pass.
- **Docs:**
  - **`docs/install.md`:**
    - Add a short "Using the Admin Dashboard" section: desktop-first; full sidebar at 1100px and wider; icon rail from 768 to 1099px; **below 768px is unsupported** (NFR-17), meaning not designed, not tested and with no page notice; the scheme toggle is per browser.
    - Update the "Not yet covered" bullet: the dashboard has its shell, and Tenant and Deployment pages arrive from Story 1.27 on.
  - **`docs/threat-model.md`:** add one sentence to T-19: the Dashboard hides by the capability lists but never relies on that; the server refuses on its own (Story 1.24); the forbidden page shows only a server `access_denied`.
  - **`deferred-work.md`:** narrow the two Story 1.25 items as described in the Problem, and add the out-of-scope items below.

**Ask First:**
- **An empty sidebar for now.** The registry has no items until Story 1.27 adds Tenants (Deployment group) and Epic 3 adds Applications. Until then the sidebar renders as an empty `nav` at its width, and the landing is a holding page. The alternative is to add a Home or Overview page, which the Design Delta removes ("Create Tenant replaces them"). Confirm the empty sidebar before implementing.
- **Retrying the interrupted request after renewal.** The spec resends it once, only when the same Admin signed in again. The alternative is that the Admin repeats the action. Confirm before changing.
- Any server change. None is expected. If one turns out to be needed, stop. It would need Isolation tests and a regenerated API contract (`sh deploy/docker/api-contract.sh --write <abs dir>`), as in Story 1.24.
- Any copy marked `[ASSUMPTION]` above that a reviewer wants changed, and any new top-bar control.

**Never:**
- No client-side authorization: no role names, no `deploymentOwner` checks for visibility, no restating of FR-39. No forbidden page without a server `access_denied`. No "hidden therefore safe" reasoning.
- No caching of capabilities across navigations. No capability, Tenant, Session ID or CSRF token in web storage, a cookie set by script, or the URL query.
- No Tenant switcher, Help or API reference link, Your credentials item, global search, alerts bell, Overview or Home page, or any disabled or "coming soon" item (FR-44: deferred features don't appear in any form).
- No page notice or alternative layout below 768px.
- No router or state library, and no new runtime dependency in `apps/admin-dashboard` or `packages/ui` (the `check-dependencies` script).
- No inline style or script, and no CSP change.
- No server, API contract or `packages/api-client` change.
- No change to the pre-Session pages' behaviour beyond the `<html>` scheme reset.
- **Out of scope**, recorded in `deferred-work.md`:
  - the Tenant switcher, the current Tenant name and environment badge, Tenant mismatch, and the final landing rules (Story 1.28);
  - Your credentials in the avatar menu (Story 1.26);
  - Help opening the API reference (Story 17.5);
  - the create-Tenant landing and the first Deployment item (Story 1.27);
  - auditing Session expiry (Epic 7);
  - the "role removed mid-session" and "Tenant deleted" banners (Story 8.4, Story 1.29);
  - proving renewal keeps values in a real form on a real page (Story 1.27's Create Tenant is the first);
  - Tenant page titles in `<title>`.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Shell loads | Full Session, Owner; capabilities = all 8 `deployment.*` | Top bar: brand link, "Dark theme" toggle, "Account" menu. No search, bell, Help or switcher. Empty `nav` "Main". Landing `h1` "Admin Dashboard", "No Tenants yet." | — |
| Non-Owner landing | Capabilities `[]` | Landing shows "You don't have access to a Tenant yet. Ask a Deployment Owner." No Deployment group could show. | — |
| No Session | Session read 401 at boot | Goes to `/signin`, with no shell rendered and no renewal | — |
| Setup incomplete | `setupComplete: false` | Goes to `/setup/credentials` | — |
| Boot failure | Session read 503, 429, bodiless 403, network error, or 2xx with no CSRF token | Hosted Generic error with the code and trace ID, and no shell. Its action reloads the path. | Unchanged from Story 1.23 |
| Width ≥ 1100 | Viewport 1100 and 1280 | Sidebar 236px, wordmark visible, window doesn't scroll | — |
| Width 768–1099 | Viewport 1099 and 768 | Icon rail 52px, wordmark visually hidden but the link still named, window doesn't scroll | — |
| Width < 768 | Viewport 767 | Same rail layout. No notice. Sign out is still reachable (smoke test only). `docs/install.md` states it's unsupported. | Unsupported, by doc |
| Sidebar gating (fixture) | Items in every group; a Deployment item and Tenant items | Only the given items. Empty groups are left out. Order is the nine EXPERIENCE groups. Wide is a disclosure, rail is a link per group. | — |
| Sidebar gating (dashboard) | Owner or non-Owner, the registry empty | The `nav` "Main" renders with no group and no link for either. The `requires` type rule is checked by `tsc` in the build. | — |
| Forbidden by URL | Direct load of `/tenants/ten_x/applications`; Tenant capabilities 403 `{code:"access_denied", traceId:"t-1"}` | Shell visible. `h1` "You don't have access to this page." `ErrorReference` code `access_denied`, trace ID `t-1`, with Copy. | — |
| Malformed Tenant in URL | `/tenants/NOT-AN-ID` | Sent to the server as is (encoded). Its 403 `access_denied` gives the same forbidden page. The dashboard never decides. | 403 |
| Tenant allowed | Tenant capabilities 200 | Not-found page, because no Tenant page exists yet | — |
| Unknown path | `/nope` | Shell with "This no longer exists." and the link to `/` | — |
| Capabilities failure | Deployment capabilities 503, network error, or 2xx with no list | `bad` banner "We couldn't load this page.", trace ID when present, Retry reads again. The top bar and Sign out still work. | Banner |
| Navigation re-reads | Brand link clicked twice | Each in-shell navigation sends a fresh capabilities read. Nothing is read from storage. | — |
| Focus on navigation | In-shell navigation | Focus moves to the new page's `h1`. On first load it stays on the document. | — |
| Theme toggle | Click "Dark theme" | `aria-pressed="true"`, `<html data-gk-scheme="dark">`, stored. A reload keeps dark. Pressing it again gives light. | — |
| Theme default | No stored choice; `emulateMedia` dark | `<html data-gk-scheme="auto">`. The toggle shows pressed. Tokens resolve dark. | — |
| Storage unavailable | `localStorage` throws | The toggle still switches for this page, with no error | Caught |
| Pre-Session scheme | Stored `dark`, then go to `/signin` | `<html data-gk-scheme="auto">`. The card follows the device. | — |
| Sign out | Avatar menu, then Sign out; DELETE 204 (or 401) | The CSRF header is sent, the token cleared, `/signin` reached, one DELETE only | — |
| Sign out fails | DELETE 503 or network error | The `signOutFailed` banner in the content area. Sign out stays available. | Banner |
| Session expired on an act | Shell mounted; marker set on `window` and on the content node; Session and capabilities now answer 401; the brand link clicked | Banner "Your session expired…" (`warn`, live) and the sheet opens. The virtual authenticator answers. Complete returns the same `adminId` and a new CSRF token. The capabilities read is resent once and the banner clears. The `window` marker and the same content node remain: no reload, no remount. | — |
| Values kept (fixture) | Text typed into an input in the shell; banner set, then cleared | Same value, same node, focus kept | — |
| Renewal cancelled | The sheet is cancelled, or `NotAllowedError` with no user activation | The banner stays and its Sign in action reopens the sheet. Nothing is resent. | — |
| Renewal refused | Complete 400 | Banner text "That credential wasn't recognised."; Sign in retries | Banner |
| Renewal rate-limited | Begin or complete 429 with `Retry-After: 30` | "Too many sign-in attempts. Try again in 30 seconds." | Banner |
| Another Admin renews | Complete returns a different `adminId` | Full load of `/`. Nothing is resent. | — |
| Concurrent 401s | Two shell requests both get 401 | One renewal (one begin, one complete), then each request is resent once | — |
| Second 401 after renewal | The resent request gets 401 again | The banner shows again. No loop: at most one resend per renewal. | — |
| CSP | Every dashboard test | No `securitypolicyviolation`, no console CSP message, no request to another origin | Test fails |
| axe | Landing, forbidden, not found, banners, menu open; light and dark; 1100 and 768 | No violations | Test fails |

</intent-contract>

## Code Map

- `packages/ui/src/components/`:
  - new `AdminShell.tsx` and `.module.css`: the grid, the `banner` slot, `main` scroll, and focus to `h1` on `pageKey` change;
  - new `TopBar.tsx` and `.module.css`: brand, wordmark and the right-hand slot;
  - new `Sidebar.tsx` and `.module.css`: groups, disclosure, rail and `data-rail`;
  - new `adminNav.tsx`: `ADMIN_NAV_GROUPS`, the nine IDs, message keys and icons;
  - new `ThemeToggle.tsx`;
  - new `SectionPage.tsx` and `.module.css`;
  - new `useMediaQuery.ts`.
- `packages/ui/src/admin.ts`: export the new components, the `AdminNavGroupId` and `AdminNavItem` types, and `useMediaQuery`. `index.ts` and the hosted entry are unchanged: the fixture's exact `HOSTED` list must still pass.
- `packages/ui/src/messages.tsx`: the new keys and English defaults.
- `apps/admin-dashboard/`:
  - `index.html`: `data-gk-scheme="auto"`.
  - `src/main.tsx`: the route table. `RootPage` is removed, and the shell route takes over its Session boot.
  - new `src/shell/Shell.tsx`: boot, providers, the top bar wiring (theme, avatar menu, Sign out), the sidebar wiring and page selection.
  - new `src/shell/capabilities.ts`: `CapabilitiesProvider`, `useCapabilities`, and the reads on every navigation.
  - new `src/shell/nav.ts`: the item registry, empty, with typed `requires`.
  - new `src/shell/renewal.ts`: `shellRequest`, the single-flight renewal and the banner state.
  - new `src/shell/theme.ts`: the stored choice and the `<html>` scheme for shell and pre-Session routes.
  - new `src/shell/LandingPage.tsx`, `ForbiddenPage.tsx` and `NotFoundPage.tsx`.
  - `src/webauthn.ts`: reused as is for renewal.
- `tests/browser/`:
  - `fixture/src/ShellFixture.tsx` (new) and `fixture/src/main.tsx` (`shell` added to `pages`);
  - new `shell.spec.ts`;
  - new `admin-shell.spec.ts`;
  - `playwright.config.ts`: the `shell` and `admin-shell` projects, both added to the default projects' `testIgnore`, and the header comment;
  - `signin.spec.ts` and `credential-setup.spec.ts`: the landing and avatar-menu updates.
- `docs/install.md`, `docs/threat-model.md` (T-19), `_bmad-output/implementation-artifacts/deferred-work.md`.

## Tasks & Acceptance

**Execution:**
- [ ] `packages/ui`: `useMediaQuery`, `ADMIN_NAV_GROUPS`, `Sidebar`, `TopBar`, `ThemeToggle`, `SectionPage`, `AdminShell`, the exports and the catalogue keys. `pnpm --filter @gatekeep/ui check` passes (raw-hex and dependency checks).
- [ ] Fixture page `shell` and `shell.spec.ts`: layout at each width, sidebar order and gating, disclosure and rail semantics, top bar contents, values kept, and axe in light and dark at 1100 and 768.
- [ ] Dashboard: the route table, the shell boot replacing `RootPage`, the capabilities provider and reads on every navigation, the empty registry, the theme, the avatar menu with Sign out, and the landing, forbidden, not-found and service-failure pages.
- [ ] Dashboard: `shellRequest` and single-flight renewal, with the banner, the sheet, resend-once, the Admin ID check, and the refused, cancelled and rate-limited cases.
- [ ] `admin-shell.spec.ts`: every dashboard matrix row, with CSP watching and axe. Update `signin.spec.ts` and `credential-setup.spec.ts`. Add the projects to `playwright.config.ts`.
- [ ] Docs: `install.md` ("Using the Admin Dashboard", and the "Not yet covered" bullet), threat model T-19, and `deferred-work.md` (narrow the two 1.25 items, add the out-of-scope items).

**Acceptance Criteria:**
- Given a signed-in Admin, when the shell loads, then the top bar has the brand, the theme toggle and the avatar menu (with Sign out), and no global search, alerts bell, Help or Tenant switcher.
- Given a window narrower than 1100px, when the shell renders, then the sidebar is a 52px icon rail whose group links keep their names. At 1100px and wider it is the full 236px sidebar. The window never scrolls at either.
- Given the sidebar, when it renders, then it lists only items for built pages whose capability the Admin holds, within the nine v1 groups in EXPERIENCE order, leaving empty groups out. The Deployment group can show only with Deployment capabilities. In this story no item is built, and later stories add their own.
- Given a page below 768px wide, when it loads, then the layout is the rail layout with no notice, and `docs/install.md` documents widths below 768px as unsupported.
- Given a direct URL to a page the Admin can't reach, when it loads, then the server's 403 `access_denied` shows "You don't have access to this page." with that response's trace ID, inside the shell.
- Given an expired Admin Session with unsaved values, when the Admin next acts, then the WebAuthn sheet appears with a `banner` explaining why, the page stays mounted with its values, and after the same Admin signs in again the interrupted request is sent once more.
- Given every new and changed browser test, when it runs, then no CSP violation occurs and axe finds no violation in light and dark at 1100 and 768px.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Why the sidebar is empty:** "Only pages built so far" plus the Design Delta, which removes the Overview group and the Home and Get started pages, leaves no item in this story. Every v1 page lives in a Tenant group (Epic 3 onward) or the Deployment group (Story 1.27 onward). Inventing a Home page to have something to list would ship a page the Delta removes. The sidebar's behaviour (order, gating, empty groups, disclosure and rail) is fully tested in the fixture with sample items, so the first story that adds an item adds only a registry entry and its page.
- **Presentational in `packages/ui`, wiring in the app:** AD-22 puts shared components in `@gatekeep/ui/admin`, and the fixture is the only place the sidebar can be exercised with items. The app keeps everything that touches the API, the URL or storage, so the package stays props-only and dependency-free.
- **Capabilities drive visibility, not roles:** AD-20 makes the table the only encoding of FR-39, so the UI asks "is `X` held?" and never "is this an Owner or Editor?". Each item declares the capability its own page reads, so an item shows exactly when its page's load would succeed. The Deployment-only rule follows from Deployment items requiring `deployment.*`, which only the Owner holds. Re-reading on every navigation costs two small GETs and makes role changes take effect without invalidation, matching Story 1.24's no-cache rule.
- **The forbidden page needs the server:** the trace ID in UX-DR22 only exists on a server refusal, and NFR-5 says hiding is never the control. So the client never decides "forbidden" by itself. A direct URL to a Tenant path triggers the Tenant capabilities read, and the server's one 403 `access_denied` (malformed, unknown, role-less or insufficient alike, as in Story 1.24) gives the page with its trace ID. That also means the page can't reveal whether a Tenant exists. Later pages get the same behaviour through their own load requests. Refused *actions* on an otherwise viewable page are a banner, owned by those pages, not this full-page state.
- **Allowed Tenant, no page:** a 200 on the Tenant capabilities read followed by "This no longer exists." is deliberate. The access check runs before routing, so not-found never answers before the server has refused.
- **Renewal keeps the page mounted:** the banner is a slot above `children` in `AdminShell`, and renewal never navigates for the same Admin, so React state (unsaved values) survives by construction. The fixture proves the slot doesn't remount its children, and the dashboard test proves no reload or remount on a real 401, using a `window` marker and DOM node identity. Resending once is safe because a 401 is answered by the Session check before any handler runs (Stories 1.21 and 1.24). The Admin ID check stops a different Admin's sign-in from carrying another context's request. The sheet opens at once, which Chromium allows, and the banner's Sign in action covers browsers that need fresh user activation.
- **Theme:** DESIGN gives the Admin Dashboard a manual toggle and Hosted Login the device's scheme. Defaulting `<html>` to `auto` in `index.html` avoids a flash before the bundle runs, with no inline script under the CSP. The only stored value is the scheme, which is not sensitive. Session, CSRF, Tenant and capabilities stay in memory or the URL.
- **Below 768px:** EXPERIENCE's Responsive table says only "Unsupported (NFR-17)" and designs no notice. A notice would be new copy and a new state outside the UX docs, so the statement goes in the operator documentation, and the layout simply stays the rail.
- **Breakpoint in one place:** `useMediaQuery` with `useSyncExternalStore` drives a `data-rail` attribute that both the CSS and the behaviour read. That avoids a CSS media query and a JS check disagreeing for a frame, and keeps the first render correct.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests`. Expected:
  - the build has no warnings;
  - the `@gatekeep/ui` tests and checks pass (raw hex, dependencies, screens props-only);
  - the api-client tests and the API contract drift check pass, unchanged;
  - the Architecture and Isolation tests pass, unchanged;
  - the browser tests pass, including `shell`, `admin-shell`, the updated `signin` and `credential-setup`, and `admin-csp`.

  From a worktree, use a worktree-only image tag, not `gatekeep/tests:local`.
- No server change, so no `api-contract.sh --write` and no Generator run. If either turns out to be needed, it's an Ask First.

Nothing runs on the host.
