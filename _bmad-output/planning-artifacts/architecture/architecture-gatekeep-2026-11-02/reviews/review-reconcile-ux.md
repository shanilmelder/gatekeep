---
type: architecture-review
lens: reconcile-ux
reviewed: _bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md
against:
  - _bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md
  - _bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md
  - design/SCREENS.md
  - design/Gatekeep Admin.dc.html (grep only)
created: '2026-11-02'
---

# Review: Architecture Spine against UX

## Verdict

**Changes required before stories are cut.** The spine's security structure holds up against the UX. It doesn't yet support several specified v1 behaviours, and most of the gaps sit where the browser meets server state.

20 findings: 7 High, 10 Medium, 3 Low. A further list covers wording conflicts, most of them on the UX side.

Three new decisions would close most of the High findings:

1. A **step contract** for Hosted Login, covering payload, time limits, history and one-time values (R-2, R-3, R-13).
2. An **operation resource** for work that outlasts a request (R-4).
3. A **corrected module graph** (R-1), including read paths for Logs, Sessions and Health.

Logo serving, theme preview and rate-limit usage each need their own rule (R-5, R-6, R-7).

## Scope and method

- Severity: **High** means a specified v1 behaviour can't be built without a new architecture decision, or following the spine as written breaks it. **Medium** means it can be built, but each implementer would have to invent a cross-cutting rule. **Low** means cleanup.
- Precedence follows EXPERIENCE Foundation: PRD, then DESIGN and EXPERIENCE, then exports. An export differing from the spine is a defect only if a UX doc or the PRD depends on it.
- AD-21's override of the JavaScript-off assumption is deliberate and isn't reported. R-14 is about first paint with JavaScript on.
- The Admin export was grepped, not read in full. I read PRD FR-6, FR-9, FR-12, FR-30, FR-34, FR-35, FR-38, FR-40, FR-47 and FR-50 for context.
- Browser CSP behaviour below comes from the specifications and known implementations, and wasn't tested for this review. R-15 in particular needs a browser test.

## Summary

| ID | Severity | Topic | Spine | UX source |
| --- | --- | --- | --- | --- |
| R-1 | High | Module graph blocks Logs, Sessions, Health and incident work | AD-1, diagram | EXPERIENCE Admin: Tenant screens |
| R-2 | High | Transaction expiry warning and restart | AD-12, AD-21 | EXPERIENCE L156, L375–378 |
| R-3 | High | One-time values: reveal, Recovery Codes, TOTP seed | AD-24, AD-21, AD-12 | EXPERIENCE L122, L131, L186, L188 |
| R-4 | High | Progress of incident response and other long work | AD-13, AD-15 | EXPERIENCE L280–281, Flow 14 |
| R-5 | High | Tenant theme preview has no render path | AD-21, AD-22, AD-23 | EXPERIENCE L282, Design Delta |
| R-6 | High | Logo storage, sanitization and serving | AD-21, AD-22, AD-14 | DESIGN theme contract, EXPERIENCE L341 |
| R-7 | High | Rate-limit usage display | AD-14, AD-26 | EXPERIENCE L287, FR-6 |
| R-8 | Medium | QR rendering vs CSP and dependency rule | AD-21, AD-22 | DESIGN L572, EXPERIENCE L186, L383 |
| R-9 | Medium | Design tokens that aren't CSS-compatible | AD-22 | DESIGN frontmatter |
| R-10 | Medium | Log event code style | AD-16 | DESIGN L543, Admin export |
| R-11 | Medium | Field search on Users and Logs | AD-16, Conventions | EXPERIENCE L106, L285 |
| R-12 | Medium | Strength meter rules | AD-21, AD-24 | EXPERIENCE L127, L261 |
| R-13 | Medium | Server-driven steps: contract, history, tabs | AD-12, AD-21 | EXPERIENCE L349, L365–367 |
| R-14 | Medium | "Card on first paint" has no markup | AD-21 | EXPERIENCE L144 |
| R-15 | Medium | CSP directives and flows that leave the origin | AD-21 | EXPERIENCE L130, L208 |
| R-16 | Medium | Cookie `SameSite` undefined | AD-12 | EXPERIENCE L182, L197, L209 |
| R-17 | Medium | Forced reset and re-enrolment has no step | AD-12, AD-13 | Flow 14, FR-50 |
| R-18 | Low | Provider failure can't reach the sign-in screen | AD-15 | Flow 5 |
| R-19 | Low | Account Portal Application isn't provisioned | AD-19 | EXPERIENCE L38 |
| R-20 | Low | Session rows lack device data | AD-12 | EXPERIENCE Sessions, Hosted export L445 |

## High findings

### R-1. The module graph blocks Logs, Sessions, Health and incident work

**Evidence.** AD-1 says dependencies follow the diagram, and architecture tests fail the build otherwise. In the diagram (spine L44–57):

- `Host.Admin` reaches only Management, and Management reaches only Directory, Identity, Keys and Tenancy.
- Management has no edge to Audit, Sessions or Operations.
- Operations is reachable only from `Host.Worker`.
- Notifications is in the Structural Seed but not in the diagram.
- No edge makes the Tenancy theme service reachable from `Host.Hosted`'s two modules except through Identity and Sessions.

**Unsupported behaviour.**

- Logs, Logs · Event drawer, Deployment Log and User · History need Audit reads.
- User · Sessions and Sign-out need Sessions.
- Health & rate limits needs Operations.
- Incident response needs Sessions, Identity, Keys and Notifications together.
- Hosted Login needs Tenancy theme reads (AD-21).

The Capability Map assigns these areas to those modules, so the map and the diagram disagree. Transitive reach doesn't help: Directory's dependency on Audit gives Management no query contract.

**Proposed fix.** Amend the diagram: Management to Audit, Sessions, Operations and Notifications; Authentication to Tenancy. Add Notifications with its own Tenancy and Audit edges. Separate Operations' worker jobs from a read contract `Host.Admin` can call. State in AD-1 whether transitive calls are permitted (recommended: not).

### R-2. Transaction expiry warning and restart

**Evidence.** EXPERIENCE L156 and L375–378 need a `role="alertdialog"` warning 2 minutes before the end, a "Keep going" that extends without a reload, and restart at Login with the email kept. AD-12 gives only the 30-minute sliding lifetime. AD-21 says the client "holds no flow logic".

**Gaps.**

- No response carries remaining time, so the client can't time the warning. An absolute timestamp would also depend on the device clock.
- No endpoint is named for "Keep going", and what slides the lifetime isn't defined.
- **Restart can't work as stated.** The authorization request (`client_id`, `redirect_uri`, `state`, `nonce`, PKCE challenge) and the typed email live with the `signin_transaction` row. Once it's gone, Gatekeep has nothing to restart at Login for, and can't return the User to the Application. The only remaining outcome is the Generic error that EXPERIENCE rules out.

**Proposed fix.** Amend AD-12:

- Every step response carries `expiresInSeconds`, re-based on receipt.
- Add `POST /login/api/transaction/extend`, CSRF-protected, and state that only step submissions and this call slide the lifetime.
- Expiry moves a row to `expired` rather than deleting it. It's kept for a bounded period holding the validated authorization parameters and email, and is purged by a job.
- A request on an `expired` row issues a fresh transaction from those parameters, with a new challenge and no completed steps.
- If the row has been purged, redirect to the Application with `login_required` or a fixed error, and correct EXPERIENCE to match.

### R-3. One-time values have no permitted path out of the server

**Evidence.**

- AD-24: `Secret<T>` "has no serializable form, and any credential-equivalent value in code uses it."
- One-time reveal (L122), Recovery Code display (L131, L188) and TOTP setup (L186) all must serialize such a value to a browser.
- AD-24 stores Recovery Codes as Argon2id, and AD-10 keeps TOTP seeds as ciphertext.
- AD-21 re-embeds the current step in the first response.

**Conflicts.**

- Read literally, AD-24 forbids all three screens.
- **Reload on Recovery Code display:** the current step needs plaintext that exists only as hashes. The options are to hold plaintext in the transaction, regenerate silently, or lose the codes. No AD chooses.
- **Reload on TOTP setup:** "the seed stays until the screen closes", and a wrong code keeps it. AD-12 doesn't let `signin_transaction` hold a pending seed. Embedding it in the HTML block also puts it in a cacheable, view-source document.
- "Browser Back after Continue doesn't show them again" isn't covered. Back-forward cache restores the React heap, and no AD sets `Cache-Control: no-store` on any response.
- The spine doesn't say what happens to a one-time reveal if the response is lost after commit.

**Proposed fix.** Add a rule to AD-24:

- Define a `RevealOnce<T>` wrapper, the only serializable form, allowed only in named response types. Architecture tests enforce the list, and the canary scan covers it.
- All such responses, and every Hosted Login HTML response, are `Cache-Control: no-store`. The client clears the values on `pagehide`.
- Pending Recovery Codes and TOTP seeds are held as Transit ciphertext on the transaction, or Portal equivalent, until the User confirms, then erased. Reload re-reads the same values. A code set becomes active only on confirmation.
- One-time values are never in the first-response data block. The step fetches them over `/login/api/*`, which relaxes AD-21's "no fetch" for these two screens only.
- A lost reveal means rotating again, and the UX states this.

### R-4. Progress of incident response and other long work

**Evidence.** EXPERIENCE L280–281 and Flow 14 require a progress `banner`, a partial-failure list with Retry, and per-Tenant results for the Deployment action. AD-13 makes revocation one command per Tenant. AD-15 runs jobs, but `job` is a `control` table, `gk_dispatch` sees only dispatch columns, and no read path exists. AD-19 has no asynchronous pattern.

**Gaps.**

- Nothing can report progress. A security notice to every User, or a Deployment-wide run, won't fit one request.
- A banner held in page state disappears on reload, and nothing stops a second Owner starting the same action.
- Retry is a `[FreshAssertion]` action, and the 5-minute window will often have passed. The UX doesn't show that sheet.
- Under AD-13 a Tenant's revocation is all-or-nothing. "What didn't finish" can therefore only mean a Tenant, an action or an email batch, and that needs defining.
- The same gap affects synchronous results shown inline, because email and social traffic leave via Worker and Hosted (Structural Seed): email Test send with SPF, DKIM and DMARC (L283, L284) and Social Test connection (L263).
- Flow 9 says "nothing is half-applied", but AD-11 destroys Transit keys after commit, so a key can be `revoked` while its material still exists.

**Proposed fix.** Add an AD for an **Operation resource**:

- `POST` returns `202` with an operation ID, and `GET /api/v1/tenants/{tenantId}/operations/{id}` returns status, with a Deployment twin.
- An `operation` row with per-step and per-Tenant results is updated by handlers, and the Dashboard polls it. Progress survives reload because the page re-attaches to any active operation.
- A partial unique index allows one active operation per action and scope.
- Retry resumes unfinished steps idempotently and requires a fresh assertion. Mirror that in EXPERIENCE.
- Test send and Test connection use the same resource. Alternatively, grant `Host.Admin` an outbound path and show that edge in the Seed.
- Show "key material destruction pending" on Signing keys and reword Flow 9.

### R-5. Tenant theme preview has no render path

**Evidence.** EXPERIENCE L282 and Design Delta: preview of login, signup, MFA, reset and error, in light and dark, with a draft kept until published. AD-21 says only that "the Dashboard preview calls" Tenancy.

**Gaps.**

- **No screens to render.** Step screens live in `apps/hosted-login`, and `packages/ui` holds components only (AD-22, Structural Seed). `apps/admin-dashboard` has no permitted way to import them.
- **An iframe is ruled out.** `frame-ancestors 'none'` (AD-21) blocks framing `Host.Hosted`, and it's a separate origin. Separately, an unpublished draft can't be public on a Tenant Subdomain.
- **Both schemes can't be forced.** DESIGN declares dark under `[data-theme="dark"]`, but Hosted Login follows `prefers-color-scheme`. If the generated CSS uses only the media query, a preview can't show dark on a light device, or both side by side. AD-21 and AD-22 don't name the selector.
- **Admin has no delivery rule.** AD-21 binds only Hosted Login. Admin CSP is undefined, and that decides whether draft CSS may load and whether a local logo preview (`blob:`) is permitted.
- **No draft model.** AD-22 has no draft or published theme state, and doesn't say whether saving a draft is an audited command.
- **Fonts.** The allowlisted Tenant fonts must also load in Admin.

**Proposed fix.** Amend AD-21 and AD-22:

- Move presentational step screens to `packages/hosted-screens`, which takes props only, used by both apps. Preview passes fixture steps.
- Have Tenancy generate tokens against one scope selector, with `:root` plus `@media (prefers-color-scheme)` for Hosted Login and `[data-theme]` on a wrapper for preview.
- Serve draft CSS from `/api/v1/tenants/{tenantId}/theme/draft.css` on Admin. Add a stateless validate endpoint returning failing pairs.
- Store `theme` versions as `draft` or `published`, each write a command. Publishing writes the Log event.
- Add an Admin delivery AD with a CSP of the same strictness plus only what preview needs.

### R-6. Logo storage, sanitization and serving

**Evidence.** DESIGN's theme contract and FR-34 need a sanitized logo, and EXPERIENCE L341 accepts PNG or SVG up to 1 MB. AD-22 lists the override as "`ac`, its derived tokens, font and radius", omitting logo. AD-21 covers CSS only. AD-14 allows one system of record. No AD assigns an owner, a route or a sanitizer.

**Why it matters.** An SVG fetched directly from a Tenant Subdomain runs on the same origin as `/account/api/*`, with the Session cookie. AD-21's CSP is described for the pages, and doesn't say it covers an image response. Sanitizing once at upload relies on one library holding forever.

**Proposed fix.** Add to AD-21: Tenancy owns logos, stored as `bytea` in a `tenant` table. Rasterize SVG to PNG at upload (preferred), or sanitize server-side, and serve with `Content-Security-Policy: default-src 'none'; sandbox`, `X-Content-Type-Options: nosniff`, a fixed content type and a hashed URL. Check real type, dimensions and size on the server. Serve previews of drafts from Admin only. Add logo and dark primary to AD-22's override list.

### R-7. Rate-limit usage display

**Evidence.** FR-6 says the Dashboard shows rate-limit usage per Tenant. EXPERIENCE L287 wants live per-Tenant usage, with zero shown as 0. DESIGN has `usage-bar`, and the export shows named buckets against limits. AD-14 has attempt counters in `UNLOGGED` tables, behind a port with no read operation, plus an in-memory limiter inside `Host.Hosted`.

**Gaps.**

- Attempt counters are keyed for enforcement (identifier, source), not as usage against a limit per bucket.
- `Host.Admin` can't read the in-memory limiter, so usage reads low during a flood, which is when it matters most.
- No list of buckets or limits exists for display. NFR-6 names endpoints, but AD-14 doesn't, and it says nothing about Management API limits, which the export's bars imply.
- **Service status:** `/healthz` is on private ports, and no AD says what aggregates them or how **email provider status** is measured.
- A crash resets counters, which is acceptable for enforcement but should be visible on this page.

**Proposed fix.** Amend AD-14: name buckets and limits in the Kernel limits file. `IRateLimiter` gains `GetUsage(tenant)`. Limiter decisions increment a per-Tenant, per-bucket, per-minute `UNLOGGED` rollup, including a periodic flush of the in-memory limiter's rejections. Add `GET /api/v1/tenants/{tenantId}/health`, polled by the page, with an Operations read contract (R-1) that aggregates `/healthz` and a provider status written by Worker from real send results. Show "since {restart}" on the page.

## Medium findings

### R-8. QR rendering vs CSP and the dependency rule

DESIGN L572 needs dark modules on `#fff` in every theme. AD-21's `self` sources exclude a `data:` image, and `@gatekeep/ui/hosted` may have no third-party runtime dependency, so a client QR library is out. AD-22's lint rejects the raw hex that DESIGN demands. The export's grid of styled spans with random fill (Hosted L163, L476) is a drawing, not an implementation.

**Fix.** Render on the server: Authentication returns the QR as an SVG path string in the fetched TOTP step (R-3), and the client renders `<svg><path d=…>`. Presentation attributes aren't subject to `style-src`. Name a server QR library in the story. Add a lint exemption for one `qr-surface` constant. A same-origin image URL is the alternative, but it puts the seed in a cacheable resource, so it isn't preferred. Say whether `otpauth://` is in the step, since "Open in authenticator app" needs it.

### R-9. Design tokens that aren't CSS-compatible

AD-22 says the frontmatter generates `tokens.css`, a TypeScript map and C# constants, and that CI compares them. These values can't pass through:

| Token | Problem |
| --- | --- |
| `elevation.motion` | Prose: `150ms-200ms ease, 6px rise and fade (gkIn)` |
| `components.toggle.size` | `28x16px` isn't a CSS value |
| `components.tabs.active-underline` | `2px '{colors.tx}'`, a shorthand with a quoted reference |
| `components.*.typography` | Composite reference, not one property |
| `components.strength-meter.segments`, `hit-area`, `borderStyle` | Mixed units and non-style data |
| `*-dark` keys | Must become the same `--bg` under the dark selector, not `--bg-dark`. `sh-dark` too. |
| `spacing.'4'` and similar | Invalid C# and awkward TS identifiers |
| `{colors.ac}` references | **Must emit `var(--ac)`, not the resolved hex**, or AD-22's Tenant override does nothing |
| `fontFamily` | Needs a fallback stack and a font-face source |
| `knob`, `code-*` | Theme-invariant, so emit once |

**Fix.** Define the generator's mapping in AD-22: emit `colors`, `rounded`, `spacing`, `elevation` and typography as atomic variables. Treat `components` as a checked reference, with `var()` aliases where a value is one property. Split `motion` in DESIGN.md into `motion-duration`, `motion-easing` and `motion-rise`, and change `toggle.size` to width and height. Those DESIGN.md edits are small and don't change the look.

### R-10. Log event code style

**Export (Admin L1501).** Terse, Auth0-style codes: `s`, `f`, `fp`, `ss`, `sv`, `spk`, `sapi`, `scoa`, `fcoa`, `seccft`, `ciba_ok`, `gd_auth_ok`, `limit_wc`, `pwd_leak`. The Design System badges match (`s`, `fp`), and the query bar uses `type:(f OR fp OR limit_wc)` (L1111). There's no shared pattern, and `ciba_ok` and `gd_auth_ok` name v1 exclusions.

**Spine (AD-16).** `{domain}.{object}.{action}`, lower case, public contract.

AD-16 should win. FR-40 requires only stable codes, and the exports rank last. Its style is the better contract, because a reader can tell what `fp` means only from a lookup. Consequences that nobody has recorded:

- **Width.** The Logs Type column is 90px, which holds about 11 characters at 11px mono. A code such as `auth.password.failed` is 20. It needs about 170–210px, and the 860px minimum table width goes up. The drawer badge is fine.
- **Tone.** DESIGN L543 sets the badge colour by success or failure. The export carries that as a separate `tone` field, so the code alone doesn't supply it, and AD-16 has no outcome. The export also uses `--{tone}-sf` (L1121), where DESIGN and the Design System use `sf2` for success. DESIGN wins.
- **No catalogue.** The spine gives no examples or domain list, or verb tense. As the public contract, it must exist before the first audit event is written.

**Fix.** Add a code-owned event catalogue to AD-16 listing code, outcome (`success`, `failure`, `info`), message key and alert mapping, with worked examples. Add an `outcome` column inside the envelope. Add a Design Delta row to EXPERIENCE for code style, column width and `sf2`.

### R-11. Field search on Users and Logs

EXPERIENCE L106 specifies Users by email, user ID, Connection, status, and Logs by event type, User, Application, outcome, time range. The spine covers only cursor pagination.

- **Outcome** has no field in AD-16 (R-10).
- **User filter vs personal data.** AD-16 keeps email in `audit_detail`, and `audit_event` holds internal references. Searching Logs by email must resolve through Identity, so it misses failed sign-ins for unknown accounts, which have no User ID. Those are the events an Admin hunting an attack wants.
- **Viewer list.** "Raw-detail permissions act on this table", yet Logs and drawer summaries show User and location (export L1122–1125, EXPERIENCE L286 "Viewer: summary only"). The spine doesn't say which fields a Viewer may get.
- **Name resolution.** Deleted Applications and erased Users must still render. AD-1 stops Audit joining Directory, so there's no resolved label source.
- **Cursor.** `seq` is assigned later by the sealer, so paging on it hides recent events. Use `(created_at, id)`.
- **Users ownership.** Filters span email and status (Identity?) and Connection (Directory?). AD-1 forbids a cross-module join, and the spine doesn't say which module owns `USER`.
- **Match semantics** (exact, prefix, case folding) and indexes are undefined, and values stay in the URL, so an email ends up in history and proxy logs.

**Fix.** Add an AD for list and search: per-screen filter allowlist, match rules (normalized email exact or prefix, others exact), required indexes and a time-range bound for Logs. Store a keyed HMAC of the normalized identifier in `audit_event`, outside personal data but searchable, so failures on unknown accounts are found and erasure still works. Define the Viewer projection. Snapshot display labels for non-personal names in the event. Name one `USER` owner. Add a note that Admin's access logs mustn't record query strings, or move email search to `POST`, which conflicts with "values stay in the URL", so EXPERIENCE must decide.

### R-12. Strength meter rules

EXPERIENCE L127 says the meter updates locally "with rules from the Connection's policy", and L320 lists strength, history, dictionary and personal-data rules. History can't be checked in the browser, and a dictionary is too big for a bundle under AD-21's hosted restrictions. No step payload carries policy, and a strength library is ruled out if the no-dependency rule extends to the app. Good and Excellent are `[ASSUMPTION]` and need one definition across the browser, Admin's live preview (L261) and the server.

CSP isn't a problem here: four segments can use classes, and React's style prop writes through CSSOM.

**Fix.** The step payload carries rule descriptors, marking each as `client` or `submit`. The checklist shows only client rules live, and submit rules appear as errors. Put the scoring in one small first-party TypeScript function with shared test vectors run against the C# implementation.

### R-13. Server-driven steps: contract, history and tabs

AD-12 and AD-21 fit FR-47 and are the right design. The contract behind them is missing.

- **Payload.** No shape covers what EXPERIENCE needs in each step: Connection-derived Login options, `attemptsLeft`, `resendAvailableIn`, `retryAt`, kept email, policy, Tenant name, support contact, WebAuthn challenges and identifiers for autofill.
- **History.** Whether a step changes the URL isn't stated. "Back is safe" (L349) needs a rule. A step submission from a stale view should return the current step, not an error, unless the transaction is invalid.
- **Multiple tabs.** There's one `__Host-gk_txn` cookie, but a transaction is per Application. A second authorization in another tab overwrites or collides with the first.
- **Same-browser detection.** "Same browser" and "email kept" (L182, L197) outlive 30 minutes, since links are valid longer than the transaction.
- **Page semantics.** L365–367 assume full page loads in places. With client-side steps, `<title>`, focus and `role="alert"` become client work.
- **JSON embedding.** The data block contains Tenant-controlled strings, so `<` and U+2028 must be escaped.
- **Skew.** `/login/api/*` "ships with its bundle", but an open tab survives an upgrade. Old bundles meeting unknown steps need a fixed reload.
- **Clients.** AD-23 generates clients from the OpenAPI document, but private surfaces aren't in the public contract.

**Fix.** Add a step contract companion: a discriminated union of step types generated from C# with a version field. An unknown step or version forces a reload. Use one fixed URL for the flow, with a transaction reference in a query parameter or a cookie per transaction ID, and no history entries per step. A separate private OpenAPI document feeds `packages/api-client` and is excluded from the public diff.

### R-14. "Card on first paint" has no markup

AD-21 says the first response embeds a JSON block "so a sign-in card renders on first paint with no fetch". With no Node and React as the only renderer, the HTML has no card. It has an empty root until the bundle downloads and runs. That removes the data fetch, but not the wait. On slow mobile (NFR-17) the User sees a blank `bg` page, and EXPERIENCE L144 specifies no loading state, because cards "arrive complete".

**Fix.** Keep AD-21's direction and restate the promise as "no data fetch before render". Add a size budget for the hosted bundle, enforced in CI, plus `modulepreload`. Have the server emit a minimal static shell in the theme, with logo tile and Tenant name, or accept a brief empty canvas and say so in EXPERIENCE.

### R-15. CSP directives and flows that leave the origin

`default-src 'none'` doesn't cover `form-action`, `base-uri` or `frame-ancestors`, so "`self` sources for the needed directives" must name them. Some browsers have applied `form-action 'self'` to redirects after a form post, which could break any real form post that ends in a redirect: Social Pending then provider (L130), code return to the Application, and Logout redirect (L208).

**Fix.** List the directives in AD-21, including `base-uri 'none'`, `form-action 'self'`, `font-src 'self'`, `img-src 'self'`, `connect-src 'self'`. State that all exits are a `navigate` step, which the client performs with `location.assign` after `fetch`, not a form post. Add a browser test across supported engines.

### R-16. Cookie `SameSite` undefined

AD-12 lists `Secure`, `HttpOnly`, `Path=/`, no `Domain`, with no `SameSite`. `Strict` would hide `__Host-gk_session` on a cross-site authorization redirect, breaking Session reuse (FR-14). It would also drop `__Host-gk_txn` on Social return (L209) and on email links opened from webmail, so "Same browser" (L182, L197) would always read as a different browser.

**Fix.** State `SameSite=Lax` for both, relying on AD-12's CSRF token and Origin checks for state changes. Admin can use `Strict`. Add a flow test for each entry.

### R-17. Forced password reset and re-enrolment has no step

FR-50 and Flow 14 force resets and TOTP re-enrolment. AD-13 covers revocation only, and neither the Key Flows diagram nor AD-12 has a state for it. EXPERIENCE doesn't draw the screen either.

**Fix.** Add per-User `credential_reset_required` flags in Identity, checked after first-factor in the server's step order. Reuse the Reset password and Factor choice steps. State in EXPERIENCE what a User with no password email sees, and that a stolen password can't complete the reset.

## Low findings

- **R-18. Provider failure.** Flow 5 says a provider outage shows Generic error, but AD-15 sends email asynchronously after commit, so the sign-in path sees success. Fix: reword Flow 5, or have the step read Worker's provider status from R-7.
- **R-19. Account Portal Application.** EXPERIENCE L38 makes the Portal a first-party Application in each Tenant. AD-19 provisions only the Management API record, and `Host.Hosted` can't write Application rows. Fix: Tenant creation provisions it, excluded from FR-44 lists, and it's always enabled for the Tenant's Connections.
- **R-20. Session data.** The Portal export shows "Chrome · macOS · London · this device" (L445). `user_session` (AD-12) has no user agent, IP or last-seen. Fix: add them as personal data covered by erasure, and mark the current session in the response.

## Wording conflicts to tidy

| Where | Issue | Resolution |
| --- | --- | --- |
| AD-22 and DESIGN L572 | Lint bans raw hex, QR requires `#fff` | Exemption (R-8) |
| AD-22 vs DESIGN contract | Omits logo and dark primary | R-6 |
| DESIGN L585 | Dark primary default is `ac-dark` but says "falls back to the light primary" | UX owner chooses |
| DESIGN derivation vs tokens | 12% mix gives `#e2efec` and `#172a28`, the tokens are `#e2f3ec` and `#0e2a21`. A Tenant entering the default colour gets a different wash. | Default theme bypasses derivation, or align tokens |
| EXPERIENCE L155, FR-9 vs AD-19 | Tenant is in the URL, so a stale tab acts on its own Tenant, and the "names both Tenants" banner can't fire | Page sends its Tenant with each write, or drop the banner and restate FR-9 evidence |
| EXPERIENCE L56 | "Current Tenant" landing with no server-side current Tenant | Client remembers last Tenant, a convenience only |
| EXPERIENCE L115, L122 | `modal` closes on Esc, reveal blocks Close until ticked | Reveal disables Esc too |
| EXPERIENCE L279, AD-11 | Routine rotate within 15 minutes of a new `next` is refused, with no copy | Add a state to Signing keys |
| EXPERIENCE L291, AD-2 | Client "last use" with no Hosted write to Application tables | Derive from audit events |
| AD-14 | Coarse limiter's response has no defined shape for the Hosted client | One fixed problem response, shown as Generic error |

## Checked, no defect

- **Precedence of exports:** Region, query bar, Live tail and Auth0-style JSON are removed or overridden by EXPERIENCE, so they aren't spine defects.
- **JSON data block under CSP:** a non-JavaScript `type` is inert, so `script-src 'self'` doesn't block it. Escaping is in R-13.
- **Theme delivery:** generated, hashed same-origin CSS fits no `unsafe-inline`, and server-side validation matches FR-34.
- **Hosted Login colour scheme:** the stylesheet in `<head>` prevents a theme flash.
- **WebAuthn:** no CSP directive applies, and per-Tenant RP ID fits AD-6.
- **Recovery Code Download:** a client `Blob` needs no CSP change.
- **Unknown host and deleted Tenant:** AD-6's fixed 404 matches L153.
- **Re-authentication gate:** `[FreshAssertion]` matches FR-46.
- **Role Capabilities:** AD-20's capability endpoint fits the read-only labels.
- **Key compromise timing:** AD-11's 15-minute `max-age` matches Flow 9.
- **Lists:** a default of 50 matches L110.
- **Fonts:** bundled in `packages/ui`, consistent with DESIGN. The allowlist itself is still undefined.
