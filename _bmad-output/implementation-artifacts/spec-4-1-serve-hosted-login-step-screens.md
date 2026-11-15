---
title: 'Story 4.1: Serve Hosted Login step screens'
type: 'feature'
created: '2026-11-15'
status: 'done'
baseline_revision: '9988cc2dcaf99ba4316fd3f85c7b162af6b2fdbd'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** Hosted Login doesn't exist yet as a served surface. `Host.Hosted` serves no bundle, and its one page is a hard-coded static HTML error (Story 2.9's `InvalidRequestPage`). `apps/hosted-login` is a stub, and nothing in CI enforces the 150 kB budget or bans hard-coded user-facing strings (FR-33, AR-31, AR-38, AD-21, UX-DR41).

**Approach:**
- `Host.Hosted` serves the built `apps/hosted-login` bundle under `/login/`.
- **Step page:** the first response for a step is the bundle's `index.html` with two server-side additions:
  - the step as a JSON data block (a `StepResponse`);
  - a `<link>` to the Tenant's content-hashed theme stylesheet in `<head>`.
- **Client:** the client reads the JSON and renders the matching props-only screen with no fetch.
- **First step:** Generic error is the first step served this way. It replaces the static invalid-request page.
- **CI gains:** a bundle-budget check, a hard-coded-string lint across every surface, and browser tests of the served step in both colour schemes.

## Boundaries & Constraints

**Always:**
- **Step page (AD-21):** every step page is the bundle's `index.html` with these server-side additions:
  - `<html lang="en" data-gk-surface="hosted" data-gk-scheme="auto">`;
  - `<link rel="stylesheet" href="/login/theme/{hash}.css">` inside `<head>`;
  - `<script type="application/json" id="gk-step">{StepResponse}</script>`.
  - The JSON is HTML-safe: `<`, `>`, `&`, U+2028 and U+2029 are escaped as `\uXXXX`, so no Tenant value can close the block.
  - The page has no other inline script, no `<style>`, no `style=` attribute and no `data:` URL.
  - Every URL is same-origin.
- **StepResponse** is `{step, stepVersion, expiresInSeconds, data, csrfToken}`, with camelCase field names.
  - `step` is a snake_case step name.
  - `data` holds the step's props.
  - Generic error has `step: "generic_error"`, `stepVersion: 1`, `expiresInSeconds: null`, `csrfToken: null` and `data: {tenant, code, traceId}`.
  - The C# type lives where Story 4.2 can add steps without touching the page writer.
- **Every step response:**
  - `Cache-Control: no-store` and `Pragma: no-cache`;
  - `SecurityHeaders.Apply`: the exact AD-21 CSP, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and `nosniff`;
  - `Content-Type: text/html; charset=utf-8`.
  - Bundle assets under `/login/assets/*` and the theme stylesheet also carry the security headers.
- **Theme stylesheet:**
  - Tenancy generates it from the default design tokens: `--gk-*` custom properties under `[data-gk-theme]`, for light, for dark under `prefers-color-scheme`, and for `data-gk-scheme` light and dark.
  - It is served at `/login/theme/{hash}.css`, where `{hash}` is a hex SHA-256 prefix of its content. Any other hash is a 404.
  - Per-Tenant overrides are Epic 15's. The generator takes the Tenant so they can be added later.
- **Generic error:**
  - Shown by `AnswerInvalidRequestPage` for an unknown client, an unregistered `redirect_uri` and every case that page covers today. The status stays 400.
  - `code` is the OpenIddict error the page answers today, `context.Error` (e.g. `invalid_request`, `invalid_client`).
  - `traceId` is the request's `Activity` trace ID in hex, falling back to `HttpContext.TraceIdentifier`. One shared helper serves Admin and Hosted.
  - `tenant` is the resolved Tenant's name. `ResolvedTenant` gains `Name`, read by the same resolution query.
  - The screen shows only fixed catalogue text, the code and the trace ID. There is no back link, because the Application isn't trusted.
- **Client (`apps/hosted-login`):**
  - Reads `#gk-step` once and maps `step` to a screen from `@gatekeep/hosted-screens`. A missing, unparsable or unknown step renders Generic error with code `invalid_step` and an empty trace ID label.
  - Wraps the screen in `HostedPage` (scheme `auto`) and `MessagesProvider`.
  - Sets `document.title` to "{step heading} – {tenant}".
  - On first load, focuses the first invalid field, else Login's email field, else the card heading. Today that is the card heading.
  - Never calls `fetch`, `XMLHttpRequest` or storage.
- **`index.html` from the catalogue:**
  - `index.html` holds `<noscript>` with the catalogue's fixed text and a fallback `<title>`.
  - A Vite build step writes both from `defaultMessages`, so the source holds no literal user-facing text.
  - The tenant-free fallback title never says "Gatekeep".
- **Bundle:**
  - `vite.config.ts` sets `base: '/login/'` and `assetsInlineLimit: 0`.
  - The JS and CSS that `index.html` loads total at most 150 kB gzip, checked by a script run in `run-tests.sh`. Fonts are already-compressed `woff2` and are excluded, but they must be same-origin.
- **Hard-coded-string lint:**
  - A Node check like `check-no-raw-hex.mjs` scans `packages/ui/src`, `packages/hosted-screens/src`, `apps/*/src` and `apps/*/index.html`.
  - It fails on JSX text containing a letter, and on a string literal containing a letter in `aria-label`, `aria-description`, `title`, `placeholder`, `alt` or `label`. `messages.tsx` is exempt.
  - The existing violations move into the catalogue. That includes the Admin placeholder `https://api.example.com` and the stub's `<p>Hosted Login</p>`.
  - A test proves a fixture with a literal fails the check.
- **Hosted image:** `deploy/docker/hosted.Dockerfile` gains a pnpm bundle stage like `admin.Dockerfile` and copies `apps/hosted-login/dist` to the web root.
- **Registries:** new routes join `RouteRegistry` and the Hosted route lists. `ProtocolHost` mirrors `Program.cs`.

**Never:**
- No Login, password, transaction, CSRF issuance or `/login/api/*` endpoints (Stories 4.2 and 4.9).
- No change to the `temporarily_unavailable` answer for a valid authorize request.
- No per-Tenant theme editing (Epic 15).
- No nonce or `unsafe-inline` in the CSP.
- No third-party URL, font or script.
- No Node in the production image.
- No ESLint dependency for the string lint.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Unknown client | `/authorize?client_id=nope…` | 400 HTML. `#gk-step` = generic_error with code and traceId (= header/trace). Theme link in `<head>`. no-store and AD-21 headers. | No error expected |
| Bad redirect | registered client, unregistered `redirect_uri` | Same page, existing code | No error expected |
| Rendered | the page in a browser, light and dark | Generic error renders with no network request after the page, its CSS, JS and fonts. Title "Something went wrong – {Tenant}". Focus on heading. One `main`. `lang="en"`. Reflows at 320px. axe clean. | No error expected |
| No JS | JavaScript disabled | the `<noscript>` fixed text shows | No error expected |
| Hostile name | Tenant display name `</script><b>x` | JSON escaped; DOM shows the literal name; no injected element | No error expected |
| Bad step JSON | missing or unknown `step` | Generic error with `invalid_step` | No error expected |
| Theme | `GET /login/theme/{hash}.css` | 200 `text/css`, security headers | wrong hash → 404 |
| Asset | `GET /login/assets/{built file}` | 200, security headers | unknown → 404 |
| Budget | built bundle | check passes ≤150 kB gzip JS+CSS | over budget → non-zero exit naming the total |
| Literal | `<p>Hello</p>` or `aria-label="Close"` in a scanned file | lint fails naming file:line | No error expected |

</intent-contract>

## Code Map

- `src/Gatekeep.Host.Hosted/Program.cs` -- pipeline: `UseTenantResolution` first (an architecture test enforces it), then `UseGatekeepForwardedClient`, `UseGatekeepProtocol`, `UseRouting` and `MapFallback(TenancyContract.NotFoundAsync)`. Add static assets and the theme route under `/login/` here. Its L18-23 comment names 4.1/4.2.
- `src/Modules/Protocol/Contracts/ProtocolContract.cs` -- `AddGatekeepProtocol(conn, pageHeaders)` (L63) takes `SecurityHeaders.Apply` as a delegate. Follow that seam to give Protocol a step-page writer port, registered by the host.
- `src/Modules/Protocol/Core/AuthorizeEndpoint.cs` -- `InvalidRequestPage` (L155, const HTML, "Story 4.1 replaces it") and `AnswerInvalidRequestPage` (L423-454: 400, no-store, `headers.Apply`). Replace the body with the step page.
- `src/Adapters/Hosting/SecurityHeaders.cs` -- exact AD-21 constants, `Apply` (L54), `UseGatekeepSecurityHeaders` (L31). Reuse; don't redefine.
- `src/Gatekeep.Host.Admin/AdminResponses.cs:303` -- `TraceId(HttpContext)`. Move it to a shared helper (e.g. in `Adapters/Hosting`) and use it from both hosts.
- `src/Gatekeep.Host.Admin/Program.cs` L25-51 -- how Admin serves `wwwroot` with headers. Pattern to mirror. The `--webroot` option is how tests point a host at a dist.
- `src/Modules/Tenancy/Contracts/ITenants.cs:282` `ResolvedTenant(TenantId, Issuer, RpId, EmailLinkBase)` and `src/Modules/Tenancy/Adapters/TenancyAdapters.cs:99-117` `ResolveAsync` -- the per-request Tenant feature. Add `Name` here.
- `src/Modules/Protocol/Core/AuthorizeEndpoint.cs:423-454` -- `AnswerInvalidRequestPage` answers only when there's no redirect URI and `context.Error` is set. `TokenEndpoint.Http(context)` gives the `HttpContext`.
- `src/Modules/Tenancy/Core/Theme/DesignTokens.g.cs` -- generated default token constants (`DesignTokens.Light/Dark`). The theme stylesheet generator reads these.
- `packages/design-tokens/generator/tokens.mjs` and `css/tokens.css` -- the scheme selector shapes to reproduce in the generated theme.
- `tests/browser/fixture/src/hosted-theme.css` -- example `[data-gk-theme]` override.
- `apps/hosted-login/{index.html,src/main.tsx,vite.config.ts,package.json}` -- stub to replace. Add a `@gatekeep/hosted-screens` dependency.
- `packages/hosted-screens/src/GenericErrorScreen.tsx` -- props `{tenant, code, traceId, backHref?, headingLevel?}`. `index.ts` holds the props-only rule.
- `packages/ui/src/components/HostedPage.tsx` -- scheme, `data-gk-theme`, the one `<main>`. `ErrorReference.tsx` holds the code and trace ID.
- `packages/ui/src/messages.tsx` -- `Messages`, `defaultMessages` (L766; `genericErrorTitle` L810), `MessagesProvider`. Add the no-script, fallback-title and moved strings.
- `packages/ui/scripts/check-no-raw-hex.mjs`, `check-dependencies.mjs`, `screens-props-only.test.mjs` -- the lint and check pattern, wired through `@gatekeep/ui`'s `check` and `test` scripts.
- `deploy/docker/run-tests.sh` -- CI order. Add the budget check after `pnpm -r build`. `deploy/docker/admin.Dockerfile` L9-31 and L58 is the bundle stage to copy into `hosted.Dockerfile`.
- `tests/browser/playwright.config.ts`, `csp-watch.ts` (`watchCsp`), `admin-host.mjs`, `admin-csp.spec.ts`, `hosted.spec.ts` -- browser projects, the CSP and cross-origin watcher, and axe.
- `tests/Isolation/Hosting/AdminBundleTests.cs` -- model for a Hosted bundle and step test (real host process, exact policy, no inline script or style, `--webroot`).
- `tests/Isolation/Protocol/ProtocolHost.cs` L112-131 -- mirrors `Program.cs`.
- `tests/Isolation/Protocol/AuthorizationCodeTests.cs` L750-765 `AssertStaticPageAsync` and the literal page text in `Applications/ApplicationSettingsProtocolTests.cs:270`, `Applications/InertApplicationTests.cs:102-105` and `CrossTenant/CrossTenantRouteTests.cs:212-226`. Switch them to asserting the step JSON and headers.
- `tests/Isolation/CrossTenant/RouteRegistry.cs` L129-140 and `RouteRegistryTests` -- every live Hosted route must be listed.
- `tests/Architecture/module-edges.txt` L14-21, `TenantRuleTests.cs:157`, `AdminCredentialIsolationTests.cs:81` (no Host.Hosted→Directory edge) -- constraints on new references.

## Tasks & Acceptance

**Execution:**
- `src/Modules/Tenancy/**` -- a theme stylesheet generator: the CSS text and its hash from the default tokens, for a Tenant -- AD-21's server-generated, content-hashed theme.
- `src/Adapters/Hosting/**` -- the shared trace ID helper, used by `AdminResponses` -- one definition.
- `src/Modules/Protocol/**` -- a `StepResponse` type and step-page port. `AnswerInvalidRequestPage` writes Generic error through it. Remove `InvalidRequestPage` -- the static page goes.
- `src/Gatekeep.Host.Hosted/**` -- the step-page writer: read the web root `index.html` once, inject the head link, the escaped JSON and the `<html>` attributes. Also serve `/login/assets/*` and `/login/theme/{hash}.css` with security headers -- the server half of AD-21.
- `deploy/docker/hosted.Dockerfile` -- bundle stage, dist into the web root.
- `apps/hosted-login/**` -- entry reading `#gk-step`, a screen map, title, focus, `<noscript>` and title from the catalogue at build, and the Vite config -- the client half.
- `packages/ui/src/messages.tsx`, `apps/admin-dashboard/src/**` -- new catalogue entries, and moving existing literals to them.
- `packages/ui/scripts/check-no-hardcoded-strings.mjs` plus a test, and `apps/hosted-login/scripts/check-bundle-budget.mjs` -- wire both into `package.json` scripts and `deploy/docker/run-tests.sh`.
- `tests/browser/**` -- a `hosted-step` project:
  - a small Node server serves `apps/hosted-login/dist` at `/login/`;
  - it injects a fixture `StepResponse` and the default theme with the same markers and headers as `Host.Hosted`;
  - it asserts the Rendered, No JS, Hostile name and Bad step rows in light and dark, with `watchCsp` showing no violation and no cross-origin request.
- `tests/Isolation/Hosting/HostedStepTests.cs` (new) -- a real `Host.Hosted` with `--webroot` on `apps/hosted-login/dist`. Assert the Unknown client, Bad redirect, Theme, Asset and Hostile name rows at the HTTP level. Update the tests that check the old literal text, plus `ProtocolHost` and `RouteRegistry`.

**Acceptance Criteria:**
- Given a sign-in step, when the first response arrives, then it embeds the step as JSON, links the theme stylesheet in `<head>`, and the client renders it with no fetch.
- Given any step response, when it's sent, then it's `no-store`, carries the exact AD-21 CSP, denies framing and sets `Referrer-Policy: no-referrer`.
- Given the bundle, when CI runs, then it stays within 150 kB gzip (JS and CSS) and the browser tests see no third-party request.
- Given an error, when Generic error shows, then only fixed text, a code and a trace ID appear, and `<noscript>` shows fixed text.
- Given the screen in both colour schemes, when the accessibility test runs, then focus precedence, `<title>`, `lang`, one `main` landmark, 320px reflow and axe pass.
- Given a surface, when lint runs, then a hard-coded user-facing string fails the build.

## Spec Change Log

## Review Triage Log

### 2026-11-15 — Review pass
- verdicts: 41 findings — high 0, medium 15, low 21, false 5, maybe-false 0
- findings:
  - `[medium]` `[patch]` (intent A) Browser-observable criteria are verified on a re-implemented Node stand-in whose parity with Host.Hosted is asserted only in comments — grouped with the theme and CSP parity rows: the served theme CSS is now checked value by value against `DesignTokens` and the harness reads the header values from `SecurityHeaders.cs`.
  - `[false]` `[reject]` (intent B) No real sign-in step exists; only Generic error is served — the spec scopes 4.1 to the delivery mechanism with Generic error as its first step; Login is Stories 4.2 and 4.9 (Never list).
  - `[low]` `[reject]` (intent C) Only the heading branch of focus precedence is exercised — the other branches need fields, which arrive with Login (4.9); the order is in `StepScreen.initialFocus` for that story to test.
  - `[false]` `[reject]` (intent D) No per-Tenant theme variant — per-Tenant overrides are Epic 15's (spec Never list); 4.1's variants are the two schemes.
  - `[low]` `[reject]` (intent E) The third-party-request guarantee is static in CI and runtime only on the stand-in — the static check covers the built files the real host serves byte for byte, and the runtime watcher covers the same bundle.
  - `[false]` `[reject]` (intent F) The Tenant name appears beyond "fixed text, a code and a trace ID" — UX-DR37 and UX-DR41 require the `<title>` "{heading} – {Tenant}" and the Tenant's name; the error body itself shows only fixed text, code and trace ID.
  - `[medium]` `[patch]` (intent G) The lint's "surface" misses literal text reached through expressions — grouped with the lint rows; child expression literals and `+` concatenation are now flagged.
  - `[false]` `[reject]` (intent H) Changes beyond the criteria (Protocol signature, `ResolvedTenant`, Admin title, framer port, Docker stage) — each is needed by the spec's design; descriptive, no defect.
  - `[medium]` `[patch]` (blind) The string lint misses `{'Hello'}` children, ternaries, other props and `.ts` files — child expression literals (conditional, logical, template, `+`) are now flagged with tests; other props and `.ts` files are rejected below.
  - `[medium]` `[patch]` (blind) A host without its bundle starts healthy and the first invalid authorize request 500s without no-store or AD-21 headers — Host.Hosted now validates the web root's `index.html` and markers at startup and refuses to start without it; the NullFileProvider fallback is gone.
  - `[medium]` `[patch]` (blind) No test ties the C# theme list to the tokens or to the harness — the colour list is derived from `DesignTokens`, and HostedStepTests asserts each scheme rule's values.
  - `[medium]` `[patch]` (blind) The harness differs from the real host: any path renders a step, and its CSP is a copy — the harness now reads the header values from `SecurityHeaders.cs`; the any-path behaviour is rejected below (edge row).
  - `[low]` `[reject]` (blind) Bad step JSON: empty tenant logs `console.error` and the bad-step tests skip title and axe — a corrupt page is not a reachable server output; the fallback renders the fixed error.
  - `[medium]` `[patch]` (blind) `catalogue-html.ts` has no tests and is imported by relative path — grouped with the Admin title row: the plugin now has fill, escape and unknown-key tests. The relative import is rejected: a package export would add public surface for a build-only helper.
  - `[low]` `[patch]` (blind) The bundle budget measures only files linked from `index.html` — it now measures every `.js` and `.css` under `dist/`.
  - `[low]` `[patch]` (blind) Asset headers: the 404 loop never asserts headers; hashed assets lack long cache — the 404 loop now asserts the AD-21 headers. The cache header is rejected: the spec doesn't ask for it, and the default is safe.
  - `[low]` `[reject]` (blind) `StepScreen` sets `tabindex` on React's `h1` via the DOM — React doesn't manage that attribute on the element, so nothing resets it; moving it into props is a refactor with no behaviour change.
  - `[low]` `[reject]` (blind) The client never checks `stepVersion` — stale-version handling is the server's (AD-21, Story 4.2); only one version exists.
  - `[false]` `[reject]` (blind) `context.Error` isn't guarded before `StepResponse.GenericError` — `AnswerInvalidRequestPage` returns early when `context.Error` is null or empty.
  - `[low]` `[reject]` (blind) `TestStepPages` copies `HostedStepPages`, so ProtocolHost tests exercise a copy — `HostedStepTests` runs the real host process and covers the real writer; sharing it would need a new assembly reference.
  - `[low]` `[patch]` (blind) The harness crashes with EISDIR on `/login/assets/..` — it now answers 404 unless the path is a file inside dist.
  - `[medium]` `[patch]` (edge) Missing or marker-less `index.html` gives an unhandled 500 — grouped with the fail-fast row above.
  - `[medium]` `[patch]` (edge) `<p>{'Hello'}</p>` passes the lint — grouped with the lint rows; fixed.
  - `[medium]` `[patch]` (edge) `aria-label={'Close ' + name}` passes the lint — grouped with the lint rows; `+` is now walked.
  - `[low]` `[reject]` (edge) String props on components (`heading=`, `body=`) and other ARIA attributes pass — flagging every capitalised component's string prop would flag identifiers and variants; the catalogue rule is enforced at the text sinks.
  - `[low]` `[reject]` (edge) `.ts` files (e.g. `document.title = 'X'`) aren't scanned — non-JSX literals are mostly non-UI; scanning them needs sink analysis beyond this lint.
  - `[low]` `[reject]` (edge) Trailing text after the last tag in `index.html` isn't flagged — no real index has text after `</html>`.
  - `[low]` `[reject]` (edge) A broken symlink crashes the lint — none exist in the scanned trees; a crash fails the build loudly.
  - `[low]` `[reject]` (edge) Single-quoted or unquoted `src`/`href` are skipped by the budget — superseded: the budget now measures every file under `dist/`.
  - `[low]` `[reject]` (edge) A referenced file missing from dist throws a raw ENOENT — a missing file fails the check, which is the right outcome.
  - `[low]` `[reject]` (edge) `..` segments or `#fragment` URLs — Vite emits neither; superseded by measuring `dist/` directly.
  - `[low]` `[reject]` (edge) woff2 with a query suffix or CSS `@import` — Vite emits neither for this bundle.
  - `[medium]` `[patch]` (edge) Assets missing at startup fix a NullFileProvider for the process life — grouped with the fail-fast row; the fallback is removed.
  - `[low]` `[reject]` (edge) The step marker's position isn't validated — the template is a repository file checked by the tests; a moved marker fails the HTTP tests.
  - `[low]` `[reject]` (edge) HEAD to the theme gets 404 — browsers fetch stylesheets with GET.
  - `[low]` `[patch]` (edge) Harness EISDIR on `/login/assets/..` — grouped with the blind row; fixed.
  - `[low]` `[reject]` (edge) The harness serves a step page for any path — a test stand-in's routing; the real host's routing is covered by HostedStepTests.
  - `[medium]` `[patch]` (edge) The claim that a hard-coded string fails the build is incomplete — grouped with the lint rows; the expression gaps are closed, remaining scope recorded above.
  - `[medium]` `[patch]` (verification) The served theme CSS is never checked value by value — grouped with the theme row; fixed.
  - `[medium]` `[patch]` (verification) The Hosted image's bundle placement is unverified — `stack-check.sh` now copies `/app/wwwroot/index.html` out of the image and asserts the step marker and a built script.
  - `[medium]` `[patch]` (verification) The Admin `<title>` now comes from the plugin and nothing checks it — AdminBundleTests asserts the built index has no `%gk:` and the catalogue title.

## Design Notes

**Why a Node harness and a real-host test.** The browser tests run before the Isolation stage, and that stage has no Postgres, so a real `Host.Hosted` can't run there. The browser harness performs the same two-marker injection as the host, with the same headers. `HostedStepTests` then proves that the real host emits exactly that shape. Keep the markers (e.g. `<!--gk-head-->` and `<!--gk-step-->`) in `index.html` so both sides replace the same text.

**Escaping example.**
`{"tenant":"\u003c/script\u003e\u003cb\u003ex"}`, never `</script>`.

**Budget.** The budget counts JS and CSS only. Fonts are `woff2`, already compressed, and gzip doesn't measure them meaningfully. The check prints the total, so growth is visible.

## Verification

**Commands:**
- **.NET build:** with `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- **JS checks:** in `gatekeep/tests:local` (repo at `/src`), run:
  - `pnpm -r build`;
  - `pnpm --filter @gatekeep/ui check` and `test`;
  - `pnpm --filter @gatekeep/admin-dashboard test`;
  - the budget check.

  Expected: all pass, and the budget prints a total ≤150 kB.
- **Browser:** run the Playwright `hosted-step`, `hosted` and `admin-*` projects. Expected: all pass.
- **Isolation:** with Testcontainers, pinning the IPv4 as `deploy/docker/run-tests.sh` does, run `HostedStepTests`, `AuthorizationCodeTests`, `ApplicationSettingsProtocolTests`, `InertApplicationTests`, `CrossTenant*`, `AdminBundleTests` and `RouteRegistryTests`, plus the Architecture suite. Don't run the full Isolation suite; CI does. The known local-only Architecture failure (`.claude/worktrees`) is expected.

## Auto Run Result

**Summary:** `Host.Hosted` now serves the built Hosted Login bundle under `/login/`. A step page is the bundle's `index.html` with the Tenant's content-hashed theme stylesheet linked in `<head>` and the step embedded as an HTML-safe `StepResponse` JSON block, sent `no-store` with the exact AD-21 headers; the client renders it with no fetch. Generic error is the first step, replacing Story 2.9's static invalid-request page. CI gains a 150 kB gzip bundle budget, a hard-coded-string lint over every surface, browser tests of the served step in both schemes, and an image check that the Hosted bundle ships.

**Files changed:**
- `src/Adapters/Hosting/StepPageTemplate.cs`, `HostedLoginFiles.cs`, `RequestTrace.cs` (new) -- the validated page template and injection, `/login` files with security headers, and the one trace-ID helper.
- `src/Modules/Protocol/Contracts/StepResponse.cs` (new), `ProtocolContract.cs`, `Core/AuthorizeEndpoint.cs` -- `StepResponse`, the `IStepPages` port, and Generic error replacing the static page.
- `src/Modules/Tenancy/**` -- `ResolvedTenant.Name`, `ThemeStylesheet` derived from `DesignTokens`, and the `/login/theme/{hash}.css` route.
- `src/Gatekeep.Host.Hosted/Program.cs`, `HostedStepPages.cs` (new) -- refuses to start without a valid bundle; writes step pages.
- `src/Gatekeep.Host.Admin/AdminResponses.cs` -- uses the shared trace ID.
- `apps/hosted-login/**` -- entry, step reader, `StepScreen`, catalogue-filled `index.html`, Vite config, budget check.
- `packages/ui/**` -- catalogue entries, the `catalogue-html` Vite plugin, and the hard-coded-string lint, each with tests.
- `apps/admin-dashboard/**` -- title and placeholder moved to the catalogue.
- `deploy/docker/hosted.Dockerfile`, `deploy/docker/run-tests.sh`, `deploy/ci/stack-check.sh` -- bundle stage, budget in CI, image bundle check.
- Tests: new `HostedStepTests`, `TestStepPages`, `hosted-step-server.mjs`, `hosted-step.spec.ts`; updated static-page assertions, `ProtocolHost`, `RouteRegistry`, `CrossTenantRouteTests`, `HostStartupTests`, `AdminBundleTests`, `admin-csp.spec.ts`.

**Review findings:** 41 findings (medium 15, low 21, false 5). Patched 9 entries (6 medium, 3 low): Hosted fails fast without a valid bundle; the lint follows child expressions and `+`; the theme colours derive from the tokens and are checked per scheme; the harness reads the header values from `SecurityHeaders.cs` and no longer crashes on a directory path; the catalogue plugin and the Admin title are tested; the budget measures every JS and CSS file; 404s under `/login` assert headers; the stack check verifies the Hosted image's bundle. Deferred none. Rejected 23 with reasons in the Review Triage Log.

**Follow-up review:** recommended. Six medium entries were patched. The specific unverified risk: the fail-fast startup change touches every path that starts `Host.Hosted` (the stack check, `RunningRoutes` and the full Isolation suite), and the new `stack-check.sh` image step was only syntax-checked locally; both run first in CI. Patched counts: high 0, medium 6, low 3.

**Verification:**
- .NET build: 0 warnings / 0 errors; API contract matches.
- `pnpm -r build`; `@gatekeep/ui` check passes; unit tests pass: ui 61, admin-dashboard 122, hosted-login 4 (budget 84.0 kB of 150 kB), api-client 36.
- Isolation `HostedStepTests`, `HostStartupTests`, `AuthorizationCodeTests`, `ApplicationSettingsProtocolTests`, `InertApplicationTests`, `CrossTenant*`, `AdminBundleTests`, `RouteRegistryTests`, `TenantResolution*` and `EventClassTests`: 295 of 295.
- Architecture: 793 of 794; the one failure is the known local-only `.claude/worktrees` check.
- Playwright (implementer): full run 694 of 695 before the `admin-csp` framer fix; after it, `hosted-step`, `hosted-login` and `admin-host` 21 of 21.

**Residual risks:**
- The lint covers JSX text, child expressions and named text attributes, not string props on components or `.ts` files.
- Focus precedence is tested only for the heading branch until a step with fields exists (Story 4.9). A Login screen must mark its email input with `data-gk-initial-focus`.
- The browser tests run against a Node stand-in; `HostedStepTests` holds the real host to the same shape.
- The theme is served `immutable` for a year under its content hash.
