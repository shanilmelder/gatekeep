---
title: 'Story 4.1: Serve Hosted Login step screens'
type: 'feature'
created: '2026-11-15'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
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
