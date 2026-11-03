---
title: 'Story 1.21: Claim bootstrap and create the first Admin'
type: 'feature'
created: '2026-11-03'
status: 'in-review'
baseline_revision: '627bf49ee180c8d615f471feb465478238a34bb2'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-19-initialise-a-deployment.md'
warnings: [oversized]
deferred: []
---

<intent-contract>

## Intent

**Problem:** `gatekeep init` (Story 1.19) issues a bootstrap token, but nothing consumes it. There is no Admin, no Admin session, no Admin API route, no OpenAPI document and no generated client. Until the Operator can claim the Deployment, nothing else in Epic 1 can be used, and whoever reaches the Admin host first must not be able to claim it.

**Approach:**
- Add a `POST /api/v1/deployment/bootstrap` route on `Host.Admin`. In one transaction it consumes the token, creates the first Admin as Deployment Owner, records completion, starts a setup-restricted Admin session with a CSRF token, and writes `bootstrap.admin.created`.
- Add the `admin` and `admin_session` tables.
- Add the server-side session, CSRF and setup-restriction checks.
- Add the Bootstrap screen in `apps/admin-dashboard` on `hosted-card`.
- Commit the OpenAPI document, with a CI diff, and generate `packages/api-client` from it.

## Boundaries & Constraints

**Always:**
- **Tables** (new migration later than `20261103000000`, `control` class, owned by Admins, registered in `TableRegistry` with column grants following `bootstrap_state` and `admin_attempt`):
  - `admin` has these columns:
    - `id uuid pk`;
    - `deployment_owner boolean not null`;
    - `created_at timestamptz not null default clock_timestamp()`;
    - `setup_completed_at timestamptz null`, which Story 1.22 sets after two credentials.

    No email or name yet: Bootstrap collects only the token. Later stories add columns. Grants: `gk_admin` gets SELECT and INSERT, and UPDATE on `setup_completed_at` only. `gk_cli` gets SELECT, for `recover-admin` later.
  - `admin_session` has these columns:
    - `id uuid pk`;
    - `id_hash bytea not null unique check (octet_length = 32)`;
    - `admin_id uuid not null references admin`;
    - `kind text not null check (kind in ('setup','full'))`;
    - `csrf_hash bytea not null check (octet_length = 32)`;
    - `created_at`, `idle_expires_at`, `absolute_expires_at` (with a check that idle ≤ absolute);
    - `ended_at null`, and `end_reason null` with a constrained set: `signed_out`, `expired`, `revoked`, `superseded`.

    The pattern is `user_session` from Story 2.6. Grants: `gk_admin` gets SELECT and INSERT, and UPDATE on `csrf_hash`, `idle_expires_at`, `ended_at` and `end_reason` only. Nobody gets DELETE.
  - The Architecture and Isolation table-coverage, grant and catalogue tests pass.
- **Claim, one command** (Admins module, `IBootstrapClaimer` or similar, used by `Host.Admin` as `gk_admin` in a Deployment scope). In one READ COMMITTED transaction with a `lock_timeout`:
  1. `SELECT … FOR UPDATE` the `bootstrap_state` row.
  2. If there is no row, or `completed_at` is set: return **NotFound**.
  3. If `expires_at <= clock_timestamp()`, or the hash doesn't match: return **Refused**. Compare in constant time (`CryptographicOperations.FixedTimeEquals`) against `BootstrapToken.Hash(submitted)`. A malformed token is also Refused, never an exception text.
  4. Otherwise: insert `admin` with `deployment_owner = true`, set `bootstrap_state.completed_at`, insert a `setup` `admin_session`, and append `bootstrap.admin.created` to the Deployment Log. The actor is `Actor.Admin(newId)` and the target is `AuditTargetKind.Admin`. Then commit.

  Declare `bootstrap.admin.created` in `AdminsEvents.cs` and regenerate `docs/audit-events.md`.
- **Session secrets:**
  - The session ID and the CSRF token are each 32 CSPRNG bytes, encoded as base64url. Only their SHA-256 is stored.
  - The cookie is `__Host-gk-admin`, with `Secure; HttpOnly; SameSite=Strict; Path=/`, and no `Domain` or `Max-Age` (a browser session cookie).
  - The CSRF token is returned once, in the claim response body.
  - The session lasts 30 minutes idle and 8 hours absolute (PRD §5.2), as constants beside the existing `SecurityLimits`, which gain Admin session values. The idle expiry slides on each authenticated request.
- **Request checks** (one `Host.Admin` component, applied server-side to every `/api/v1/deployment/*` route; NFR-5):
  - **Session:** a missing, unknown, ended or expired session gets 401 with no body detail. An expired session is ended with `expired`.
  - **State-changing requests** (POST, PUT, PATCH, DELETE) also need an `Origin` exactly equal to the Admin origin, and an `X-Gatekeep-CSRF` header whose SHA-256 matches. Otherwise they get 403. The bootstrap claim is exempt from the session and CSRF checks, but still needs the exact Origin.
  - **Setup restriction:** a `setup` session may call only endpoints marked setup-allowed. Every other endpoint gets 403.
  - **Session endpoint:** add one setup-allowed endpoint, `GET /api/v1/deployment/session`, which returns `{ adminId, kind, deploymentOwner, setupComplete, csrfToken }`, rotating the CSRF token (see Design Notes). The UI uses it to send a setup session to credential setup. Story 1.22 adds the registration endpoints as setup-allowed.
  - **Test endpoint:** a non-setup-allowed endpoint that is test-only or already needed, such as a minimal `GET /api/v1/deployment/capabilities` returning `[]` for a setup session, proves the 403. Prefer one that is needed. Otherwise use a test-only marker, documented.
- **Responses:**
  - **Claim success:** 201, `{ csrfToken, adminId }`, and the cookie.
  - **Refused:** 400 with a problem body that carries only a fixed `code` (`bootstrap_refused`) and the trace ID. The UI shows Generic error with them.
  - **Rate-limited:** each Refused attempt is counted through the Story 1.20 limiter (`CreateAttemptLimiter`, policy `admins.bootstrap.claim`, limit 5 per 15 minutes, subject the client address that Caddy forwards per the existing hosting setup). Counts commit even when the claim is refused (AD-5 `FailureContext`). Over the limit, the claim gets 429 with a `Retry-After` and `code` `rate_limited`, checked before the token is compared.
  - **NotFound:** the response is identical to Host.Admin's unknown `/api/*` path: the same status, headers and body bytes, which a test compares.
  - **Bootstrap page:** once bootstrap is complete, the `/bootstrap` document request also returns the same 404 as an unknown path. A server-side check sits before the SPA fallback, so the page itself is gone.
- **Tenant hosts:** while bootstrap is incomplete, `Host.Hosted` answers every request with its fixed 404. No Tenant can exist, so there is no new code. An Isolation test proves it for an arbitrary host and path.
- **OpenAPI:**
  - Generate the v1 document from the `Host.Admin` endpoints with `Microsoft.AspNetCore.OpenApi` at build time (or an equivalent first-party mechanism), and commit it at `docs/api/openapi-v1.json`.
  - The tests pipeline regenerates it in Docker and fails on any difference: a new `run-tests.sh` stage before `pnpm -r build`, with a fixed message telling you how to regenerate.
  - The document marks the auth requirement (cookie and CSRF) and the problem responses.
- **`packages/api-client`:**
  - Its types are generated from the committed document with `openapi-typescript`, a reviewed dev-only dependency.
  - It has a small hand-written `fetch` wrapper with no runtime dependency that:
    - sends `credentials: 'same-origin'`;
    - adds `X-Gatekeep-CSRF` on state-changing calls;
    - parses problem bodies into `{ code, traceId }`.
  - The generated file is committed. The pipeline regenerates it and fails on a difference.
  - The admin-dashboard depends on it.
- **Bootstrap screen** (`apps/admin-dashboard`, route `/bootstrap`):
  - It is a `HostedPage` and `HostedCard` in the Gatekeep default theme (EXPERIENCE L232, L236). Admin pre-session pages may use "Gatekeep".
  - The card holds a labelled one-time token field (`autocomplete="off"`, paste allowed, surrounding whitespace trimmed) and one primary action, Claim.
  - While the claim is pending, the button shows its pending state.
  - On success, the page keeps the CSRF token in memory only (no web storage) and navigates to `/setup/credentials`. That page is a placeholder card saying two passkeys are registered next, and Story 1.22 replaces it. It calls `GET /api/v1/deployment/session` and shows nothing else.
  - On Refused or rate-limited, it shows `GenericErrorScreen` with the code and trace ID. Its action returns to the token field, which keeps no value.
  - All text comes from the catalogue. No raw colours. It meets the CSP from Story 1.20.
- **Canary:** add a canary flow for the claim, with the planted token submitted both correctly and wrongly. The token must appear in no log, audit event, response header or database column (other than its hash in `bootstrap_state`), and the session ID and CSRF token must appear in no log or audit event. Update `CanarySurfaceTests` for the new routes.
- **Tests:**
  - Isolation tests against the real `Host.Admin` process and Postgres cover every matrix row.
  - Architecture tests cover the new edges: `Host.Admin` to Audit and to Adapters.Postgres. Add them to `module-edges.txt`.
  - Browser tests cover the Bootstrap screen in a new `bootstrap.spec.ts`, against the admin host with the API answered by Playwright route interception: the success navigation, the Generic error, the pending state, axe in light and dark, and CSP violations.
  - Nothing runs outside Docker.

**Ask First:** none. This runs unattended, so decide and record the decision in the spec.

**Never:**
- No WebAuthn or credential registration: that is Story 1.22. No sign-in: Story 1.23. No capability enforcement beyond the setup restriction: Story 1.24. No Admin shell: Story 1.25.
- No token, session ID or CSRF token in any log, audit event, URL or web storage. Only hashes are stored.
- No second Admin from any path. No way to reopen bootstrap.
- No Host.Hosted change beyond the test.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Valid claim | Fresh token, unexpired | 201 `{csrfToken, adminId}`; `__Host-gk-admin` cookie with the exact attributes; one `admin` (`deployment_owner`), `completed_at` set, one `setup` session, one `bootstrap.admin.created` event, all in one transaction (same `xmin`) | — |
| Wrong token | Wrong 64-hex value; malformed value | 400 `bootstrap_refused` + trace ID; attempt counted; no row changes | — |
| Expired token | `expires_at` passed | Same as a wrong token | — |
| Rate limited | 6th refused attempt in 15 min from one client | 429 `rate_limited` + `Retry-After`, even with the right token | — |
| Completed | Claim after success, with any token | Byte-identical to unknown `/api/*` 404; no second Admin; no attempt counted | — |
| Bootstrap page gone | `GET /bootstrap` after completion | Byte-identical to an unknown path's 404 | — |
| Concurrent claims | Two valid submissions at once | Exactly one 201; the other gets the 404 | — |
| No init | No `bootstrap_state` row | 404 as completed | — |
| Wrong origin | Claim with a missing or foreign `Origin` | 403; nothing changes | — |
| Session endpoint | Setup session cookie, GET session | 200 `{kind:'setup', deploymentOwner:true, setupComplete:false}` | — |
| Setup restriction | Setup session on a non-setup endpoint | 403 | — |
| CSRF | State-changing call with a setup cookie, missing or wrong CSRF, or wrong Origin | 403 | — |
| No session | API call without a cookie, or with an unknown, ended or expired one | 401; an expired session gets `ended_at` and `expired` | — |
| Idle slide | Authenticated request | `idle_expires_at` moves forward, never past absolute | — |
| Tenant host | Any request to `Host.Hosted` before bootstrap | Fixed 404 | — |
| Canary | Claim flows, right and wrong | Token, session ID and CSRF token absent from logs and events; token absent from DB except its hash | Test fails otherwise |
| OpenAPI drift | Endpoint changed without regenerating | Pipeline stage fails with the regenerate hint | — |
| Bootstrap UI | Paste a token with spaces, submit | Pending, then navigates to `/setup/credentials` | Refused or 429 → Generic error with code and trace |

</intent-contract>

## Code Map

- `src/Gatekeep.Host.Admin/Program.cs` and its csproj: wiring, static files, the `/api` fallback 404 and the SPA fallback. The new references need module-edge entries.
- `src/Adapters/Hosting/*` (`GatekeepHosting.cs`, `HostSettings.cs` with `HostDatabases`, `SecurityHeaders.cs`), for how the admin origin and forwarded client address are known. Check the existing configuration and Caddy forwarding.
- `src/Modules/Admins/*`: `AdminsContract`, `BootstrapToken`, `BootstrapIssuer` (transaction style), `AdminAttemptLimiter`, `AdminsEvents`.
- `src/Gatekeep.Kernel/{Persistence,Audit,RateLimiting,Limits}`, plus the Audit module's `AuditContract.CreateAppender()`. `src/Gatekeep.Cli/InitCommand.cs` shows the scope and appender pattern.
- `src/Adapters/Postgres/Migrations/*` (`CreateBootstrapStateTable`, `CreateSessionTables`, `ConstrainSessionEndReason`) and `Schema/TableRegistry.cs`.
- `apps/admin-dashboard/*`, `packages/api-client`, `packages/hosted-screens` (`GenericErrorScreen`), `packages/ui` (the hosted entry), and `tests/browser/*` (`admin-host.mjs`, `admin-csp.spec.ts`, `playwright.config.ts`).
- `tests/Isolation/Hosting/{HostProcess,AdminBundleTests}.cs`, `tests/Isolation/RateLimiting/AdminAttemptLimiterTests.cs`, `tests/Isolation/Canary/*`, `tests/Architecture/*`.
- `deploy/docker/run-tests.sh`, plus the Dockerfiles that build the bundle and the tests image, for the new OpenAPI and api-client drift stage. `Directory.Packages.props` for new packages, with lock files regenerated in Docker.
- Verification runs only in Docker: `docker compose -f deploy/compose.test.yaml run --rm --build tests`. Database timeouts in Isolation under parallel load pass on rerun.

## Tasks & Acceptance

**Execution:**
- [x] The migration and registry for `admin` and `admin_session`, with grants.
- [x] Admins: the claim command, Admin sessions with CSRF, the `bootstrap.admin.created` event and the catalogue.
- [x] `Host.Admin`: the claim, session and test endpoints; the request checks; the bootstrap page 404; wiring and module edges.
- [x] OpenAPI document, `packages/api-client` generation, and the pipeline drift stage.
- [x] `apps/admin-dashboard`: the Bootstrap and credential-setup placeholder pages.
- [x] Isolation, Architecture, canary and browser tests for every matrix row.

**Acceptance Criteria:**
- Given a valid token at Bootstrap, when it is consumed, then the first Admin is created as Deployment Owner in one command, and `bootstrap.admin.created` is written to the Deployment Log.
- Given a wrong or expired token, when it is submitted, then Generic error shows, and attempts are rate limited through `admin_attempt`.
- Given a completed bootstrap, when the route is requested, then it returns the same 404 as an unknown path.
- Given bootstrap logs and events, when the canary scan runs, then the token appears in none of them.
- Given the first Admin, when they are created, then a setup-restricted `admin_session` starts with a CSRF token, and it allows only credential registration.
- Given incomplete bootstrap, when any Tenant host is requested, then the fixed 404 is returned.
- Given a consumed token and incomplete credential setup, when it is submitted again, then the route returns the same 404, and no second Admin is created.
- Given the first API routes, when CI runs, then the OpenAPI document is committed and diffed, and `packages/api-client` is generated from it.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Used path: 404, not Generic error.** EXPERIENCE L236 says a used path shows Generic error. The story's AC and AD-31 say it returns the same 404 as an unknown path. The AC and AD-31 win, because a 404 doesn't reveal that the Deployment exists. Generic error is kept for a wrong or expired token on an open bootstrap.
- **Losing the setup session:** completion is recorded at claim (AD-31). A first Admin who loses the setup session before registering two credentials recovers with `gatekeep recover-admin` (Story 1.32). Until then, the restriction stops a half-set-up Owner from doing anything.
- **CSRF transport (revised in review):** the CSRF token is derived from the session ID (SHA-256 of a fixed label and the session ID), so `GET /api/v1/deployment/session` is read-only and returns the same token to every tab. The earlier rotate-on-GET design changed state on a GET and broke concurrent tabs.
- **Decisions made while building and reviewing:**
  - **Settings:**
    - `Gatekeep:PublicOrigin` is required: requests are compared with it in browser form, default port dropped.
    - `Gatekeep:ForwardedBy` is required. Its value is Caddy's admin-edge subnet in Compose, or `none`. Only from that network is `X-Forwarded-For` believed, using the right-most hop. IPv6 clients are counted per /64.
  - **No `Host.Admin -> Adapters.Postgres` edge:** Host.Admin builds an `NpgsqlDataSource` directly, the established host pattern, and doesn't ship the migrator.
  - **Claim order and limits:**
    1. A completed or never-issued bootstrap returns the unknown-path 404 before the Origin check. Completion is cached in the process because it never reopens, so a database restore needs a Host.Admin restart.
    2. The attempt is counted and committed before the row lock is taken.
    3. The lock waits at most 5 seconds.
    4. At most 4 claims run at once, and the rest get a fast 503, so a flood can't drain the connection pool.
    5. The commit ignores client cancellation.
  - **Endpoints:**
    - `DELETE /api/v1/deployment/session` (sign-out) exists but isn't setup-allowed, because a setup session signing out would strand the only Owner.
    - `GET /api/v1/deployment/capabilities` returns `{ capabilities: [] }`. It isn't setup-allowed, which proves the restriction.
    - Endpoints without the deployment-API marker under the prefix are denied.
  - **Request checks:** they run in the order Origin, then session, then CSRF, then the setup restriction. A missing cookie with a foreign Origin on a state-changing call is therefore 403. The Deployment Owner check on the surface is Story 1.24's, since only one Admin can exist.
  - **Session rows:** ending is write-once, and the lifetimes are capped by CHECKs. A partial unique index allows only one Deployment Owner.
  - **Responses:**
    - The 503 when the database is down has no body and keeps the security headers.
    - A 401 clears a stale cookie.
    - The trace ID in problem bodies is the W3C trace ID that the logs carry.
  - **`/bootstrap` match:** exact and case-sensitive. After completion it returns the API's 404, but other SPA paths return 200, so `/bootstrap` stays distinguishable. Accepted, because the API and the page no longer work.
  - **Browser tests:** they serve the real host's document at `/bootstrap` and intercept only the API, because the browser harness has no database. Isolation tests prove the server gate.
  - **`packages/api-client`:** typed from the generated `paths`. `openapi-typescript` needs the TypeScript 5 compiler API, so it uses a TypeScript 5.9.3 catalog that only `packages/api-client` takes.
  - **OpenAPI document:** carries enums, documented 503s and the `Set-Cookie`, plus an `x-gatekeep-setup-allowed` extension for Story 1.22.
- **Residual risk:** if the browser never receives the 201, or the setup session is lost before two credentials are registered, the Deployment needs `gatekeep recover-admin` (Story 1.32). Bootstrap can't be reopened.
