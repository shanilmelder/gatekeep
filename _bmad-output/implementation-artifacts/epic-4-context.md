# Epic 4 Context: Database login

<!-- Generated from planning artifacts. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Let a User sign up, verify an email address, sign in with a password, reset a forgotten password and log out through Hosted Login. This is the core of the "add sign-in to a new project" journey. Epic 2 ran the code flow on a test-only authenticator over the `user`, `user_session` and `signin_transaction` tables. This epic replaces that with real Hosted Login step screens, bound sign-in transactions, password credentials, email delivery through the job pipeline, the database Connection with its password policy, per-Application Connections, the single revocation path wired to real triggers, and OpenID conformance against real sign-in. Every step must be safe against enumeration, fixation, step skipping and leakage.

## Stories

- Story 4.1: Serve Hosted Login step screens
- Story 4.2: Bind sign-in transactions and issue Sessions
- Story 4.3: Purge expired sign-in state
- Story 4.4: Configure a Tenant's email provider
- Story 4.5: Send email through the job pipeline
- Story 4.6: Configure the database Connection
- Story 4.7: Sign up and verify an email address
- Story 4.8: Keep sign-up neutral and limited
- Story 4.9: Sign in with a password
- Story 4.10: Revoke access through one path
- Story 4.11: Reset a forgotten password
- Story 4.12: Choose Connections per Application
- Story 4.13: Log out
- Story 4.14: Run OpenID conformance on real sign-in

## Requirements & Constraints

- **No enumeration:** across sign-in, sign-up, reset and verification, the content, status, next step and timing must not differ for known and unknown identifiers, within a stated tolerance. Login is identifier-first, and the step after Continue never depends on the account. An unknown account runs an equivalent dummy Argon2id hash. Sign-up with an existing address changes nothing, sends a notice to that address and looks identical. Rate-limit responses must not reveal accounts either.
- **Verification:** no Session or token exists for an unverified email unless a Dev Tenant turns verification off. A verification link is single-use, stored hashed, and invalidates any pending credential from an earlier unverified sign-up.
- **Reset:** the confirmation is identical for every address. The reset link lasts 30 minutes, is single-use, and is superseded by a newer reset or a password change. A completed reset never creates a Session, runs `RevokeAccess` and sends a notification.
- **Password policy:** Argon2id with parameters stored per hash and upgraded at the next successful sign-in. The minimum length can't go below 12 ("Minimum is 12 characters."). Strength, history, dictionary and personal-data rules apply per database Connection. The server refuses a failing password and names the rule. A Tenant has one database Connection in v1, and `user.email` is unique per Tenant. The same email in two Tenants gives two unrelated Users.
- **Session and transaction security:**
  - The Session identifier is 256-bit, stored only as SHA-256, and replaced at authentication so the old one stops working.
  - Transactions are bound to the browser, Tenant and Application, slide for 30 minutes, and refuse replay after expiry or completion.
  - A step needs a server record that earlier steps passed.
  - Every state-changing request needs a CSRF token bound to the Session or transaction plus an exact-host Origin check. `SameSite` alone isn't enough.
  - Cookies can't cross Tenant subdomains or the parent domain.
- **Rate limits:** sign-in, sign-up, resend and reset are limited per Tenant and per source, and reset also per recipient. Forwarded addresses are trusted only from Caddy's network address. Outbound email is limited per recipient.
- **Tokens:** the Session records `amr`, `auth_time` and the Connection. A User token's audience is the requested API, else the Tenant's default audience, else only the Tenant's userinfo endpoint. It is never the Epic 2 placeholder.
- **Logout:** ends the Session and its bound refresh tokens. It redirects only to a registered URL with a valid `id_token_hint`. Otherwise the User is logged out and sees the logged-out state with no redirect.
- **Revocation (FR-48):** triggers are password reset or change, Factor or Passkey added or removed, Recovery Codes regenerated or used, email change, User blocked or deleted, Factor reset, and Admin revoke. All Sessions and Token Families in scope end at once, except the acting Session for self-service changes. Access tokens stay valid until expiry.
- **Hosted Login surface:** every error state shows only fixed text, a code and a trace ID. Every response is `no-store`, denies framing and sets `Referrer-Policy: no-referrer`. Hosted Login meets WCAG 2.2 AA and works on current desktop and mobile browsers. Text ships in English, held in message catalogues, and a hard-coded user-facing string fails lint. Controls for deferred features never appear.
- **Leakage:** the canary scan must find no password, token, Session identifier or reset link in logs, Audit events or `Referer`.
- **Performance:** sign-in API requests complete under 500ms at p95 at 20 sign-ins per second, excluding deliberate hashing cost.
- **Conformance:** Basic OP, Config OP and RP-Initiated Logout OP run in CI against a Dev Tenant.

## Technical Decisions

- **Hosted Login delivery:**
  - One React bundle, shared with the Account Portal and served by `Host.Hosted`, with no Node in production. The CI budget is 150 kB compressed, with no third-party runtime request.
  - The first response embeds the step as JSON and links the Tenant theme stylesheet in `<head>`. The client renders with no fetch and holds no flow logic.
  - Every response is a `StepResponse` with `step`, `stepVersion`, `expiresInSeconds`, step data and a CSRF token. A stale `stepVersion` returns the current valid step. `POST /login/api/transaction/extend` backs "Keep going".
  - JavaScript is required, and `<noscript>` shows fixed text.
  - Leaving the origin, back to an Application or for a logout redirect, is a top-level GET, never a form post.
  - The CSP string is exactly `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`.
  - Step screens are props-only components in `packages/hosted-screens`, built on `@gatekeep/ui/hosted`, with tokens from `packages/design-tokens`. Raw hex values fail lint.
- **Sessions and transactions:** `user_session` and `signin_transaction` are `tenant` tables. Cookies are `__Host-gk_session` and `__Host-gk_txn`: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/` and no `Domain`. The transaction holds the authorization parameters and completed steps, and is the only source of truth for what may come next. Expired transactions stay one hour so a restart keeps the email.
- **Revocation:** `ISessions.RevokeAccess(context, scope, exceptSessionId)` is the only path. A generated test walks the FR-48 trigger list, with unbuilt triggers listed as pending, so the list can't shrink silently. Each completed code flow creates one ad-hoc authorization anchored to a `user_session`, and that authorization is the Token Family.
- **Credentials:**
  - High-entropy values (Session IDs, verification and reset links) are stored as SHA-256. Credential-equivalent values use `Secret<T>`.
  - Logging runs through a scrubbing sink.
  - Identity owns the typed credential tables: `password_credential`, `one_time_token` and `password_history`. There is no generic credential table.
  - Password policy checks run in Authentication, which has the edge to Directory.
- **Hashing budget:** all Argon2id work passes a Deployment-wide semaphore with per-Tenant shares. On overflow the request gets the generic failure. Attempt counters are `UNLOGGED` `tenant` tables behind the `IRateLimiter` port. There is no Redis.
- **Email:**
  - The provider credentials in `email_provider` are Transit ciphertext under the Tenant `email` key, with the Tenant ID as `associated_data`. `Host.Admin` can encrypt them but not decrypt them, and only `Host.Worker` decrypts.
  - Sending is a job. `gk_hosted` may enqueue only notification types. The recipient is an ID resolved at send time. A link payload is Transit `payload` ciphertext, erased on completion.
  - A link's host comes from the stored issuer, never request headers.
  - Email is a port with SMTP and HTTP adapters. Templates are subject and body text with fixed variable substitution, five defaults and no template engine.
- **Ownership:** Notifications owns `email_provider` and `email_template`. Directory owns `connection` and `application_connection`. Authentication owns `signin_transaction` and the attempt counters. Sessions owns `user_session`, `authorization` and `token`. Each new table's registry entry, RLS policies and grants go in the same migration.
- **Jobs:** recurring purges come from `Host.Worker`'s code-owned schedule, one Tenant scope at a time. They remove expired transactions and tokens, and Sessions with no live Token Family.
- **Conformance:** `GATEKEEP_CONFORMANCE_TENANT` relaxes a rule for one named Dev Tenant, per request, with the deviation recorded. Startup is refused with it set while any Prod Tenant exists, and labelling a Tenant Prod is refused while it's set.
- **Conventions:** every mutation is one `CommandContext` command that writes state and its Audit event together. Fresh WebAuthn assertion gates the email provider change. Editors and machine principals are refused provider changes. Limits come from the one Kernel limits file. Errors use RFC 9457 with `code` and `traceId`.

## UX & Interaction Patterns

- **Login content** depends only on the Connections enabled for the Application, never on the identifier:
  - Password enabled: an email field, then the password step.
  - No Connections: Generic error.
  - Sign-up disabled: the "Sign up" link is hidden.
  - "Use a recovery code" always shows.
  - A reusable Session skips Login unless `prompt=login` or `max_age` requires it.
- **Focus and titles:** focus goes to the first invalid field, else Login's email field on first load, else the card heading. `<title>` reads "{step heading} – {Tenant}", with "Error:" added after a failed submit. Pages have `lang="en"` and one `main` landmark. `role="alert"` is only for errors injected after load.
- **WCAG specifics:** the email carries across steps, and paste and password managers work on every credential field. Controls are at least 44px, with 24px inline hit areas. Layout reflows at 320px and 200% zoom. Reduced motion removes `gkIn`.
- **Theming:** Hosted Login follows `prefers-color-scheme` with no toggle, and dark uses the same components on `-dark` tokens. Text uses `tx2`.
- **Password step:** the identifier chip wraps and never truncates. Edit keeps the email. The email sits in a read-only `username` field in the same form. Copy: "Incorrect email or password.", identical for unknown accounts.
- **Strength meter:** four segments, with rules delivered as step data. A distinct "not met" glyph and text show unmet rules. A debounced `role="status"` label announces changes. The breach check runs on the server at submit only.
- **Transaction expiry:** a `role="alertdialog"` warning appears 2 minutes before expiry, with "Keep going". On expiry, sign-in restarts at Login with the email kept.
- **Resend:** `aria-disabled` for 30 seconds so focus stays, with the countdown outside live regions.
- **Link expired:** "This link has expired or was already used.", with "Send a new link", which leads to the neutral confirmation.
- **Reset:** the neutral confirmation reads "If an account exists for that email, we've sent a link." After Password changed, the only action is "Log in".
- **`autocomplete` values:** `username webauthn` on Login email, `username` on Signup email, `current-password`, and `new-password`.
- **Admin screens:**
  - Database · Settings is a sign-up toggle only.
  - Password policy shows defaults, read-only "Tenant Owner only" for Editors.
  - Application · Connections with nothing enabled shows a banner: "No Connections enabled. Users can't sign in."
  - Email provider with nothing set shows "No provider set" with Add, re-authenticates on save, then shows a `toast`.
- **Design Delta:**
  - Hosted Login: remove company SSO and Apple buttons. Remove the passkey hint on the password step and the breach tick on Signup. Mask passwords by default. "Back to {Tenant}" becomes "Log in". Generic error uses fixed text.
  - Database: remove the Custom database and Import tabs.
  - Email provider: email only.
- **Banned:** drag and drop, infinite scroll, modals over modals, and deferred-feature controls.

## Cross-Story Dependencies

- **Within the epic:**
  - 4.1's screen shell, `StepResponse` and lint underpin every Hosted Login story.
  - 4.2's binding and Session issuance come before 4.7, 4.9, 4.11 and 4.13.
  - 4.4 and 4.5 come before sign-up, the existing-address notice and reset email.
  - 4.6 creates `connection` and `password_history`, used by 4.7, 4.9, 4.11 and 4.12. Default `connection` is a Tenant creation step, with a backfill.
  - 4.10 is wired into 4.11.
  - 4.14 needs real sign-in and logout.
- **From earlier epics:**
  - Epic 1: the Tenant creation Operation, the capability table and `FreshAssertionGate`, Security Alerts, the canary scan, and the cross-Tenant suite with its pending list. 4.7 and 4.11 each remove a link artifact from that list.
  - Epic 2: `user`, `user_session`, `signin_transaction`, `authorization` and `token` (2.6). `RevokeAccess` (2.7). The system Application, which in 4.12 must follow every enabled Connection. The code flow through `IAuthentication.Begin`; the test-only authenticator stays out of release builds. The static error page that 4.1 replaces.
  - Epic 3: Applications and APIs. User-token audiences replace the placeholder.
- **For later epics:**
  - Story 8.5 keeps the terms URL, the Dev-only verification-off setting and the default audience added in 4.6.
  - Epic 6 adds Passkey creation after verification. Epic 10 adds backoff, lockout states and breach checks. Epic 14 adds email code and social Connections. Epic 15 adds template editing and test sends.
  - Later epics add further FR-48 triggers.
