---
title: Gatekeep PRD
status: final
created: 2026-11-01
updated: 2026-11-02
---

# PRD: Gatekeep

## 0. Document Purpose

This PRD defines what Gatekeep v1 must do and is the input to `bmad-ux`, `bmad-architecture` and `bmad-create-epics-and-stories`. It uses the terms in §3 exactly, numbers requirements globally, and tags inferred decisions as `[ASSUMPTION]`, indexed in §12.

It builds on `design/design-prompt.md`, `design/SCREENS.md` and the three design exports, which show the full long-term product. **This PRD decides what ships and when, and it wins any conflict with the design:** a designed screen or control is not a v1 commitment unless §7 says so. Market context is in `research-landscape.md` in the brief run. The product brief was left unfinished, so this PRD does not depend on it.

## 1. Vision

Gatekeep is a self-hosted identity and access management platform that Esm builds, owns and runs for their own production projects. Its long-term scope is comparable to Auth0. It gives each project sign-in, multi-factor authentication, access control and audit logs through standard protocols, from infrastructure Esm controls.

Gatekeep exists because Esm wants to build it. No specific failure of Keycloak, Clerk or any other product drives it, and this PRD claims no feature gap. Learning how this layer works by building it is a goal in its own right.

Once real people's credentials are involved, though, the learning goal stops setting the quality bar. Production does. Gatekeep v1 is the smallest product that is safe with multiple Tenants, and every other designed capability waits until v1 meets the v2 entry condition in §7.4.

## 2. Target User

### 2.1 Jobs To Be Done

- **Own the layer:** run authentication for my projects without depending on a third-party identity vendor.
- **Reuse it:** add sign-in to a new project in minutes, without rebuilding it.
- **Keep projects separate:** give each project or environment its own Users, keys and settings, so a problem in one can't reach another.
- **Trust it:** know that it follows the standards, that I can see what it's doing, and that I can recover it when something goes wrong.
- **Learn it:** understand identity protocols well enough to explain and operate what I've built.

### 2.2 Non-Users (v1)

- Third parties paying for Gatekeep as a service.
- Companies adopting it for workforce identity.
- Business customers of Esm's apps who need their own SSO or organization management (see v2).

[ASSUMPTION: A-1. Esm operates every Tenant. Tenants separate Esm's own projects and environments and aren't sold to or administered by strangers.]

### 2.3 Key User Journeys

- **UJ-1. Esm adds sign-in to a new project.** Esm is starting a web app. In the Admin Dashboard they create a Tenant, register an Application, enable password and Passkey login, and follow a quickstart. **Climax:** the app's first test User signs in through Hosted Login and the app receives a valid token. **Edge case:** a mismatched callback URL shows an error at Gatekeep and never redirects.
- **UJ-2. Maya signs in and secures their account.** Maya uses one of Esm's apps. Maya signs up with an email address, verifies it, creates a Passkey, and saves the recovery codes shown. **Climax:** the next sign-in takes one Passkey prompt. **Edge case:** after losing the device, Maya uses a recovery code, must enrol a new Passkey, receives a notification, and finds all other Sessions ended.
- **UJ-3. Esm responds to a suspected key compromise.** A Security Alert or Log entry suggests a Signing Key is at risk. Esm reviews Logs, revokes the key, and revokes the Tenant's Sessions and refresh tokens. **Climax:** Gatekeep promotes a new key automatically, and tokens signed by the revoked key are rejected within the JWKS cache limit. Applications recover when Users sign in again. No other Tenant is touched.
- **UJ-4. Esm upgrades Gatekeep and recovers from a failure.** Esm applies a new release after a fresh backup. The upgrade fails partway. **Climax:** Esm restores the backup on the previous version, using the documented procedure, and no credential that existed at backup time is lost.
- **UJ-5. Esm's service calls an API.** A backend job needs to call one of Esm's APIs. Esm registers a machine-to-machine Application and grants it Permissions. **Climax:** the job gets a token carrying only those Permissions, and the API rejects anything else.
- **UJ-6. Esm responds to a compromised server.** Evidence off the server suggests an intruder reached the host. Esm rebuilds on clean hardware from a backup that predates the compromise, using the escrowed Master Key, then follows the runbook to replace every key and secret, end all access and notify Users. **Climax:** every credential the intruder could have read is dead. **Edge case:** if both the server and the escrowed Master Key are lost, Users re-enrol and all keys are replaced.

## 3. Glossary

- **Deployment:** one running installation of Gatekeep, operated by the Operator. Contains one or more Tenants.
- **Operator:** the person who installs and runs a Deployment. In v1, Esm.
- **Tenant:** an isolated container inside a Deployment. It holds its own Users, Applications, APIs, Connections, Signing Keys, branding, settings and Logs. Environments such as Dev, Staging and Prod are separate Tenants, and no grouping level exists above a Tenant.
- **Tenant Subdomain:** a Tenant's permanent address under the Deployment's dedicated zone (FR-7).
- **Prod Tenant:** a Tenant labelled Prod.
- **Admin:** a person who signs in to the Admin Dashboard. An Admin is not a User and belongs to no Tenant.
- **Deployment Owner:** the Admin role that creates and deletes Tenants and manages Admins. Held at Deployment level.
- **Tenant Role:** an Admin's role in one Tenant: Owner, Editor or Viewer. A Tenant Owner, Editor or Viewer is an Admin holding that role. It grants nothing in any other Tenant.
- **User:** an end user who signs in to an Application. Belongs to exactly one Tenant.
- **Application:** a client registered in a Tenant: single-page, regular web, native or machine-to-machine.
- **API:** a resource server registered in a Tenant, identified by an audience, with its own Permissions.
- **Permission:** a named scope defined on an API.
- **Role:** a named set of Permissions assigned to Users. Roles are separate from Tenant Roles.
- **Connection:** a way for Users to authenticate first: database, social, Passkey or email one-time code.
- **Passkey:** a WebAuthn credential. With user verification, it satisfies both the first factor and MFA.
- **Factor:** a second authentication method enrolled by a User: TOTP or a WebAuthn security key.
- **Recovery Code:** a single-use code for regaining access. It is a recovery method, not a Factor.
- **Phishing-resistant:** bound to the site by the browser. In v1, only WebAuthn qualifies.
- **Hosted Login:** the end-user sign-in, sign-up and recovery screens served by Gatekeep.
- **Account Portal:** the Hosted Login area where Users manage their own account.
- **Admin Dashboard:** the web interface used by Admins, on its own hostname.
- **Management API:** the authenticated API offering Tenant-scoped Admin Dashboard capabilities programmatically.
- **Signing Key:** a Tenant's key for signing tokens, with a state of next, current, previous, retired or revoked.
- **Master Key:** the key protecting all stored secrets and private keys. It is held apart from the data it protects and never included in a backup.
- **Session:** a User's authenticated state with Gatekeep, separate from tokens issued to an Application.
- **Token Family:** a refresh token and all tokens rotated from it.
- **Log:** a tamper-evident record of an event in a Tenant.
- **Deployment Log:** a tamper-evident record of events above Tenant level.
- **Security Alert:** a notification sent through a channel independent of the Deployment.

## 4. Features

### 4.1 Deployment and Operations

**Description:** The Operator can install, secure, upgrade, back up and restore a Deployment without outside help. Realizes UJ-4, UJ-6.

**Functional Requirements:**

#### FR-1: Install a Deployment

The Operator can install a Deployment from a released version using documented steps.

**Consequences (testable):**
- A clean install on an on-premises Docker host reaches a working Admin Dashboard using only the documentation.
- The core runtime needs no cloud-managed service. External dependencies are limited to those in §10.
- The documentation covers the wildcard DNS and TLS certificates that Tenant Subdomains need.
- A Deployment refuses to start if required secrets are missing or left at insecure defaults.

#### FR-2: Bootstrap the first Admin

The Operator can create the first Admin through a one-time process.

**Consequences (testable):**
- Bootstrap requires a one-time token available only from the server.
- The Deployment serves no Tenant traffic until bootstrap completes.
- The first Admin is a Deployment Owner and must register two WebAuthn credentials before making changes.
- The bootstrap path can't be used again.

#### FR-3: Upgrade between releases

The Operator can upgrade a Deployment from the previous minor release, or the latest patch of it, by following release notes.

**Consequences (testable):**
- An upgrade refuses to start without a backup taken within the previous 24 hours.
- An upgrade that fails leaves a state recoverable through FR-4.
- Valid Sessions and tokens survive an upgrade, except in a release that names a security reason for ending them.

#### FR-4: Back up and restore

The Operator can back up a Deployment and restore it, including onto clean hardware.

**Consequences (testable):**
- A backup without the Master Key reveals no secret or private key.
- Restore onto clean hardware succeeds using only the off-server backup, the escrowed Master Key and the documentation.
- A restored Deployment accepts credentials that existed at backup time.
- A restore reports the backup's timestamp and the window of lost changes.
- By default, a restore invalidates all earlier Sessions and refresh tokens. The Operator can opt out only for a planned rollback such as UJ-4.
- A key, Admin or credential revoked after the backup can't return to use. A post-restore step re-applies revocations from the off-server record in FR-40.

#### FR-5: Recover Admin access

The Operator can regain Admin access after losing all Admin credentials.

**Consequences (testable):**
- Recovery requires infrastructure-level access to the Deployment.
- Recovery issues a single-use, short-lived enrolment. It doesn't disable WebAuthn.
- Recovery ends all sessions of the affected Admin, writes to the Deployment Log and raises a Security Alert.

#### FR-6: Monitor Deployment health

The Operator can see service status, email provider status and rate-limit usage.

**Consequences (testable):**
- The Deployment exposes a health signal that external monitoring can read.
- The Admin Dashboard shows rate-limit usage per Tenant.

#### FR-45: Send Security Alerts

The Deployment sends Security Alerts to the Operator through a channel independent of the Deployment.

**Consequences (testable):**
- Security Alerts fire for: an Admin added or raised in role, an Admin sign-in from a new device, FR-5 recovery, a Management API grant, Signing Key rotation or revocation, MFA policy lowered, email provider changed, a callback URL added in a Prod Tenant, refresh token reuse above a threshold, a failed sign-in spike, a Log verification failure, and a restore.
- A delivery test is part of SM-5.

### 4.2 Tenants

**Description:** A Deployment holds multiple Tenants that behave as separate identity systems. This is a v1 requirement and carries the highest isolation risk in the product. Realizes UJ-1, UJ-3.

**Functional Requirements:**

#### FR-7: Manage Tenants

A Deployment Owner can create and delete Tenants. A Tenant Owner can change a Tenant's Dev, Staging or Prod label. The Deployment Owner who creates a Tenant becomes its Tenant Owner.

**Consequences (testable):**
- Each Tenant is served from its own Tenant Subdomain, which gives it its own issuer, Hosted Login address, discovery document and JWKS.
- A Tenant Subdomain can't change after creation, is never reused, and can't use a reserved infrastructure name.
- Requests for an unknown subdomain get a generic rejection and never reach a Tenant.
- Removing the Prod label needs re-authentication (FR-46), writes to the Log and relaxes no existing setting.
- Deleting a Tenant needs typed confirmation and re-authentication. Its Signing Keys are destroyed, its JWKS is withdrawn, and its security Logs are kept for 90 days.
- A test proves that deleting one Tenant leaves every other Tenant's data, keys and Logs unchanged.

#### FR-8: Enforce Tenant isolation

The system keeps each Tenant's data, keys and Sessions isolated from every other Tenant.

**Consequences (testable):**
- Each Tenant's tokens carry that Tenant's unique issuer and are signed by keys found only in that Tenant's JWKS.
- The Management API rejects tokens from any other Tenant.
- No request can read or change a Tenant's data without a Tenant Role or an authorized machine-to-machine Application in that Tenant, apart from the Deployment Owner actions in FR-7 and FR-50.
- The automated cross-Tenant suite runs on every release. It covers every Management API, Admin Dashboard, OAuth, OIDC and Hosted Login endpoint, and every artifact type: code, refresh token, reset link, email code, verification link, invite, Passkey and Recovery Code.
- Every background job runs with one explicit Tenant, or is declared Deployment-wide and reviewed. A job with no Tenant context fails rather than running unscoped.
- Caches, rate-limit counters and queued jobs are keyed by Tenant.
- The Tenant boundary is enforced below application logic, so one missed filter doesn't expose data.
- The same email in two Tenants produces two unrelated Users.
- Session cookies can't be sent to, or set by, another Tenant's subdomain or the parent domain. A test covers both directions.
- Every email link is built from the Tenant's stored issuer, never from request headers.

#### FR-9: Switch Tenants

An Admin can switch between Tenants they hold a Tenant Role in from the top bar.

**Consequences (testable):**
- The current Tenant name and environment badge are visible on every Admin Dashboard page, and Prod Tenants have a visibly distinct treatment.
- Tenants the Admin has no Tenant Role in aren't listed.
- Every Admin action names its target Tenant, and a mismatch with the page's Tenant is rejected.

#### FR-10: Configure Tenant settings

A Tenant Owner or Editor can configure a Tenant's display name, support contact, session lifetimes, default audience and error page.

**Consequences (testable):**
- Each change takes effect only in that Tenant and is written to the Log.
- Values stay within the limits in §5.2.
- A custom error page receives only an error code and trace ID.

**Out of Scope:**
- Comparing and promoting configuration between Tenants (v2).

### 4.3 Applications and APIs

**Description:** Tenant Owners and Editors register the clients and resource servers that use a Tenant. Realizes UJ-1, UJ-5.

**Functional Requirements:**

#### FR-11: Manage Applications

A Tenant Owner or Editor can create, edit and delete single-page, regular web, native and machine-to-machine Applications.

**Consequences (testable):**
- Each Application has a client ID and, where the type requires it, a credential.
- Callback, logout and web origin URLs are matched exactly in every Tenant, with the RFC 8252 loopback port exception for native Applications.
- Native Applications use the system browser. A custom URI scheme in a Prod Tenant needs an explicit acknowledgement.
- Deleting an Application revokes its refresh tokens and grants.

#### FR-12: Manage client credentials

A Tenant Owner can create, rotate and revoke an Application's client secret.

**Consequences (testable):**
- A secret is shown once, when created, and is stored only as a hash or under the Master Key.
- During rotation, the old secret stays valid for an overlap within §5.2, and an "end now" option stops it immediately.

#### FR-13: Choose grant types

A Tenant Owner or Editor can enable Authorization Code with PKCE, Refresh Token and Client Credentials per Application.

**Consequences (testable):**
- PKCE with S256 is required on every authorization code flow, including confidential clients. `plain` is rejected.
- Codes are single-use, expire within §5.2, and are bound to the client, redirect URI and PKCE challenge.
- Replaying a code is refused and revokes tokens issued from it.
- Authorization responses include `iss`.
- An unregistered `redirect_uri` shows an error at Gatekeep and never redirects.
- Implicit and Resource Owner Password grants aren't available.

#### FR-14: Control Connections per Application

A Tenant Owner or Editor can enable or disable each Connection per Application.

**Consequences (testable):**
- Hosted Login shows only Connections enabled for the requesting Application.
- An existing Session is reused for an Application only if it was established through a Connection enabled for that Application. Otherwise, the User signs in again.

#### FR-15: Configure token settings

A Tenant Owner or Editor can set ID token, access token and refresh token lifetimes per Application or API, within §5.2.

**Consequences (testable):**
- Refresh tokens rotate on every use, with no option to turn this off.
- Reuse of a rotated refresh token revokes its whole Token Family and writes to the Log.
- Absolute and inactivity lifetimes are both enforced.

#### FR-16: Manage APIs

A Tenant Owner or Editor can create APIs, define Permissions, set offline access and RBAC per API, and authorize machine-to-machine Applications for selected Permissions. Realizes UJ-5.

**Consequences (testable):**
- A token never contains a Permission that isn't currently granted. Permissions are re-evaluated at every refresh.
- An API's identifier is unique in its Tenant and can't change after creation.
- Setup guidance tells developers to use different API identifiers for Dev, Staging and Prod.
- Each Tenant lists the built-in Management API, so machine-to-machine access can be granted against it under FR-42.

### 4.4 Authentication

**Description:** Users authenticate through Hosted Login using the Connections a Tenant enables. Realizes UJ-1, UJ-2.

**Functional Requirements:**

#### FR-17: Sign in and sign up with a password

A User can sign up, verify their email and sign in with an email and password.

**Consequences (testable):**
- Login is identifier-first, and the step after the identifier doesn't depend on whether the account exists or how it signs in.
- No Session or token is issued for an unverified email, unless a Dev Tenant turns this off.
- Sign-up with an existing address changes nothing on the account, sends a notice to that address, and looks identical to a new sign-up.
- Verifying an address invalidates any pending credential from an earlier unverified sign-up.
- A Tenant Owner or Editor can disable sign-up for a Connection.
- When a Tenant sets a terms URL, sign-up requires acceptance, and the version and time are recorded.

#### FR-18: Enforce password policy

A Tenant Owner can set password strength, history, dictionary and personal-data rules per database Connection.

**Consequences (testable):**
- A password that fails policy is rejected with guidance.
- Policy can't go below the floor in §5.2.

#### FR-19: Reset a password

A User can reset a forgotten password by email.

**Consequences (testable):**
- The confirmation is identical for known and unknown addresses.
- Reset links are single-use, expire within §5.2, and are invalidated by a newer reset or a password change.
- A completed reset never creates a Session. The User then signs in, including any required Factor.

#### FR-20: Sign in with social providers

A User can sign in with Google, GitHub or Microsoft where enabled. [ASSUMPTION: A-2. These three are enough for v1.]

**Consequences (testable):**
- Each Tenant supplies its own provider credentials.
- A social identity is keyed on the provider's issuer and subject, never on email.
- A social identity is never linked automatically to an existing account.
- A social sign-in is refused unless the provider asserts a verified email.
- A social sign-in whose verified email matches an existing User creates no account and shows a neutral error with a path to the existing sign-in method. This reveals the account only to someone who has proved control of that address (NFR-20).
- `email_verified` is passed to Applications only when the provider asserts it.

#### FR-21: Sign in with a Passkey

A User can create a Passkey and use it to sign in. Realizes UJ-2.

**Consequences (testable):**
- Hosted Login offers Passkey creation after email verification, unless a Tenant turns the prompt off.
- User verification is required, and no attestation is requested.
- Passkey discovery is browser-mediated and needs no account lookup.
- A Passkey created in one Tenant can't be used in another, because it's bound to the exact Tenant Subdomain rather than the parent domain.

**Notes:** v2 custom domains need a Passkey migration plan.

#### FR-22: Sign in with an email one-time code

A User can sign in with a one-time code sent by email.

**Consequences (testable):**
- Codes are single-use, and their expiry and attempt limit stay within §5.2.
- Requesting a new code doesn't reset the attempt count.
- A Tenant can choose whether this Connection creates new accounts.

#### FR-23: Standards-based sign-in

Applications can authenticate Users through OpenID Connect and OAuth 2.0.

**Consequences (testable):**
- Each Tenant publishes a valid OpenID Connect discovery document and JWKS, and offers token, userinfo and token revocation (RFC 7009) endpoints.
- Gatekeep follows RFC 9700, and any deviation is recorded.
- Gatekeep passes the OpenID Foundation conformance tests for the Basic OP, Config OP and RP-Initiated Logout OP profiles on every release.
- Access tokens are JWTs with `typ: at+jwt`. Tokens use one fixed asymmetric algorithm per Tenant, and others, including `none`, are rejected. [ASSUMPTION: A-16]
- `prompt=login`, `max_age` and `auth_time` are honoured, and `amr` reports the methods used.

#### FR-24: Log out

A User can end their Session, and Applications can trigger logout.

**Consequences (testable):**
- Logout ends the Session and the refresh tokens bound to it.
- Logout redirects only to registered URLs and needs `id_token_hint` or equivalent to redirect.

**Out of Scope:**
- OIDC Back-Channel Logout (v2). Until then, an Application keeps its own session until it next checks with Gatekeep, and quickstarts document this.

#### FR-47: Protect Sessions and sign-in transactions

The system protects every sign-in against fixation, step skipping and cross-site attacks.

**Consequences (testable):**
- The Session identifier changes at authentication, at Factor completion, at re-authentication and at password change. Earlier identifiers stop working.
- Each sign-in transaction is bound to the initiating browser, Tenant and Application, is short-lived, and can't be replayed.
- A step can't be reached without a server-side record that earlier steps passed. A post-MFA URL requested directly is refused.
- Sign-in forms are protected against login CSRF, and requests to social providers use `state`, `nonce` and PKCE. A provider without OIDC, such as GitHub, has no ID token, so it uses single-use `state` and PKCE without `nonce`.

### 4.5 Multi-Factor Authentication and Attack Protection

**Description:** Tenant Owners set MFA policy and protections. Users enrol and use Factors and Passkeys. Realizes UJ-2.

**Functional Requirements:**

#### FR-25: Set MFA policy

A Tenant Owner can set MFA to Never or Always per Tenant and choose which Factors are allowed.

**Consequences (testable):**
- With Always, no Connection, reset, lockout recovery or verification flow completes sign-in or issues a token until a second factor from a different category is verified. A Recovery Code stands in for this step only as FR-27 allows.
- A user-verified Passkey satisfies Always on its own.
- An email code never counts as a second factor.
- Email-based flows can't remove, replace or bypass a Factor.
- Enrolling a first Factor needs a verified email and triggers a notification. A stolen password alone can't enrol one.
- After a change from Never to Always, Users with no Factor or Passkey enrol at their next sign-in under the same rule.
- Disallowing a Factor doesn't strand Users. Those relying on it enrol a replacement at next sign-in.
- Lowering the policy needs re-authentication (FR-46), and every change writes to the Log.
- A test matrix of every Connection and recovery path under Always ends with a verified second factor or an FR-27 Recovery Code.

**Out of Scope:**
- Adaptive, risk-based policy, User step-up authentication and "remember this browser" (v2). Admin re-authentication is v1 (FR-46).

#### FR-26: Enrol and use Factors

A User can enrol and use TOTP and WebAuthn security key Factors.

**Consequences (testable):**
- TOTP codes can't be reused within their validity window.
- Under Always, removing the last Factor or Passkey is refused unless another remains.

#### FR-27: Use Recovery Codes

A User receives Recovery Codes at their first enrolment of a Passkey or Factor. Realizes UJ-2.

**Consequences (testable):**
- Codes are shown once, with confirmation that they were saved. Each works once and is stored only in a non-reversible form.
- Regenerating codes invalidates the old set.
- A Recovery Code replaces only the Factor step. For a User with only a Passkey, it replaces the sign-in, followed by mandatory re-enrolment, a notification and the effects in FR-48.
- With Always, a Passkey-only User has no email recovery. If they lose both their Passkey and Recovery Codes, a Tenant Owner or Editor resets their credentials (FR-31) after checking identity outside the product. The reset issues a single-use enrolment link, shown once to the Admin and passed on outside the product. The User then enrols again under FR-25, and no Session or token exists before enrolment completes.
- With Never, a Tenant can allow email recovery for Passkey-only Users, with a 24-hour delay and a notification.

#### FR-28: Limit sign-in attacks

The system limits repeated failed sign-ins, per account and per source.

**Consequences (testable):**
- Limits apply separately to password, TOTP, Recovery Code, email code and Passkey steps, and survive a new challenge.
- Thresholds are configurable per Tenant, within §5.2, and can't be turned off.
- The system backs off rather than locking outright. A failed-attempt limit doesn't block a valid Passkey.
- Blocked and locked states appear only after valid credentials. Otherwise, the User sees the same generic failure.
- Lockout emails are rate limited per recipient and can't undo an Admin block.
- Each lockout writes to the Log.

#### FR-29: Detect breached passwords

The system checks passwords against known breach data at sign-up, reset, change and sign-in. [ASSUMPTION: A-14. The breach dataset is held locally.]

**Consequences (testable):**
- A User's password is never sent in a recoverable form to any external service.
- A breached password is rejected at sign-up, reset and change.
- At sign-in, a breached password isn't proof of identity on its own. The User completes a verified Factor or an out-of-band reset before setting a new password, and no Session or token is issued first.
- Each detection writes to the Log.

### 4.6 Users and Authorization

**Description:** Tenant Owners and Editors manage Users and control what they can do.

**Functional Requirements:**

#### FR-30: Search and view Users

An Admin can search Users by field in a Tenant and view profile, identities, last login, Sessions, Factors and history.

**Consequences (testable):**
- No credential-equivalent value (§5.1, NFR-3) appears in the Admin Dashboard or in Management API responses.

#### FR-31: Administer a User

A Tenant Owner or Editor can create, block, unblock, delete, send verification to, reset the Factors and Passkeys of, and revoke the Sessions and refresh tokens of a User.

**Consequences (testable):**
- Blocking, deletion and Factor reset apply the effects in FR-48.
- After a Factor reset, the User enrols again under FR-25 and receives a notification.
- For a Passkey-only User, the reset issues the single-use enrolment link in FR-27. It's shown once and stored only hashed.
- Deletion requires typed confirmation.
- Every action writes to the Log with the acting Admin.

**Out of Scope:**
- Impersonation (see §6).

#### FR-32: Manage Roles

A Tenant Owner or Editor can create Roles, assign Permissions to them and assign them to Users.

**Consequences (testable):**
- With RBAC on for an API, a User's effective Permissions appear in access tokens for it.
- A removed Role or Permission doesn't appear in any token issued after removal.

#### FR-48: Revoke access on credential change

The system ends existing access when a credential changes, so that a recovering User evicts an attacker.

**Consequences (testable):**
- Triggers: password reset or change, Factor or Passkey added or removed, Recovery Codes regenerated or used, email change, User blocked or deleted, Factor reset, and Admin "revoke".
- Effects: all Sessions and Token Families end at once. For a change the User makes in the Account Portal or during sign-up or enrolment, the acting Session continues.
- Access tokens stay valid only until expiry, bounded by §5.2. Quickstarts state this residual window.

#### FR-49: Export and erase User data

A Tenant Owner can export or erase a User's personal data.

**Consequences (testable):**
- Logs, including off-server copies, identify a person by an internal reference. Erasure deletes the personal data behind that reference, so the event record and hash chain stay intact.
- Export and erasure write to the Log.

### 4.7 Hosted Login and Branding

**Description:** Hosted Login carries each Tenant's branding, and Users manage their own account there. Realizes UJ-2.

**Functional Requirements:**

#### FR-33: Provide Hosted Login screens

Users can complete every v1 flow through the Hosted Login screens in §7.2, following `design/Gatekeep Hosted Login.dc.html`.

**Consequences (testable):**
- Every error state has a screen and shows no internal detail beyond an error code and trace ID.
- Hosted Login, the Account Portal and the Admin Dashboard send a strict Content Security Policy, deny framing and set `Referrer-Policy: no-referrer`.
- Controls for deferred features don't appear.

#### FR-34: Theme Hosted Login

A Tenant Owner or Editor can set a Tenant's logo, colours, font and corner radius, previewing the login, signup, MFA, reset and error screens before publishing.

**Consequences (testable):**
- Theme values are validated against typed allowlists, and theming can't inject scripts.
- Logos are served as sanitized images, and no theme asset loads from a third party.
- Colour choices that break NFR-16 contrast are refused.
- Changes to a Prod Tenant write to the Log.

**Out of Scope:**
- Custom HTML templates, custom domains (v2) and translation management (later).

#### FR-35: Provide the Account Portal

A User can edit their profile, manage their password, Passkeys and Factors, review and end Sessions, and delete their account.

**Consequences (testable):**
- Sensitive changes are email, password, adding or removing a Factor or Passkey, regenerating Recovery Codes and deleting the account.
- Sensitive changes need re-proof within §5.2 using the strongest enrolled method. A Recovery Code or email code doesn't qualify when a stronger method is enrolled.
- An email change takes effect only after the new address is verified. The old address is told and can reverse it for 72 hours.
- The Account Portal tabs are Profile, Security and Sessions.

#### FR-36: Send transactional email

A Tenant Owner can configure an email provider, and a Tenant Owner or Editor can edit verification, password reset, one-time code, account locked and security notification templates per Tenant.

**Consequences (testable):**
- Changing the provider needs re-authentication (FR-46), writes to the Log and raises a Security Alert.
- Admins can send a test email, which reports SPF, DKIM and DMARC state.
- Reset, verification and code templates must contain the system-generated link or code and can't change its destination.
- Templates can't load remote content, execute code or read another Tenant's data.
- Outbound email is rate limited per recipient.
- Users always receive notifications, with no option to disable them, for: password changed, email change requested, Factor or Passkey added or removed, Recovery Code used and Recovery Codes regenerated.

### 4.8 Keys and Secrets

**Description:** Each Tenant has its own Signing Keys. Rotation is routine and causes no downtime. Revocation is the emergency action and has a stated token impact. Realizes UJ-3, UJ-6.

**Functional Requirements:**

#### FR-37: Rotate Signing Keys

The system rotates a Tenant's Signing Key automatically, and a Tenant Owner can rotate it at any time.

**Consequences (testable):**
- Every Tenant always holds a next key, published in the JWKS for at least the JWKS cache limit before it signs anything.
- Tokens signed by the previous key verify until they expire. The key then becomes retired, leaves the JWKS, and has its private material destroyed.
- No key stays current beyond the maximum age in §5.2.
- Rotation doesn't affect other Tenants.

#### FR-38: Revoke Signing Keys

A Tenant Owner can revoke a Signing Key after re-authentication (FR-46), invalidating tokens it signed.

**Consequences (testable):**
- A revoked key leaves the JWKS at once, and its private material is destroyed.
- Revoking the current key promotes the next key at once, with no manual steps, and a new next key is created.
- Resource servers stop trusting a revoked key within the JWKS cache limit in §5.2, and quickstarts honour it.
- The same action offers to revoke the Tenant's Sessions and refresh tokens.
- A test shows a token forged with a revoked key is rejected by a quickstart API inside that limit.

#### FR-50: Respond to a Tenant or Deployment compromise

A Tenant Owner can revoke every Session and refresh token in a Tenant, and force password resets and TOTP re-enrolment. A Deployment Owner can do this across every Tenant and revoke all Signing Keys, which FR-38 replaces automatically. Realizes UJ-3, UJ-6.

**Consequences (testable):**
- Both actions need re-authentication (FR-46), and write to the Log and Deployment Log.
- A Tenant Owner can send a security notice to all of a Tenant's Users.

### 4.9 Administration and Audit

**Description:** Admins sign in separately from Users, hold scoped Tenant Roles, and everything they do is recorded. Realizes UJ-3.

**Functional Requirements:**

#### FR-39: Manage Admins

A Deployment Owner can invite and remove Admins and give them Tenant Roles. One Admin account can hold Tenant Roles across Tenants. [ASSUMPTION: A-3. Owner, Editor and Viewer are enough; the design's Support role waits.]

**Consequences (testable):**
- Capabilities follow the matrix below, enforced server-side. A test denies each role each action outside it.
- Invites are single-use, expire within §5.2 and are bound to the invited email.
- Removing an Admin ends their sessions at once, and lists any Management API clients they created, with an offer to revoke them.
- A Deployment can't lose its last Deployment Owner.

| Capability | Viewer | Editor | Owner |
| --- | --- | --- | --- |
| Read configuration and Users | Yes | Yes | Yes |
| Read raw Log detail with personal data | No | Yes | Yes |
| Manage Applications, APIs, Roles, Users, theme and templates | No | Yes | Yes |
| Configure Tenant settings, enable or disable Connections, export configuration | No | Yes | Yes |
| Manage client secrets, password policy, MFA policy, Connection credentials, email provider and Tenant label | No | No | Yes |
| Rotate or revoke Signing Keys; grant Management API access | No | No | Yes |
| Export or erase User data; run FR-50 Tenant actions | No | No | Yes |

#### FR-46: Sign in as an Admin

Admins sign in to the Admin Dashboard with WebAuthn only.

**Consequences (testable):**
- Admin credentials are stored apart from every Tenant's Users, and no Tenant Connection can sign in an Admin.
- No email reset, email code, social login or TOTP can sign in an Admin or remove an Admin credential.
- Every Admin registers two WebAuthn credentials, or one and a Recovery Code held offline. A Recovery Code sets up a new credential and can't reach any other action.
- A lost credential is recovered by another Deployment Owner or through FR-5.
- Admin sessions have the lifetimes in §5.2.
- The Admin Dashboard is on its own hostname, outside every Tenant's origin, and reachable only by VPN or private network.
- These actions need a fresh WebAuthn assertion within §5.2: Admin grant or removal, Signing Key revocation, lowering MFA policy, changing a Prod Tenant's callback URLs or label, rotating a client secret, changing the email provider, granting Management API access, Tenant deletion, and FR-50 actions.

#### FR-40: Search Logs

An Admin can filter a Tenant's Logs and open an event's raw detail, subject to FR-39. A Deployment Owner can do the same for the Deployment Log.

**Consequences (testable):**
- Logs cover sign-ins, failures, password resets, email changes, Factor and Recovery Code events, Session and token revocation, Admin changes, key operations, Management API grants, Token Family revocations and rejected cross-Tenant attempts.
- The Deployment Log covers bootstrap, Admin sign-in, recovery, Tenant creation and deletion, upgrades, restores and Deployment configuration.
- Events carry stable type codes, which form part of the public contract.
- Logs never contain a credential-equivalent value (NFR-3). A test plants canary values through each flow and scans for them.
- Logs can't be changed or deleted through the Admin Dashboard or Management API.
- Logs are hash-chained or equivalent, and a verification command reports any change or gap.
- Security events and revocations are copied off the server in near real time to a store the server can't rewrite or delete.

**Out of Scope:**
- Configurable Log streams and live tail (v2).

#### FR-41: Export configuration

A Tenant Owner or Editor can export a Tenant's configuration as a readable file from Tenant settings.

**Consequences (testable):**
- Exports contain no secrets or private keys.

**Out of Scope:**
- Applying configuration from a file (v2).

### 4.10 Developer Experience

**Description:** Gatekeep is developer-first: identifiers are exact, responses are honest, and integration is quick. Realizes UJ-1, UJ-5.

**Functional Requirements:**

#### FR-42: Offer the Management API

An authorized machine-to-machine Application can perform Tenant-scoped Admin Dashboard actions through the Management API, except those excluded below. [ASSUMPTION: A-13. Like the Admin Dashboard, it's reachable only by VPN or private network.]

**Consequences (testable):**
- Excluded: Admin management and every action that FR-46 says needs a fresh WebAuthn assertion, in all Tenants.
- Only a Tenant Owner, after re-authentication, can grant Management API Permissions, and each grant raises a Security Alert.
- A client can't grant a Permission it doesn't hold, or create or change any client's Management API access.
- Tokens have the lifetime in §5.2 and are issued only to a client bound to one Tenant.
- Every client with access is listed with its grants and last use. Access is written to the Log.
- The API is versioned, and a breaking change requires a new version.

#### FR-43: Publish quickstarts and API reference

Developers can follow quickstarts for React, Next.js, Node, .NET and Python, using standard OIDC libraries, and read a reference for every public API, shipped with each release.

**Consequences (testable):**
- A developer following a quickstart completes UJ-1 within 30 minutes, and server-side quickstarts cover UJ-5.
- Each Application's quickstart tab pre-fills its client ID, never a secret.
- Every quickstart validates signature, `iss`, `aud`, `exp` and a fixed algorithm, and uses `sub`, not email, as the User key.
- Quickstart APIs reject ID tokens used as access tokens.
- A negative test pack runs on every release: wrong Tenant, wrong audience, expired, ID token, `alg: none` and revoked key.

**Out of Scope:**
- First-party SDKs (v2).

### 4.11 Admin Dashboard

**Description:** The Admin Dashboard implements the admin design for v1 features only. Its character is set by the design system's line: "Quiet, dense, exact." It's for people who read tokens, so tables stay dense, identifiers stay copyable, and colour carries meaning rather than decoration.

**Functional Requirements:**

#### FR-44: Present only available features

An Admin can reach every v1 feature from the sidebar, in light or dark mode, on desktop and tablet.

**Consequences (testable):**
- Deferred features don't appear as screens, disabled controls, links or copy.
- With no Tenants, a Deployment Owner lands on a create-Tenant form. Otherwise, Admins land on the current Tenant's Applications list.

## 5. Cross-Cutting Requirements

### 5.1 Security

- **NFR-1:** A written threat model covers the product before implementation of authentication begins, and is updated when a feature changes a trust boundary.
- **NFR-2:** Passwords are stored with a modern memory-hard hash, and parameters can be raised without resetting Users.
- **NFR-3:** Secrets and private keys are encrypted under the Master Key, with Tenant-specific keys derived from or wrapped by it. The Master Key can be rotated without resetting Users. An offline escrow copy is stored apart from backups, and restoring with it is rehearsed. Refresh tokens, Session identifiers and one-time values are stored hashed. Credential-equivalent values never reach Logs, error messages, debug output or exports. These include passwords, secrets, tokens, reset and verification links, email and authorization codes, Recovery Codes, TOTP seeds, Session identifiers and any URL query containing them.
- **NFR-4:** All external traffic uses TLS. Session and sign-in transaction cookies use the `__Host-` prefix. Every state-changing request needs a CSRF token bound to the Session and an Origin check against the exact host. `SameSite` alone isn't accepted.
- **NFR-5:** Authorization happens server-side on every request. Hiding something in the Admin Dashboard isn't a control.
- **NFR-6:** Sign-in, sign-up, reset, email code, verification resend, token, Factor and recovery endpoints are rate limited per Tenant and per source. Forwarded client addresses are trusted only from a configured proxy. Hashing work has a Deployment-wide concurrency budget with per-Tenant shares, so one Tenant can't exhaust it. A failed sign-in spike tightens limits and raises a Security Alert.
- **NFR-7:** Dependencies are pinned and scanned on every release, and a known critical vulnerability blocks release.
- **NFR-8:** Before real Users sign in, Esm completes a self-assessment of v1 against OWASP ASVS 5.0 at Level 2, with a stored result per requirement. Critical means a route to account or Deployment takeover. High means a realistic incident affecting many Users, an Admin or a Tenant boundary. All such findings are fixed. It's re-run in full before each major release, and for affected chapters when a trust boundary changes. [ASSUMPTION: A-15. Version and level.]
- **NFR-9:** A tested runbook covers vulnerability intake through a published security contact, a fix target of 7 days for critical issues, User notification within 72 hours of confirming a breach, and updates if the scope widens. It also covers Tenant key compromise (UJ-3) and full server compromise (UJ-6): rebuilding on clean hardware, replacing every key and secret, including the TLS key and Master Key, forcing re-enrolment, and reaching Users if Gatekeep is down.
- **NFR-20:** Across sign-in, sign-up, reset, email code and verification, response content, status, next step and timing don't differ for known and unknown identifiers, within a stated tolerance. The only exception is the social email conflict in FR-20.
- **NFR-21:** Tenant Subdomains sit under a dedicated zone used only by Gatekeep, so the wildcard certificate covers no Application or mail host. The certificate's private key isn't readable by the application process. Any DNS credential is limited to validation records, and kept off the server if feasible. CAA records are set, Certificate Transparency monitoring raises alerts, and emergency certificate replacement is rehearsed.

### 5.2 Security Limits

Hard limits are enforced by the Deployment, and no setting can exceed them. [ASSUMPTION: A-12. All values are starting points.]

| Value | Default | Hard limit |
| --- | --- | --- |
| Access token and ID token lifetime | 15 minutes | 1 hour |
| Refresh token absolute lifetime | 30 days | 90 days |
| Refresh token inactivity lifetime | 7 days | 30 days |
| Failed attempts before backoff, per account | 5 in 15 minutes | 20 in 15 minutes |
| User Session lifetime, idle / absolute | 3 days / 7 days | 30 days absolute |
| Admin session lifetime, idle / absolute | 30 minutes / 8 hours | Same |
| Management API token lifetime | 15 minutes | 15 minutes |
| Authorization code lifetime | 60 seconds | 60 seconds |
| Reset link lifetime | 30 minutes | 30 minutes |
| Email code | 6 digits, 10 minutes, 5 attempts | Same |
| Admin invite lifetime | 72 hours | 72 hours |
| Credential enrolment link lifetime | 24 hours | 24 hours |
| Client secret overlap | 24 hours | 7 days |
| Recent authentication | 5 minutes | 5 minutes |
| Password minimum length | 12 characters | Can only be raised |
| Signing Key maximum age | 180 days | 365 days |
| JWKS cache limit | 15 minutes | 15 minutes |
| Log retention | 90 days | 90-day floor in Prod Tenants |

v1 has no setting for Signing Key maximum age, client secret overlap or Log retention. Each is fixed at its default, and only a release can change it, within the hard limit.

### 5.3 Reliability and Performance

- **NFR-10:** Prod Tenants target 99.5% monthly availability, about 3.6 hours of downtime, including planned upgrades. [ASSUMPTION: A-4. The server is reachable from the public internet, with no redundant power, network or hardware.]
- **NFR-11:** Sign-in API requests complete in under 500ms at p95 at a peak of 20 sign-ins per second, excluding deliberate password-hashing cost and third-party providers. [ASSUMPTION: A-5]
- **NFR-12:** Expected load is under 10,000 Users across the Deployment at launch. [ASSUMPTION: A-6]
- **NFR-13:** Restoring from backup takes under 1 hour, with no more than 24 hours of data lost. Backups are stored off the server. [ASSUMPTION: A-7]

### 5.4 Privacy

- **NFR-14:** Each Tenant meets User export and erasure requests through FR-49. [ASSUMPTION: A-8. GDPR-style rights apply, since real strangers may use these apps.]
- **NFR-15:** Logs have the retention in §5.2, fixed in v1. The floor can't be lowered.

### 5.5 Accessibility and Platform

- **NFR-16:** Hosted Login meets WCAG 2.2 AA. [ASSUMPTION: A-9]
- **NFR-17:** Hosted Login works on current desktop and mobile browsers. The Admin Dashboard is desktop-first and responsive to tablet.
- **NFR-18:** Interfaces follow `design/Gatekeep Design System.dc.html`: design tokens rather than raw values, one jade signal colour for primary actions, allowed states and focus, status colours that describe state only, and mono type with copy controls for identifiers, codes and anything a developer might copy. Fonts and assets are bundled, with no third-party requests at runtime.
- **NFR-19:** v1 ships in English, with text kept separable for later translation.

## 6. Non-Goals (Explicit)

Gatekeep v1 is not:

- A commercial service: no billing, plans, usage metering, vendor support centre or public sign-up for Tenants.
- A certified product: no SOC 2 or ISO certification, and no certifications page. OpenID conformance testing still applies (FR-23).
- A marketplace or plug-in ecosystem.
- A host for customer code: no Actions or custom database scripts until v2.
- A push-notification product: no mobile authenticator app.
- A channel for SMS or voice messages.
- A regulated-identity platform: no FAPI mode.
- A multi-region product: no data residency choice.
- A tool for legacy migration: no Rules and Hooks screens, ever. Nothing legacy exists to migrate.
- An impersonation tool: impersonation bypasses authentication and needs its own safeguards before it can be considered.
- A multi-language product: no translation editor.

## 7. Release Scope

### 7.1 In Scope for v1

Everything in §4 and §5. [ASSUMPTION: A-10. Esm is the sole builder and Operator, with 1–3 web apps at launch and no payment, health or other regulated data. Applications use another login until SM-3 passes.] This table places the 14 sections of `design/design-prompt.md`:

| Section | v1 | v2 | Later |
| --- | --- | --- | --- |
| 1 Onboarding & Home | Create-Tenant form | Wizard, Home dashboard | |
| 2 Applications | Applications, credentials, tokens, quickstart tab | Private Key JWT, mTLS, add-ons, third-party apps | Dynamic client registration |
| 3 APIs | APIs, Permissions, machine-to-machine access | User consent policy | |
| 4 Authentication | Password, social, Passkeys, email code | SAML and OIDC enterprise Connections, SCIM, self-service SSO, magic link, custom database | LDAP, more social providers |
| 5 Organizations | | All | |
| 6 User management | Users, Roles | Import and export jobs, account linking, bulk actions, query syntax, User metadata | |
| 7 Authorization | RBAC | | FGA |
| 8 MFA & security | TOTP, WebAuthn, Recovery Codes, attack limits, breached passwords, Signing Keys | Adaptive MFA, step-up, remember browser, bot detection, IP allowlists, Security Center, sender-constrained tokens, PAR, JAR | Duo-style integration |
| 9 Actions | | Actions with sandboxing, custom token exchange | Flow builder, Forms |
| 10 AI agents | | | All |
| 11 Branding | Theme, email templates and provider | Custom domains, custom templates | Translations |
| 12 Monitoring | Logs, health and rate limits | Log streams, live tail, analytics | |
| 13 Tenant & team | Tenants, Admins, audit, machine-to-machine Management API access, configuration export | Promotion between Tenants, Dashboard SSO, configuration as code, token pages | |
| 14 Developer experience | Five quickstarts, API reference | First-party SDKs, more frameworks, API console, token tools, global search | |

Device Authorization is also v2. CIBA and token exchange follow sections 10 and 9. [ASSUMPTION: A-17. Items the design lists but earlier drafts didn't place are assigned as shown.]

### 7.2 Hosted Login Screens

In v1:

- **Sign-in:** login, password step, Passkey sign-in, email code entry, MFA method picker, TOTP challenge, security key challenge, Recovery Code entry, re-authentication.
- **Enrolment:** signup, email verification, Passkey creation, Factor choice, TOTP setup, security key setup, Recovery Code display.
- **Recovery:** forgot password and its neutral confirmation, reset password, password changed.
- **Protection:** blocked account, account locked, breached password check, password reset required, authenticator reset required.
- **Exit:** logout, social email conflict, generic error.
- **Account Portal:** Profile, Security and Sessions tabs.

Deferred: progressive profiling, magic link, push, SMS, User step-up, organization picker, invitation, third-party consent, account linking, device activation, agent approval, CAPTCHA, Connected apps and Privacy tabs.

### 7.3 Design Changes Required

**Screens to design in `bmad-ux`, because the exports lack them:** MFA method picker, TOTP challenge, Recovery Code entry, re-authentication, email version of code entry, neutral forgot-password confirmation, social email conflict, email recovery waiting state, Admin sign-in, bootstrap, Admin invite acceptance and credential setup, Admin re-authentication, create-Tenant form without Region, and FR-50 actions.

**Where the design must change to match this PRD:**

- Remove secret Reveal, refresh rotation toggles, the Admin MFA toggle and "Notify only" for breached passwords.
- Show exact-match callback URLs only, and one fixed asymmetric signing algorithm instead of HS256.
- Remove social dev keys, Region, MFA override copy and every deferred control inside v1 screens.
- Replace sample domains with Tenant Subdomains. `gatekeep.dev` and `.us.` segments are placeholders.
- Show the Tenant switcher as a flat list of Tenants, with Tenant Roles per Tenant on the team screen.
- Use §3 terms, including Hosted Login instead of Universal Login.
- Rename the blocked-account email template to account locked. An Admin block has no self-service unlock.
- Tie Hosted Login's breach-check copy to the local dataset, since the k-anonymity sentence no longer applies.

### 7.4 Sequence and v2 Entry

Build v1 in this order, so that the riskiest foundations come first and the first production cutover is the target:

1. **Foundation:** threat model, install, Master Key, Admin sign-in, Tenants, isolation suite, Logs.
2. **Core sign-in:** Applications, standards endpoints, password, Passkeys, MFA, recovery, Signing Keys.
3. **Protection and operations:** attack limits, Security Alerts, backup and restore, compromise response, conformance.
4. **Remaining v1:** social, email code, RBAC, theme, Account Portal, quickstarts.
5. **Cutover:** complete the ASVS self-assessment, then move the first production app.

**v2 entry condition:** SM-1 is met, with NFR-10 achieved in each month of those 90 days and no critical incident.

## 8. Success Metrics

**Primary**
- **SM-1: Production cutover.** At least one of Esm's production apps uses Gatekeep for real Users, with no fallback login in use, and stays on it for 90 days. [ASSUMPTION: A-11. 90 days is long enough to show stability.] Validates FR-1, FR-17, FR-23.
- **SM-2: No isolation failures.** Zero failures in the cross-Tenant suite on every release, and zero cross-Tenant access found in Logs, which record rejected attempts. Validates FR-8.
- **SM-3: Security gate passed.** NFR-8 is complete with no critical or high findings open, and the threat model and runbooks exist, before real Users sign in. Validates NFR-1, NFR-8, NFR-9.

**Secondary**
- **SM-4: Protocol conformance.** Gatekeep passes the FR-23 conformance profiles on every release. Validates FR-23.
- **SM-5: Recovery proven.** Before launch and each quarter, Esm rehearses on spare hardware: key rotation and revocation, a failed upgrade, a clean-hardware restore using the escrowed Master Key, re-application of revocations, Security Alert delivery and a tabletop run of UJ-6. Validates FR-3, FR-4, FR-37, FR-38, FR-45, FR-50.
- **SM-6: Integration time.** A new project reaches a working sign-in within 30 minutes. Validates FR-43.
- **SM-7: Understanding.** Esm writes a walkthrough of each v1 protocol flow without reference to generated code. Validates §2.1 Learn it.

**Counter-metrics (do not optimize)**
- **SM-C1: Features shipped or stories closed.** A larger Gatekeep is more to secure. Counterbalances SM-1.
- **SM-C2: Fastest possible sign-in.** Don't trade hashing cost, MFA or rate limiting for speed. Counterbalances NFR-11.
- **SM-C3: Time to production.** A missed date is better than an unsafe launch. Counterbalances SM-1.

## 9. Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Tenant isolation flaw | One bug exposes every project | FR-8 suite and enforcement below application logic, threat model |
| Server compromise | Every Tenant's keys and secrets are exposed | Master Key apart from data, off-server Logs, UJ-6 runbook, Admin Dashboard off the public internet |
| On-premises server failure | Sign-in stops for every project, and data may be lost | Backups off the server, SM-5 rehearsals. Accepted: no redundancy, so outages can last hours |
| No independent security review | The self-assessment can miss what its author missed | **Accepted risk.** Esm chose self-assessment after being advised that an external test was preferable. Automated checks and ASVS evidence reduce this but don't remove it |
| Scope grows towards the full design | v1 never ships | §6 and §7 hold the line; changes go through `bmad-correct-course` |
| Generated code the Operator doesn't understand | Flaws can't be spotted or fixed | SM-7, and Esm reviews every authentication story |
| Email provider failure or compromise | Verification, reset and code sign-in stop, or reset emails are diverted | Passkey sign-in as an independent path, provider status in FR-6, email can't bypass Factors, Security Alert on provider change |
| Credential stuffing without bot defences | Accounts are attacked and sign-in slows | FR-28, FR-29, NFR-6. Accepted until v2; revisit if a failed sign-in spike recurs |
| Application keeps a session after Gatekeep revokes access | A blocked User stays signed in to an app until it re-checks | Short token lifetimes, documented in quickstarts. Accepted until v2 Back-Channel Logout |

## 10. Dependencies

- An email provider, with SPF, DKIM and DMARC.
- A dedicated DNS zone with wildcard DNS and TLS certificates.
- VPN or private network access to the Admin Dashboard.
- Off-server storage for backups and copied security events.
- Offline storage for the escrowed Master Key.
- An alert channel independent of the Deployment.
- Spare hardware or a virtual machine for rehearsals.
- Client credentials from each social provider.
- A local breached-password dataset.
- OpenID Foundation conformance test suite.

## 11. Open Questions

No open question blocks UX or architecture. Each of these has a safe default and is revisited as stated.

1. **Do mandatory PKCE, `id_token_hint` for logout and the fixed algorithm pass the named conformance plans?** Not yet verified. Check during architecture. Security rules win, so any incompatibility is recorded as a deviation rather than relaxed in a Prod Tenant.
2. **Should the zone be submitted to the Public Suffix List?** It would make Tenants cross-site in browsers, as defence in depth. Registration isn't in Esm's control. Decide during architecture; v1 doesn't depend on it.
3. **When should Back-Channel Logout move into v1?** Revisit if an Application can't accept the residual session window after a revocation.
4. **Is the server really public and without redundancy?** A-4 assumes so. If it has redundancy, raise NFR-10.

## 12. Assumptions Index

- **A-1 (§2.2):** Esm operates every Tenant, and Tenants aren't sold to others.
- **A-2 (FR-20):** Google, GitHub and Microsoft are enough for social login in v1.
- **A-3 (FR-39):** Owner, Editor and Viewer are enough for Tenant Roles.
- **A-4 (NFR-10):** The server is internet-reachable with no redundancy, so 99.5% is the availability target.
- **A-5 (NFR-11):** 500ms at p95, at a peak of 20 sign-ins per second.
- **A-6 (NFR-12):** Fewer than 10,000 Users at launch.
- **A-7 (NFR-13):** 1 hour to restore, with up to 24 hours of data loss.
- **A-8 (NFR-14):** GDPR-style privacy rights apply.
- **A-9 (NFR-16):** WCAG 2.2 AA is the accessibility target.
- **A-10 (§7.1):** Esm is the sole builder and Operator, with 1–3 web apps at launch and no payment, health or other regulated data. Applications use another login until SM-3 passes.
- **A-11 (SM-1):** 90 days on Gatekeep is long enough to show stability.
- **A-12 (§5.2):** The security limit values are starting points.
- **A-13 (FR-42):** The Management API is reachable only by VPN or private network.
- **A-14 (FR-29):** The breach dataset is held locally.
- **A-15 (NFR-8):** The assessment uses ASVS 5.0 at Level 2.
- **A-16 (FR-23):** Each Tenant uses one fixed asymmetric signing algorithm.
- **A-17 (§7.1):** Previously unplaced design items are assigned as listed in §7.1.
- **A-18 (§5.2):** A credential enrolment link lasts 24 hours.
