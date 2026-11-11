# Epic 3 Context: Applications and APIs

<!-- Generated from planning artifacts. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Let Tenant Owners and Editors register the clients and resource servers that use a Tenant, through the Admin Dashboard and the same Tenant-scoped API routes. The epic covers Applications of the four types, their exact-match URLs and grant types, client secrets with rotation overlap, token lifetimes, and deletion. It also covers APIs with `resource:action` Permissions and machine-to-machine grants. The climax is the machine-client journey: a backend job gets a token carrying only the Permissions it was granted, and the API rejects anything else. Epic 2 built the protocol pipeline (`application` and `client_secret` tables, client authentication, Client Credentials with a placeholder audience). This epic puts real configuration behind it.

## Stories

- Story 3.1: List and create Applications
- Story 3.2: Configure Application URLs and grants
- Story 3.3: Create, rotate and revoke client secrets
- Story 3.4: Set token lifetimes
- Story 3.5: Delete an Application
- Story 3.6: Define APIs and Permissions
- Story 3.7: Authorize a machine-to-machine Application

## Requirements & Constraints

- **Roles, enforced on the server:** Viewers read only. Editors manage Applications and APIs. Only Tenant Owners manage client secrets and grant Management API access. The UI shows "Tenant Owner only" to Editors, and a Viewer sees no create button.
- **Application types:** single-page, regular web, native and machine-to-machine. Regular web and machine-to-machine need a credential. Single-page and native need none. Each Application has a client ID, and duplicate names are allowed.
- **URLs:** callback, logout and origin URLs are absolute, one per line, matched exactly, with no wildcards. Native Applications get only the RFC 8252 loopback port exception and must use the system browser, never an embedded view. A custom URI scheme in a Prod Tenant needs explicit acknowledgement.
- **Grants:** only Authorization Code with PKCE, Refresh Token and Client Credentials exist. A grant turned off for an Application must be refused at the authorization or token endpoint.
- **Fresh WebAuthn assertion (within 5 minutes):** required for changing a Prod Tenant's callback URLs, rotating a client secret and granting Management API access. Every fresh-assertion action is refused to machine principals. A Prod callback change also raises a Security Alert, and so does each Management API grant.
- **Client secrets:**
  - 256-bit, shown once through `RevealOnce`, stored only as SHA-256.
  - On rotation, the old secret overlaps for the fixed 24-hour default (hard limit 7 days, not configurable in v1), and "End old secret now" stops it at once.
  - Revocation takes effect at once and writes to the Log.
  - The canary scan must find no secret value in logs, Audit events or exports.
- **Lifetimes:** access and ID tokens default to 15 minutes (hard limit 1 hour). Refresh tokens default to 30 days absolute (hard 90) and 7 days inactivity (hard 30). An over-limit value is refused on both UI and API with "Maximum is {limit}." No option disables rotation or chooses an algorithm. When an Application and an API set different lifetimes, the shorter one applies.
- **APIs:** the identifier is unique in the Tenant and locked after creation. Setup guidance advises different identifiers for Dev, Staging and Prod. A Permission is `resource:action` and unique per API. Offline access and RBAC are per-API settings that write to the Log. Every Tenant lists the built-in Management API, so the list is never empty.
- **Machine grants:** a token carries only currently granted Permissions. An ungranted scope is omitted, not an error. A removed grant is gone from the next token, and Permissions are re-read at every refresh. With offline access off, no refresh token is issued for that API. Management API Permissions go only to machine-to-machine Applications, never through Roles.
- **Deletion:** the modal states the token effect, and no typed confirmation is needed. The Application is marked deleted and its refresh tokens and grants are revoked. A deleted client is refused at the token endpoint.
- **Isolation:** another Tenant's Application or API is refused, and each new route joins the cross-Tenant suite.

## Technical Decisions

- **Ownership:** Directory owns `application`, `client_secret`, `client_usage`, `api`, `permission` and `api_grant`. Protocol consumes them through Directory's contract. Each new table's registry entry, RLS policies and grants go in the same migration.
- **Authorization:** the one capability table in the Admins contract is the only encoding of roles. Each capability declares `MachineAllowed` and `FreshAssertion`, which can be a predicate on the target. The Prod callback rule is the `WhenProdTenant` predicate on `tenant.application_callbacks.manage`, evaluated in the route handler before `FreshAssertionGate.RequireAsync`. The UI reads the caller's capabilities from an endpoint. A generated test denies every role and machine principal everything outside the table.
- **Routes:** `/api/v1/tenants/{tenantId}/*` on `Host.Admin` is one route set with two schemes (Admin session or Management API token). The Tenant is always in the path, and a token's Tenant must equal it. Errors use RFC 9457 with a stable `code` and `traceId`. Lists use cursor pagination of 50. The OpenAPI document is committed and diffed in CI, and `packages/api-client` is generated from it.
- **Client authentication:** the Gatekeep handler calls Directory to check `client_secret`, which is what makes overlap possible. OpenIddict's secret column stays empty, and Directory writes `application` rows itself.
- **Revocation:** deletion revokes only through `ISessions.RevokeAccessAsync` with the `Application` scope. Purging the rows is an Operation (`202` plus `operation` resource), because cross-module deletion is never a cascade. Foreign keys are composite with `ON DELETE RESTRICT`.
- **System Application:** it stays hidden from list, edit, delete and export. Its database guards raise SQLSTATEs `GK011`, `GK012` and `GK013`. The edit, delete and secret routes must map them to refusals and grant those routes' roles the reads the guards need.
- **Management API isolation:** Management API tokens come only from `Host.Admin`'s Client Credentials endpoint, signed by `management` keys. `Host.Hosted`'s token endpoint must refuse the Management API audience. The built-in API record and its Management Permissions become a Tenant creation step, with a backfill for existing Tenants.
- **Limits** are constants in the one Kernel limits file. Every setting validates against them.
- **Conventions:** every mutation is one `CommandContext` command that writes state and its Audit event (`{domain}.{object}.{action}`) together. IDs are UUIDv7 with prefixed public IDs (`app_`). `client_usage` writes are operational and exempt from audit. Credential values use `Secret<T>`.

## UX & Interaction Patterns

- **Landing:** an Admin with a Tenant lands on that Tenant's Applications list. The empty state shows "No applications yet" with Create application.
- **Create Application** (spec only): name plus type. A Tenant Owner gets the one-time reveal if the type needs a secret. An Editor's Application is created with no secret, and Credentials says a Tenant Owner must create one.
- **One-time reveal:** a modal with Copy. Close stays disabled until "I've copied this" is ticked, and the value is never shown again.
- **Settings:** with no URLs, a helper explains exact match. URL errors appear per line. Saving shows a `toast`.
- **Credentials:** single-page and native show "No secret needed." A rotate failure shows a `banner`. Success copy reads like "Old secret valid for 24h."
- **Tokens:** defaults are shown.
- **APIs and API detail:** the Management API is always listed. A duplicate identifier shows inline. "No permissions yet" comes with Add. Settings hold identifier (locked), access token lifetime, offline access and Enable RBAC. The machine-to-machine table stays.
- **Design Delta removals:** secret Reveal, Private Key JWT, mTLS and public keys; Implicit, Password, Device, CIBA and Token Exchange grants; wildcard copy; signing algorithm and rotation/reuse toggles; HS256, the Algorithm column and consent controls; dynamic registration, SDK column and AI-agent/third-party filters. Samples use exact-match URLs on Tenant Subdomains.
- Validation runs on the server. Browser checks are feedback only.

## Cross-Story Dependencies

- **Within the epic:**
  - 3.1 creates the Applications list, create flow and detail page that 3.2 to 3.5 extend.
  - 3.1's Owner reveal depends on 3.3's secret creation. Until then, creation follows the Editor path.
  - 3.6 creates `api` and `permission`, which 3.7 (`api_grant`) needs.
  - 3.4's Application lifetimes and 3.6's API lifetimes combine by the shorter-wins rule.
- **From Epic 1:** capability table and `FreshAssertionGate`, Admin shell, Tenant creation Operation (3.6 adds a stage), Operations (3.5 purge), Security Alerts, the cross-Tenant suite and the canary scan.
- **From Epic 2:**
  - `application` and `client_secret` from 2.5 (`client_secret.expires_at` and `revoked_at` exist for rotation).
  - Client authentication, the 2.7 revocation path, the 2.8 system Application, and grant and PKCE enforcement from 2.9 to 2.11.
  - 3.7 removes 2.5's placeholder audience (`urn:gatekeep:placeholder`) and the blanket `invalid_target` refusal of `resource`/`audience`.
- **For later epics:** Story 4.12 adds per-Application Connections. Epic 5 adds RBAC that uses API Permissions. Epic 17 adds Management API grants and the Admin-host token endpoint (Owner only, fresh assertion, Security Alert).
