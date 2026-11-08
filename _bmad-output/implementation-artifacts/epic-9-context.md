# Epic 9 Context: Signing Key operations

<!-- Generated from planning artifacts. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Let a Tenant Owner view, rotate and revoke a Tenant's Signing Keys from the Admin Dashboard, with no manual follow-up. Epic 2 already built the `signing_key` lifecycle, the per-Tenant JWKS and automatic rotation. This epic adds the on-demand operations on top. The key case is responding to a suspected key compromise: the Owner revokes the key, Gatekeep promotes `next` at once, tokens signed by the revoked key stop being trusted within the JWKS cache limit, and no other Tenant is touched.

## Stories

- Story 9.1: View Signing Keys
- Story 9.2: Rotate a Signing Key on demand
- Story 9.3: Revoke a Signing Key

## Requirements & Constraints

- **Viewing:**
  - Show every state: `next`, `current`, `previous`, `retired` and `revoked`.
  - Key IDs are shown in mono with Copy.
  - No response ever carries private material. The public JWKS sample never contains a `management` key.
- **Rotation on demand:**
  - It promotes `next` to `current`, moves `current` to `previous`, and creates a replacement `next`. All of this is one command that also writes a Log event.
  - Routine promotion needs `next` to have been published for at least 15 minutes, which is the JWKS cache limit. A younger `next` is refused, and the refusal says how much time remains.
  - Rotation never affects other Tenants.
- **Revocation:**
  - The Tenant Owner must give a fresh WebAuthn assertion first. Signing Key revocation is on the fresh-assertion list.
  - A revoked key leaves the JWKS at once. A job then destroys its private material, and a failed destruction retries.
  - Revoking `current` promotes `next` even if it's younger than 15 minutes. The Log records that the promotion was unaged, and a new `next` is created.
  - The same action offers to revoke the Tenant's Sessions and refresh tokens. That goes only through the single revocation path.
  - Test: a token forged with the revoked key is rejected after the JWKS cache limit by a fixture resource server in `tests/Protocol`.
  - On failure the command rolls back. The key stays unchanged, other Tenants are untouched, and nothing is half-applied.
- **Who can act:**
  - Rotate and revoke are for the Tenant Owner only. A Deployment Owner can act when they also hold a Tenant Role.
  - Editors and Viewers can only read. Editors see the controls read-only, labelled "Tenant Owner only".
  - Machine principals (Management API) are refused.

## Technical Decisions

- **Key state:**
  - The `signing_key` row is authoritative. Its `purpose` is `signing` or `management`.
  - Every state change is one `CommandContext` command that writes the state and the audit event together.
  - At commit, each Tenant has exactly one `current` and one `next` per purpose. Any command that consumes or revokes `next` creates its replacement.
- **Creating a key:**
  - Transit key names are `sig-{tenantId}-{rowId}` or `mgmt-{tenantId}-{rowId}`, built from a pre-generated row ID.
  - Create the Transit key first, then commit the row. The orphan sweep removes any Transit key whose row never commits.
  - `Host.Admin` may create Signing and Management keys through `IKeyCustody`. Destroying them is a `Host.Worker` job that runs after commit.
- **JWKS:**
  - JWKS serves the `next`, `current` and `previous` keys with `purpose = signing`, with `Cache-Control: max-age=900`.
  - `Host.Hosted` caches JWKS for up to 5 seconds per Tenant. A `NOTIFY` on any state change clears that cache, which is what makes a revoked key leave "at once".
  - `management` keys are never published, so they don't need the 15-minute ageing.
- **Retirement:** `previous` becomes `retired` once the hard token lifetime plus 15 minutes has passed since rotation. Epic 2's jobs handle that, and the maximum key age is a fixed constant.
- **Authorization:**
  - These actions are entries in the one capability table in the Admins contract. Each declares `MachineAllowed` and `FreshAssertion`, and handlers evaluate them.
  - Every fresh-assertion capability is denied to machine principals.
  - The UI reads the caller's capabilities from an endpoint to decide what to show.
- **Routes:**
  - Routes sit under `/api/v1/tenants/{tenantId}/*` on `Host.Admin`. The Dashboard and the Management API share one route set.
  - The Tenant in a token must equal the Tenant in the path.
  - Errors use RFC 9457 and carry a trace ID.
- **Session revocation:** use `ISessions.RevokeAccessAsync` with the `Tenant` scope, which writes `sessions.access.revoked`. A generated test scans for any other revocation write.
- **Audit codes** follow `{domain}.{object}.{action}`.

## UX & Interaction Patterns

- **Signing keys page** (Security group, the `GEN.keys` design):
  - A table with Key ID, Algorithm, Status and Created, plus a public JWKS sample below it.
  - Changes from the design: drop the Expires column, add the Retired state, and include `previous` in the JWKS sample.
  - The page always has `next` and `current`, so it's never empty.
  - Rotate is a page action. A rotate or revoke failure shows a `banner` with the trace ID.
- **Revoke flow:**
  - Revoke on a key opens the Confirmation modal. The modal states the token impact and offers to revoke Sessions and refresh tokens.
  - If the last assertion is over 5 minutes old, confirming triggers the browser's WebAuthn sheet. A failure shows inside the same modal, and no second modal opens.
- **Read-only access:**
  - A Viewer sees values read-only, with no action buttons, and a view-only `banner`.
  - An Editor sees the controls labelled "Tenant Owner only".

## Cross-Story Dependencies

- **Within the epic:** 9.1 builds the page and the read endpoint. 9.2 and 9.3 add actions to that page.
- **From Epic 2 (done):**
  - 2.3: `signing_key`, the per-Tenant JWKS and the `NOTIFY` cache invalidation.
  - 2.4: automatic rotation, retirement, the destruction job and the orphan sweep. Reuse its promote and create logic rather than rewriting it.
  - 2.7: `RevokeAccessAsync`.
- **From Epic 1 (done):**
  - The capability table and Tenant-scoped routes (1.24).
  - The Admin shell (1.25).
  - Fresh assertions and the re-authentication gate (1.26).
  - `IKeyCustody`, jobs, audit and `FailureContext`.
  - The shared UI components: table, modal, `banner`, `toast` and Copy.
- **Not built yet:** token issuance (2.5, 2.9, 2.10) is still in the backlog. That's why the forged-token test uses a fixture resource server and a self-forged token instead of a real token flow.
- **Later epics:**
  - Epic 11 alerts on failed key destruction.
  - FR-50's "revoke all Signing Keys" in Deployment incident response reuses this lifecycle. It creates and promotes new keys of both purposes in one Operation.
