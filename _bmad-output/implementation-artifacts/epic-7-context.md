# Epic 7 Context: Logs and audit evidence

<!-- Generated from planning artifacts. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Turn the audit events that every state change already writes into tamper-evident, searchable evidence. Events are sealed into hash chains, copied off the server to a store the server can't rewrite, verified by a CLI command and kept for a fixed retention. Admins can search a Tenant's Logs and open raw detail, with the amount shown depending on their role. Deployment Owners can search the Deployment Log. A canary scan and a generated event catalogue keep secrets out of every log as features are added. This matters because after a compromise the Operator must still be able to prove what happened.

## Stories

- Story 7.1: Seal audit events into hash chains
- Story 7.2: Copy evidence off the server
- Story 7.3: Verify chains and apply retention
- Story 7.4: Search a Tenant's Logs
- Story 7.5: Open an event's raw detail
- Story 7.6: View a User's history
- Story 7.7: Search the Deployment Log
- Story 7.8: Plant canaries and publish the event catalogue

## Requirements & Constraints

- Tenant Logs cover sign-ins, failures, password resets, email changes, Factor and Recovery Code events, Session and token revocation, Admin changes, key operations, Management API grants, Token Family revocations and rejected cross-Tenant attempts.
- The Deployment Log covers bootstrap, Admin sign-in, recovery, Tenant creation and deletion, upgrades, restores and Deployment configuration. Only a Deployment Owner can read it. Every other Admin and every machine principal is refused.
- Event type codes are part of the public contract. Changing one is a contract break.
- No surface (Admin Dashboard, Management API or any route) can change or delete a Log.
- Logs, error responses, debug output, operational logs and the database never hold a credential-equivalent value. A canary planted through each flow must never appear raw, including when a flow is forced to fail with debug logging on.
- Raw Log detail that holds personal data is visible to Editors and Owners only. A Viewer gets the summary only, and the server enforces this, not just the UI.
- Log retention is 90 days and fixed in v1. No route, setting or CLI command can change it, and the floor can't be lowered.
- Off-server copies arrive within 60 seconds of sealing. Sealing targets 5 seconds.
- Configurable Log streams, live tail and a query bar are out of scope (v2).

## Technical Decisions

- **Writing:** audit is written only through the Kernel `IAuditAppender`, on the `CommandContext` connection. No module depends on Audit to write.
- **Chains:** there is one chain per Tenant in `audit_event` and one Deployment chain in the `control` table `deployment_audit_event`, with the same shape. The envelope holds the type code and internal references only. Personal data (IP address, user agent, email) lives in `audit_detail` / `deployment_audit_detail`, outside the hash. Erasure and raw-detail permissions act only on those detail tables, so erasing a User doesn't break the chain.
- **Sealing:** a sealer in `Host.Worker` runs as `gk_sealer` and assigns `epoch`, `seq`, `prev_hash` and `hash = SHA-256(prev_hash || RFC 8785 canonical envelope)`. Sealing runs separately from the write so writers never serialize on a chain head. If sealing lags more than 60 seconds, the dead-man heartbeat reports it and a Security Alert is raised.
- **Immutability:** triggers make the envelope immutable. Registry roles get only `INSERT` and `SELECT`. `gk_sealer` may set the seal columns once. Only `gk_retention` deletes `audit_event` rows. `gk_worker` deletes `audit_detail` rows for erasure.
- **Retention:** whole sealed ranges are deleted, then a checkpoint event is written carrying the last deleted hash. A deleted Tenant's chain stays until its retention ends, then an Operation purges it.
- **Verification:** `gatekeep audit verify` (in `Gatekeep.Cli`) walks the chain and every off-server head, and reports the position of any change or gap. A checkpoint is accepted only if it is past retention and its hash matches the off-server record. A break between epochs is accepted only where a signed restore record names it.
- **Off-server record:** worker jobs copy sealed security events, revocations and one chain head per `(epoch, seq)` to an S3-API bucket on a separate provider, with Object Lock in compliance mode and retention matching the Log retention. The server's credential can write but can't delete or shorten retention. Records are signed by a Deployment Transit key that only `Host.Worker` and `Gatekeep.Cli` can use. Replayable revocations come from a code-owned table of event types and carry only the internal IDs needed to re-apply them, with no personal data.
- **Alerts:** the sealing job checks sealed events against Notifications' code-owned alert table and enqueues one alert job per match, keyed on event ID, in the same `gk_sealer` transaction. An alert can't come before its committed event.
- **Codes:** event codes take the form `{domain}.{object}.{action}`, in lower case. The catalogue is generated into `docs/`, and the build fails when a code changes.
- **Search:** search filters on indexed envelope columns. A User or email search first resolves to the internal reference.
- **Authorization:** the "read raw Log detail" capability comes from the single capability table in the Admins contract. Handlers evaluate it, and the UI reads the caller's capabilities from an endpoint.
- **Credentials:** values that are credential-equivalent use `Secret<T>`, which has no serializable form. Operational logging goes through the scrubbing sink. The canary scan covers Logs, operational logs and the database, and a flow registered with no canary fails the build.

## UX & Interaction Patterns

- **Logs page:** field search is one field `select` plus a mono value. Fields are event type, User, Application, outcome and time range, and the values are kept in the URL. The empty state reads "No events in this range". The retention note reads 90 days. The design's Live view, Log streams, query bar and SIEM sentence are removed.
- **Event drawer:** a row opens a right-hand `drawer` (440px, capped at half the window) with a code badge, summary rows and raw JSON with Copy. Esc closes it. A Viewer sees the summary only.
- **User · History:** this tab lists a User's recent events. The empty state reads "No events yet". Viewers see summaries only. For an Editor, a row opens the same drawer with raw detail.
- **Deployment Log:** this page is specified but not drawn. It is built from the Logs page and is never empty, because bootstrap events always exist.
- Replace sample domains with Tenant Subdomains.

## Cross-Story Dependencies

- These are already built: the audit event write per state change (Story 1.5), the scrubbing sink and canary scan (Story 1.6), Tenant-scoped jobs and Operations (Stories 1.8 and 1.9), the capability table (Story 1.24), the alert channel and off-server store (Story 1.30), Tenant deletion (Story 1.29) and User data erasure (Story 5.9).
- Story 7.1's sealing comes before shipping (7.2), verification and retention (7.3), and the off-server heads that 7.3 verifies against.
- Story 7.5's drawer and its summary-only rule for Viewers are reused by 7.6 and 7.7. Story 7.4's search page is the base for 7.7.
- Story 7.6 adds a History tab to the User profile from Epic 5.
- Story 7.7 tests the Deployment event classes that aren't built yet by fixture. Story 7.8 puts the email change and Management API grant event classes on a pending list, which Stories 16.8 and 17.2 close.
- Admin invites and Role management come in Epic 8. Epic 7 enforces the existing Viewer, Editor and Owner capabilities.
