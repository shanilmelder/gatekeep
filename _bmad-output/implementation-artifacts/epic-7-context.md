# Epic 7 Context: Logs and audit evidence

<!-- Generated from planning artifacts. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Make every Gatekeep audit event tamper-evident and provable, and let Admins use it. Events already written by `IAuditAppender` are sealed into hash chains, one per Tenant plus one Deployment chain. Security evidence is copied off the server to a store the server can't rewrite. A verification command and a fixed retention floor prove the Logs are intact. Admins can search a Tenant's Logs, open raw detail as their role allows, see a User's history, and (Deployment Owner only) search the Deployment Log. A canary scan and a generated event catalogue keep "no secret ever reaches a log" true as features are added. This epic is the evidence base that compromise response, restore and Security Alerts rely on.

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

- **Coverage:** Tenant Logs cover sign-ins, failures, password resets, email changes, Factor and Recovery Code events, Session and token revocation, Admin changes, key operations, Management API grants, Token Family revocations and rejected cross-Tenant attempts. The Deployment Log covers bootstrap, Admin sign-in, recovery, Tenant creation and deletion, upgrades, restores and Deployment configuration.
- **Immutability:** no route, setting or surface (Admin Dashboard, Management API, Cli) can change or delete a Log. Only retention deletes rows.
- **Verification:** the chain is hash-linked, and `gatekeep audit verify` reports the position of any altered or missing row.
- **Off-server copy:** security events and revocations are copied off the server in near real time (within 60 seconds) to a store the server can't rewrite or delete.
- **No credentials in logs:** credential-equivalent values never reach Logs, errors, debug output, exports or operational logs. A canary test planted through each flow proves it, including when flows fail with debug logging on.
- **Retention (exact values):** "Log retention | 90 days | 90-day floor in Prod Tenants". v1 has no setting for Log retention. It's fixed at its default, and only a release can change it, within the hard limit. "Logs have the retention in §5.2, fixed in v1. The floor can't be lowered." A deleted Tenant's security Logs are kept for 90 days. A test must assert the constant meets the floor and that no route, setting or Cli command changes it.
- **Access:** raw detail follows the Admin capability matrix. Viewers get summary only, enforced server-side. Editors and Owners see raw JSON. Deployment Log is Deployment Owner only, and machine principals are refused.
- **Event codes** are a public contract. A changed code is a contract break.
- **Erasure:** erasing a User removes `audit_detail` only, so the chain still verifies afterwards.

## Technical Decisions

- **Write path (already built in Story 1.5):** audit is written only through Kernel `IAuditAppender` on the `CommandContext` connection. Tables are `audit_event` and `audit_detail` (tenant), plus `deployment_audit_event` and `deployment_audit_detail` (`control`), with the same shape. No module depends on Audit to write.
- **Envelope vs detail:** the envelope holds a stable type code and internal references only. Personal data (IP, user agent, email) lives in the `*_detail` tables, outside the hash. Erasure and raw-detail permissions act on detail only.
- **Sealing:** a sealer job in `Host.Worker`, under `gk_sealer`, assigns `epoch`, `seq`, `prev_hash` and `hash = SHA-256(prev_hash || canonical envelope)`. Canonical form is RFC 8785 JSON. Sealing is separate from writing, so writers never serialize on a chain head during a sign-in flood. The target is 5 seconds. Lag above 60 seconds is reported through the heartbeat.
- **DB enforcement:** triggers make the envelope immutable. Registry-granted roles have only `INSERT` and `SELECT`. `gk_sealer` may set only the seal columns, once. `gk_retention` alone deletes `audit_event` rows. `gk_worker` deletes `audit_detail` rows for erasure. No role has `BYPASSRLS`.
- **Jobs:** sealing runs under `gk_sealer` and retention under `gk_retention`, as the job registry states. `gk_sealer` can enqueue only alert types.
- **Retention:** deletes only whole sealed ranges and writes a checkpoint event carrying the last deleted hash. A deleted Tenant's chain stays until its retention ends, then an Operation purges it. §5.2 values are constants in one Kernel file.
- **Verify:** walks each chain and every off-server head. A checkpoint is accepted only if it's past retention and its hash matches the off-server record. A break between epochs is accepted only where a signed restore record names it (restore starts a new `epoch` per chain).
- **Off-server record:** Worker jobs copy sealed security events, revocations and one chain head per `(epoch, seq)` within 60 seconds of sealing to an S3-API bucket on a separate provider, with Object Lock in compliance mode. Retention matches §5.2. The server's credential can write but not delete or shorten retention. Records are signed by a Deployment Transit key that only `Host.Worker` and `Gatekeep.Cli` can use. Replayable revocations come from a code-owned event-type table carrying internal IDs only, with no personal data.
- **Alerts:** the sealing job checks sealed events against one code-owned table in Notifications and enqueues one alert job per match, keyed on event ID, in the same `gk_sealer` transaction. An alert therefore can't precede its event. The heartbeat to an external dead-man's check carries the latest sealed and shipped positions, the oldest unsealed age and the oldest undelivered alert age.
- **Codes:** `{domain}.{object}.{action}`, lower case. They replace the export's short sample codes. The catalogue is generated into `docs/`.
- **Search:** filters on indexed envelope columns only. A User or email search resolves to the internal reference first. Lists use cursor pagination, default 50.
- **Credential handling:** `Secret<T>` has no serializable form. Operational logging runs through the scrubbing sink. The canary scan covers Logs, operational logs and the database.
- **Release gates:** canary scan and catalogue test are mandatory release gates.

## UX & Interaction Patterns

- Logs uses a field search: one field `select` plus a value (event type, User, Application, outcome, time range), kept in the URL. No Live view, Log streams or query bar in v1. Empty state: "No events in this range".
- A row opens a `drawer` with code badge, summary rows and raw JSON with Copy. Esc closes it. Viewers see summary only.
- User · History: empty state "No events yet". Viewers see summaries only, and Editors open the drawer for raw detail.
- Deployment Log is Spec only, composed from Logs. It always has bootstrap events and appears under the Deployment nav for Deployment Owners only.
- Apply the Admin Dashboard Design Delta (for example, real Tenant Subdomains instead of sample domains).

## Cross-Story Dependencies

- Builds on Epic 1: audit tables and `IAuditAppender` (1.5), scrubbing sink and first canary scanner (1.6), OpenBao/Transit (1.7), Object Lock adapter and alert channel (1.30), DB roles and RLS (1.4).
- 7.1 comes before 7.2 and 7.3 (both need sealed ranges and heads). Verify in 7.3 checks off-server heads from 7.2.
- 7.5 and 7.6 rely on the Admin capability matrix (Epic 8 / FR-39). 7.6 extends the User detail from Epic 5. User erasure (5.9) must leave chains verifiable.
- 7.7 tests Deployment events not yet built by fixture.
- 7.8 leaves email change and Management API grant event classes on a pending list, closed by Story 16.8 and Story 17.2.
- Later consumers: Security Alerts and the heartbeat (Epic 11), restore and revocation replay with a new epoch (Epic 12), compromise response (Epic 13).
