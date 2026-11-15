---
title: 'Story 4.5: Send email through the job pipeline'
type: 'feature'
created: '2026-11-16'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-4-configure-a-tenant-s-email-provider.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** A Tenant can configure an email provider (Story 4.4), but nothing sends email. There is no send job, no templates, no adapter for any provider and no per-recipient limit, and Users have no stored email to resolve a recipient from. Verification (4.7), reset (4.11) and notices (4.8, 4.11) all need this (FR-36, AR-18, AD-15).

**Approach:**
- **The job:** one Tenant-scoped job type, `notifications.email.send`. Its payload is IDs only (`user_id`, `template_id`), plus an optional credential: the link token or one-time code, which is Transit ciphertext the runner already erases on completion.
- **At send time, the Operations handler:**
  1. resolves the User's email through Identity;
  2. applies the per-recipient limit;
  3. renders the Tenant's template (an override row, else the built-in default) by fixed substitution;
  4. builds links on the stored email link base;
  5. decrypts the provider secret;
  6. sends through a Kernel `IEmailSender` port, implemented in a new `Adapters.Email` over the vetted egress module.

**Decided 2026-11-16:**
- **Over the limit:** mail past 5 per recipient per 15 minutes is dropped and logged, not delayed.
- **SMTP:** runs on MailKit, over a connection opened and checked by `Adapters.Egress`.

## Boundaries & Constraints

**Always:**
- **User email:** the migration adds `user.email text NULL` with a unique index on `(tenant_id, lower(email))` where it isn't null, and gives `gk_worker` column SELECT on `user (id, email)`. Identity exposes a read of a User's email by ID. Story 4.7 writes it; 4.5 only reads it.
- **Templates:**
  - **Fixed IDs:** five, each with a fixed Guid in `NotificationsContract`: `verification`, `password_reset`, `one_time_code`, `account_locked` and `security_notification`.
  - **Defaults:** built-in subject and plain-text body per template, in code.
  - **`email_template` table:** `(tenant_id, template_id PK, subject, body, updated_at)`, a Notifications `tenant` table with RLS, `tenant_row_guard`, registry entry and Tenant purge. It holds only Tenant overrides, which Story 15.4 edits; 4.5 reads them and writes none. Grants: `gk_worker` SELECT and DELETE.
- **Fixed substitution:** variables are `{{tenant_name}}`, `{{link}}` (verification and reset) and `{{code}}` (one-time code). Each template allows only its own variables.
  - **Text replacement only:** `{{name}}` is replaced by literal text; there's no escaping language, loop, condition or other syntax.
  - **No re-expansion:** an unknown or not-allowed `{{…}}` is left as literal text, and substituted values are never expanded again.
  - **Subject:** CR and LF are removed from it after substitution.
  - **Body:** plain text only. No HTML part, remote content or attachment.
- **Links:** `{{link}}` is the Tenant's stored `EmailLinkBase` (the issuer, never request headers) plus the template's fixed path plus `?token=` and the URL-encoded credential. The paths are `login/verify-email` for verification and `login/reset-password` for reset. Their pages arrive in 4.7 and 4.11.
- **Job type `notifications.email.send`:**
  - Tenant scope, run as `gk_worker`, `maxAttempts` 5, `mayCarryCredential: true`.
  - **Enqueuers:** `gk_hosted` and `gk_worker`. The Worker can't encrypt a payload, so a credential-bearing send is enqueued only by Hosted.
  - **Payload:** ids `user_id` and `template_id`. Verification, reset and code templates need a credential; the others refuse one.
  - **Guard:** a new migration re-renders the job guard. Copy the rendered-guard pattern of `Migration20261124000000PurgeExpiredSignInState`.
- **Handler (in Operations), in order. Each terminal path writes one Tenant audit event, with no address, link or code in it:**
  1. **Read state:** load the provider. No provider gives `notifications.email.undeliverable`.
  2. **Resolve the recipient:** read the User's email now. No User or no email gives `undeliverable`.
  3. **Per-recipient limit:** apply it through `IRateLimiter` with the policy `notifications.email.recipient` (`SecurityLimits.EmailPerRecipientLimit` = 5 per `EmailPerRecipientWindow` = 15 min), keyed by the User ID. Over the limit gives `notifications.email.held_back`, and nothing is sent. Give `gk_worker` the `tenant_attempt` grants the limiter needs.
  4. **Render:** use the override or the default, and the credential through `JobRun.DecryptCredentialAsync`.
  5. **Send:** decrypt the provider secret (`email-{tenant}`, Tenant as associated data), then call `IEmailSender`. The result is either:
     - `Sent`, giving `notifications.email.sent`;
     - `Permanent` (a refused recipient, bad credentials, any other 4xx), giving `undeliverable`, and the job completes;
     - `Transient` (connect failure, timeout, 429, 5xx), which throws so the runner retries with backoff. An exhausted job goes dead as today.

  Events target the User (`AuditTargetKind.User`). Plaintext secrets, addresses, links and codes are never logged.
- **`IEmailSender` (Kernel port), one adapter per kind** in a new `src/Adapters/Email` project, wired by Hosting for the Worker:

  | Kind | Request |
  |------|---------|
  | `smtp` | `Adapters.Egress` resolves the host, refuses non-public addresses (`EgressAddresses`), connects, then hands the stream to MailKit `SmtpClient.ConnectAsync(stream, host, port, …)`. `starttls` uses `StartTls`, `implicit` uses `SslOnConnect`, with certificate validation on. AUTH with username and secret when a username is set. A text/plain message. |
  | `sendgrid` | `POST https://api.sendgrid.com/v3/mail/send` (`eu`: `api.eu.sendgrid.com`), `Authorization: Bearer` |
  | `postmark` | `POST https://api.postmarkapp.com/email`, `X-Postmark-Server-Token`, `MessageStream` (default `outbound`) |
  | `mailgun` | `POST https://api.mailgun.net/v3/{domain}/messages` (`eu`: `api.eu.mailgun.net`), basic auth `api:{key}`, form-encoded |
  | `ses` | `POST https://email.{region}.amazonaws.com/v2/email/outbound-emails`, SigV4 (service `ses`), reusing `Adapters/ObjectLock/SigV4.cs` (move it to a shared place if needed) |
  | `custom_http` | `POST {endpoint}` JSON `{"from":{"address","name"},"to":"…","subject":"…","text":"…"}` with header `{authHeaderName}: {secret}` |

  - Every HTTP kind goes through `EgressHttp`, which checks the resolved address, follows no redirects and refuses plain HTTP. That gives `custom_http` its resolved-address check.
  - `EgressRuleTests`' allowlists gain only the Egress SMTP connect.
  - MailKit and MimeKit are added through central package versions with locked restore.
- **Ownership:** Operations owns the handler. Notifications owns templates, rendering, provider reads, events and the port contract. Identity owns the email read. Module edges stay in `module-edges.txt`, with new adapter edges added deliberately.

**Never:**
- No consumer yet: verification (4.7), the existing-address notice (4.8) and reset (4.11) enqueue it later. Hosted gets no enqueue wiring here.
- No template editing or test send (Stories 15.4 and 15.5).
- No Deployment or Admin email (Story 8.1).
- No HTML email, template engine or tracking.
- No delayed resend of held-back mail.
- No plaintext SMTP.
- No recipient address in a payload, event or log.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Verification sent | provider configured, User with email, job with credential | adapter called once with `to` = the email at send time, subject/body from the default with the tenant name and link `{EmailLinkBase}login/verify-email?token=…`; event `sent`; payload erased | No error expected |
| Address changed after enqueue | User email updated before the job runs | the new address is used | No error expected |
| Override template | Tenant row for `password_reset` | its subject and body used | No error expected |
| Unknown variable | override body has `{{user.password}}` | left literal; no other substitution | No error expected |
| Header injection | tenant name with `\r\nBcc:` | subject has no CR or LF | No error expected |
| No provider / no email / no User | — | nothing sent; event `undeliverable`; job done | No error expected |
| Over limit | 6th send to one User within 15 min | 6th not sent; event `held_back`; job done | No error expected |
| Transient | adapter answers 503 or times out | job retries; after 5, dead | retried |
| Permanent | adapter answers 400/401 | event `undeliverable`; job done, no retry | No error expected |
| Each kind | fake endpoint per kind | request shape and auth as in the table | No error expected |
| custom_http to a private address | endpoint resolves to 10.0.0.1 | refused by egress, not sent | `undeliverable` |
| SMTP | fake SMTP server over TLS | EHLO, STARTTLS or implicit TLS, AUTH, one message to the resolved address | No error expected |
| Credential misuse | `account_locked` job with a credential, or `verification` without one | refused: `undeliverable` | No error expected |

</intent-contract>

## Code Map

- **Jobs:**
  - `src/Gatekeep.Kernel/Jobs/{IJobEnqueuer.cs,JobPayload.cs,JobType.cs}`: payload is IDs plus one `Secret<byte[]>? Credential`.
  - `src/Modules/Operations/Contracts/{JobRegistry.cs:6-80,JobRun.cs}`: `JobDefinition`, `mayCarryCredential`, `DecryptCredentialAsync`.
  - `src/Modules/Operations/Core/{ProductionJobs.cs:37-197,JobEnqueuer.cs:35-120,JobRunner.cs:63-70,328-436,ExpiredStatePurgeJobs.cs}`: registry, encryption, payload erasure on done/dead, a Tenant handler example.
  - `JobGuardRenderer.cs` and `Migration20261124000000PurgeExpiredSignInState.cs:40+`: the rendered guard block.
  - `tests/Isolation/Jobs/{JobGuardTests.cs:25-73,JobTestSupport.cs}` (`JobDatabase`, `FakeKeyCustody`) and `tests/Architecture/JobRegistryRuleTests.cs:22-26,68-93,149` (Hosted may enqueue only `notifications.*` Tenant, non-never-dead types).
- `src/Gatekeep.Host.Worker/WorkerJobs.cs:38-62` and `src/Modules/Operations/Core/OperationStore.cs:14`: Worker runner wiring (`JobRunServices`). Add the sender here.
- `src/Modules/Notifications/{Contracts/EmailProviders.cs,Contracts/NotificationsContract.cs,Contracts/NotificationsEvents.cs,Core/EmailProviderStore.cs,Core/NotificationsPurge.cs}`: Story 4.4's provider. Add a Worker read with the ciphertext.
- `src/Gatekeep.Kernel/Secrets/{IKeyCustody.cs,KeyName.cs}`: `email-{tenant}` decrypt (`deploy/openbao/policies/host-worker.hcl:112-125` allows it).
- `src/Modules/Tenancy/Contracts/{ITenants.cs:219,283,TenantAddress.cs:5-12,46-52}`: `EmailLinkBase` (the stored issuer). `gk_worker` reads `tenant` and `tenant_host`.
- `src/Modules/Identity/Contracts/IdentityContract.cs` and `Core/IdentityCore.cs`: placeholders. Add the email read. `Migration20261102090000CreateSessionTables.cs:24-29` defines `user` (no email).
- **Limiter:**
  - `src/Gatekeep.Kernel/RateLimiting/IRateLimiter.cs`;
  - `src/Modules/Authentication/Core/TenantAttemptLimiter.cs` and `AuthenticationContract.cs:17-44,106` (`CreateAttemptLimiter`, policy pattern);
  - `tenant_attempt` in `TableRegistry.cs:763-782` (`gk_worker` has only SELECT(tenant_id) and DELETE).
- **Egress:**
  - `src/Adapters/Egress/{EgressHttp.cs:67-160,EgressAddresses.cs}`: resolve, check, connect; `EgressPermit` test seam.
  - `tests/Architecture/EgressRuleTests.cs:23-31,61-89`: where sockets and handlers may be made.
  - `src/Adapters/Hosting/GatekeepHosting.cs:88-100`: wiring pattern (`WebhookAlertChannel`, `S3ObjectLockStore`).
  - `src/Adapters/ObjectLock/SigV4.cs`.
- `Directory.Packages.props`: central versions, locked restore (`BuildEnforcementTests.cs:122-170`).
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs`: add the email limits.
- **Test doubles:** `tests/Isolation/OffServer/{AlertSinkFixture.cs,OffServerDoubles.cs}` (in-process loopback listener via `EgressPermit`) and `tests/Isolation/Custody/CustodyTestDoubles.cs`.
- `tests/Architecture/module-edges.txt`. Edges already present: Operations → Notifications, Identity, Authentication, Tenancy; Host.Worker → Operations, Adapters.Hosting; Adapters.Hosting → Adapters.Egress.
- **Latest migration:** `Migration20261125000000ConfigureEmailProviders.cs` (count 41).

## Tasks & Acceptance

**Execution:**
- **Migration `Migration20261126000000SendEmail` and `TableRegistry`:**
  - `user.email` with its index and the `gk_worker` column read;
  - `email_template` (RLS, guard, grants, purge);
  - `gk_worker` limiter grants on `tenant_attempt`;
  - the rendered job guard.

  The migration count goes to 42.
- `src/Gatekeep.Kernel/**`: the `IEmailSender` port and message and result types, plus the limits.
- `src/Modules/Identity/**`: the email read. `src/Modules/Notifications/**`: template IDs, defaults, renderer, the template read, a Worker provider read, events, and the `email_template` purge.
- `src/Modules/Operations/**`: the job definition and the send handler.
- `src/Adapters/Egress/**`: a vetted SMTP connect (resolve, check public, connect, timeout). `src/Adapters/Email/**` (new project): the six adapters.
- **Packages:** MailKit and MimeKit in `Directory.Packages.props`.
- **Wiring:** `src/Adapters/Hosting/**` and `src/Gatekeep.Host.Worker/**`.
- **Tests:**
  - `tests/Isolation/Notifications/EmailSendTests.cs` (new): every matrix row, through the job runner with fakes. For SMTP, a loopback TLS SMTP fake with a test certificate trusted through the `EgressPermit` seam.
  - Renderer unit tests.
  - Updates to `EgressRuleTests`, `JobGuardTests`, `JobRegistryRuleTests` if needed, `module-edges.txt`, `MigrateCommandTests` (42), `TenantPurgeRegistryTests`, the audit catalogue and docs.

**Acceptance Criteria:**
- Given a queued email, when the worker sends it, then the recipient is resolved from an ID at send time, the link payload is ciphertext, and it's erased afterwards.
- Given an email link, when it's built, then its host comes from the stored issuer, never request headers.
- Given the five default templates, when a message is sent, then subject and body use fixed variable substitution only.
- Given one recipient, when the per-recipient limit is passed, then further email is held back (dropped and logged).

## Spec Change Log

## Review Triage Log

## Design Notes

**Default copy:** short, plain and on brand. Name the Tenant, never "Gatekeep". Keep every string in one Notifications defaults file. For example:
- verification: "Verify your email for {{tenant_name}}" / "Confirm this address to finish setting up your {{tenant_name}} account:\n\n{{link}}\n\nIf you didn't ask for this, ignore this email."
- one-time code: "Your {{tenant_name}} code" / "Your code is {{code}}. It expires soon. Don't share it."

**Why dropping, not delaying:** the limit exists to stop an inbox being flooded. Delayed delivery would still deliver the flood.

## Verification

**Commands:**
- **.NET build:** with `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors. Restore must succeed with the lockfiles updated.
- **Isolation:** with Testcontainers, pinning the IPv4 as `run-tests.sh` does, run `EmailSendTests`, `Jobs/*`, `MigrateCommandTests`, `TenantPurge*`, `TenantTablesTests`, `CrossTenant*`, `Canary*` and `AuditCatalogue*`, plus the Architecture suite. Don't run the full Isolation suite. The local-only `.claude/worktrees` failure is expected.
