---
title: 'Story 1.30: Connect the alert channel and off-server store'
type: 'feature'
created: '2026-11-06'
status: 'done'
baseline_revision: 'ba1f82a903cb7117ec73083d19f7da15d5d63937'
review_loop_iteration: 1
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/epic-1-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-7-hold-keys-in-openbao-behind-ikeycustody.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-10-run-the-stack-under-compose-with-safe-secrets.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-11-route-traffic-through-caddy-and-default-deny-networks.md'
  - '{project-root}/docs/threat-model.md'
  - '{project-root}/docs/install.md'
warnings: ['oversized']
deferred:
  - 'Audit shipper re-ships a chunk after a crash between the PUT and the offset save'
  - 'Read the alert webhook URL from a secret file'
  - 'Bind a signed record to its object key when verifying (Story 7.2)'
  - 'Filtering egress proxy for the egress network (T-59)'
  - 'EgressHttp edge cases: empty DNS answer, named-zone literal, secret size cap, handler mutability, hung connect'
  - 'Audit-ship canary flow with real OpenBao lines and both days'"'"' prefixes'
---

<intent-contract>

## Intent

**Problem:** Gatekeep has nowhere outside the server to send a Security Alert or keep evidence. The Deployment key `dep-records` exists, but nothing uses it. No host has any egress, and nothing controls outbound HTTP once one does. OpenBao's audit device writes only to a volume on the server.

**Approach:**
- Add two Kernel ports with adapters:
  - `IAlertChannel`, with an HTTPS webhook adapter;
  - `IOffServerStore`, with an S3-API Object Lock adapter that writes objects in compliance mode;
  - a Kernel writer that signs records with `dep-records`.
- Route all outbound HTTP through one `EgressHttp` handler that refuses private addresses.
- Startup in `Host.Worker`, and the Cli commands that use the channel or the bucket, refuse when a setting is missing or unsafe.
- Add Cli commands that send a test alert and write a signed test record.
- Add a shipper service that copies OpenBao's audit file into the bucket.

## Boundaries & Constraints

**Always:**
- **One outbound path.** Every outbound HTTP request in `src/` goes through `EgressHttp`. It is a `SocketsHttpHandler` whose `ConnectCallback` resolves the name itself and connects only to an address it has checked, so DNS rebinding can't swap one in after the check. It has no proxy, no redirects, no cookies and a 10-second connect timeout.
  - **Refused IPv4 ranges:** `0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`, `192.0.2/24`, `192.168/16`, `198.18/15`, `198.51.100/24`, `203.0.113/24`, `224/4`, `240/4` and `255.255.255.255`.
  - **Refused IPv6 ranges:** `::`, `::1`, `fc00::/7`, `fe80::/10`, `ff00::/8` and `2001:db8::/32`.
  - **Embedded IPv4:** an IPv4-mapped (`::ffff:0:0/96`), NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) address is judged by the IPv4 address inside it.
  - **Refusal:** a name with no allowed address is refused with `EgressRefusedException`, which names the host but never an address list.
- **Allowed exceptions.** Only two handlers are built elsewhere:
  - the OpenBao unix-socket handler (`OpenBaoKeyCustody.CreateHandler`);
  - the loopback health probe (`src/Adapters/Hosting/HealthProbe.cs`).
- **No way to relax the block outside tests.** The private-address refusal can be relaxed only through an `internal` seam that `Tests.Isolation` reaches through `InternalsVisibleTo`. No setting, environment variable, Cli argument or Compose value relaxes it.
- **No egress for `Host.Admin`.** `Host.Admin` gets no egress: no reference to `Adapters.Egress`, and no egress network.
- **Network membership.** In this story only `worker`, `cli` and the new `openbao-audit-shipper` join the new non-internal `egress` network.
- **Alert contents.** An alert carries only these fields:
  - `code`, a `{domain}.{object}.{action}` code;
  - `alertId`, a UUIDv7;
  - `raisedAt`, in UTC;
  - `deployment`, the Admin hostname;
  - optional `tenantId` and `eventId`;
  - a fixed `summary` taken from the code.
  It carries no personal data, credential, token, URL query or free text.
- **Records and the bucket.**
  - **Object Lock:** every object is written with `x-amz-object-lock-mode: COMPLIANCE`, `x-amz-object-lock-retain-until-date` of at least `RetentionPeriods.LogDays` days from the write, and `Content-MD5`.
  - **Signed records:** a signed record is canonical JSON holding `kind`, `id`, `writtenAt` and `payload`. Its `signature` is `{ key: "dep-records", version, value }`, made through `IKeyCustody.SignAsync` over the canonical bytes of the other four fields.
  - **Credential rights:** the server's bucket credential may only `PutObject`, never delete, change retention or read.
- **Startup refusal, on the existing path.**
  - **Worker:** startup refuses through the existing `HostSettings.Resolve` path, naming every missing or unsafe setting and never a value. A setting is refused when:
    - it is missing;
    - a URL isn't absolute `https`, or has user info;
    - a bucket name breaks S3 naming;
    - a secret file is missing or empty;
    - `SecretDefaults.IsUnsafe` flags it.
  - **Cli:** the commands `alerts test`, `records test` and `audit-ship` refuse in the same way before doing anything, with their own `GATEKEEP_*` variables.
  - **Names:** new setting names obey the `HostSettingNames` scrubber rule.
- **Failures leak nothing.** Adapter failures throw `AlertChannelException` or `OffServerStoreException`. Each is shaped like `KeyCustodyException`: an operation and a failure kind (`Refused`, `Rejected` or `Unavailable`). It never carries a response body, a header, the URL, a secret or a remote error message. A request answered 2xx succeeds. Everything else fails, and the failure is never retried inside the adapter.
- **Audit device.** OpenBao's audit device keeps its default HMAC of request and response values. The configuration test asserts `log_raw`, `hmac_accessor = false` and `elide_list_responses = false` are absent.
- **Shipper.**
  - **What it ships:** it ships only bytes appended to the audit file. It keeps its read offset in its own volume, ships within 30 seconds of a write, and starts over from 0 when the file shrinks.
  - **Object keys:** `openbao-audit/{yyyy}/{MM}/{dd}/{fileId}-{startOffset:D20}.jsonl`.
  - **Access:** it reads the file read-only, through a shared group, and nothing else can read it.
- **Canaries.** Canary flows cover every new Cli command, adapter and the shipper. Each captures what left the process (webhook bodies and headers, bucket objects and their metadata) for the scan.
- **Threat model.** `docs/threat-model.md` is updated in this PR.

**Never:**
- Alert derivation from events, the Notifications alert table or any `alerts.*` job type (Story 11.1). Decrypt-rate or threshold alerts (Story 11.2). The heartbeat (Story 11.3).
- Shipping sealed events, revocations or chain heads (Story 7.2), or anything that reads back from the bucket.
- Egress for `Host.Hosted`, which comes with social providers in Epic 14.
- Audit-file rotation, or a second audit device.
- The AWS SDK, or any S3 or HTTP client package. SigV4 for one `PUT` is written by hand over `EgressHttp`.
- `IHttpClientFactory`, `AddHttpClient`, or a parameterless `new HttpClient()` anywhere in `src/`.
- Network checks at startup. Startup validates only settings and files.
- Signing the shipped audit chunks. See Design Notes.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|---|---|---|---|
| Test alert | `gatekeep alerts test` with valid settings, sink reachable | Sink receives one `POST`, JSON per the alert shape with code `operations.alert.test`, header `Authorization: Bearer <token file>`; Cli prints `Test alert delivered` and the `alertId`, exit 0 | — |
| Sink refuses | Sink answers 401, 404 or 500 | Cli prints a fixed `Alert channel rejected the alert` line, exit 1; no body, status text or URL printed | `AlertChannelException(Rejected)` |
| Sink unreachable or slow | Connection refused or no answer within 10 s | Fixed `Alert channel unavailable` line, exit 1 | `Unavailable` |
| Private target | Channel URL resolves to `10.0.0.1`, `127.0.0.1`, `::ffff:192.168.1.1`, `[fd00::1]` or `host.docker.internal` | Nothing is sent; fixed `Alert channel refused: private address` line, exit 1 | `EgressRefusedException` mapped to `Refused` |
| Redirect | Sink answers 302 to a public URL | Not followed, so it counts as a failure | `Rejected` |
| Test record | `gatekeep records test` with valid settings | One object `records/test/{yyyy}/{MM}/{dd}/{recordId}.json` holding the signed record, in compliance mode, retained at least 90 days; the signature verifies against `dep-records`; Cli prints the object key, exit 0 | — |
| Write-only credential | The server credential tries a delete, a delete of a version, shorter retention, governance bypass or a read | Each is refused and the object version stays | Asserted against the bucket |
| Overwrite | A second `PUT` to the same key | The first version stays, still locked | — |
| Missing setting | Worker started without any one of the alert or bucket settings | Exit 1; the Critical refusal line names exactly the missing names | Existing refusal path |
| Unsafe setting | `http://` URL, user info in the URL, bad bucket name, empty or default token or key file | Refused by name | Same |
| Shipper | A Transit encrypt of a canary plaintext and a sign, then the shipper runs | Within 30 s, objects under `openbao-audit/` hold those requests; neither the canary, its base64, nor any key material or token appears in them | — |
| Shipper restart | Restarted after shipping part of the file | Resumes at its offset with no gap and no duplicate chunk key | — |
| Admin egress | `Host.Admin` | No egress network; the architecture test fails if it references `Adapters.Egress` | — |

</intent-contract>

## Code Map

- **Kernel:**
  - new `src/Gatekeep.Kernel/Alerts/` for `IAlertChannel`, `SecurityAlert` and `AlertChannelException`;
  - new `src/Gatekeep.Kernel/Records/` for `IOffServerStore`, `OffServerStoreException` and `OffServerRecordWriter` (`IKeyCustody`, `IOffServerStore` and `TimeProvider` produce the signed canonical JSON, with retention from `RetentionPeriods.LogDays`);
  - the signing key is `KeyName.ForDeployment(DeploymentKeyClass.Records)` (`src/Gatekeep.Kernel/Secrets/KeyName.cs:45`);
  - `IKeyCustody.SignAsync` returns `KeySignature(KeyVersion, Value)`.
- **New adapters,** following the folders listed in the architecture spine (`Adapters/{AlertChannel,ObjectLock}`, plus `Egress`). Each gets a csproj, a lock file and an entry in `Gatekeep.slnx`:
  - `src/Adapters/Egress/` for `EgressHttp.Create()` and the address classifier;
  - `src/Adapters/AlertChannel/` for `WebhookAlertChannel`;
  - `src/Adapters/ObjectLock/` for `S3ObjectLockStore` and the SigV4 signer.
  - Follow the `OpenBaoKeyCustody` pattern: the constructor takes an `HttpMessageHandler` (`OpenBaoKeyCustody.cs:44-93`), and failures are shaped like `KeyCustodyException`.
- **Settings:**
  - `src/Adapters/Hosting/HostSettings.cs`: `HostProfile` (:24) gets an `UsesOffServer` flag; `HostSettingNames` gets the new names; `Resolve` (~:139-210) refuses by name with `CheckSecretFile`.
  - `src/Adapters/Hosting/GatekeepHosting.cs:24-74`: when the flag is set, register `EgressHttp`, `IAlertChannel` and `IOffServerStore`.
  - `src/Gatekeep.Host.Worker/WorkerJobs.cs:11` (`WorkerSettings.Profile`): set the flag on the profile.
  - The Worker only registers them in this story; nothing calls them yet.
- **Cli:**
  - `src/Gatekeep.Cli/Program.cs:42-56` (the args switch) and :77-122 (environment reading);
  - new `AlertsTestCommand.cs`, `RecordsTestCommand.cs` and `AuditShipCommand.cs` (`audit-ship`, with `--once`);
  - build custody the way `InitCommand.cs:213` does;
  - `Gatekeep.Cli.csproj` gets the references.
- **Deploy:**
  - `deploy/compose.yaml`: the `egress` network (not internal); the `openbao-audit-shipper` service (cli image, `command: ["audit-ship"]`, `openbao-audit` read-only, a `shipper-state` volume, bucket secrets, `egress`, the `x-hardened` anchor); `worker` and `cli` join `egress` and get the alert and bucket environment and secrets.
  - `deploy/openbao/openbao.hcl:52-61`: audit `mode = "0640"`.
  - `deploy/docker/openbao.Dockerfile`: `/var/log/openbao` set to `0750` under a shared `openbao-audit` group, which the shipper joins with `group_add`.
  - The secrets layout follows the existing `${GATEKEEP_SECRETS_DIR}` directories (e.g. `alerts/`, `records/`).
- **Stack check, `deploy/ci/stack-check.sh`:**
  - the install values give the Worker placeholder, non-default settings (`https://alerts.invalid/...` and so on), so it starts;
  - the no-egress block (:195-202) keeps `hosted` and `admin` refused, and asserts that `worker` and `openbao-audit-shipper` join only `egress` plus their own networks;
  - add `cli alerts test` aimed at a private address: it must exit 1 with the private-address line.
- **Tests, `tests/Isolation/`:**
  - new `OffServer/` holding:
    - `ObjectLockFixture`: Testcontainers `ContainerBuilder` on a pinned, pullable `minio/minio:RELEASE.*` tag at least two weeks old. It creates a versioned, locked bucket with default compliance retention and a `PutObject`-only server user through `mc`.
    - `AlertSinkFixture`: an in-process Kestrel listener inside the tests container that records each request.
    - `AlertChannelTests`, `ObjectLockStoreTests`, `EgressHttpTests`, `AuditShipTests` and `OffServerCliTests`.
  - Fixtures are reached at the mapped address (`deploy/docker/run-tests.sh:6-15`), so the adapters take the internal permit seam.
  - `OpenBaoFixture` (`tests/Isolation/Custody/OpenBaoFixture.cs:37`, `AuditLog`) supplies the audit file and the `dep-records` signing.
- **Tests to extend:**
  - `tests/Isolation/Hosting/HostStartupTests.cs` and `tests/Isolation/Jobs/WorkerStartupTests.cs:33`: the refusals. The `HostProcess.cs` harness gives the Worker valid off-server settings by default.
  - `tests/Isolation/Stack/ComposeConfigTests.cs`: the egress check at :97, secrets at :399 and :492, and networks at :518.
  - `tests/Isolation/Custody/CustodyTests.cs:190-231`: add Transit plaintext to the audit-log canary.
  - `tests/Isolation/Canary/CanaryFlows.cs` (:191-253 and the `NoCredentialSurfaces` from :259): flows `alerts.channel`, `records.objectlock` and `openbao.audit.ship`, plus the three Cli surfaces, captured with `run.Capture`.
- **Architecture tests, `tests/Architecture/`:**
  - new `EgressRuleTests.cs`, in the style of `KeyCustodyRuleTests.cs:59-129`:
    - `new SocketsHttpHandler` and `new HttpClientHandler` appear only in `src/Adapters/Egress/`, the OpenBao adapter and `HealthProbe.cs`;
    - no parameterless `new HttpClient()`, `AddHttpClient` or `IHttpClientFactory` anywhere;
    - `Host.Admin` never references `Adapters.Egress`;
    - with snippet theories.
  - `module-edges.txt`:
    - `Adapters.AlertChannel -> Adapters.Egress` and `Adapters.ObjectLock -> Adapters.Egress`;
    - `Adapters.Hosting -> Adapters.Egress`, `Adapters.Hosting -> Adapters.AlertChannel` and `Adapters.Hosting -> Adapters.ObjectLock`;
    - `Cli -> Adapters.AlertChannel`, `Cli -> Adapters.ObjectLock` and `Cli -> Adapters.Egress`;
    - `Tests.Isolation` to each new adapter;
    - then run `dotnet run --project tests/Architecture/Generator` to refresh `docs/architecture/module-dependencies.md`.
  - The OpenBao audit configuration assertion goes with the existing hcl tests.
- **Docs:**
  - `docs/install.md`:
    - a new "Alert channel and off-server bucket" step listing the provider requirements: an HTTPS webhook, a bucket on a separate provider with Object Lock and versioning, default compliance retention of at least 90 days, and a sample write-only policy;
    - every setting and secret file;
    - update :174 and :230 for the egress network.
    - `tests/Architecture/InstallDocTests.cs:112` covers the topics.
  - `docs/threat-model.md`: the OpenBao row at :101 (shipped), :103 and :107 (egress network and `EgressHttp` built), TB-10 at :105, T-28 at :245 and T-32 at :249 if wording changes. G-11 stays open, since nothing alerts on sign counts.
  - `_bmad-output/implementation-artifacts/deferred-work.md`:
    - narrow the item at :59-60 to rotation and a second device;
    - leave the Story 1.26 alert items at :218-219 for Story 11.1, since they need derivation.

## Tasks & Acceptance

**Execution:**
- [x] **Kernel ports and record writer**, as in the Code Map. Unit-test the canonical bytes and that the signature covers them.
- [x] **`Adapters.Egress`:** the classifier, the vetted `ConnectCallback`, no proxy, redirects or cookies, and the internal permit seam with `InternalsVisibleTo("Gatekeep.Tests.Isolation")`.
- [x] **`Adapters.AlertChannel` and `Adapters.ObjectLock`:** the webhook adapter, and SigV4 `PUT` with the Object Lock headers and `Content-MD5`, path-style URLs and failure mapping.
- [x] **Settings and startup:** the `HostProfile` flag, names and refusals; registration in `GatekeepHosting`; the Worker profile; the Cli variables and refusals.
- [x] **Cli:** `alerts test`, `records test` and `audit-ship [--once]`, with the fixed output lines from the matrix.
- [x] **Deploy:** the Compose network, service, volumes and secrets; the OpenBao audit mode and group; the stack check.
- [x] **Isolation tests:**
  - every matrix row, with the two fixtures;
  - startup refusals for each missing and unsafe setting;
  - the Compose test updates;
  - the audit-log canary, with Transit plaintext added;
  - the three canary flows and Cli surfaces.
- [x] **Architecture tests:** `EgressRuleTests` with self-checks, the edges and diagram, and the hcl assertion.
- [x] **Docs:** `install.md`, the threat model and `deferred-work.md`.

**Acceptance Criteria:**
- Given `IAlertChannel` and its webhook adapter, when `gatekeep alerts test` runs, then a service outside the Deployment receives the alert, and the alert carries only the listed fields.
- Given the Object Lock adapter and a locked bucket, when `gatekeep records test` writes a signed record, then the object is in compliance mode for at least 90 days and its signature verifies against `dep-records`. The server credential can't delete it, delete its version, shorten its retention or read it.
- Given install configuration, when any alert or bucket setting is missing or unsafe, then `Host.Worker` and the three Cli commands refuse to start, naming each such setting and printing no value.
- Given alert bodies, bucket objects and shipped audit chunks, when the canary scan runs, then no credential-equivalent value appears.
- Given outbound HTTP from any host, when it runs, then it goes through `EgressHttp`, which refuses every private, loopback, link-local and embedded-private address, and the architecture test fails on any other handler.
- Given the OpenBao audit device, when a Transit operation runs, then its record reaches the bucket through the shipper within 30 seconds and holds no key material or plaintext.

## Spec Change Log

- **2026-11-06 — the bucket credential also has `s3:PutObjectRetention`.** S3 needs it for a `PUT` that carries Object Lock headers. Against a COMPLIANCE object it can only lengthen retention, never shorten it, so nothing can be erased early (T-61). The "never change retention" rule now means never shorten or remove it. `ObjectLockStoreTests` assert a 403 `AccessDenied` for delete, delete-version, read and list.
- **2026-11-06 — "no reference to `Adapters.Egress`" means no direct one.** `Host.Admin` and `Host.Hosted` load the egress assemblies through `Adapters.Hosting`, as the Code Map's edges require. They stay off the `egress` network, they register no `IAlertChannel` (`OffServerRegistrationTests`), and `EgressRuleTests` keep `EgressHttp` and `UsesOffServer` out of their source.
- **2026-11-06 — the MinIO fixture image is `bitnamilegacy/minio`, pinned by digest.** `minio/minio:RELEASE.*` tags can no longer be pulled.
- **2026-11-06 — more refused ranges, and IPv4 is tried first.** The refusal also covers:
  - IPv4 `192.88.99.0/24`;
  - IPv6 `3fff::/20`, `fec0::/10`, `100::/64`, `2001::/32` (Teredo), `2001:10::/28`, `2001:20::/28`, `64:ff9b:1::/48` and `::ffff:0:0:0/96`.

  `EgressHttp` dials allowed IPv4 addresses before IPv6, so a dead IPv6 route can't use up the 10-second connect timeout.
- **2026-11-06 — refusals say why.** A `Refused` failure says whether the address or the token or credential file was refused. The Cli prints the private-address line only for the address, and a fixed `… file unusable` line otherwise.
- **2026-11-06 — the shipper.**
  - It ships chunks of at most 1 MiB.
  - It spots a replaced file by the hash of its first bytes.
  - It refuses at startup when its state directory can't be written.
  - The audit directory is setgid (`2750`), so a file OpenBao recreates keeps the `openbao-audit` group.

## Review Triage Log

### 2026-11-06 — Review pass

- **Verdicts:** 4 reviewers (Blind Hunter, Edge Case Hunter, Verification Gap and Intent Alignment) found 59 findings, about 30 distinct after merging duplicates. 27 were patched, including the 3 found by verification, 7 deferred and 3 recorded as spec changes. None were rejected.
- **Found by verification, before review:**
  - `[high]` `[patch]` `records test` against `https://[::1]` crashed with exit 134. SigV4 built the `Host` header without the IPv6 brackets. Fixed and unit-tested.
  - `[medium]` `[patch]` The classifier refused `::ffff:1.1.1.1`. IPv4-mapped addresses are now unwrapped before the IPv6 ranges are checked.
  - `[medium]` `[patch]` `cli.Dockerfile` used `COPY --chmod`, which needs BuildKit, so the stack-check build failed. The build stage now sets the mode.
- **Patched from review:**
  - `[high]` `[patch]` VG: the bucket's default retention hid missing Object Lock headers. A capturing-handler test now asserts mode, retain-until and `Content-MD5`, and the fixture default is GOVERNANCE 1d.
  - `[high]` `[patch]` VG: nothing showed that the shipper container can read the audit file. The stack check now waits for its fixed "unavailable" line, then expects it running with 0 restarts.
  - `[medium]` `[patch]` BH, ECH: startup accepted token and credential files that the adapters refuse. One rule, `SecretDefaults.IsUnsafeCredential`, is now used everywhere.
  - `[medium]` `[patch]` BH, VG, ECH, IA: every `Refused` printed "private address". The reason is now carried, with fixed token and credential lines, and the stack check proves the token is readable.
  - `[medium]` `[patch]` BH, ECH: the shipper ignored file identity. A hash of the first bytes now catches a replaced and regrown file.
  - `[medium]` `[patch]` BH: a 4 MiB chunk couldn't finish inside the 10-second timeout. Chunks are now capped at 1 MiB.
  - `[medium]` `[patch]` BH, ECH: a failed save looped forever, adding locked versions, and corrupt state reset silently. The state directory is now probed at startup, and corrupt state prints a fixed line.
  - `[medium]` `[patch]` BH, ECH: local-use NAT64, site-local, Teredo, ORCHID, SIIT, `3fff::/20` and `192.88.99.0/24` weren't refused. They are now.
  - `[medium]` `[patch]` BH, ECH: one dead IPv6 route used up the whole connect timeout. IPv4 is now tried first.
  - `[medium]` `[patch]` ECH: HTTP/3 skips `ConnectCallback`. An architecture test now forbids `Version30` and `RequestVersionOrHigher`.
  - `[medium]` `[patch]` VG: the `EgressRuleTests` regexes could be dodged. String literals are emptied first, and the rule catches target-typed `new()`, subclasses and raw sockets.
  - `[medium]` `[patch]` VG: DNS rebinding was untested. An internal resolver seam now shows that only checked public addresses are dialled.
  - `[medium]` `[patch]` VG: the Worker's registrations were never resolved. `OffServerRegistrationTests` now resolves them.
  - `[medium]` `[patch]` VG: each missing setting was only tested together with the others. There is now one row per setting, for the Worker and each Cli command.
  - `[medium]` `[patch]` VG: the write-only credential tests accepted any status of 400 or more. They now require 403 `AccessDenied`, and a new test shows that a GOVERNANCE `PUT` still can't be removed.
  - `[low]` `[patch]` BH: `start-openbao.sh` aborted under `set -e` when it couldn't create the audit file. Creating it is now inside the warn-only block.
  - `[low]` `[patch]` BH: a recreated audit log lost its group. The directory is now setgid `2750`.
  - `[low]` `[patch]` BH: the shipper had `pull_policy: never` and no build. It now has the cli image's build.
  - `[low]` `[patch]` ECH: the SigV4 IPv6 host was untested. A test now covers it.
  - `[low]` `[patch]` ECH: `AuditShipTests` could flake at midnight. Both days' prefixes are now searched.
  - `[low]` `[patch]` VG: no-retry was only partly asserted. There is now one request each on a timeout and on a 500.
  - `[low]` `[patch]` VG: the bucket metadata scan covered three fields. It now covers every HEAD header.
  - `[low]` `[patch]` VG: nothing showed that a Cli refusal happens before custody is reached. The fake socket's request count is now asserted to be 0.
  - `[low]` `[patch]` VG: the stack check didn't try `host.docker.internal`. It now does when the name resolves.
  - `[low]` `[patch]` ECH: bucket names were too strict. Only dotted-quad IPv4 names are refused now.
- **Recorded as spec changes:** IA, VG: `s3:PutObjectRetention`; IA, VG: the transitive Egress reference; IA: the MinIO image. See the Spec Change Log.
- **Deferred:**
  - `[low]` `[defer]` ECH, IA: a crash between `PUT` and save re-ships the same key as a second version.
  - `[medium]` `[defer]` BH: the webhook URL is a plain environment variable. `install.md` now says it must carry no credential.
  - `[low]` `[defer]` BH: a signed record can be replayed under another key. Belongs to Story 7.2's verifier.
  - `[low]` `[defer]` IA: no filtering egress proxy (T-59).
  - `[low]` `[defer]` ECH: an empty DNS answer reads as "private address", and a literal with a named zone gives Unavailable.
  - `[low]` `[defer]` ECH: secret file reads have no size cap.
  - `[low]` `[defer]` VG, ECH, IA:
    - the hung-connect path isn't exercised;
    - a partial last line gets glued to the next after an OpenBao crash;
    - the handler can be changed after `Create()`;
    - the canary flow uses synthetic audit lines and builds its prefix from `UtcNow`.
- **Already tracked:** `MasterKeyRotationTests.Full_rotation_…` fails at the census step on `main` too. It is the existing Story 12.7 item in `deferred-work.md`.

## Design Notes

- **Why a webhook and hand-written SigV4.** The spine says vendors are chosen at install, behind ports. An HTTPS `POST` with a bearer token reaches most alert services, either directly or through their webhook bridges. One `PUT` with SigV4 is about 100 lines, testable and auditable, and it keeps all traffic on `EgressHttp`. The AWS SDK would bring its own HTTP stack and a large dependency surface.
- **Why the Worker refuses but sends nothing yet.** Story 1.30 connects the ports, and Story 11.1 derives alerts from events. Refusing at startup now means no Deployment runs without a channel and bucket once alerts and shipping arrive. The Cli test commands are how an Operator proves both work at install.
- **Why the shipper doesn't sign.** Signing would put an OpenBao AppRole that can sign into a long-running container on an internet-facing network. Object Lock already stops erasure. TB-10 already accepts that an intruder on the server can forge additions, because both Z-3 and Z-5 can sign. Gatekeep's own records (Story 7.2) stay signed.
- **Why tests relax the block only in-process.** Every Docker test endpoint has a private address. A setting that allows private targets would be one copy-paste away from an SSRF hole in production. The `internal` seam can't be reached from configuration.
- **Why Hosted gets no egress now.** Nothing in Hosted sends outbound requests until social sign-in arrives. Each network the hosts join widens what an intruder can reach, so Hosted joins `egress` only when it needs it.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests`. Expected:
  - the build has no warnings;
  - the Architecture tests pass, including `EgressRuleTests`, the module edges and diagram, and `InstallDocTests`;
  - the Isolation tests pass, including the new `OffServer/` tests, `HostStartupTests`, `WorkerStartupTests`, `ComposeConfigTests`, `CustodyTests` and the canary flow and surface tests;
  - the browser tests are unchanged.
- `docker compose -f deploy/compose.test.yaml run --rm --build stack` (on Windows, from PowerShell with `GATEKEEP_HOST_REPO=/run/desktop/mnt/host/d/Projects/Personal/gatekeep`, `GATEKEEP_HTTP_PORT=18080` and `GATEKEEP_HTTPS_PORT=18443`): the stack check passes, including the egress-network assertions and the private-address refusal.

Nothing runs on the host. From a worktree, use a worktree-only image tag.

## Auto Run Result

Status: done

**Summary:**
- Gatekeep can now reach two places outside the server:
  - an HTTPS webhook alert channel, behind `IAlertChannel`;
  - an S3-API Object Lock bucket, behind `IOffServerStore`, written in compliance mode for at least `RetentionPeriods.LogDays` days with a hand-written SigV4 `PUT`.
- `OffServerRecordWriter` signs records with `dep-records`.
- Every outbound request goes through `EgressHttp`. It resolves names itself, dials only addresses it has checked, tries IPv4 first, and refuses private, loopback, link-local, reserved and embedded-private addresses. It has no proxy, follows no redirect, and allows no HTTP/3. Architecture tests forbid any other handler, socket or client.
- `Host.Worker` and the new Cli commands `alerts test`, `records test` and `audit-ship` refuse unsafe or missing settings by name. Startup and the adapters refuse token and credential files by one shared rule.
- The `openbao-audit-shipper` service copies what OpenBao appends to its audit log into the bucket in 1 MiB chunks. It reads the log through the setgid `openbao-audit` group, resumes from its offset, and spots a shrunk or replaced file.
- Only `worker`, `cli` and the shipper join the new `egress` network.

**Files:**
- **Kernel:** `src/Gatekeep.Kernel/Alerts/` and `Records/`, plus `Secrets/SecretDefaults.cs`.
- **New adapters:** `src/Adapters/Egress/`, `AlertChannel/` and `ObjectLock/`.
- **Hosting:** `src/Adapters/Hosting/` (settings and registration) and `src/Gatekeep.Host.Worker/WorkerJobs.cs`.
- **Cli:** `src/Gatekeep.Cli/` (`AlertsTestCommand`, `RecordsTestCommand`, `AuditShipCommand` and `OffServerSettings`).
- **Deploy:** `deploy/compose.yaml`, `compose.release.yaml`, the OpenBao config, Dockerfile and start script, `cli.Dockerfile`, and `deploy/ci/stack-check.sh`.
- **Tests:** `tests/Isolation/OffServer/`, plus the startup, Compose, custody and canary tests.
- **Architecture tests:** `tests/Architecture/EgressRuleTests.cs`, plus the module edges and diagram.
- **Docs:** `docs/install.md`, `threat-model.md` and `key-custody.md`.

**Review:**
- Verification found 3 issues, all fixed: the SigV4 IPv6 `Host` header, an IPv4-mapped public address being refused, and `COPY --chmod` without BuildKit.
- Four reviewers found 59 findings, about 30 distinct.
- 27 were patched, 7 deferred and 3 recorded as spec changes. None were rejected.

**Follow-up review:** recommended. The shipper's state format, the egress rule regexes and the refusal reasons all changed during review, and their only proof is the new tests.

**Verification:**
- The full suite ran in the `tests` container:
  - Architecture: 694/694.
  - Browser: 527 passed.
  - Isolation: 2759/2771. Eleven tests failed under shared-Docker load, and their ten classes pass on rerun (690/690). The other failure, `MasterKeyRotationTests.Full_rotation_…`, also fails on `main` and is an existing Story 12.7 item.
- The local stack check couldn't run, because a running `gatekeep-dev` stack holds the fixed edge subnets. CI's `stack` job runs it.
