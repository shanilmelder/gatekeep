# Epic 12 Context: Backup, restore and upgrade

<!-- Generated from planning artifacts. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Give the Operator (Esm) a safe way to back up, restore, upgrade and re-key a single-host Gatekeep Deployment. A dead server, a failed upgrade or a suspected Master Key exposure must all be recoverable from off-server artifacts and documentation alone. No credential that existed at backup time may be lost, and no credential revoked after the backup may come back. This epic makes the "upgrade fails partway, restore on the previous version" journey (UJ-4) real, and it supplies the restore base that compromise response (Epic 13) builds on.

## Stories

- Story 12.1: Back up the Deployment
- Story 12.2: Restore a Deployment onto clean hardware
- Story 12.3: Reconcile keys and end stale access after restore
- Story 12.4: Replay revocations after restore
- Story 12.5: Sign release images
- Story 12.6: Upgrade between releases
- Story 12.7: Rotate the Master Key

## Requirements & Constraints

- **Backup:** runs nightly and is stored off the server. Without the Master Key, a backup reveals no secret or private key. The server's own credential can't delete or overwrite a backup inside retention, which is at least 30 days.
- **Restore:** works on clean hardware using only the off-server backup, the escrowed Master Key and the docs. It takes under 1 hour and loses at most 24 hours of data. Credentials from backup time keep working. It reports the backup timestamp, the lost-change window and the last shipped `seq`.
- **Default invalidation:** a restore ends all earlier Sessions, refresh tokens and Admin sessions unless the Operator passes `--planned-rollback` (the UJ-4 case).
- **Revocations stay revoked:** keys, Admins and credentials revoked after the backup must stay dead. They are re-applied from the signed off-server record. A replayed password change sets `password_reset_required`, which the Story 10.8 forced-reset flow clears.
- **Upgrade:** supported from the previous minor release or its latest patch. It refuses without a backup manifest under 24 hours old, and refuses any image whose signature fails. Valid Sessions and tokens survive unless the release names a security reason. A failed upgrade is recovered by restore, never by down-migration.
- **Master Key:** rotates without any User action, and sign-in keeps working throughout. An offline escrow copy is kept apart from backups. Every generation stays escrowed until the last backup that needs it has expired. The rotation rehearsal result is recorded in `docs/runbooks`.
- **Supply chain:** dependencies are pinned and scanned, and a known critical vulnerability blocks release. Images are signed, ship with an SBOM and are deployed by digest.
- **Rehearsal:** recovery is rehearsed on spare hardware before launch and each quarter. This covers a failed upgrade, a clean-hardware restore, revocation replay and alert delivery.
- **Secrets:** credential-equivalent values never reach logs, errors, debug output or exports.

## Technical Decisions

- **Docker only:** every command (`gatekeep restore`, `upgrade`, `rekey`, Master Key rotation) runs in the CLI container through `docker compose run --rm ...`. Nothing is installed on the host except Docker. `deploy/` holds the host-level files, including OpenBao policies.
- **Backup set:** a pgBackRest encrypted set with WAL archiving, plus an OpenBao (Raft) snapshot. Both are recorded in one manifest with the release version, timestamp and Master Key generation. Immutability comes from Object Lock or a pull from another machine; the backup story chooses which. The pgBackRest repository key is escrowed with the Master Key, and neither is ever in a backup. The breach dataset isn't backed up. Pinned versions are pgBackRest 2.60.0, OpenBao 2.7.2 and PostgreSQL 18.6.
- **Master Key:** the OpenBao barrier and static seal key, a 32-byte file on the Docker host, outside every data volume and backup. It reaches OpenBao only as a read-only Compose secret, and is never in an image, environment variable, data volume, log or repository. Rotation is a seal rotation followed by a Transit rewrap.
- **Restore sequence:** restore runs on the same release version as the backup, refuses Tenant traffic until it finishes, and is Deployment-wide only. It has four ordered steps:
  1. Reconcile `signing_key` rows against Transit. Any row with no Transit key moves to `revoked`, and a replacement is created.
  2. Verify the signature on each off-server record, report and skip failures, and replay the rest of the revocations.
  3. Unless `--planned-rollback` is set, end all Sessions, refresh tokens and Admin sessions, and rotate every Signing Key.
  4. Write a signed restore record off the server naming each chain's head, then start a new `epoch` per chain. `--planned-rollback` skips step 3 only.
- **Bootstrap guard:** restore refuses a backup with incomplete bootstrap unless given an explicit flag, and using that flag raises a Security Alert.
- **Off-server record:** sealed security events, revocations and chain heads go to an Object Lock (compliance mode) S3-API bucket on a separate provider. They are signed by a Deployment Transit key that only `Host.Worker` and `Gatekeep.Cli` can use. The replayable revocation types are a code-owned table carrying the internal IDs needed to re-apply them: keys, Token Families, Sessions, Users, Admins, client secrets, password changes, Factor and Passkey removals, and Recovery Code use.
- **Audit:** `gatekeep audit verify` accepts a break between epochs only where a signed restore record names it. The restore event raises a Security Alert through the code-owned alert table.
- **Key custody:** all key access goes through the Kernel `IKeyCustody` port. The CLI's OpenBao policy can create, rotate, rewrap and delete keys, encrypt `social` and `email`, and sign and verify off-server records. Nobody may export keys. Transit key names are prefixed by purpose (`sig-`, `mgmt-`, `{class}-{tenantId}`, `dep-{class}`).
- **Upgrade:** stop the hosts, run forward-only migrations as `gk_migrator`, then start the new version. Before any of that, verify each image signature against a public key pinned on the server, outside the image.
- **Release signing:** build and signing are separate CI jobs. The build job runs third-party code and holds no secrets. The signing key is held in hardware by Esm. Dependencies install from lockfiles with install scripts disabled.

## Cross-Story Dependencies

- Story 12.1's manifest is the input to Story 12.2 (restore) and to Story 12.6's 24-hour freshness check.
- Stories 12.3 and 12.4 implement restore steps 1 to 4 inside the Story 12.2 command.
- Story 12.5's signatures and server-pinned key are prerequisites for Story 12.6's signature check.
- Story 12.6's rollback path depends on `--planned-rollback` from Story 12.3.
- Epic 10 (Story 10.8, forced credential reset) must already ship the flow that clears `password_reset_required`.
- Epic 7: real restore and upgrade events replace the Story 7.7 Deployment Log fixtures. The off-server record, sealer and chains come from the audit and alert work in Epics 7 and 11.
- Epic 11 (Story 11.1): the restore Security Alert closes its pending-list entry.
- Epic 9: Signing Key lifecycle, JWKS and rotation.
- Epic 1: the Compose stack and safe secrets.
- Epic 13 (`gatekeep rekey`, compromise response) builds on this epic's restore.
