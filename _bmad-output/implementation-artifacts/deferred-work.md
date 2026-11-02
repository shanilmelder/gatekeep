- source_spec: `_bmad-output/implementation-artifacts/spec-1-1-scaffold-the-monorepo-and-enforce-module-boundaries.md`
  summary: Prove `.github/workflows/ci.yml` fails a real pull request on lockfile drift and on a critical advisory.
  evidence: The architecture tests run equivalent commands but never run the workflow, so removing `--locked-mode` or the `pnpm audit` step fails nothing. It needs a GitHub remote, which doesn't exist yet; run one deliberately failing PR when the repo is created.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-2-prove-key-custody-on-the-target-host.md`
  summary: Add acceptance criteria to Stories 1.7 and 1.10 that record results for static seal, Raft, socket access from containers, OpenBao host login and per-host quotas, and decide the host login method.
  evidence: Story 1.2 recorded these five proofs as `not-run`, they need only Linux, and no story currently requires them.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-2-prove-key-custody-on-the-target-host.md`
  summary: Decide how the root-only key file reaches the non-root OpenBao service, with owner, mode, key generation, mount order and the behaviour when the volume is missing at boot.
  evidence: AD-10 bans environment files and `LoadCredentialEncrypted` needs a TPM; Story 1.7 inherits this undecided.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-2-prove-key-custody-on-the-target-host.md`
  summary: Recheck seal rotation, restore and `gatekeep rekey` (AD-10, AD-18, Stories 12.2, 12.7, 13.4) against the key file design, including destroying old copies.
  evidence: These paths assumed a TPM-sealed key. A copied file has no hardware binding, so old copies stay valid until rotation.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-2-prove-key-custody-on-the-target-host.md`
  summary: Run the custody spike on a real TPM2 host before adopting the TPM design, and amend AD-10 again.
  evidence: AD-10 and AR-20 name the TPM design as the target, but no story schedules the spike.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-2-prove-key-custody-on-the-target-host.md`
  summary: Extend Story 1.10's LUKS criterion to the key volume, and cover the boot passphrase step in the install docs and alerts.
  evidence: Story 1.10 tests only the OpenBao and PostgreSQL volumes, while AD-10 now needs the key volume on LUKS, and a reboot waits for a person against NFR-10.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-3-write-the-threat-model.md`
  summary: Add acceptance criteria to the stories named in `docs/threat-model.md` Gaps to close (G-1 to G-14), and record Esm's decision on G-15.
  evidence: The gaps have no criterion in any story, so closing them depends on a reviewer reading the threat model. Editing epics was outside Story 1.3.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-3-write-the-threat-model.md`
  summary: Point the `ARCHITECTURE-SPINE.md` Deferred entry for the threat model at `docs/threat-model.md`, and amend AD-10, AD-18 and AD-26 for the gaps it raises.
  evidence: The spine still lists the threat model as pending, and G-9, G-11 and G-12 are spine-level changes.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-4-enforce-tenant-isolation-in-the-database.md`
  summary: Catch `ARCHITECTURE-SPINE.md` up with Story 1.4: name `migration_history` in AD-27, add `Cli -> Adapters.Postgres` to the AD-1 diagram, and correct AD-3 if the known limit wording changes.
  evidence: AD-27 does not list `migration_history`, and the spine diagram has no adapter edge, though the edge list and generated diagram do.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-4-enforce-tenant-isolation-in-the-database.md`
  summary: Add a test that a failed `TenantScope.BeginAsync` returns its connection to the pool.
  evidence: Removing the cleanup passed every test, and the failure is hard to force before Story 1.5 gives it a real caller.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-4-enforce-tenant-isolation-in-the-database.md`
  summary: Add column-level grants to `TableEntry` and the catalogue audit.
  evidence: AD-2 and TB-6 require per-column allow-lists, but the registry is table-level. The audit reports any column grant as unlisted, so the first story needing one must add this.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-4-enforce-tenant-isolation-in-the-database.md`
  summary: Correct AD-3 so it no longer says an unscoped query always raises an error.
  evidence: `Known_limit_an_unscoped_query_the_planner_proves_empty_returns_nothing` shows a query that evaluates the policy for no row returns nothing.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-4-enforce-tenant-isolation-in-the-database.md`
  summary: Audit function ACLs, `SECURITY DEFINER` and `pg_default_acl` in the catalogue test.
  evidence: None exist yet, but triggers in Stories 1.8 and 7.1 add functions, and `PUBLIC` can execute new functions by default.
