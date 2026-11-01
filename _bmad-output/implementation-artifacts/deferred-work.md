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
