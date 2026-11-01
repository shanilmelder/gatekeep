- source_spec: `_bmad-output/implementation-artifacts/spec-1-1-scaffold-the-monorepo-and-enforce-module-boundaries.md`
  summary: Prove `.github/workflows/ci.yml` fails a real pull request on lockfile drift and on a critical advisory.
  evidence: The architecture tests run equivalent commands but never run the workflow, so removing `--locked-mode` or the `pnpm audit` step fails nothing. It needs a GitHub remote, which doesn't exist yet; run one deliberately failing PR when the repo is created.
