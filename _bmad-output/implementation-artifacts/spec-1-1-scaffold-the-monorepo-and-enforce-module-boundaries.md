---
title: 'Story 1.1: Scaffold the monorepo and enforce module boundaries'
type: 'chore'
created: '2026-11-02'
status: 'done'
route: 'dispatch'
review_loop_iteration: 0
baseline_commit: 'b8587034be73e43d9ea7420941ad34d7b7ca261f'
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-1-context.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The repository holds only planning files, so later stories have nowhere to land and nothing stops an illegal module dependency from merging.

**Approach:** Create the .NET solution and pnpm workspaces from the Structural Seed at the Stack versions, make one edge list the single source for the build check and the generated diagram, and add CI that installs from lockfiles and fails on a known critical vulnerability.

## Boundaries & Constraints

**Always:**
- Central Package Management; one `net10.0` target; one version for every deployable.
- Every direct dependency between projects is an edge in the list, and transitive reach grants nothing.
- Every module and host may reference Kernel; Kernel references nothing inside Gatekeep.
- The edge list reproduces the spine diagram exactly.

**Never:**
- Turborepo or Nx. Hand-written API clients.
- Domain logic, routes, tables, migrations, Dockerfiles or Compose files: later stories own them.
- Changes to `design/`.

**Decisions:**
- CI host: GitHub Actions, in `.github/workflows/ci.yml`. No remote exists yet, so a real pull-request run stays unproven until a GitHub repo is created.
- Toolchain: install the pinned SDK, Node and pnpm on this machine, so local builds match CI.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Clean build | Fresh clone | .NET and pnpm builds pass | N/A |
| Listed edge | `Protocol` references `Keys` | Build passes | N/A |
| Unlisted edge | `Keys` references `Identity` | Build fails | Error names both projects and the edge list |
| Transitive use | `Host.Worker` uses a `Tenancy` type via `Operations` | Build fails | Compiler error; add an edge or remove the use |
| Host to module | `Host.Admin` references `Keys` with no listed edge | Build fails | Same error as unlisted edge |
| Kernel inward | `Kernel` references any module | Build fails | Same error as unlisted edge |
| Stale diagram | Edge list changed, diagram not regenerated | Architecture test fails | Error gives the regenerate command |
| Lockfile drift | Manifest changed, lockfile not | CI install fails | Locked or frozen install error |
| Critical CVE | Dependency with a critical advisory | CI fails | Audit output names the package |

</frozen-after-approval>

## Code Map

- `_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md:42` -- the 48 allowed edges; source for the edge list.
- `ARCHITECTURE-SPINE.md:30` -- layer table; `:529` Stack; `:601` Structural Seed.
- `_bmad-output/implementation-artifacts/epic-1-context.md` -- Epic 1 constraints.
- Repo has no code yet; nothing to reuse. `.gitignore` needs build-output entries added.

## Tasks & Acceptance

**Execution:**
- [x] `global.json`, `.nvmrc`, root `package.json` -- pin SDK, Node and pnpm -- one toolchain for every clone.
- [x] `Gatekeep.slnx`, `Directory.Build.props`, `Directory.Packages.props` -- solution, CPM, lockfiles, warnings as errors, `DisableTransitiveProjectReferences`, `NuGetAuditLevel` critical -- transitive reach must not compile.
- [x] `src/Gatekeep.Kernel`, `src/Gatekeep.Host.{Hosted,Admin,Worker}`, `src/Gatekeep.Cli`, `src/Modules/{Tenancy,Admins,Identity,Authentication,Sessions,Directory,Protocol,Keys,Audit,Notifications,Management,Operations}` -- minimal compiling projects with `Contracts`, `Core`, `Adapters` folders in each module and references matching the edges -- the Structural Seed.
- [x] `tests/Architecture/module-edges.txt` -- the edge list, with `dependency` and `composition` kinds -- single source of truth.
- [x] `Directory.Build.targets` -- fail the build on any `ProjectReference` not in the edge list -- enforcement in `dotnet build`, not only in tests.
- [x] `tests/Architecture` -- tests that project references equal the list exactly, that the diagram is current, and the I/O matrix's unlisted-edge cases; diagram generator -- covers matrix.
- [x] `docs/architecture/module-dependencies.md` -- generated Mermaid diagram -- the documented diagram.
- [x] `pnpm-workspace.yaml`, `pnpm-lock.yaml`, `.npmrc`, `apps/{hosted-login,admin-dashboard}`, `packages/{design-tokens,ui,hosted-screens,api-client}` -- minimal compiling workspaces at the React and Vite Stack versions, `ignore-scripts=true`, `api-client` empty until the OpenAPI document exists -- frontend half of the seed.
- [x] `.github/workflows/ci.yml` -- locked restore, frozen install with scripts disabled, build, test, critical audit for NuGet and pnpm -- third acceptance criterion.
- [x] `.gitignore` -- add `bin/`, `obj/`, `node_modules/`, `dist/` -- keep output out of git.

**Acceptance Criteria:**
- Given a clean clone, when the build runs, then the solution and all workspaces compile at the Stack versions using Central Package Management.
- Given the edge list, when a project references a module with no listed edge, then the build fails, and the diagram is generated from the same list.
- Given a pull request, when CI runs, then dependencies install from lockfiles with install scripts disabled, and a known critical vulnerability fails the build.

## Implementation Notes

- **Kernel references are not edges.** `module-edges.txt` holds the 48 spine edges exactly. References to Kernel are a standing rule in `Directory.Build.targets` and the tests, as the spine diagram says ("not drawn").
- **`ignoreScripts: true` in `pnpm-workspace.yaml`.** Tested on pnpm 12.16.1: `ignore-scripts=true` in `.npmrc` does not stop scripts, including a root `preinstall`. `.npmrc` stays as specified; the workspace setting does the work. CI also passes `--ignore-scripts`.
- **Added beyond the task list:** `nuget.config` (clears machine feeds), `tsconfig.base.json`, and `tests/Architecture/Generator` (the diagram generator, a separate project in the solution).
- **NuGet critical audit is the restore step.** `NuGetAuditLevel` critical plus warnings as errors makes NU1904 fail `dotnet restore --locked-mode`; there is no separate audit step.
- **Test runner.** `IsTestingPlatformApplication=false` keeps `dotnet test tests/Architecture` working on SDK 10 with xunit.v3.
- **Edge check hook.** The check runs before the private NuGet target `_GenerateRestoreProjectPathWalk`, otherwise Kernel-to-module fails with MSBuild's cycle error (MSB4006) instead of GK0001. If a later SDK renames that target, `BuildEnforcementTests` will fail on the Kernel case; the `ResolveProjectReferences` hook still blocks the build.
- **Toolchain on this machine.** SDK and Node are user-level installs in `%LOCALAPPDATA%\Programs` (`dotnet-10.0.403`, `node-v26.13.0-win-x64`, pnpm inside the Node folder) because the SDK installer could not elevate. They are not on PATH by default.
- **`engineStrict: true` in `pnpm-workspace.yaml`.** A wrong Node version fails `pnpm install`, but `pnpm -r build` still runs. A wrong pnpm version hands over to the pinned one rather than failing.
- **Review patches.** Each matrix row now has an automated test, and the pnpm tests need Node 26 on PATH. The public-type check in `ModuleEdgeTests` counts braces rather than parsing C#.


## Spec Change Log

## Review Triage Log

| # | Finding | Verdict | Route | Evidence |
|---|---------|---------|-------|----------|
| 1 | Test projects can't hold a legal reference (edge hunter, blind) | medium | patch | GK0001 covers all projects, while the equality test scans only `src`, so a listed test edge fails it. `tests/Isolation` will hit this. |
| 2 | Child processes and the CI job have no timeout (edge hunter, blind) | medium | patch | `process.WaitForExit()` is unbounded and `ci.yml` sets no `timeout-minutes`. |
| 3 | Edge list has two grammars (edge hunter, blind) | low | patch | `Parse` drops repeated spaces and MSBuild matches literally. Strict splitting is a direct correction. |
| 4 | Tab-separated edge line throws (edge hunter) | false | reject | A loud `FormatException` on a line outside the format is correct behaviour. |
| 5 | `ProjectReference` with `Update` or `Remove` gives a null reference (edge hunter, blind) | low | reject | Needs a guard for a form nothing here uses, and it fails loudly. |
| 6 | Nested `Directory.Build.*` drops enforcement (edge hunter, blind) | medium | patch | MSBuild stops at the nearest file, which silently removes GK0001 and audit settings for that subtree. |
| 7 | `composition` isn't limited to hosts (edge hunter, blind) | low | reject | No composition edges exist; the fix is a new guard, and the Design Notes already accept the limit. |
| 8 | "An edge exposes only the contract" is unchecked (edge hunter, blind, gap) | medium | patch | A public type in `Core` or an `InternalsVisibleTo` widens every edge and nothing fails. A source-level test is small. |
| 9 | `NU1900` fails restore when the feed is down (edge hunter) | low | reject | Fails closed and loudly, which is right for a security gate. Restore needs the network anyway. |
| 10 | `1 critical` assertion is brittle (edge hunter, blind) | low | patch | It breaks on a second advisory and matches `21 critical`. Direct correction. |
| 11 | Constructor failure leaks a temp copy (edge hunter) | low | reject | Rare, and limited to a temp folder. |
| 12 | Composition path never runs in a test (gap, blind) | medium | patch | No input reaches the dashed arrow or the `composition ` replace. Filed pre-verified. |
| 13 | Install-script block is untested (gap, blind) | medium | patch | Both pnpm tests pass the flag themselves, so deleting `ignoreScripts` fails nothing. Filed pre-verified. |
| 14 | Per-project framework, version, CPM and warning overrides are unchecked (gap) | medium | patch | Setting `TreatWarningsAsErrors` false on one project removes its audit gate unnoticed. Filed pre-verified. |
| 15 | Lockfile and audit tests don't run `ci.yml` (gap) | medium | defer | Needs a GitHub remote, which doesn't exist. Filed pre-verified. |
| 16 | `VersionOverride` bypasses CPM (blind) | medium | patch | `CentralPackageVersionOverrideEnabled` is unset. One-line fix for an Always rule. |
| 17 | No `CentralPackageTransitivePinningEnabled` (blind) | low | reject | No vulnerable transitive exists; enable it when one needs pinning. |
| 18 | Advisory tests have no trait and depend on live feeds (blind, gap) | low | reject | Fails loudly, and restore depends on the feed regardless. Withdrawal of these old advisories is unlikely. |
| 19 | No scheduled audit (blind) | low | reject | NFR-7 scans on release and the story scans on PR. This is an addition, not a correction. |
| 20 | `Pnpm_lockfile_drift` asserts loosely (blind) | low | patch | Asserting `ERR_PNPM_OUTDATED_LOCKFILE` is a direct correction. |
| 21 | Node and pnpm pins only warn (blind) | low | patch | `engines` isn't strict, against "one toolchain for every clone". One-line setting. |
| 22 | `Gatekeep.slnx` membership is unchecked (blind) | medium | patch | CI builds only the solution, so an unlisted csproj escapes GK0001. |
| 23 | Module folders and edge-free modules are unchecked (blind) | low | reject | All modules have edges and folders today. New guards would be needed. |
| 24 | Workspace graph isn't exercised (blind) | low | reject | Compiling is all the acceptance criteria ask; Stories 1.13 onward add the links. |
| 25 | Version is duplicated by hand (blind) | low | reject | All equal today; needs a new check, better placed with the release gates. |
| 26 | `.gitignore` misses secrets and tool output (blind) | medium | patch | `.env*`, `*.pem` and `*.pfx` aren't ignored in a project that forbids secrets in git. |
| 27 | No `.gitattributes`, `.editorconfig` or README (blind) | low | reject | Line endings are normalised and tests pass; install docs are Story 1.12. |
| 28 | Generator resolves the root from the current directory (blind) | low | reject | Fails loudly, and the documented command runs from the repo root. |
| 29 | Placeholder comments read "a Admins" (blind) | low | patch | Direct text correction. |
| 30 | Edge list isn't tied to the spine diagram by a test (gap) | low | reject | They match today; the spine is a planning document outside the build. |

## Design Notes

- **One project per module.** The story says twelve module projects, so layers are folders. Core types stay `internal`, and Contracts are `public`, so an edge exposes only the contract.
- **`composition` edges.** AD-1 lets a composition root reference a module's adapter registration, which a `ProjectReference` can't tell apart from normal use. These edges are listed explicitly, are drawn dashed, and start empty; a later story adds each one it needs.
- **Deferred to the stories that need them:** `src/Adapters/*`, `deploy/`, `tests/{Isolation,Protocol,Flows}`, and layer checks inside a module.
- **Known discrepancy:** a planning review says Admins depends on Tenancy, but the spine diagram has no such edge. The diagram wins here; the story that needs it adds the edge.

## Verification

**Commands:**
- `dotnet restore --locked-mode && dotnet build Gatekeep.slnx` -- expected: success, no warnings.
- `dotnet test tests/Architecture` -- expected: all pass.
- `pnpm install --frozen-lockfile --ignore-scripts && pnpm -r build` -- expected: success.
- Temporarily add an unlisted `ProjectReference`, then build -- expected: failure naming the edge; revert.
- Temporarily add a package with a critical advisory, then run the CI audit -- expected: failure; revert.
