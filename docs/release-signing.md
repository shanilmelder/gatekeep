# Release signing

How a Gatekeep release is built, signed and published, and how Esm runs the signing side (Story 12.5, AD-25, NFR-7). The Operator's side, checking a release before deploying it, is in `docs/install.md`, "Install a signed release".

## What it guarantees

Every release image is built in CI, ships with an SPDX SBOM, is signed by a key that exists only inside Esm's YubiKey, and is deployed by digest. A Docker host checks each digest against the public key pinned in its own `deploy/trust/` directory before it runs anything. No transparency log is involved: the pinned key is the only root of trust, so checking needs no Sigstore service.

The release workflow, `.github/workflows/release.yml`, runs on a pushed `v*` tag and has two jobs.

| Job | Runs on | Holds | Does |
| --- | --- | --- | --- |
| `build` | GitHub-hosted | A read-only token. No secret, no environment, no registry login | Runs the gates (the tests container and the stack check), then `deploy/release/build.sh` in the `release-tools` image: each release image as an OCI archive, `<svc>.tar`, its SBOM, `<svc>.spdx.json`, and `digests.txt`. Uploads them as the `release-dist` workflow artifact |
| `sign` | Esm's signing machine, label `gatekeep-signing` | `contents: write` and `packages: write`, behind the `release-signing` environment, which waits for Esm's approval | Checks out the tag for `deploy/release/publish.sh` alone and downloads the artifact. Pushes each archive to GHCR, checks each pushed digest against `digests.txt`, signs each digest (bound to its service and the release tag) and attests its SBOM with the YubiKey, writes `release.env`, and creates or updates the GitHub release with `release.env`, `digests.txt` and the SBOMs |

The `build` job runs third-party code: the NuGet and pnpm restores, buildx and syft. That's why it gets nothing worth stealing, and why the `sign` job never runs anything it produced. The archives are only pushed byte for byte. Comparing each pushed digest with `digests.txt` is a transfer-integrity check: it catches a push that changed the bytes, not a tampered build, since the archives and `digests.txt` both come from the `build` job.

The release images are every service `deploy/compose.yaml` builds (`hosted`, `admin`, `worker`, `caddy`, `cli`, `openbao`) and `release-tools`, which runs the check on the Docker host. Each is `ghcr.io/<owner>/gatekeep-<svc>`. `ReleaseConfigTests` fails if a new service is built without being released.

`publish.sh` refuses a signing key that isn't hardware: `GATEKEEP_SIGNING_KEY` must be `sk` (the YubiKey's PIV signature slot), `sk:<slot>`, or a `pkcs11:` URI. It also refuses, before pushing anything, a cosign other than v2.6.5 or a crane other than v0.22.1, a tag that isn't `vX.Y.Z` or `vX.Y.Z-<pre-release>`, and a `digests.txt` that doesn't name every release image. Each signature carries `org.gatekeep.service=<svc>` and `org.gatekeep.release=<tag>`, so `release-verify` refuses a signed image in another service's slot and images from two releases. A key file is accepted only by the CI rehearsal (`deploy/ci/release-check.sh`), which runs the same scripts with a throwaway key against a local registry.

## The signing machine

A machine Esm controls and uses for nothing else of consequence. It holds no private key: the key is generated inside the YubiKey and can't be read out. It needs:

- a YubiKey 5 series with PIV, and the PC/SC daemon (`pcscd`) running;
- cosign **2.6.5, the pivkey build** (`cosign-linux-pivkey-pkcs11key-amd64` from the cosign release; check it against its published signature before use). The plain build can't reach a YubiKey;
- crane 0.22.1, the GitHub CLI (`gh`), Git, and Docker, for `docker login` and the final check with `release-verify`;
- the GitHub Actions runner, registered to this repository only.

### Generate the signing key on the YubiKey

Once, on a new or reset YubiKey. Choose a new PIN and PUK and keep them offline with the other escrowed material (`docs/key-custody.md`). The management key is random and discarded.

```sh
cosign piv-tool reset
cosign piv-tool set-pin
cosign piv-tool set-puk
cosign piv-tool generate-key --random-management-key=true --pin-policy=never --touch-policy=always
```

`--touch-policy=always` means the YubiKey signs nothing until Esm touches it, once per signature. `--pin-policy=never` keeps the PIN out of the runner entirely: no PIN is ever in an environment variable, a CI secret or a file. Physical touch is the per-signature control, and the GitHub approval is the per-release control.

Keep the attestation, which shows the key was generated on the device and never imported:

```sh
cosign piv-tool attestation --output release-signing.attestation
```

### Export the public key

```sh
cosign public-key --sk --outfile release-signing.pub
```

This file is public, but isn't committed: it travels to each Docker host by a channel other than the release itself (see "Pin the key on a Docker host").

### Register the runner

Register a runner for this repository only, with the label `gatekeep-signing`, from the repository's **Settings, Actions, Runners, New self-hosted runner** page, which gives the token. Run it in the foreground, only while a release is being signed, as an unprivileged user:

```sh
./config.sh --url https://github.com/<owner>/gatekeep --token <token> --labels gatekeep-signing --no-default-labels
./run.sh
```

Stop it (Ctrl-C) when the release is published, and unplug the YubiKey. A runner that isn't running can't pick up a job, so a workflow from a pull request that names `gatekeep-signing` waits rather than runs. Also set, in **Settings, Actions, General**: workflows from forks need approval for every outside contributor.

### Set up the environment and variable

- **Settings, Environments, `release-signing`**: Esm as the required reviewer, "Prevent self-review" off (Esm cuts and approves releases), and deployment branches and tags limited to the tag rule `v*`.
- **Settings, Rules**: a tag ruleset on `v*` that only Esm can create, update or delete.
- **Settings, Secrets and variables, Actions, Variables**: `GATEKEEP_SIGNING_KEY` = `sk`. It's a variable, not a secret, because it names hardware and holds nothing secret.

## Cut a release

1. Tag the release commit on `main` and push the tag. A signed tag is preferred.

   ```sh
   git tag -s v1.2.3 -m "Gatekeep v1.2.3"
   git push origin v1.2.3
   ```

2. Wait for the `build` job to pass. It runs every gate first, so a failing gate stops the release before any image exists.
3. Start the runner on the signing machine, plug in the YubiKey, and approve the `sign` job in the run's page (the `release-signing` environment).
   The artifact is kept for 7 days, so approve within 7 days of the build, or the `sign` job has nothing to sign.
4. Touch the YubiKey each time it blinks: two touches per image, one for the signature and one for the SBOM attestation, fourteen in all.
5. Check the GitHub release has `release.env`, `digests.txt` and one `.spdx.json` per image, then stop the runner and unplug the YubiKey.
6. **First release only:** in the repository's **Packages**, make each `gatekeep-<svc>` package public and link it to this repository. Packages pushed with the job's token start private, so a Docker host can't pull the images or their signatures until then.
7. Check every image in `release.env`, its signature and its SBOM attestation, against the exported key, by running `release-verify` from the signing machine's checkout of the tag, with the exported key as the pinned key:

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.release.yaml --env-file release.env --profile release run --rm release-verify
   ```

   Run it with `GATEKEEP_TRUST_DIR` set to the absolute path of the directory holding the exported `release-signing.pub`, and `release.env` downloaded from the release. It must end with `every image is signed by the pinned key`.

If `publish.sh` stops on a digest that differs from `digests.txt`, nothing was signed. It means the push changed the bytes. It doesn't show the build was sound, which no step here proves.

### A sign job that fails partway

Re-run **only the `sign` job** from the run's page, while the build's artifact still exists (7 days). It pushes the same archives, gets the same digests and signs them again, which is harmless: a second signature by the same key for the same release changes nothing. The publish step updates an existing GitHub release rather than failing on it.

Never re-run the whole workflow for a tag. That rebuilds every image to new digests and moves the release's registry tags to them, so the first images and the new ones are both signed for the same tag. If the artifact has expired, cut a new tag instead.

## Pin the key on a Docker host

Copy `release-signing.pub` to `deploy/trust/release-signing.pub` on the Docker host by hand, never from the release page, and compare its SHA-256 with the one shown on the signing machine:

```sh
docker run --rm -v ./deploy/trust:/trust:ro busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec sha256sum /trust/release-signing.pub
```

`deploy/trust/` is a host directory, like the secrets directory: never a Docker volume, never committed (`.gitignore`), never in an image (`.dockerignore`), and mounted read-only into `release-verify` only. `GATEKEEP_TRUST_DIR` moves it; a relative value is resolved against `deploy/`.

## A lost or replaced key

The private key can't be backed up, by design. If the YubiKey is lost, broken or suspected compromised, generate a new key on a new YubiKey, export its public key, pin it on every Docker host by hand, and cut a new release. Releases signed by the old key no longer verify on a host that pins the new one. With `--pin-policy=never`, whoever holds the YubiKey can sign with a touch, so replace the pinned key on every Docker host at once.
