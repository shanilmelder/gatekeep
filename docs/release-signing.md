# Release signing

How a Gatekeep release is built, signed and published, and how Esm runs the signing side (Story 12.5, AD-25, NFR-7). The Operator's side, checking a release before deploying it, is in `docs/install.md`, "Install a signed release".

## What it guarantees

Every release image is built in CI, ships with an SPDX SBOM, is signed by an encrypted cosign key that only the `sign` job of a `v*` tag receives, and is deployed by digest. A Docker host checks each digest against the public key pinned in its own `deploy/trust/` directory before it runs anything. No transparency log is involved: the pinned key is the only root of trust, so checking needs no Sigstore service.

The release workflow, `.github/workflows/release.yml`, runs on a pushed `v*` tag and has two jobs, each on its own fresh GitHub-hosted runner (`ubuntu-latest`), so the machine that signs never ran anything the build ran.

| Job | Runs on | Holds | Does |
| --- | --- | --- | --- |
| `build` | `ubuntu-latest` | A read-only token. No secret, no environment, no registry login | Runs the gates (the tests container and the stack check), then `deploy/release/build.sh` in the `release-tools` image: each release image as an OCI archive, `<svc>.tar`, its SBOM, `<svc>.spdx.json`, and `digests.txt`. Uploads them as the `release-dist` workflow artifact |
| `sign` | `ubuntu-latest`, a fresh runner of its own | `contents: write` and `packages: write`, behind the `release-signing` environment, which only a `v*` tag can deploy to. No approval: it starts as soon as `build` passes. The environment's secrets `COSIGN_PRIVATE_KEY` and `COSIGN_PASSWORD`, in the signing step's environment only | Checks out the tag for `deploy/release/publish.sh` alone and downloads the artifact. Pushes each archive to GHCR, checks each pushed digest against `digests.txt`, signs each digest (bound to its service and the release tag) and attests its SBOM with the cosign key, writes `release.env`, and creates or updates the GitHub release with `release.env`, `digests.txt` and the SBOMs |

The `build` job runs third-party code: the NuGet and pnpm restores, buildx and syft. That's why it gets nothing worth stealing, and why the `sign` job never runs anything it produced. The archives are only pushed byte for byte. Comparing each pushed digest with `digests.txt` is a transfer-integrity check: it catches a push that changed the bytes, not a tampered build, since the archives and `digests.txt` both come from the `build` job.

The release images are every service `deploy/compose.yaml` builds (`hosted`, `admin`, `worker`, `caddy`, `cli`, `openbao`) and `release-tools`, which runs the check on the Docker host. Each is `ghcr.io/<owner>/gatekeep-<svc>`. `ReleaseConfigTests` fails if a new service is built without being released.

`publish.sh` takes the key by reference only. The `sign` job sets `GATEKEEP_SIGNING_KEY` to `env://COSIGN_PRIVATE_KEY`, and `publish.sh` refuses it if `COSIGN_PRIVATE_KEY` or `COSIGN_PASSWORD` is empty, so an unencrypted key is never used. It still accepts a hardware key (`sk`, `sk:<slot>` or a `pkcs11:` URI), and refuses a key file or any other `env://` variable. It also refuses, before pushing anything, a cosign other than v2.6.5 or a crane other than v0.22.1, a tag that isn't `vX.Y.Z` or `vX.Y.Z-<pre-release>`, and a `digests.txt` that doesn't name every release image. Each signature carries `org.gatekeep.service=<svc>` and `org.gatekeep.release=<tag>`, so `release-verify` refuses a signed image in another service's slot and images from two releases. A key file is accepted only by the CI rehearsal (`deploy/ci/release-check.sh`), which runs the same scripts with a throwaway key against a local registry.

## The signing machine

A fresh GitHub-hosted runner for each `sign` job, discarded when the job ends. Nothing persists on it between releases, and it never ran the `build` job's third-party code. It holds no private key at rest: the key and its password are secrets of the `release-signing` environment, which GitHub hands only to the `sign` job of a `v*` tag, and only to its signing step, as environment variables. Nothing writes them to disk.

The job installs cosign **2.6.5** and crane **0.22.1** itself, in the step "Install the pinned cosign and crane": it copies each binary out of the same upstream image, by the same digest, that `deploy/docker/release-tools.Dockerfile` builds from, so the release and the CI rehearsal sign with the same binaries. `publish.sh` refuses any other version, and `ReleaseConfigTests.Sign_job_installs_the_cosign_and_crane_the_release_tools_image_pins` fails if the workflow and the Dockerfile drift apart. The runner image already has the GitHub CLI (`gh`), Git and Docker, for `docker login` and the final check with `release-verify`.

**What this relies on.** GitHub's hosted runner isolation, and the `release-signing` environment's `v*` tag rule, which decides when the key is handed out. A YubiKey on a machine used for nothing else is still the stronger setup: `publish.sh` still accepts `sk`.

### Generate the signing key

Once, on a trusted machine, never a CI runner. Choose a long random password and keep it, and a copy of `cosign.key`, offline with the other escrowed material (`docs/key-custody.md`).

```sh
cosign generate-key-pair
```

It writes `cosign.key`, the private key encrypted with the password, and `cosign.pub`. Store both secrets on the environment, never at repository level, then delete the local `cosign.key` once the escrowed copy is safe:

```sh
gh secret set COSIGN_PRIVATE_KEY --env release-signing < cosign.key
gh secret set COSIGN_PASSWORD --env release-signing
```

### Export the public key

```sh
cosign public-key --key cosign.key --outfile release-signing.pub
```

Or rename `cosign.pub` to `release-signing.pub`. This file is public, but isn't committed: it travels to each Docker host by a channel other than the release itself (see "Pin the key on a Docker host").

### Restrict outside contributors

In **Settings, Actions, General**: workflows from forks need approval for every outside contributor. A fork's pull request never gets the signing key either way, since the secrets belong to the `release-signing` environment, which only a `v*` tag can deploy to.

### Set up the environment

- **Settings, Environments, `release-signing`**: deployment branches and tags limited to the tag rule `v*`, and the secrets `COSIGN_PRIVATE_KEY` and `COSIGN_PASSWORD`.

There is no required reviewer: Esm accepted that **pushing a `v*` tag is the approval**. GitHub offers required reviewers on public repositories, so one can be added on the environment if that changes. The `sign` job signs and publishes as soon as `build` passes, with no step in between. Whoever can push a `v*` tag can publish a signed release, which is why the tag ruleset below matters.

- **Settings, Rules**: a tag ruleset on `v*` that only Esm can create, update or delete.

## Cut a release

1. Tag the release commit on `main` and push the tag. A signed tag is preferred. Pushing the tag publishes the release, with nothing asking again, so check the commit first.

   ```sh
   git tag -s v1.2.3 -m "Gatekeep v1.2.3"
   git push origin v1.2.3
   ```

2. Wait for the `build` job to pass. It runs every gate first, so a failing gate stops the release before any image exists.
3. The `sign` job then runs on its own, with no approval step.
4. Check the GitHub release has `release.env`, `digests.txt` and one `.spdx.json` per image.
5. **First release only:** in the repository's **Packages**, make each `gatekeep-<svc>` package public and link it to this repository. Packages pushed with the job's token start private, so a Docker host can't pull the images or their signatures until then.
6. Check every image in `release.env`, its signature and its SBOM attestation, against the exported key, by running `release-verify` from a checkout of the tag, with the exported key as the pinned key:

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.release.yaml --env-file release.env --profile release run --rm release-verify
   ```

   Run it with `GATEKEEP_TRUST_DIR` set to the absolute path of the directory holding the exported `release-signing.pub`, and `release.env` downloaded from the release. It must end with `every image is signed by the pinned key`.

If `publish.sh` stops on a digest that differs from `digests.txt`, nothing was signed. It means the push changed the bytes. It doesn't show the build was sound, which no step here proves.

### A sign job that fails partway

Re-run **only the `sign` job** from the run's page, while the build's artifact still exists (7 days). It pushes the same archives, gets the same digests and signs them again, which is harmless: a second signature by the same key for the same release changes nothing. The publish step updates an existing GitHub release rather than failing on it.

Never re-run the whole workflow for a tag. That rebuilds every image to new digests and moves the release's registry tags to them, so the first images and the new ones are both signed for the same tag. If the artifact has expired, cut a new tag instead.

## Pin the key on a Docker host

Copy `release-signing.pub` to `deploy/trust/release-signing.pub` on the Docker host by hand, never from the release page, and compare its SHA-256 with the one shown on the machine that generated the key:

```sh
docker run --rm -v ./deploy/trust:/trust:ro busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec sha256sum /trust/release-signing.pub
```

`deploy/trust/` is a host directory, like the secrets directory: never a Docker volume, never committed (`.gitignore`), never in an image (`.dockerignore`), and mounted read-only into `release-verify` only. `GATEKEEP_TRUST_DIR` moves it; a relative value is resolved against `deploy/`.

## A lost or replaced key

If the key or its password may have leaked (the repository or a runner compromised, a secret exposed), treat every release since as suspect: generate a new key pair, replace both secrets, pin the new public key on every Docker host by hand, and cut a new release. Releases signed by the old key no longer verify on a host that pins the new one. Replace the pinned key on every Docker host at once, since whoever has the old key and password can sign until then. If only the secrets were lost, restore them from the escrowed copy.
