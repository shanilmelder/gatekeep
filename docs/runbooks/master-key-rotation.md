# Master Key rotation

How the Operator replaces the Master Key, OpenBao's static seal key, with a new generation (Story 12.7, AD-10, NFR-3). Users and Tenants do nothing: sign-in keeps working throughout, and every Signing Key, ciphertext, HMAC and wrapped key made before the rotation still verifies, decrypts, matches or unwraps afterwards. Every command is a `docker` command, run from the repository root, with the same `GATEKEEP_SECRETS_DIR` as the install (`docs/install.md`). `docs/key-custody.md` has the custody setup this builds on.

This runbook never holds a key, recovery share or token, and nor may any note, ticket or chat about a rotation.

## When to rotate

- **A suspected exposure** of the Master Key, its escrow copies, the secrets directory or a host with Docker access (T-29, T-30). Rotate as soon as the host is trusted again: a rotation run by an intruder who still has Docker access protects nothing.
- **Someone with access leaves**, or an escrow drive goes missing.
- **On a schedule** you choose. Nothing in Gatekeep requires one.

A rotation doesn't replace the recovery shares (`gatekeep rekey`, Story 13.4, will), and it doesn't make an old snapshot unreadable: a snapshot taken before the rotation still opens with the generation it was taken under. That's why every generation stays escrowed until the last backup that needs it has expired (see "Escrow and retirement").

## What it does

| Step | Service | Result |
| --- | --- | --- |
| 1. `prepare` | `master-key-rotate` | Generation N (`master/master-key` and `master/master-key-id`) moves to `master/previous/`; generation N+1 is written in its place |
| 2. Rotation mode | `openbao` with `deploy/compose.rotate.yaml` | OpenBao gets both generations, unseals, and re-wraps its root key under N+1. Only in this mode does its socket answer the unauthenticated generate-root endpoints |
| 3. Root key | `master-key-rotate-root` | With 3 of the 5 recovery shares it makes a short-lived root token, rotates OpenBao's root key and starts a new barrier keyring term, then revokes the token. Generation N and a snapshot taken under it no longer open anything written after this |
| 4. Base mode | `openbao` | OpenBao restarts on generation N+1 alone, with unauthenticated generate-root off again |
| 5. `finish` | `master-key-rotate` | The online copy of generation N is shredded |
| 6. Transit keys | `cli rotate-transit-keys` | Every `dep-email`, `dep-payload` and Tenant `totp`, `social`, `email`, `payload` and `tpk` key gains a new version, so values written from now on are under versions no earlier snapshot holds |

Step 6 leaves HMAC keys (`hmac-*`, `dep-hmac`) alone, since a new version would stop every stored HMAC matching (T-54), and leaves Signing and Management keys and `dep-records` to their own lifecycle (Epic 9). Older Transit versions stay decryptable: nothing is re-encrypted (G-16).

## Before you start

- **The recovery shares**: at least 3 of the 5 from `openbao-init.json` on the escrow drives. You type them at a prompt in step 3, so have them where you can read them without attaching an escrow drive to the Docker host.
- **Both escrow drives**, to store generation N+1 at step 1, apart from backups.
- **A healthy stack**: every service healthy, and `audit verify` clean.

  ```sh
  docker compose -f deploy/compose.yaml ps
  docker compose -f deploy/compose.yaml run --rm cli audit verify
  ```

- **The images built** for the release you run. The rotation services run from the OpenBao image, so the install's build covers them:

  ```sh
  docker compose -f deploy/compose.yaml --profile tools --profile setup build
  ```

  A Deployment installed from a signed release builds nothing: it adds `-f deploy/compose.release.yaml --env-file deploy/release.env` after the other files in every command here, as `docs/install.md` shows, and the rotation services then run the release's OpenBao image by its digest. They never pull an image.

The hosts keep running throughout. Each OpenBao restart makes `/healthz` answer `503 unhealthy: custody` for a few seconds, and requests that need custody fail until it's back.

## Steps

1. **Prepare.** It refuses while `master/previous/` holds anything, so a rotation can't start over one that hasn't finished. It prints the two generation numbers and the escrow label.

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.rotate.yaml run --rm master-key-rotate prepare
   ```

2. **Escrow the new generation** now, before anything is sealed with it: copy `master/master-key` from the secrets directory to both offline drives under the label `prepare` printed, `master-key-gen<N+1>-<UTC date>`, and check each copy's SHA-256 by eye, as in `docs/key-custody.md`, step 3. Don't go on until both copies are made.

3. **Start OpenBao in rotation mode.** Compose recreates it with both generations. It's healthy once it has unsealed.

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.rotate.yaml up -d --wait openbao
   ```

4. **Rotate the root key.** It refuses, before asking for a share, unless OpenBao is in rotation mode. Type each recovery share at its prompt; nothing you type is echoed. It prints only the new key term.

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.rotate.yaml run --rm master-key-rotate-root
   ```

   With no terminal (`-T`), it reads the shares from standard input instead, as `openbao-init.json` or one per line. The stack check's rehearsal does this; on a Deployment, prefer the prompt.

5. **Restart OpenBao in base mode**, on the new generation alone:

   ```sh
   docker compose -f deploy/compose.yaml up -d --wait openbao
   ```

6. **Finish.** It refuses unless the root-key step has run since `prepare` (it leaves a marker, holding only the new key term, on the `openbao-socket` volume) and OpenBao is unsealed and out of rotation mode, then shreds `master/previous/` and removes the marker. On an encrypted disk this removes the only online copy; `shred` can't promise more on a journaling or copy-on-write file system.

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.rotate.yaml run --rm master-key-rotate finish
   ```

7. **Rotate the Transit keys.** It prints counts only. A key that doesn't exist is skipped; any other failure names the key and stops. Running it again only adds another version.

   ```sh
   docker compose -f deploy/compose.yaml run --rm cli rotate-transit-keys
   ```

8. **Check.** Every service healthy, and every chain intact:

   ```sh
   docker compose -f deploy/compose.yaml up -d --wait
   docker compose -f deploy/compose.yaml run --rm cli audit verify
   ```

## Escrow and retirement

- **Label every generation** `master-key-gen<N>-<UTC date>`, the label `prepare` prints, and keep the recovery shares beside the generations they serve. A rotation doesn't change the shares.
- **Keep generation N escrowed until the last backup taken before this rotation has expired.** Only generation N opens those backups: `finish` prints this rule. Write down the rotation's date with the escrow copies, so you can tell when that is.
- **Then destroy both copies of generation N.** Until then, anyone holding generation N and one of those backups can read that backup.
- **Never in a backup.** The escrow drives and the secrets directory stay apart from every backup set.

## If a step fails

- **`prepare` refuses** because `master/previous/` holds something: a rotation is under way. If it's yours, carry on from wherever it stopped. If `prepare` itself failed partway, it says so: it puts generation N back where it was unless it reports it couldn't.
- **`prepare` was killed partway**, leaving `master/` without `master-key` or `master-key-id` and generation N in `master/previous/`: move `previous/`'s two files back into `master/`, then run step 1 again. Generation N+1 was never written, or never used, so nothing is lost.

  ```sh
  docker compose -f deploy/compose.yaml run --rm --entrypoint sh keygen -c 'rm -f /secrets/master-key /secrets/master-key-id && mv /secrets/previous/master-key /secrets/previous/master-key-id /secrets/ && chmod 0444 /secrets/master-key-id'
  ```

- **OpenBao won't start in rotation mode**, and its log starts `start-openbao: refusing to start:`: it names the file it refused, for example a key ID that isn't one generation above the previous. Fix that file and run step 3 again. Before step 3 has ever unsealed, you can abandon the rotation instead: put `master/previous/`'s two files back in `master/` (replacing generation N+1) and start OpenBao in base mode.
- **After rotation mode has unsealed, only go forward.** OpenBao's root key is wrapped under generation N+1 from then on, so generation N alone no longer starts it. Rotation mode (both generations) and base mode (N+1) both work.
- **The root step refuses a share**, or too few were given: no token was made and nothing rotated. Run step 4 again with the right shares.
- **The root step says it couldn't revoke the root token**: run step 4 again. Each run revokes every other root token it finds, and warns when it does.
- **The root step fails after rotating the root key** but not the keyring: run step 4 again. Each run rotates both, so running it twice is harmless.
- **OpenBao stays sealed in base mode** (step 5): it's not yet on generation N+1 alone. Run step 3, then step 5 again.
- **`finish` says the root-key step hasn't run since `prepare`**: steps 3 and 4 were skipped, or step 4 failed. Run step 3, step 4 and step 5, then `finish` again. Shredding generation N before then could leave OpenBao's root key unrotated, or still wrapped only under generation N.
- **`finish` refuses** for any other reason: OpenBao is sealed, unreachable or still in rotation mode, or it couldn't tell. Run step 5, then `finish` again. Generation N stays in `master/previous/` until it succeeds.
- **`rotate-transit-keys` fails**: it names the key and the failure. Fix the cause, then run it again.
- **Generation N+1 is lost** before `finish`: restore it from escrow into `master/master-key`, with `gatekeep-master-<N+1>` in `master/master-key-id`. After `finish`, restore from escrow the same way.

## Rehearsal record

The stack check (`deploy/ci/stack-check.sh`) rehearses the whole rotation on a fresh install: every step above with the stack's own recovery shares, the key search for both generations during the window, the refusals of a second `prepare` and of the root step outside rotation mode, every service healthy and `/healthz` 200 afterwards, and generation 1 alone, with its own ID, staying sealed.

| Date | Environment | Commit | Result |
| --- | --- | --- | --- |
| 2026-11-05 | Docker Desktop Linux VM | `feature/12-7-rotate-the-master-key`, uncommitted work on `c68541d` | Passed: `deploy/ci/stack-check.sh` ended `rotation rehearsal passed` and `passed`. The first run failed at `finish` (`shred` refused the `0400` file on the Docker Desktop bind mount), which `finish` now fixes by making the file writable first |
