---
name: validate-bundle
description: Use immediately after `./make-dist.sh` to verify the standalone bundle is shippable. Runs structural checks (no dev data leak, no retired falcon-extras files, native binaries absent, eyas-mcp wheels staged, BUILD-INFO matches package.json) and an optional smoke-boot. Trigger phrases: "validate the bundle", "is the zip shippable", "check make-dist output", "verify the standalone build".
---

# validate-bundle

Catches the failure modes we've hit on real ship days. Each check below maps to a specific bug we've already paid for.

## Run

```bash
bash .claude/skills/validate-bundle/run.sh
```

That script auto-locates the most recent `project-eyas-v*.zip` in the repo root, runs every check below, and exits non-zero on any failure.

To target a specific bundle:
```bash
bash .claude/skills/validate-bundle/run.sh path/to/project-eyas-vX.Y.Z.zip
```

## Checks performed

### Structural (fatal on miss)

1. **No dev `data/` leak.** `unzip -l` must NOT show `project-eyas-vX/data/auth.json`, `data/cost-log.jsonl`, `data/perf-log.jsonl`, or `data/dev.log`. Next.js NFT tracing previously copied the dev host's `data/` into the standalone tree; recipients then saw the dev's password hash + cost log. `make-dist.sh` scrubs `$STAGE/data` — this check verifies the scrub.
2. **No retired `falcon-extras/` files or `vendor/falcon-extras-wheels/`.** The sidecar was removed; every Eyas tool runs in-process. Anything under those paths means a stale staging step crept back into `make-dist.sh`.
3. **No platform-specific native bindings.** Anything matching `*.node` (e.g. `@node-rs/argon2-linux-x64-gnu/argon2.linux-x64-gnu.node`) means a native module slipped back into the bundle. We migrated off `@node-rs/argon2` to `crypto.scrypt` to avoid this; if a `.node` file appears, a new dep brought a native binding back.
5. **eyas-mcp wheels staged.** `vendor/falcon-mcp-wheels/` must contain at least one `.whl`. Without wheels the recipient's offline install path falls back to PyPI, which corp-blocked networks can't reach.
6. **`BUILD-INFO.txt` and `build-info.json` present and consistent.** Both must exist; `build-info.json.appVersion` must equal `package.json.version`. Catches version drift after a forgotten `npm version` bump.
7. **`server.js` at bundle root.** The bundle's entrypoint. Without it, `start.sh` errors with the "may be corrupt" message.
8. **`start.sh` is executable** (mode bit set in zip).

### Smoke-boot (skippable)

Beyond structural checks, the only definitive proof the bundle works is launching it. The skill optionally:

1. Extracts the zip to a `/tmp/<bundle-name>-validate-$$/` dir.
2. Writes a minimal `.env` containing only `AUTH_SESSION_SECRET=<random>` (no real Falcon/Anthropic creds — the bundle now supports running with empty credentials, deferring config to `/register`).
3. Starts `node server.js` in the background.
4. Polls `http://127.0.0.1:<port>/api/health` until 200 (timeout 60s).
5. Asserts `/login` and `/register` both render (HTTP 200, contains "CrowdStrike — For Internal Use Only" classification banner copy).
6. Kills the process, removes the temp dir.

Pass this stage (`SKIP_BOOT=0`, the default) only after the structural checks all pass — there's no point booting a bundle that's missing files.

To skip boot (faster, structural-only): `SKIP_BOOT=1 bash .claude/skills/validate-bundle/run.sh`.

## Pass criteria

All structural checks ✓. If boot enabled, `/api/health` returned 200 within 60s and `/login` + `/register` both rendered.

## Fail handling

| Check | Likely cause | Fix |
|---|---|---|
| `data/` leak | NFT trace re-copying the dev tree's data dir | Re-check `make-dist.sh` has `rm -rf "$STAGE/data"` after the standalone copy |
| Retired `falcon-extras` files present | A sidecar staging step was restored in `make-dist.sh` | Remove it; nothing under `falcon-extras/` ships |
| Native `.node` file | New dep with a per-platform binary | Replace with a JS / WASM equivalent (cross-platform standalone is the constraint; see auth scrypt migration as precedent) |
| Wheels missing | Build host doesn't have python3, or PyPI was unreachable during build | Re-run on a host with PyPI access; the warning is in `make-dist.sh` stderr |
| `BUILD-INFO.txt` version drift | `npm version` bump didn't happen, or `versions.json` wasn't updated | Bump appropriately and rebuild |
| Boot fails on `/api/health` | Bundle is structurally sound but server crashes on startup | Read `node server.js` stderr from the temp dir; common cause is a missing optional dep |
