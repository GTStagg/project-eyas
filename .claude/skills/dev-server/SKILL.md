---
name: dev-server
description: Use whenever you're about to start, restart, or kill the Next.js dev server, or whenever the dev server is "acting weird" (404s on routes that exist, broken UI after a code change, port conflicts, HMR not picking up edits, two dev servers fighting). Catches the stray-process + corrupt-.next + competing-instance failure modes that produce these symptoms. Trigger phrases include "restart the dev server", "kill stray dev servers", "clean dev boot", "the dev server is broken", "/config 404", "fresh dev restart", "is the dev server clean", "why is HMR weird".
---

# dev-server

The Next.js dev server has three failure modes that look like "code is broken" but are actually environment problems. Each maps to a specific symptom and a specific fix. **Run this skill any time you're about to monkey with the dev server, or any time symptoms below show up.**

## Symptoms → diagnosis → fix

| Symptom | Likely cause | Fix |
|---|---|---|
| `/config` returns 404 but the file exists | Two `next-server` processes trampling the same `.next` | Kill all + clear `.next` + start one |
| Broken UI on `/` after a code change | Same as above, or HMR partial-write | Same |
| "Port 3000 is in use, using 3001 instead" in dev output | A previous `next-server` is still alive on 3000 | Kill the stray, restart on 3000 |
| HMR didn't pick up an edit | Stale build cache from a crashed prior session | Clear `.next`, restart |
| `lsof -ti :3000` returns nothing but you can't bind to 3000 | lsof's view is incomplete (different uid, namespace, or `/proc` lookup miss) | Use `pkill -f`, not `lsof \| kill` |

## The procedure

Always: **list → kill → verify dead → clear `.next` → start → confirm single**.

Don't skip steps. The mistake that produces all the symptoms above is killing one server while another is still running, then starting a third — three competing processes compile in parallel against the same `.next` directory and corrupt it.

## Run

```bash
bash .claude/skills/dev-server/clean-restart.sh
```

That script does the full sequence: kills every `next-server` / `next dev` process owned by you, verifies port 3000 is free, clears `.next`, starts one new dev server in the background, and confirms exactly one server is now running. It refuses to start a new server if a kill failed (so you can investigate instead of compounding the mess).

Flags:
- `KEEP_NEXT=1` — skip the `rm -rf .next` step (faster, but only safe when you're sure the cache isn't corrupt)
- `NO_START=1` — kill + clear only, don't start a new server (use when you're about to run `make-dist.sh` and need a clean tree)
- `PORT=3001` — target a non-default port

## Manual checks (use when the script's behavior is wrong)

```bash
# What's running
ps aux | grep -E "next-server|next dev" | grep -v grep

# Kill them all (don't rely on lsof for this)
pkill -f "next-server"
pkill -f "next dev"

# Confirm dead — wait 2s then re-check
sleep 2 && ps aux | grep -E "next-server|next dev" | grep -v grep

# Hard kill if any survived
pkill -9 -f "next-server"
pkill -9 -f "next dev"

# Clear build cache
rm -rf .next

# Start one
npm run dev
```

## Why `lsof -ti :3000 | xargs kill` is unreliable

It looks correct and is the obvious incantation, but:

1. `lsof` can return empty if the process is in a different namespace, owned by a different uid, or `/proc` is in a weird state — `kill` then gets no PIDs and silently no-ops while the server keeps running.
2. The Next.js dev wrapper spawns a `sh -c next dev` shell, a `node` process, AND a `next-server` worker. `lsof -i :3000` only catches the one holding the socket — the parents survive and respawn the child.

`pkill -f "next-server"` and `pkill -f "next dev"` together cover the parent + worker pair regardless of which one currently holds the port.

## Related foot-guns (memory-indexed)

- **Don't run `make-dist.sh` while dev is alive** (`feedback_dont_build_with_dev_running`). Build writes/deletes `.next/`; concurrent `next dev` crashes ENOENT. Re-check port 3000 before EVERY build, not just the first one in a session. This skill's `NO_START=1` mode is the right thing to run before `make-dist.sh`.
- **`globalThis`-pin process-wide module state** (`module_state_globalthis_pinning`). Two dev servers each have their own module state; they'll fight over `data/settings.json` writes and the file mutex.
- **DB bootstrap blocks routes** (`standalone_secret_warmup_blocking`-adjacent). If two servers race the DB open + WAL, you can land on a corrupt SQLite state — another reason single-instance matters now that the DB cutover landed.

## Pass criteria

After running the script:
- Exactly one `next-server` process owned by your uid (`ps aux | grep next-server | grep -v grep | wc -l` returns `1`)
- `http://localhost:3000` (or `$PORT`) responds with a 200 or 307 to a probe
- Dev output shows `✓ Ready in <N>s` and `[db] bootstrap complete` (if DB scaffold is present)

If any of those fail, do NOT assume your code change is the problem — re-run the skill until the environment is clean before debugging the code.
