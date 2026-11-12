---
name: cost-summary
description: Use to inspect Anthropic API spend over a recent window — segments the `cost_log` table in `data/eyas.db` by surface (chat / triage routes / dashboards / scheduler) and by model, prints USD spend + % share + cache hit rate. Optional `--since <date>` window. Run before each QA cycle to confirm chat % stays near the 68% baseline and no surface has drifted on iterations or output cost. Trigger phrases: "what did the last week cost", "cost summary", "anthropic spend breakdown", "is chat still 68%".
---

# cost-summary

Turns the append-only `cost_log` table in `data/eyas.db` into a one-shot view of where Anthropic spend is going. Designed to be run before each QA cycle and after large prompt changes — both the times you want to know whether you've drifted.

## Run

```bash
bash .claude/skills/cost-summary/run.sh                  # full log
bash .claude/skills/cost-summary/run.sh --since 7d       # last 7 days
bash .claude/skills/cost-summary/run.sh --since 24h
bash .claude/skills/cost-summary/run.sh --since 2026-05-01
```

## Output

```
Cost summary · 2026-04-26 → 2026-05-07 · 1,237 calls

By surface (USD)                 spend     %    calls   ⌀ iter   cache hit %
  chat                          $42.18  68.4    412    7.3      82.1
  triage-detections              $5.91   9.6     98    4.1      71.4
  briefing                       $4.02   6.5     31    3.0      88.2
  …
  TOTAL                         $61.66 100.0  1,237

By model
  claude-sonnet-5-5             $58.21  94.4
  claude-opus-5-5                $3.45   5.6

Cost shape (USD)
  output                  $7.40 12.0%   ← writing answers
  cache write            $19.83 32.2%   ← first turn / new tools block
  cache read             $32.11 52.1%   ← cached prefix replay
  input (uncached)        $2.32  3.8%

Headline ratios
  output / total          12.0%   ← higher = LLM is working hard, lower = cache + setup heavy
  cache read / total      52.1%   ← higher = better cache reuse
  cache hit %             80.7%   ← cache_read / (cache_read + cache_write + input)
```

## What it tells you

- **Chat % of total.** Baseline is ~68%. Drift much above means a route regressed (longer prompts, more iterations, less caching). Drift much below means chat usage dropped — usually a sign someone hit a bug.
- **Output / total %.** ~12% baseline. If this jumps, the model is generating more (longer responses, more tool-call retries). If it drops, the cache is doing more of the work.
- **Cache hit %.** Above 80% is healthy. Below 60% means the prompt prefix is changing call-to-call (rebuilds the cache instead of reusing) — usually a misplaced timestamp, randomized ordering, or a tools-block edit.
- **⌀ iter per surface.** Average tool-call iterations. Chat baseline is ~7. Routes should be 3–5; spikes mean the agent is bouncing on a tool error or re-trying.

## Limits

- Prices come straight from `lib/cost/pricing.ts` (longest-prefix match on model id), the same table the in-app /cost page uses.
- A surface that doesn't appear in the log either wasn't called in the window or never logs (the read-only dashboard fetchers don't go through `logUsage()` because they don't run the agent loop).
- Doesn't cross-reference `data/perf-log.jsonl` — that's `npm run perf-summary`. Use the two together: cost surfaces what you're paying for; perf surfaces what's slow.

## When this catches things

- After bumping a system prompt — re-run, confirm cache hit % didn't crater.
- Before a demo cycle — confirm spend is on a sustainable trend, not a 5x spike from an iteration loop bug.
- After a model swap — confirm the model bucket actually moved.
