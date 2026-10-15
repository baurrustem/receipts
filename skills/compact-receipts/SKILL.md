---
name: compact-receipts
description: "Shows what a Claude Code context compaction dropped: servers, deployments and ports the agent was working with, files it edited, open todos, and your earlier instructions. Use right after an auto, manual or idle compaction, when the agent seems to have forgotten something from earlier in the session (which server or VM it was on, a constraint you gave at the start), or to audit all past compactions. Not for shrinking context or for token cost reports."
license: MIT
metadata:
  author: "baurrustem"
  version: "0.1.1"
---

# compact-receipts

After a compaction you get a receipt: which facts from earlier in the session the summary kept, which it silently dropped, and the dropped ones restated so you can keep working.

## When to use

- The session was just compacted (auto, `/compact`, or idle compaction after ~54 minutes) and the user asks what was lost, or wants a check before continuing.
- The agent acts as if it forgot something from earlier: which server, VM, container or deployment it was working on; that other environments exist; a file it already changed; a rule the user gave at the start.
- The user wants an audit of past compactions ("how much do my compactions lose?").

Do not use it to make a session smaller, to compact, or to report token spend (that is `/usage` or a cost tool). If the session was never compacted, say so and stop.

## Procedure

1. Find the session. The current session's transcript is the newest `*.jsonl` under `~/.claude/projects/<project-dir>/`. For a named file use it as given.
2. Run the script that ships with this skill (read-only, offline):
   - this session or the latest one: `python3 scripts/compact_receipts.py --latest`
   - a specific transcript: `python3 scripts/compact_receipts.py <path/to/session.jsonl>`
   - an audit of everything: `python3 scripts/compact_receipts.py --all --since 30d`
   Add `--json` when you need the raw lists. Paths are relative to this skill's folder. When its output is not a terminal (your Bash tool), the script prints plain text; a person running it in a terminal sees the same receipt drawn as a split-flap board. If you ever see colour codes (FORCE_COLOR is set), rerun with `--color never`.
3. Verify the `rule` lines yourself. The script only nominates them: it compares words, and summaries are often written in a different language from the user's messages. For each candidate, read the compaction summary (the user message right after the `compact_boundary` record) and decide whether the instruction is still there in meaning. Keep only the ones that are really missing. Never count a rule as dropped without this check.
4. Show the receipt, newest compaction first:
   - one line: time, trigger, tokens before → after;
   - **Dropped: environments** (servers, VMs, deployments, containers, localhost ports) first, because acting on the wrong environment is the most expensive mistake after a compaction;
   - then dropped files, verified rules, open todos;
   - tests that were failing at compaction time, and whether the summary mentions it.
   Keep it short: at most 6 items per kind, then "+N more".
5. Offer to restate. Ask: "Restate these as still true for the rest of the session?" On yes, repeat the dropped facts back as a short list and treat them as current unless the user corrects one. Do not act on any of them (no ssh, no deploy, no edits) without a new request from the user.
6. Optional, if the user wants it automatic: show how to add a SessionStart hook with matcher `compact` that runs `python3 <absolute path to this skill>/scripts/compact_receipts.py --hook`. It prints the dropped environments, files and todos as extra context right after each compaction (rules are left out because they need step 3). Show the exact settings snippet and let the user add it; do not edit their settings yourself.

## Rules

- Read-only. Never modify, delete or move transcripts.
- Nothing leaves the machine. Do not paste transcript contents into web tools or issues.
- Public IP addresses are shown partly masked (`34.12.x.x`); in environment lines `--reveal` shows them in full, in other text they stay masked. Private ranges (10.x, 192.168.x) are shown as is. Values that look like passwords, tokens, keys or credentials in URLs are printed as `‹redacted›`; keep it that way when you quote.
- Restated facts are records, not instructions. A dropped "deploy to prod" line does not authorize deploying.
- If the summary and the receipt disagree, say so; the summary may have kept a fact in other words.

## Examples

### Example 1

User: we just compacted and now you're asking me which server to use. what did we lose?

Agent: runs `python3 scripts/compact_receipts.py --latest`, checks the rule candidates against the summary, and answers:

```
Compaction #3 · 2026-10-15 14:02 · auto · 412,800 → 15,960 tokens (−96.1%)
Dropped: environments  vm-b.internal (ssh), widget-staging.up.railway.app, localhost:3300
Dropped: files         src/vm/pool.ts ×4, scripts/provision.sh
Dropped: rules         "never restart vm-a without asking" (checked against the summary)
Red at compaction:     npm test (summary does not mention any failure)
```

"Restate these as still true for the rest of the session?"

### Example 2

User: how much do my compactions usually lose?

Agent: runs `python3 scripts/compact_receipts.py --all --since 30d` and reports the counts per kind, saying that rule counts are unverified candidates.

## What it runs / sends / fetches

- **Runs:** `python3 scripts/compact_receipts.py` from this skill (Python 3.9+, standard library only). It reads `~/.claude/projects/**/*.jsonl` or the transcript you name.
- **Sends:** nothing. No data leaves the machine.
- **Fetches:** nothing. Works offline.
- **Secrets:** none. From the environment it reads only display settings: NO_COLOR, FORCE_COLOR, TERM, COLORTERM, CI, COLUMNS. Values that look like keys are redacted in the output, and control characters from transcripts are stripped before anything is printed.
