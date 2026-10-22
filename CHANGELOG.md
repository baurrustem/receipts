# Changelog

All notable changes to this repo. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The plugin version in `.claude-plugin/plugin.json` follows [Semantic Versioning](https://semver.org/). Each skill release links its gate report in `releases/<skill>/`.

## [0.1.3] - 2026-10-22

Fixes from the security review of 0.1.2. None of them sends data anywhere; the script still reads local transcripts only.

### Security

- **compact-receipts:** `--json` output is cleaned like the text receipt. Session paths, labels and failing test commands used to go straight to `json.dumps`, so C1 controls (CSI U+009B, OSC U+009D), bidi, zero-width and tag characters reached stdout as they were, and ESC and BEL came back to life under `jq -r`.
- **compact-receipts:** the hook's extra context gets the same cleaning, so these characters cannot reach the model's context after a compaction either.
- **compact-receipts:** U+2028 and U+2029 become spaces (they could fake a line break). Lone surrogates are dropped (under a strict output encoding they raised `UnicodeEncodeError`), and so are invisible characters outside the format category: variation selectors, which can carry hidden bytes, the combining grapheme joiner and Hangul fillers. An emoji may lose its U+FE0F as a result.
- **compact-receipts:** paths, todos, test commands and instructions are cleaned before redaction, so a zero-width character inside `PASSWORD=` or a key no longer hides the value from the redaction and then disappears from the output.
- **compact-receipts:** the docker container pattern backtracked exponentially on `docker exec --a --a … "$C"`: 0.19 s at 20 options, about 4x more per 2 extra options. One such command could hang `--all`, `--latest` and the SessionStart hook. The option token is now unambiguous, and 200 options take under a millisecond. The command-splitting, credential-assignment and `mysql -p` patterns were quadratic on long blank runs, long runs of short words and repeated `mysql`; all three are linear now, and a randomized test checks that the new code redacts exactly what the old patterns did. Shell parsing for ssh targets runs only on segments that name an ssh-family tool, on their first 4 KB. As a backstop, Bash commands and user messages are cut to 64 KB, and paths, todos and test commands to 4 KB, before any pattern runs.

### Fixed

- **compact-receipts:** a transcript with a malformed record (for example `"message": "x"`) or a dangling symlink in a project folder no longer stops `--all` with a traceback. Odd record shapes are skipped. A file that still fails prints `cannot parse <path>: <error type>` on stderr, the other files are reported, `--json` stays valid, and the exit code is 1.
- **compact-receipts:** the plain receipt names the project folder next to the session file, because `--latest` picks the most recently modified session with a compaction across all projects.

### Changed

- **compact-receipts:** SKILL.md runs the script by its absolute path everywhere (a `scripts/compact_receipts.py` in the user's repo could have run instead). It says that `--latest` spans projects and that the current session is better passed as a transcript path. It says that `--all --json` adds a `summary` when nothing is found. The disclosure now lists HOME and LINES, which the script also reads.
- Test fixtures build credential-shaped strings at runtime, so shape-based secret scanners stay quiet.

On the author's 31 compacted sessions (93 compactions) `--hook` prints byte for byte what 0.1.2 printed, and `--all --json` gives the same counts. The only changed label is one instruction whose emoji lost its U+FE0F.

## [0.1.2] - 2026-10-22

### Fixed

- **compact-receipts:** a missing or unreadable session path prints one line, `cannot read <path>: <reason>`, instead of a Python traceback. The other paths in the same call are still reported, and the exit code is 1.
- **compact-receipts:** `--since` without `--all` or `--latest` used to search nothing and report "no sessions with a compaction found". It is now rejected with a usage error (exit code 2) that says to add `--all` or `--latest`.
- **compact-receipts:** `--json` always prints valid JSON. When nothing is found it prints `{"sessions": []}` (plus an empty `summary` with `--all`) and still exits 1 with the message on stderr.

## [0.1.1] - 2026-10-15

### Added

- **compact-receipts:** in a terminal the receipt and the `--all` audit print as a split-flap departures board (the Receipts board look): yellow NOT MENTIONED flaps, a flap-in animation for the title and the headline count, a progress line while reading sessions. Plain text stays the default whenever output is piped or run by an agent; `--color auto|always|never`, `NO_COLOR` and `TERM=dumb` are honoured. `--json` and `--hook` output are unchanged.

### Security

- Control and format characters (ESC, BEL, the rest of C0/C1, bidi and zero-width marks) are stripped from transcript text before it reaches the terminal, in both plain and board output: labels, compaction time and trigger, session file and project folder names. Junk token counts no longer stop an `--all` run.

## [0.1.0] - 2026-10-15

### Added

- **compact-receipts** (Receipts #01): a receipt of what a Claude Code context compaction left out — environments (ssh targets, VMs, deploy hosts, localhost ports, containers), edited files, open todos, and candidate instructions for the agent to check by meaning. `--all` audit across sessions, `--json`, `--exclude`, and a `--hook` mode for a SessionStart hook with matcher `compact`. Read-only, offline, standard library only. Gate report: `releases/compact-receipts/gate-report.json`.
- Repository scaffold: Claude Code plugin and marketplace manifests, skill template (`skills/_template`), eval protocol and case template (`evals/`), validator, eval statistics and skill scaffolding scripts (`scripts/`), CI with gitleaks.
