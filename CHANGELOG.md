# Changelog

All notable changes to this repo. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The plugin version in `.claude-plugin/plugin.json` follows [Semantic Versioning](https://semver.org/). Each skill release links its gate report in `releases/<skill>/`.

## [0.1.1] - 2026-10-15

### Added

- **compact-receipts:** in a terminal the receipt and the `--all` audit print as a split-flap departures board (the Receipts board look): yellow NOT MENTIONED flaps, a flap-in animation for the title and the headline count, a progress line while reading sessions. Plain text stays the default whenever output is piped or run by an agent; `--color auto|always|never`, `NO_COLOR` and `TERM=dumb` are honoured. `--json` and `--hook` output are unchanged.

### Security

- Control and format characters (ESC, BEL, the rest of C0/C1, bidi and zero-width marks) are stripped from transcript text before it reaches the terminal, in both plain and board output: labels, compaction time and trigger, session file and project folder names. Junk token counts no longer stop an `--all` run.

## [0.1.0] - 2026-10-15

### Added

- **compact-receipts** (Receipts #01): a receipt of what a Claude Code context compaction left out — environments (ssh targets, VMs, deploy hosts, localhost ports, containers), edited files, open todos, and candidate instructions for the agent to check by meaning. `--all` audit across sessions, `--json`, `--exclude`, and a `--hook` mode for a SessionStart hook with matcher `compact`. Read-only, offline, standard library only. Gate report: `releases/compact-receipts/gate-report.json`.
- Repository scaffold: Claude Code plugin and marketplace manifests, skill template (`skills/_template`), eval protocol and case template (`evals/`), validator, eval statistics and skill scaffolding scripts (`scripts/`), CI with gitleaks.
