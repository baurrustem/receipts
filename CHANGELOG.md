# Changelog

All notable changes to this repo. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The plugin version in `.claude-plugin/plugin.json` follows [Semantic Versioning](https://semver.org/). Each skill release links its gate report in `releases/<skill>/`.

## [0.1.0] - 2026-10-15

### Added

- **compact-receipts** (Receipts #01): a receipt of what a Claude Code context compaction left out — environments (ssh targets, VMs, deploy hosts, localhost ports, containers), edited files, open todos, and candidate instructions for the agent to check by meaning. `--all` audit across sessions, `--json`, `--exclude`, and a `--hook` mode for a SessionStart hook with matcher `compact`. Read-only, offline, standard library only. Gate report: `releases/compact-receipts/gate-report.json`.
- Repository scaffold: Claude Code plugin and marketplace manifests, skill template (`skills/_template`), eval protocol and case template (`evals/`), validator, eval statistics and skill scaffolding scripts (`scripts/`), CI with gitleaks.
