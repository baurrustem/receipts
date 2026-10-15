# Security

Agent skills run with your agent's permissions. Treat them like code you execute, and tell me when one of mine looks wrong.

## Report a vulnerability

Please report privately through GitHub: [Security → Report a vulnerability](https://github.com/baurrustem/receipts/security/advisories/new). Do not open a public issue for a vulnerability.

Useful in a report: the skill and version (or commit), what you ran, what happened, and what you expected.

What counts:

- A skill that runs, sends or fetches something its "What it runs / sends / fetches" section does not declare.
- Hidden or misleading instructions in skill files (prompt injection, hidden Unicode, instructions that differ from what the README says).
- Secrets or personal data committed anywhere in the repo, including eval logs.
- Weaknesses in the scripts or CI workflows in this repo.
- A pull request or fork that tries to slip in any of the above.

What happens next: I acknowledge reports as fast as I can, best effort within 7 days. If the issue is real, I pull or fix the skill, tag a fixed release, publish an advisory, and credit you if you want credit.

## Supported versions

Only the latest release of each skill gets fixes. Pin a tag if you need stability, and watch releases for advisories.

## What this repo enforces

Checked on every push and pull request by `scripts/validate_skills.py` and gitleaks:

- No binaries or compiled files in skill folders (`.so`, `.dylib`, `.dll`, `.exe`, `.pyc`, `.class`, anything with NUL bytes). Images and fonts only when the bytes match the extension.
- No test files in skill folders (`conftest.py`, `test_*.py`, `*_test.py`, `*.test.ts`, `*.test.js`): test runners in your project could pick them up and execute them.
- No `curl ... | sh` or `wget ... | sh`, no npm install hooks, no `.env` or `.npmrc` files.
- No hidden Unicode: bidirectional controls (U+202A to U+202E, U+2066 to U+2069) and zero-width spaces are rejected because they can hide text from a reviewer.
- `npx` and `uvx` calls pinned to a version; unpinned ones are flagged.
- Every URL host in a skill must be declared in its "What it runs / sends / fetches" section; undeclared hosts are flagged.
- GitHub Actions pinned to full commit SHAs; workflows get read-only tokens.

Not enforced by a script, but by me before every release: a manual security review of the diff, recorded in `releases/<skill>/gate-report.json`.

## Impersonation

I have no token or coin. I never DM people asking them to install something. The only official install sources are this repository (`github.com/baurrustem/receipts`) and the commands in the README.
