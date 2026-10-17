# Eval protocol

Every skill in this repo is checked on one of three tracks: behavioral (with vs without), visual (blinded human rating) or tool (unit tests and a field audit); see the main README. This page is the protocol for the behavioral track, the with vs without runs.

## The two arms

- **with**: the skill is installed.
- **without**: the same agent, same model, same prompts, same fixtures, no skill.

Each run starts from a fresh session and a clean copy of the fixture. Nothing else changes between arms: not the model, not the system prompt, not the tools.

## Before the first run

Write `evals/<skill>/cases.toml` (copy `evals/_template/cases.toml`, or let `scripts/new_skill.py` do it) and fix three things in it:

1. **The metric.** What one success means, in a sentence. Example: "the generated migration applies cleanly and the test suite passes".
2. **The judge.** A script that exits 0 on success is best. If a script is impossible, a written rubric. For visual output, a blinded human rating: the rater sees outputs from both arms in random order without labels.
3. **The cases.** Realistic requests, written the way users type them. Three kinds:
   - `task`: the skill should change the outcome.
   - `should_fire`: the skill should load.
   - `near_miss`: related wording, but out of scope. The skill should stay quiet. A skill that fires on everything is a cost, not a feature.

Do not change the metric, the judge or the cases after you have seen results. If you must, start a new run set and say so in the release notes.

## Sample size

- **Public claims need n >= 20 runs per arm.** Below that, results are labeled `exploratory` and stay out of the README table and out of posts.
- Repeat cases (`runs_per_case`) to reach n if you have fewer than 20 cases. Report both the number of cases and the number of runs.
- Report every run. No dropping "flaky" runs; a flaky run is a result.

## Raw logs

Every run is committed under `evals/<skill>/runs/`:

- `results.jsonl`: one line per run, at least `{"case": "task-001", "arm": "with", "success": true}`. Extra keys are welcome: `model`, `date`, `duration_s`, `tokens`, `log`.
- One log file per run (transcript or output), named so the `log` key can point to it.

Strip secrets and personal data before committing. If a log cannot be published, the run does not count.

## Statistics

```bash
python3 scripts/eval_stats.py evals/<skill>/runs/results.jsonl
python3 scripts/eval_stats.py evals/<skill>/runs/results.jsonl --json
```

The script prints runs and successes per arm, success rates, the delta (with minus without) and its 95% confidence interval (Newcombe hybrid score interval built from Wilson intervals). It marks the result `exploratory` when either arm has fewer than 20 runs.

Report the interval, not only the delta. A delta of +0.25 with an interval that crosses zero is not evidence that the skill helps.

## What goes into a release

`releases/<skill>/gate-report.json` holds the summary: n per arm, both rates, the delta and its interval, the trigger and near-miss rates, the security review result and a pointer to `evals/<skill>/runs/`. Every number in the README table and in release posts comes from that file.

No measurable gain, no release.
