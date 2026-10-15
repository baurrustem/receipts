"""Tests for skills/compact-receipts/scripts/compact_receipts.py on a synthetic transcript."""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "skills" / "compact-receipts" / "scripts"))
import compact_receipts as cr  # noqa: E402


def assistant(uuid, tool, tool_input, tool_id=None):
    return {"type": "assistant", "uuid": uuid, "timestamp": "2026-10-15T10:00:00Z",
            "message": {"content": [{"type": "tool_use", "id": tool_id or uuid + "-t", "name": tool, "input": tool_input}]}}


def tool_result(uuid, tool_id, text, is_error=False):
    return {"type": "user", "uuid": uuid, "message": {"content": [
        {"type": "tool_result", "tool_use_id": tool_id, "content": text, "is_error": is_error}]}}


def user(uuid, text):
    return {"type": "user", "uuid": uuid, "message": {"content": text}}


def boundary(uuid, preserved=()):
    return {"type": "system", "subtype": "compact_boundary", "uuid": uuid, "timestamp": "2026-10-15T11:00:00Z",
            "compactMetadata": {"trigger": "auto", "preTokens": 400000, "postTokens": 16000,
                                "preservedMessages": {"allUuids": list(preserved)}}}


def summary(uuid, text):
    return {"type": "user", "uuid": uuid, "isCompactSummary": True, "message": {"content": text}}


SESSION = [
    user("u1", "Never restart vm-a without asking me first. Use the staging box for tests."),
    assistant("a1", "Bash", {"command": "ssh -i ~/.ssh/k deploy@vm-b.internal 'systemctl status app'"}),
    assistant("a2", "Bash", {"command": "curl -s https://widget-staging.up.railway.app/health && curl http://localhost:3300/api"}),
    assistant("a3", "Bash", {"command": "curl https://api.openai.com/v1/models; curl https://demo.example/x; npm i left-pad@0.0.18"}),
    assistant("a4", "Edit", {"file_path": "/repo/src/vm/pool.ts", "old_string": "a", "new_string": "b"}),
    assistant("a5", "Edit", {"file_path": "/repo/src/vm/pool.ts", "old_string": "b", "new_string": "c"}),
    assistant("a6", "Write", {"file_path": "/repo/README.md", "content": "x"}),
    assistant("a7", "Bash", {"command": "npm test"}, tool_id="t7"),
    tool_result("r7", "t7", "1 failed, 12 passed", is_error=True),
    assistant("a8", "TodoWrite", {"todos": [{"content": "Migrate pool to vm-c", "status": "pending"},
                                             {"content": "Write docs", "status": "completed"}]}),
    assistant("a9", "Bash", {"command": "docker logs -f api-worker"}),
    user("u2", "export TOKEN=sk-abcdefghijklmnopqrstuvwx is important, always load it from env"),
    boundary("b1", preserved=["a9"]),
    summary("s1", "Primary Request: improve README.md. Files: README.md updated. Current Work: polishing docs."),
]


class CompactReceiptsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "session.jsonl"
        self.path.write_text("\n".join(json.dumps(r) for r in SESSION) + "\n")
        self.result = cr.analyze(self.path)
        self.c = self.result["compactions"][0]
        self.dropped = {(f.kind, f.label) for f in self.c.dropped}
        self.kept = {(f.kind, f.label) for f in self.c.kept}

    def tearDown(self):
        self.tmp.cleanup()

    def test_one_compaction_with_metadata(self):
        self.assertEqual(len(self.result["compactions"]), 1)
        self.assertEqual(self.c.trigger, "auto")
        self.assertEqual((self.c.pre_tokens, self.c.post_tokens), (400000, 16000))

    def test_environments_dropped(self):
        self.assertIn(("env", "vm-b.internal (ssh)"), self.dropped)
        self.assertIn(("env", "widget-staging.up.railway.app"), self.dropped)
        self.assertIn(("env", "localhost:3300"), self.dropped)

    def test_noise_is_not_an_environment(self):
        labels = {lbl for kind, lbl in self.dropped | self.kept if kind == "env"}
        self.assertFalse(any("openai" in lbl for lbl in labels), labels)       # third-party API
        self.assertFalse(any("example" in lbl for lbl in labels), labels)      # RFC test domain
        self.assertFalse(any("0.0.18" in lbl for lbl in labels), labels)       # package version

    def test_preserved_message_counts_as_kept(self):
        self.assertIn(("env", "api-worker (docker)"), self.kept)

    def test_files(self):
        self.assertIn(("file", "/repo/README.md"), self.kept)
        pool = [f for f in self.c.dropped if f.label == "/repo/src/vm/pool.ts"]
        self.assertEqual(len(pool), 1)
        self.assertEqual(pool[0].count, 2)

    def test_open_todo_dropped_completed_ignored(self):
        self.assertIn(("todo", "Migrate pool to vm-c"), self.dropped)
        self.assertNotIn(("todo", "Write docs"), self.dropped | self.kept)

    def test_rules_and_redaction(self):
        rules = [lbl for kind, lbl in self.dropped if kind == "rule"]
        self.assertTrue(any("restart vm-a" in r for r in rules), rules)
        self.assertTrue(all("sk-abc" not in r for r in rules), rules)
        self.assertTrue(any("‹redacted›" in r for r in rules), rules)

    def test_red_tests(self):
        self.assertEqual(self.c.red, ["npm test"])
        self.assertFalse(self.c.summary_mentions_failure)

    def test_ip_masking(self):
        facts = cr.env_facts("ssh root@34.120.5.9", "x", reveal=False)
        self.assertEqual([f.label for f in facts if f.key == "host:34.120.5.9"][0], "34.120.x.x (ssh)")
        facts = cr.env_facts("ssh root@34.120.5.9", "x", reveal=True)
        self.assertIn("34.120.5.9 (ssh)", [f.label for f in facts])

    def test_hook_mode_outputs_context_without_rules(self):
        payload = json.dumps({"source": "compact", "transcript_path": str(self.path)})
        out = io.StringIO()
        stdin = sys.stdin
        try:
            sys.stdin = io.StringIO(payload)
            with redirect_stdout(out):
                self.assertEqual(cr.main(["--hook"]), 0)
        finally:
            sys.stdin = stdin
        data = json.loads(out.getvalue())
        ctx = data["hookSpecificOutput"]["additionalContext"]
        self.assertIn("vm-b.internal", ctx)
        self.assertNotIn("restart vm-a", ctx)

    def test_hook_ignores_other_sources(self):
        out = io.StringIO()
        stdin = sys.stdin
        try:
            sys.stdin = io.StringIO(json.dumps({"source": "startup", "transcript_path": str(self.path)}))
            with redirect_stdout(out):
                cr.main(["--hook"])
        finally:
            sys.stdin = stdin
        self.assertEqual(out.getvalue(), "")

    def test_receipt_and_aggregate_text(self):
        text = cr.receipt_text(self.result)
        self.assertIn("Compaction #1", text)
        self.assertIn("dropped env", text)
        agg = cr.aggregate([self.result])
        self.assertEqual(agg["compactions"], 1)
        self.assertGreaterEqual(agg["new_drops"]["env"], 3)


if __name__ == "__main__":
    unittest.main()
