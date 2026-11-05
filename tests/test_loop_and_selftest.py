"""ReAct loop behaviour and the portable --self-test."""
import json
import os
import subprocess
import sys
import tempfile
import shutil
import unittest

from tests._sandbox import SandboxTestCase, REPO, T

import phoenix as P  # noqa: E402


class ListBackend(P.ModelBackend):
    def __init__(self, replies):
        self.replies = list(replies)

    def generate(self, messages):
        return self.replies.pop(0) if self.replies else None


def tool(name, **args):
    return '```tool:%s```' % json.dumps({"name": name, "args": args})


class ParseToolCallTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(P.parse_tool_call('x ' + tool("calc", expr="1+1")),
                         {"name": "calc", "args": {"expr": "1+1"}})

    def test_no_block_is_plain_answer(self):
        self.assertIsNone(P.parse_tool_call("just an answer"))
        self.assertIsNone(P.parse_tool_call(None))

    def test_bad_json(self):
        self.assertIn("_error", P.parse_tool_call('```tool:{"name": calc}```'))

    def test_missing_name(self):
        self.assertEqual(P.parse_tool_call('```tool:{"args":{}}```'),
                         {"_error": "tool call needs a 'name' field"})

    def test_args_must_be_object(self):
        self.assertEqual(P.parse_tool_call('```tool:{"name":"calc","args":[1]}```'),
                         {"_error": "tool call 'args' must be an object"})

    def test_args_default(self):
        self.assertEqual(P.parse_tool_call('```tool:{"name":"terminate"}```'),
                         {"name": "terminate", "args": {}})


class RunLoopTests(SandboxTestCase):
    def run_loop(self, replies, max_steps=P.MAX_STEPS):
        final = P.run_loop("task", ListBackend(replies), T.build_registry(),
                           self.run_dir, self.approvals, max_steps=max_steps, quiet=True)
        with open(os.path.join(self.run_dir, "transcript.jsonl")) as f:
            events = [json.loads(l) for l in f]
        return final, events

    def test_terminate(self):
        final, ev = self.run_loop([tool("calc", expr="2*3"), tool("terminate", summary="done")])
        self.assertEqual(final, "done")
        self.assertIn("6", [e for e in ev if e["type"] == "observation"][0]["text"])
        self.assertEqual(ev[-1]["type"], "end")

    def test_plain_answer_stops(self):
        final, ev = self.run_loop(["the answer is 4"])
        self.assertEqual(final, "the answer is 4")
        self.assertIn({"plain_answer"}, [{e.get("reason")} for e in ev if e["type"] == "stop"])

    def test_unknown_tool_is_observed_not_run(self):
        final, ev = self.run_loop([tool("rm_everything"), tool("terminate", summary="ok")])
        obs = [e["text"] for e in ev if e["type"] == "observation"]
        self.assertTrue(obs[0].startswith("ERROR: unknown tool 'rm_everything'"))
        self.assertEqual(final, "ok")

    def test_gated_tool_refusal_reaches_the_model(self):
        final, ev = self.run_loop([tool("gmail_send", to="a@b.c", subject="s", body="b"),
                                   tool("terminate", summary="ok")])
        obs = [e["text"] for e in ev if e["type"] == "observation"]
        self.assertTrue(obs[0].startswith("REFUSED: 'gmail_send' needs Brandon's tap"))

    def test_ask_brandon_stops(self):
        final, ev = self.run_loop([tool("ask_brandon", question="send it?"),
                                   tool("terminate", summary="should not reach")])
        self.assertTrue(final.startswith("STOPPED: asked Brandon"))

    def test_max_steps(self):
        final, ev = self.run_loop([tool("calc", expr="1")] * 5, max_steps=3)
        self.assertTrue(final.startswith("Stopped after 3 steps"))

    def test_replies_exhausted(self):
        final, _ = self.run_loop([tool("calc", expr="1")])
        self.assertTrue(final.startswith("Stopped: no more model replies"))

    def test_tool_exception_is_observed(self):
        reg = T.build_registry()
        reg["boom"] = {"name": "boom", "desc": "", "fn": lambda a, c: 1 / 0}
        final = P.run_loop("t", ListBackend([tool("boom"), tool("terminate", summary="x")]),
                           reg, self.run_dir, self.approvals, quiet=True)
        with open(os.path.join(self.run_dir, "transcript.jsonl")) as f:
            obs = [json.loads(l)["text"] for l in f if '"observation"' in l]
        self.assertTrue(obs[0].startswith("ERROR: tool raised ZeroDivisionError"))
        self.assertEqual(final, "x")

    def test_file_backend_splits_steps(self):
        p = os.path.join(self.base, "replies.txt")
        with open(p, "w") as f:
            f.write("one\n===STEP===\n\n===STEP===\ntwo\n")
        b = P.FileBackend(p)
        self.assertEqual([b.generate([]), b.generate([]), b.generate([])], ["one", "two", None])


class SelfTestTests(unittest.TestCase):
    def test_self_test_restores_real_roots(self):
        before = (T.WORKSPACE, T.GENESIS, T.RUNS_DIR, T.CRON_REGISTRY)
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            ok = P.self_test()
        self.assertTrue(ok, buf.getvalue())
        self.assertEqual((T.WORKSPACE, T.GENESIS, T.RUNS_DIR, T.CRON_REGISTRY), before)

    def test_cli_self_test_passes_from_any_clone_and_home(self):
        # Copy the harness to an arbitrary directory, run it with a fresh empty
        # HOME and an unrelated cwd: it must PASS and must not create ~/workspace.
        base = tempfile.mkdtemp(prefix="phx-clone-")
        try:
            clone = os.path.join(base, "somewhere", "phoenix-forge")
            os.makedirs(clone)
            for f in ("phoenix.py", "tools.py"):
                shutil.copy(os.path.join(REPO, f), clone)
            home = os.path.join(base, "home")
            os.makedirs(home)
            env = dict(os.environ, HOME=home)
            p = subprocess.run([sys.executable, os.path.join(clone, "phoenix.py"), "--self-test"],
                               cwd=base, env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn("PASS: file_read returned fixture", p.stdout)
            self.assertIn("SELF-TEST: PASS", p.stdout)
            self.assertEqual(os.listdir(home), [])
            self.assertFalse(os.path.exists(os.path.join(clone, ".selftest_fixture.txt")))
        finally:
            shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
