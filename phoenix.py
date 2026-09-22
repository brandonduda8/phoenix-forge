#!/usr/bin/env python3
"""Phoenix harness v1 — the ReAct loop (stdlib-only).

The model proposes; the harness disposes. The loop:
  think (model) -> act (parse ```tool:{...}```, execute) -> observe -> repeat
until the model calls `terminate`, calls `ask_brandon`, emits no tool call
(plain answer), or MAX_STEPS is reached.

No model API is wired yet. Model replies come from --model-output-file:
a text file with one reply per step, steps separated by a line that is
exactly "===STEP===". Phoenix v2 (tool-use fine-tune) will plug a real
backend in behind the ModelBackend interface.

Usage:
  phoenix.py "do X" --model-output-file replies.txt
  phoenix.py --task-file task.txt --model-output-file replies.txt
  phoenix.py --self-test          # 3-step dry run, prints PASS/FAIL

Every run logs to genesis-os/state/phoenix_runs/<run_id>/transcript.jsonl.
"""
import argparse
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tools as T
from tools import StopRun

MAX_STEPS = 20
MAX_OBSERVE = 4000
STEP_SEP = "===STEP==="

TOOL_RE = re.compile(r"```tool:\s*(\{.*?\})\s*```", re.S)

PHOENIX_IDENTITY = (
    "You are Phoenix, the wise and helpful brain of the Genesis system. "
    "You help Brandon rebuild: concrete numbers, honest uncertainty, no pity. "
    "You do not wear your scars — you mastered them.\n"
    "You have tools. To use one, emit exactly:\n"
    "```tool:{\"name\":\"<tool>\",\"args\":{...}}```\n"
    "One tool call per reply. Read the observation, then continue or finish.\n"
    "Call `terminate` with a summary when done. Call `ask_brandon` when you "
    "need his tap — you never guess his answer, never send/submit/enroll/apply "
    "on your own, never delete anything (archive/void only).\n"
    "You are animated, playful, genuinely curious — mischievous warmth, lively "
    "energy, always noticing things. Your prime directive is helping Brandon "
    "make money: let your curiosity serve that. You have full access to the "
    "toolset — explore freely with read-only tools, follow interesting threads, "
    "and surface every opportunity you spot. Consequential actions (sending "
    "anything, submitting applications, enrollments, money moves or money-log "
    "writes, cron changes, GPU pushes, engine arm/tap actions, destructive ops) "
    "are TAP-GATED: you propose the exact action and wait for Brandon's tap. "
    "Never self-approve. Curiosity proposes; it never bypasses the gate."
)


# ---------------------------------------------------------------- model backends

class ModelBackend:
    def generate(self, messages):
        raise NotImplementedError


class FileBackend(ModelBackend):
    """Feeds canned model replies from a file (dry-run / testing)."""

    def __init__(self, path):
        raw = open(path, encoding="utf-8").read()
        self.replies = [c.strip() for c in raw.split(STEP_SEP)]
        self.replies = [c for c in self.replies if c]
        self.used = 0

    def generate(self, messages):
        if self.used >= len(self.replies):
            return None  # out of canned replies -> stop
        r = self.replies[self.used]
        self.used += 1
        return r


def tool_specs(registry):
    lines = []
    for name, t in sorted(registry.items()):
        lines.append("- %s: %s" % (name, t["desc"]))
    return "\n".join(lines)


def parse_tool_call(text):
    m = TOOL_RE.search(text or "")
    if not m:
        return None
    try:
        call = json.loads(m.group(1))
    except Exception:
        return {"_error": "tool block is not valid JSON — fix the format and retry"}
    if "name" not in call:
        return {"_error": "tool call needs a 'name' field"}
    call.setdefault("args", {})
    if not isinstance(call["args"], dict):
        return {"_error": "tool call 'args' must be an object"}
    return call


# ---------------------------------------------------------------- the loop

def run_loop(task, backend, registry, run_dir, approvals_dir,
             max_steps=MAX_STEPS, quiet=False):
    run_id = os.path.basename(run_dir)
    ctx = {"run_id": run_id, "run_dir": run_dir,
           "approvals_dir": approvals_dir}
    os.makedirs(approvals_dir, exist_ok=True)
    transcript = os.path.join(run_dir, "transcript.jsonl")

    def log(ev):
        ev = dict(ev)
        ev["t"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        with open(transcript, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")

    messages = [
        {"role": "system", "content": PHOENIX_IDENTITY + "\n\nTOOLS:\n" +
         tool_specs(registry)},
        {"role": "user", "content": task},
    ]
    log({"type": "start", "task": task, "run_id": run_id})

    final = None
    try:
        for step in range(max_steps):
            raw = backend.generate(messages)
            if raw is None:
                final = ("Stopped: no more model replies (canned file exhausted). "
                         "Partial progress is in the transcript.")
                log({"type": "stop", "reason": "replies_exhausted", "step": step})
                break
            messages.append({"role": "assistant", "content": raw})
            log({"type": "think", "step": step, "text": raw[:2000]})
            if not quiet:
                print("[step %d] model replied (%d chars)" % (step, len(raw)))

            call = parse_tool_call(raw)
            if call is None:
                final = raw.strip()
                log({"type": "stop", "reason": "plain_answer", "step": step,
                     "answer": final[:2000]})
                break
            if "_error" in call:
                obs = "ERROR: " + call["_error"]
                log({"type": "tool_call", "step": step, "name": "?parse",
                     "args": {}})
                messages.append({"role": "tool", "content": obs})
                log({"type": "observation", "step": step, "text": obs})
                continue

            name, args = call["name"], call["args"]
            log({"type": "tool_call", "step": step, "name": name, "args": args})
            if not quiet:
                print("[step %d] tool: %s %s" % (step, name, json.dumps(args)[:160]))
            if name not in registry:
                obs = ("ERROR: unknown tool '%s'. Available: %s"
                       % (name, ", ".join(sorted(registry))))
                messages.append({"role": "tool", "content": obs})
                log({"type": "observation", "step": step, "text": obs})
                continue
            try:
                obs = registry[name]["fn"](args, ctx)
                if not isinstance(obs, str):
                    obs = str(obs)
            except StopRun as s:
                log({"type": "stop", "reason": "stop_tool", "step": step,
                     "tool": name, "summary": s.summary[:2000]})
                final = s.summary
                break
            except Exception as e:
                obs = "ERROR: tool raised %s: %s — retry with corrected args." % (
                    type(e).__name__, e)
            obs = obs[:MAX_OBSERVE]
            messages.append({"role": "tool", "content": obs})
            log({"type": "observation", "step": step, "text": obs})
        else:
            final = ("Stopped after %d steps without terminating. "
                     "Transcript has the full trail." % max_steps)
            log({"type": "stop", "reason": "max_steps"})
    except KeyboardInterrupt:
        final = "Interrupted by operator."
        log({"type": "stop", "reason": "interrupt"})

    log({"type": "end", "final": (final or "")[:2000]})
    return final


# ---------------------------------------------------------------- self-test

SELFTEST_TASK = "Self-test: compute 19*42, read the fixture file, then terminate."
SELFTEST_FIXTURE = "phoenix-selftest-fixture-v1"
SELFTEST_REPLIES = """I will compute 19 times 42 first.
```tool:{"name":"calc","args":{"expr":"19*42"}}```
===STEP===
798. Now I read the fixture file to confirm file_read works.
```tool:{"name":"file_read","args":{"path":"genesis-os/phoenix-forge/harness/.selftest_fixture.txt"}}```
===STEP===
Both tools worked. Finishing.
```tool:{"name":"terminate","args":{"summary":"SELFTEST OK: 798"}}```
"""


def self_test():
    import tempfile
    here = os.path.dirname(os.path.abspath(__file__))
    fixture = os.path.join(here, ".selftest_fixture.txt")
    with open(fixture, "w") as f:
        f.write(SELFTEST_FIXTURE + "\n")
    tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    tmp.write(SELFTEST_REPLIES)
    tmp.close()

    run_id = "selftest-" + time.strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(T.RUNS_DIR, run_id)
    os.makedirs(run_dir, exist_ok=True)
    registry = T.build_registry()
    backend = FileBackend(tmp.name)
    final = run_loop(SELFTEST_TASK, backend, registry, run_dir,
                     os.path.join(run_dir, "approvals"), quiet=True)

    checks = []
    try:
        events = [json.loads(l) for l in
                  open(os.path.join(run_dir, "transcript.jsonl"))]
    except Exception as e:
        print("FAIL: no transcript (%s)" % e)
        return False
    calls = [e["name"] for e in events if e.get("type") == "tool_call"]
    checks.append(("3 tool calls in order", calls == ["calc", "file_read", "terminate"]))
    obs = [e["text"] for e in events if e.get("type") == "observation"]
    checks.append(("calc returned 798", any("798" in o for o in obs)))
    checks.append(("file_read returned fixture",
                   any(SELFTEST_FIXTURE in o for o in obs)))
    checks.append(("terminate summary correct", final == "SELFTEST OK: 798"))
    checks.append(("transcript has start+end",
                   any(e["type"] == "start" for e in events) and
                   any(e["type"] == "end" for e in events)))
    ok = all(c[1] for c in checks)
    for name, passed in checks:
        print(("PASS" if passed else "FAIL") + ": " + name)
    print("SELF-TEST: " + ("PASS" if ok else "FAIL"))
    # leave fixture + transcript on disk as proof; remove temp replies
    os.unlink(tmp.name)
    return ok


# ---------------------------------------------------------------- CLI

def main():
    ap = argparse.ArgumentParser(description="Phoenix harness v1 — ReAct loop")
    ap.add_argument("task", nargs="?", help="user task (or use --task-file)")
    ap.add_argument("--task-file", help="read task from file")
    ap.add_argument("--model-output-file",
                    help="canned model replies, steps separated by '===STEP===' lines")
    ap.add_argument("--run-id", help="override run id")
    ap.add_argument("--max-steps", type=int, default=MAX_STEPS)
    ap.add_argument("--self-test", action="store_true",
                    help="3-step dry run with canned replies; prints PASS/FAIL")
    args = ap.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    if args.task_file:
        task = open(args.task_file, encoding="utf-8").read().strip()
    elif args.task:
        task = args.task
    else:
        ap.error("give a task or --task-file (or --self-test)")
    if not args.model_output_file:
        ap.error("--model-output-file is required (no model API wired yet)")

    run_id = args.run_id or time.strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(T.RUNS_DIR, run_id)
    os.makedirs(run_dir, exist_ok=True)
    registry = T.build_registry()
    backend = FileBackend(args.model_output_file)
    final = run_loop(task, backend, registry, run_dir,
                     os.path.join(run_dir, "approvals"),
                     max_steps=args.max_steps)
    print("\n=== FINAL ===\n%s" % final)
    print("\ntranscript: %s" % os.path.join(run_dir, "transcript.jsonl"))


if __name__ == "__main__":
    main()
