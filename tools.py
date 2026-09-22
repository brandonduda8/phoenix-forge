#!/usr/bin/env python3
"""Phoenix harness v1 — tool registry (stdlib-only).

Every tool is a plain function: fn(args: dict, ctx: dict) -> str.
ctx carries: run_id, run_dir, approvals_dir, genesis root, workspace root.
43 tools: real implementations plus tap-gated and honest stubs.

Safety gates live HERE, in code — never in the model:
  * TAP_GATED tools refuse unless state/phoenix_runs/<run_id>/approvals/<tool>.approved exists.
  * file_* tools are jailed to ~/workspace.
  * shell has a destructive-command blocklist, a cwd jail, a 60s timeout,
    and secret-scrubbing on output.
"""
import ast
import html
import json
import math
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.parse

HOME = os.path.expanduser("~")
WORKSPACE = os.path.join(HOME, "workspace")
GENESIS = os.path.join(WORKSPACE, "genesis-os")
TOOLS_DIR = os.path.join(GENESIS, "tools")
RUNS_DIR = os.path.join(GENESIS, "state", "phoenix_runs")
PLANS_FILE = os.path.join(GENESIS, "state", "phoenix_plans.json")
SHELL_TIMEOUT = 60
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"

# ---------------------------------------------------------------- gates

# Tools that NEVER execute without a per-run approval flag file:
#   state/phoenix_runs/<run_id>/approvals/<tool>.approved
TAP_GATED = {
    "gmail_send", "application_submit", "outreach_send", "engine_arm",
    "gpu_run", "cron_add", "telegram_send",
    "sprint_done", "money_add", "growth_arm", "dragon_arm",
    "calendar_add", "schedule_delivery",
}

# Sub-action gates for multi-use tools: (tool, action) -> gate name
SUB_GATES = {
    ("sprint", "done"): "sprint_done",
    ("money_log", "add"): "money_add",
    ("growth", "arm"): "growth_arm",
    ("growth", "tap"): "growth_arm",
    ("dragon", "arm"): "dragon_arm",
    ("dragon", "tap"): "dragon_arm",
    ("kaggle_run", "push"): "gpu_run",
}


def _approved(ctx, gate):
    flag = os.path.join(ctx["approvals_dir"], gate + ".approved")
    return os.path.isfile(flag)


def _gate_refused(tool, gate):
    return (
        "REFUSED: '%s' needs Brandon's tap. Nothing was executed.\n"
        "To approve this run only, the operator creates:\n"
        "  state/phoenix_runs/<run_id>/approvals/%s.approved\n"
        "then the run may be retried. I never self-approve." % (tool, gate)
    )


# ---------------------------------------------------------------- shell safety

BLOCKED_SHELL = [
    r"rm\s+(-[rf]+\s+)+/(?:\s|$)", r"rm\s+(-[rf]+\s+)+~(?:\s|$)",
    r"\bmkfs\b", r"\bdd\s+.*of=/dev/", r":\(\)\s*\{",
    r"\b(shutdown|reboot|poweroff|halt)\b",
    r"chmod\s+-R\s+.*\s+/(?:\s|$)", r"chown\s+-R\s+.*\s+/(?:\s|$)",
    r"\|\s*(ba)?sh\s*$", r"curl\b.*\|\s*(ba)?sh", r"wget\b.*\|\s*(ba)?sh",
    r">\s*/dev/sd[a-z]", r"\betc/passwd", r"\betc/shadow",
]
BLOCKED_SHELL_RE = [re.compile(p) for p in BLOCKED_SHELL]

SECRET_RE = [
    (re.compile(r"(?i)(api[_-]?key|password|passwd|secret|bearer|token)\s*[:=]\s*['\"]?\S+"),
     lambda m: m.group(1) + "=[REDACTED]"),
    (re.compile(r"nvapi-[A-Za-z0-9_\-]{8,}"), lambda m: "nvapi-[REDACTED]"),
]


def _scrub(text):
    for rx, rep in SECRET_RE:
        text = rx.sub(rep, text)
    return text


def _jail_ok(path):
    real = os.path.realpath(path)
    return real == WORKSPACE or real.startswith(WORKSPACE + os.sep)


def tool_shell(args, ctx):
    cmd = args.get("command", "").strip()
    if not cmd:
        return "ERROR: 'command' is required."
    for rx in BLOCKED_SHELL_RE:
        if rx.search(cmd):
            return "REFUSED: command matches the destructive-command blocklist. Not executed."
    # block `cd` escapes out of the workspace jail
    for m in re.finditer(r"(?:^|[;&|])\s*cd\s+(\S+)", cmd):
        dest = os.path.realpath(os.path.join(WORKSPACE, os.path.expanduser(m.group(1))))
        if not (dest == WORKSPACE or dest.startswith(WORKSPACE + os.sep)):
            return "REFUSED: 'cd' outside ~/workspace is not allowed."
    try:
        p = subprocess.run(cmd, shell=True, cwd=WORKSPACE, capture_output=True,
                           text=True, timeout=SHELL_TIMEOUT)
        out = (p.stdout or "") + (p.stderr or "")
        out = _scrub(out)
        tail = out[-3500:]
        return "exit=%d\n%s" % (p.returncode, tail if tail.strip() else "(no output)")
    except subprocess.TimeoutExpired:
        return "ERROR: timed out after %ds." % SHELL_TIMEOUT
    except Exception as e:
        return "ERROR: %s" % e


# ---------------------------------------------------------------- file tools (jailed)

def _wpath(path):
    if not path:
        return None
    p = os.path.realpath(os.path.join(WORKSPACE, os.path.expanduser(path)))
    return p if _jail_ok(p) else None


def tool_file_read(args, ctx):
    p = _wpath(args.get("path", ""))
    if not p:
        return "REFUSED: path is outside ~/workspace."
    if not os.path.isfile(p):
        return "ERROR: file not found: %s" % args.get("path")
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except Exception as e:
        return "ERROR: %s" % e
    if len(data) > 6000:
        data = data[:6000] + "\n...[truncated %d chars]" % (len(data) - 6000)
    return data


def tool_file_write(args, ctx):
    p = _wpath(args.get("path", ""))
    if not p:
        return "REFUSED: path is outside ~/workspace."
    content = args.get("content", "")
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        return "OK: wrote %d bytes to %s" % (len(content), os.path.relpath(p, WORKSPACE))
    except Exception as e:
        return "ERROR: %s" % e


def tool_file_edit(args, ctx):
    p = _wpath(args.get("path", ""))
    if not p:
        return "REFUSED: path is outside ~/workspace."
    old, new = args.get("old_text", ""), args.get("new_text", "")
    if not old:
        return "ERROR: 'old_text' is required."
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except Exception as e:
        return "ERROR: %s" % e
    if old not in data:
        return "ERROR: old_text not found in file (no changes made)."
    data = data.replace(old, new, 1)
    with open(p, "w", encoding="utf-8") as f:
        f.write(data)
    return "OK: replaced 1 occurrence in %s" % os.path.relpath(p, WORKSPACE)


# ---------------------------------------------------------------- web tools

def _curl(url, timeout=25):
    p = subprocess.run(
        ["curl", "-s", "--max-time", str(timeout), "-A", UA, url],
        capture_output=True, text=True, timeout=timeout + 10,
        env={**os.environ})
    return p.stdout if p.returncode == 0 else ""


def tool_web_search(args, ctx):
    q = args.get("query", "").strip()
    if not q:
        return "ERROR: 'query' is required."
    url = "https://www.bing.com/search?q=%s&format=rss" % urllib.parse.quote_plus(q)
    xml = _curl(url)
    items = re.findall(r"<item>.*?</item>", xml, re.S)
    if not items:
        return "No results (search backend returned nothing — say so, do not invent results)."
    out = []
    for it in items[:8]:
        ti = re.search(r"<title>(.*?)</title>", it, re.S)
        li = re.search(r"<link>(.*?)</link>", it, re.S)
        de = re.search(r"<description>(.*?)</description>", it, re.S)
        title = html.unescape(re.sub(r"<!\[CDATA\[|\]\]>", "", ti.group(1)).strip()) if ti else ""
        link = html.unescape(li.group(1).strip()) if li else ""
        desc = html.unescape(re.sub(r"<[^>]+>", "", de.group(1)).strip())[:200] if de else ""
        out.append("- %s\n  %s%s" % (title[:100], link[:120], ("\n  " + desc) if desc else ""))
    return "\n".join(out)


def tool_web_fetch(args, ctx):
    url = args.get("url", "").strip()
    if not url:
        return "ERROR: 'url' is required."
    try:
        p = subprocess.run([sys.executable, os.path.join(TOOLS_DIR, "webcrawl.py"),
                            "md", url],
                           capture_output=True, text=True, timeout=150, cwd=GENESIS)
        out = (p.stdout or "") + (p.stderr or "")
        if not out.strip():
            return "ERROR: fetch returned nothing."
        return out[:6000]
    except subprocess.TimeoutExpired:
        return "ERROR: fetch timed out."
    except Exception as e:
        return "ERROR: %s" % e


def tool_web_shot(args, ctx):
    url = args.get("url", "").strip()
    if not url:
        return "ERROR: 'url' is required."
    n = len([f for f in os.listdir(ctx["run_dir"]) if f.startswith("shot_")])
    out = os.path.join(ctx["run_dir"], "shot_%d.png" % n)
    try:
        p = subprocess.run([sys.executable, os.path.join(TOOLS_DIR, "webcrawl.py"),
                            "shot", url, out],
                           capture_output=True, text=True, timeout=150, cwd=GENESIS)
        if os.path.isfile(out):
            return "OK: screenshot saved to %s" % os.path.relpath(out, WORKSPACE)
        return "ERROR: screenshot failed: %s" % (p.stderr or p.stdout)[:300]
    except subprocess.TimeoutExpired:
        return "ERROR: screenshot timed out."
    except Exception as e:
        return "ERROR: %s" % e


def tool_weather(args, ctx):
    lat = args.get("lat", 41.886)
    lon = args.get("lon", -87.981)  # default: Villa Park, IL
    url = ("https://api.open-meteo.com/v1/forecast?latitude=%s&longitude=%s"
           "&current=temperature_2m,relative_humidity_2m,weathercode,wind_speed_10m"
           "&daily=temperature_2m_max,temperature_2m_min,precipitation_probability_max"
           "&temperature_unit=fahrenheit&timezone=America%%2FChicago" % (lat, lon))
    raw = _curl(url)
    try:
        d = json.loads(raw)
        cur = d.get("current", {})
        day = d.get("daily", {})
        return ("Villa Park, IL now: %sF, humidity %s%%, wind %s mph. "
                "Today: high %sF / low %sF, precip chance %s%%." % (
                    cur.get("temperature_2m"), cur.get("relative_humidity_2m"),
                    cur.get("wind_speed_10m"),
                    (day.get("temperature_2m_max") or [None])[0],
                    (day.get("temperature_2m_min") or [None])[0],
                    (day.get("precipitation_probability_max") or [None])[0]))
    except Exception:
        return "ERROR: weather backend returned unparseable data."


# ---------------------------------------------------------------- misc safe tools

def tool_calc(args, ctx):
    expr = args.get("expr", "").strip()
    if args.get("now"):
        return time.strftime("Now: %A %Y-%m-%d %H:%M %Z (America/Chicago)")
    if not expr:
        return "ERROR: 'expr' is required (or pass now=true)."
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        return "ERROR: bad expression: %s" % e
    allowed = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
               ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
               ast.Pow, ast.USub, ast.UAdd, ast.Load)
    for node in ast.walk(tree):
        if not isinstance(node, allowed):
            return "REFUSED: only plain arithmetic is allowed."
        if isinstance(node, ast.Constant) and not isinstance(node.value, (int, float)):
            return "REFUSED: only numbers allowed."
    try:
        return str(eval(compile(tree, "<calc>", "eval"), {"__builtins__": {}}, {}))
    except Exception as e:
        return "ERROR: %s" % e


def tool_memory_search(args, ctx):
    q = args.get("query", "").strip().lower()
    if not q:
        return "ERROR: 'query' is required."
    words = [w for w in re.findall(r"[a-z0-9]+", q) if len(w) > 2]
    if not words:
        return "ERROR: query has no searchable words."
    files = []
    for base in (os.path.join(HOME, "MEMORY.md"),):
        if os.path.isfile(base):
            files.append(base)
    mdir = os.path.join(HOME, "memory")
    if os.path.isdir(mdir):
        for f in sorted(os.listdir(mdir)):
            if f.endswith(".md"):
                files.append(os.path.join(mdir, f))
    hits = []
    for fp in files:
        try:
            lines = open(fp, encoding="utf-8", errors="replace").read().splitlines()
        except Exception:
            continue
        for i, line in enumerate(lines):
            low = line.lower()
            score = sum(2 if w in low.split() else 1 for w in words if w in low)
            if score and line.strip():
                hits.append((score, fp, i + 1, line.strip()[:220]))
    hits.sort(reverse=True)
    if not hits:
        return "No memory hits for that query."
    out = []
    for score, fp, ln, txt in hits[:5]:
        out.append("[%s:%d] %s" % (os.path.basename(fp), ln, txt))
    return "\n".join(out)


def _load_plans():
    if os.path.isfile(PLANS_FILE):
        try:
            return json.load(open(PLANS_FILE))
        except Exception:
            return {}
    return {}


def tool_plan(args, ctx):
    action = args.get("action", "list")
    plans = _load_plans()
    if action == "create":
        pid = "plan-%d" % int(time.time())
        steps = [{"text": s, "status": "todo"} for s in args.get("steps", [])]
        plans[pid] = {"title": args.get("title", pid), "steps": steps,
                      "created": time.strftime("%Y-%m-%d %H:%M")}
        json.dump(plans, open(PLANS_FILE, "w"), indent=1)
        return "OK: created %s with %d steps." % (pid, len(steps))
    if action == "list":
        if not plans:
            return "No plans."
        return "\n".join("- %s: %s (%d steps)" % (pid, p["title"], len(p["steps"]))
                         for pid, p in plans.items())
    pid = args.get("plan_id", "")
    if pid not in plans:
        return "ERROR: unknown plan_id. Use action=list."
    p = plans[pid]
    if action == "show":
        lines = ["%s: %s" % (pid, p["title"])]
        for i, s in enumerate(p["steps"]):
            lines.append("  [%d] %s — %s" % (i, s["status"], s["text"][:100]))
        return "\n".join(lines)
    if action == "mark_step":
        i = int(args.get("step", -1))
        st = args.get("status", "done")
        if not (0 <= i < len(p["steps"])):
            return "ERROR: bad step index."
        p["steps"][i]["status"] = st
        json.dump(plans, open(PLANS_FILE, "w"), indent=1)
        return "OK: step %d marked %s." % (i, st)
    if action == "delete":
        del plans[pid]
        json.dump(plans, open(PLANS_FILE, "w"), indent=1)
        return "OK: deleted %s." % pid
    return "ERROR: unknown action. Use create|list|show|mark_step|delete."


# ---------------------------------------------------------------- Genesis system wrappers

def _run_script(name, argv, timeout=120):
    try:
        p = subprocess.run([sys.executable, os.path.join(TOOLS_DIR, name)] + argv,
                           capture_output=True, text=True, timeout=timeout, cwd=GENESIS)
        out = _scrub((p.stdout or "") + (p.stderr or ""))
        return out.strip()[:4000] or "(no output)"
    except subprocess.TimeoutExpired:
        return "ERROR: %s timed out." % name
    except Exception as e:
        return "ERROR: %s" % e


def tool_job_scan(args, ctx):
    return _run_script("job_scan.py", [], timeout=180)


def tool_sprint(args, ctx):
    action = args.get("action", "progress")
    if action == "done":
        if not _approved(ctx, "sprint_done"):
            return _gate_refused("sprint done", "sprint_done")
        jid = str(args.get("id", "")).strip()
        if not jid:
            return "ERROR: 'id' is required."
        return _run_script("sprint.py", ["done", jid])
    if action in ("queue", "progress"):
        return _run_script("sprint.py", [action])
    return "ERROR: unknown action. Use queue|progress|done (done needs Brandon's tap)."


def tool_money_log(args, ctx):
    action = args.get("action", "summary")
    if action == "add":
        if not _approved(ctx, "money_add"):
            return _gate_refused("money_log add", "money_add")
        kind = args.get("kind", "")
        amount = str(args.get("amount", ""))
        note = args.get("note", "")
        if kind not in ("income", "expense") or not amount or not note:
            return "ERROR: kind=income|expense, amount, note are required."
        return _run_script("money_log.py", ["add", "--kind", kind, "--amount", amount,
                                            "--note", note])
    if action == "summary":
        return _run_script("money_log.py", ["summary"])
    return "ERROR: unknown action. Use summary|add (add needs Brandon's tap)."


def tool_growth(args, ctx):
    action = args.get("action", "status")
    if action in ("arm", "tap"):
        if not _approved(ctx, "growth_arm"):
            return _gate_refused("growth " + action, "growth_arm")
        target = str(args.get("target", "")).strip()
        if not target:
            return "ERROR: 'target' engine id is required."
        return _run_script("growth.py", [action, target])
    if action in ("list", "show", "status", "next", "revenue"):
        argv = [action] + ([str(args.get("target", ""))] if args.get("target") else [])
        return _run_script("growth.py", argv)
    return "ERROR: unknown action."


def tool_dragon(args, ctx):
    action = args.get("action", "status")
    if action in ("arm", "tap"):
        if not _approved(ctx, "dragon_arm"):
            return _gate_refused("dragon " + action, "dragon_arm")
        target = str(args.get("target", "")).strip()
        if not target:
            return "ERROR: 'target' engine id is required."
        return _run_script("dragon.py", [action, target])
    if action in ("list", "show", "status", "next", "revenue"):
        argv = [action] + ([str(args.get("target", ""))] if args.get("target") else [])
        return _run_script("dragon.py", argv)
    return "ERROR: unknown action."


def tool_kaggle_run(args, ctx):
    action = args.get("action", "status")
    slug = args.get("slug", "brandonduda/phoenix-forge-v1-gpt-oss-20b-lora")
    cli = os.path.join(WORKSPACE, "skills", "kaggle", "bin", "kaggle.py")
    if action == "status":
        try:
            p = subprocess.run([sys.executable, cli, "status", slug],
                               capture_output=True, text=True, timeout=60)
            return (p.stdout or p.stderr).strip()[:1000]
        except Exception as e:
            return "ERROR: %s" % e
    if action == "push":
        if not _approved(ctx, "gpu_run"):
            return _gate_refused("kaggle_run push", "gpu_run")
        return "APPROVED flag present — push is executed by the operator, not the model."
    return "ERROR: unknown action. Use status|push (push needs Brandon's tap)."


# ---------------------------------------------------------------- human loop

class StopRun(Exception):
    def __init__(self, summary):
        self.summary = summary


def tool_ask_brandon(args, ctx):
    question = args.get("question", "").strip()
    if not question:
        return "ERROR: 'question' is required."
    path = os.path.join(ctx["run_dir"], "ask_brandon.txt")
    with open(path, "a", encoding="utf-8") as f:
        f.write(time.strftime("[%Y-%m-%d %H:%M] ") + question + "\n")
    raise StopRun("STOPPED: asked Brandon — '%s'. The run pauses here; "
                  "his answer is never fabricated." % question[:160])


def tool_terminate(args, ctx):
    summary = args.get("summary", "").strip() or "(no summary given)"
    raise StopRun(summary)


# ---------------------------------------------------------------- stubs (v1: not yet implemented)

def _stub(name, note):
    def fn(args, ctx):
        return ("STUB: '%s' is not implemented in harness v1 yet. %s "
                "I do not pretend it ran." % (name, note))
    fn.__name__ = "tool_" + name
    return fn


# ---------------------------------------------------------------- registry

def _t(name, desc, fn):
    return {"name": name, "desc": desc, "fn": fn}


def build_registry():
    reg = {}
    for name, desc, fn in [
        ("web_search", "Web search. args: {query}. Returns titles, URLs, snippets.",
         tool_web_search),
        ("web_fetch", "URL -> markdown via webcrawl.py. args: {url}.", tool_web_fetch),
        ("web_shot", "URL -> PNG screenshot saved in the run dir. args: {url}.", tool_web_shot),
        ("weather", "Weather via Open-Meteo (no key). args: {lat?, lon?} default Villa Park IL.",
         tool_weather),
        ("shell", "Run a shell command. args: {command}. Cwd-jailed to ~/workspace, 60s timeout, destructive commands blocked.",
         tool_shell),
        ("file_read", "Read a workspace file. args: {path} (relative to ~/workspace).",
         tool_file_read),
        ("file_write", "Create/overwrite a workspace file. args: {path, content}.",
         tool_file_write),
        ("file_edit", "Surgical edit of a workspace file. args: {path, old_text, new_text}.",
         tool_file_edit),
        ("calc", "Safe arithmetic. args: {expr} or {now: true}.", tool_calc),
        ("memory_search", "Keyword search over MEMORY.md + daily notes. args: {query}.",
         tool_memory_search),
        ("plan", "Multi-step plan. args: {action: create|list|show|mark_step|delete, ...}.",
         tool_plan),
        ("job_scan", "Run the Genesis job-alert swarm scan. args: {} (takes ~1 min).",
         tool_job_scan),
        ("sprint", "Job-sprint tracker. args: {action: queue|progress|done, id?}. 'done' needs Brandon's tap.",
         tool_sprint),
        ("money_log", "Money ledger. args: {action: summary|add, ...}. 'add' needs Brandon's tap.",
         tool_money_log),
        ("growth", "Growth Division. args: {action: status|list|next|show|revenue, target?}. arm/tap need Brandon's tap.",
         tool_growth),
        ("dragon", "Dragon revenue engines. args: {action: status|list|next|show|revenue, target?}. arm/tap need Brandon's tap.",
         tool_dragon),
        ("kaggle_run", "Kaggle GPU kernels. args: {action: status|push, slug?}. push needs Brandon's tap (finite GPU hours).",
         tool_kaggle_run),
        ("ask_brandon", "Ask Brandon a question / request a tap. args: {question}. STOPS the run.",
         tool_ask_brandon),
        ("terminate", "End the run with a summary. args: {summary}.", tool_terminate),
        ("job_stage", "Stage a VERIFIED opening into candidates.json. args: {title, company, url, tier: REMOTE|VILLA_PARK, pay?, notes?, source?}. Never stage unverified listings.",
         tool_job_stage),
        ("image_search", "Web image search. args: {query, max_results?}. Returns image URLs + source pages.",
         tool_image_search),
        ("gmail_search", "Search Gmail (read-only). args: {query, max?}. Returns sender/subject/date + message ids.",
         tool_gmail_search),
        ("gmail_read", "Read a Gmail message (read-only). args: {id} (a message id from gmail_search).",
         tool_gmail_read),
        ("gmail_draft", "Save a Gmail draft (nothing sent). args: {to, subject, body, cc?, bcc?, html?}.",
         tool_gmail_draft),
        ("calendar_read", "Read Google Calendar agenda. args: {days?}.",
         tool_calendar_read),
        ("calendar_add", "Create a calendar event. args: {summary, start (RFC3339), end?, location?, description?, attendees?}. NEEDS Brandon's tap.",
         tool_calendar_add),
        ("vekmem_recall", "Vector recall over prospects/jobs/research. args: {query, top?}.",
         tool_vekmem_recall),
        ("tts_speak", "Text -> spoken MP3 saved in the run dir. args: {text (max 2000 chars), voice?, language?, speed?}.",
         tool_tts_speak),
        ("image_generate", "Generate an image via the media pipeline, saved in the run dir. args: {prompt, orientation?: square|vertical|landscape}.",
         tool_image_generate),
        ("stt_transcribe", "Transcribe an audio file (workspace path). args: {path}. Offline model not installed — reports honestly instead of faking.",
         tool_stt_transcribe),
        ("llm_ask", "Sub-call to Gemini for heavy reasoning via the local proxy. args: {prompt, system?, model?, max_tokens?}. Honest if the proxy is down.",
         tool_llm_ask),
        ("delegate", "Spawn a subagent for a self-contained task.",
         _stub("delegate", "Spawning subagents is a parent-agent capability; the harness cannot do it from inside a run.")),
        ("gmail_send", "Send an email. args: {to, subject, body}. ALWAYS needs Brandon's tap.",
         tool_gmail_send),
        ("application_submit", "Submit a job application. ALWAYS Brandon's tap — the machine never submits.",
         lambda a, c: _gate_refused("application_submit", "application_submit")),
        ("outreach_send", "Send outreach/audit emails. ALWAYS Brandon's per-batch approval.",
         lambda a, c: _gate_refused("outreach_send", "outreach_send")),
        ("engine_arm", "Arm a Dragon/Growth engine. ALWAYS Brandon's tap.",
         lambda a, c: _gate_refused("engine_arm", "engine_arm")),
        ("telegram_send", "Send a Telegram message. ALWAYS Brandon's tap.",
         lambda a, c: _gate_refused("telegram_send", "telegram_send")),
        ("cron_add", "Schedule a reminder/recurring task (durable registry; real crontab install when available). args: {schedule (5-field cron), command, note?}. ALWAYS Brandon's tap.",
         tool_cron_add),
        ("cron_list", "List recorded cron entries. args: {scope?: run|all} (read-only).",
         tool_cron_list),
        ("mcp", "Minimal JSON-RPC MCP client over stdio. args: {command (server launch), method?, params?, timeout?}. Server commands are blocklist-checked.",
         tool_mcp),
        ("python_execute", "Run Python in a PERSISTENT session (variables survive across calls). args: {code, session?: name, reset?: true}. Cwd-jailed to ~/workspace, non-interactive only.",
         tool_python_execute),
        ("chart", "Emit a chart-spec JSON (UI renders it; no image deps). args: {type: bar|line|pie, title?, labels:[], series:[{name, values:[]}]}.",
         tool_chart),
        ("schedule_delivery", "Queue a future Telegram/email delivery (durable queue; a runner must pick it up). args: {deliver_at, channel: telegram|email, content, to?}. ALWAYS Brandon's tap.",
         tool_schedule_delivery),
    ]:
        reg[name] = _t(name, desc, fn)
    return reg


# ================================================================ v2 tools
# Real implementations for the v1 stubs. Stdlib only; skill CLIs via
# subprocess. All pre-existing gates are preserved: tap-gated tools stay
# tap-gated, file tools stay jailed, shell keeps its blocklist.

import datetime
import queue
import socket
import threading
import urllib.error
import urllib.request

GWS = "/opt/hatch/bin/hatch_gws_cli"
TTS_BIN = "/opt/hatch/bin/tts"
MG_BIN = "/opt/hatch/bin/media-generation"
IMGSEARCH_BIN = "/opt/hatch/bin/image-search"
GEMINI_PROXY_PORT = 18789
CRON_REGISTRY = os.path.join(GENESIS, "state", "phoenix_cron.json")


def _gws(argv, timeout=120):
    """Run hatch_gws_cli with an argv list (no shell). Returns (rc, output)."""
    try:
        p = subprocess.run([GWS] + argv, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, _scrub(((p.stdout or "") + (p.stderr or "")).strip())
    except subprocess.TimeoutExpired:
        return 124, "ERROR: timed out."
    except Exception as e:
        return 1, "ERROR: %s" % e


def _gws_offline(out):
    low = out.lower()
    return ("not_connected" in low or "not connected" in low
            or "connect_url" in low or "missing access_token" in low)


def _find_text(obj, keys=("body", "text", "plain_text", "snippet"), depth=0):
    """Tolerant recursive text finder for unknown JSON shapes."""
    if depth > 4:
        return None
    if isinstance(obj, dict):
        for k in keys:
            v = obj.get(k)
            if isinstance(v, str) and v.strip():
                return v
        for v in obj.values():
            r = _find_text(v, keys, depth + 1)
            if r:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = _find_text(v, keys, depth + 1)
            if r:
                return r
    return None


def _summarize_gmail_json(out, max_items=10):
    try:
        d = json.loads(out)
    except Exception:
        return out[:2000] if out else "(empty response)"
    items = None
    if isinstance(d, list):
        items = d
    elif isinstance(d, dict):
        for k in ("messages", "results", "items", "threads", "data"):
            if isinstance(d.get(k), list):
                items = d[k]
                break
    if not items:
        return json.dumps(d)[:2000]
    lines = []
    for m in items[:max_items]:
        if isinstance(m, dict):
            frm = str(m.get("from") or m.get("sender") or "")[:60]
            subj = str(m.get("subject") or "")[:80]
            date = str(m.get("date") or "")[:30]
            mid = str(m.get("id") or m.get("message_id") or m.get("thread_id") or "")
            snip = str(m.get("snippet") or "")[:120]
            line = "- %s | %s | %s" % (frm, subj, date)
            if snip:
                line += "\n  %s" % snip
            if mid:
                line += "\n  id: %s" % mid
            lines.append(line)
        else:
            lines.append("- %s" % str(m)[:160])
    more = len(items) - max_items
    if more > 0:
        lines.append("... and %d more" % more)
    return "\n".join(lines)


# ---------------------------------------------------------------- TTS / STT / media

def tool_tts_speak(args, ctx):
    text = args.get("text", "").strip()
    if not text:
        return "ERROR: 'text' is required."
    if len(text) > 2000:
        return "ERROR: text too long (max 2000 chars per speak call)."
    voice = str(args.get("voice", "avocado_v2:MAI_03"))
    n = len([f for f in os.listdir(ctx["run_dir"]) if f.startswith("tts_")])
    out = os.path.join(ctx["run_dir"], "tts_%d.mp3" % n)
    cmd = [TTS_BIN, "speak", "--text", text, "--output", out,
           "--voice", voice, "--timeout-secs", "180"]
    if args.get("language"):
        cmd += ["--language", str(args["language"])]
    if args.get("speed"):
        cmd += ["--speed", str(args["speed"])]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    except subprocess.TimeoutExpired:
        return "ERROR: TTS timed out after 240s."
    except Exception as e:
        return "ERROR: %s" % e
    if os.path.isfile(out) and os.path.getsize(out) > 0:
        return "OK: audio saved to %s (%d bytes), voice %s." % (
            os.path.relpath(out, WORKSPACE), os.path.getsize(out), voice)
    return "ERROR: TTS failed: %s" % ((p.stderr or p.stdout or "")[:500])


def tool_stt_transcribe(args, ctx):
    p = _wpath(args.get("path", ""))
    if not p:
        return "REFUSED: path is outside ~/workspace."
    if not os.path.isfile(p):
        return "ERROR: audio file not found: %s" % args.get("path")
    for mod in ("faster_whisper", "whisper", "vosk"):
        try:
            __import__(mod)
            return ("ERROR: '%s' is importable but no transcription backend is "
                    "wired yet — report this to the operator." % mod)
        except ImportError:
            continue
    return ("NOT AVAILABLE: no offline speech-to-text model is installed "
            "(checked faster-whisper, whisper, vosk — none present, and the "
            "harness installs nothing). The audio file exists at %s and is "
            "ready; I will not fake a transcript." %
            os.path.relpath(p, WORKSPACE))


def tool_image_generate(args, ctx):
    prompt = args.get("prompt", "").strip()
    if not prompt:
        return "ERROR: 'prompt' is required."
    orientation = str(args.get("orientation", "square")).lower()
    if orientation not in ("square", "vertical", "landscape"):
        return "ERROR: orientation must be square|vertical|landscape."
    n = len([d for d in os.listdir(ctx["run_dir"]) if d.startswith("img_")])
    outdir = os.path.join(ctx["run_dir"], "img_%d" % n)
    os.makedirs(outdir, exist_ok=True)
    cmd = [MG_BIN, prompt, "--output-dir", outdir, "--orientation", orientation,
           "--image-output-format", "png", "--timeout-secs", "300"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=330)
    except subprocess.TimeoutExpired:
        return "ERROR: image generation timed out after 330s."
    except Exception as e:
        return "ERROR: %s" % e
    found = []
    for root, _, files in os.walk(outdir):
        for f in files:
            if f.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
                fp = os.path.join(root, f)
                if os.path.getsize(fp) > 1024:
                    found.append(fp)
    if found:
        found.sort(key=os.path.getmtime)
        return "OK: image generated -> %s" % os.path.relpath(found[-1], WORKSPACE)
    tail = ((p.stdout or "") + (p.stderr or ""))[-600:]
    return "ERROR: generation produced no image file. CLI said: %s" % _scrub(tail)


def tool_image_search(args, ctx):
    q = args.get("query", "").strip()
    if not q:
        return "ERROR: 'query' is required."
    try:
        maxr = max(1, min(int(args.get("max_results", 5)), 10))
    except Exception:
        maxr = 5
    try:
        p = subprocess.run([IMGSEARCH_BIN, q, "--max-results", str(maxr)],
                           capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        return "ERROR: image search timed out."
    except Exception as e:
        return "ERROR: %s" % e
    out = (p.stdout or "").strip()
    if not out:
        return "ERROR: image search returned nothing: %s" % (p.stderr or "")[:200]
    try:
        d = json.loads(out)
        items = d if isinstance(d, list) else (d.get("results") or d.get("items") or [])
        lines = []
        for it in items[:maxr]:
            if isinstance(it, dict):
                url = (it.get("media_url") or it.get("thumbnail_cdn_url")
                       or it.get("url") or "")
                page = it.get("source_page") or it.get("page_url") or ""
                lines.append("- %s%s" % (url, (" (page: %s)" % page) if page else ""))
            else:
                lines.append("- %s" % str(it)[:200])
        return "\n".join(lines) if lines else out[:2000]
    except Exception:
        return out[:2000]


# ---------------------------------------------------------------- Gmail (draft free, send tap-gated)

def tool_gmail_search(args, ctx):
    q = args.get("query", "").strip()
    if not q:
        return "ERROR: 'query' is required."
    try:
        maxn = max(1, min(int(args.get("max", 10)), 50))
    except Exception:
        maxn = 10
    rc, out = _gws(["gmail", "+triage", "--query", q, "--max", str(maxn),
                    "--format", "json"])
    if _gws_offline(out):
        return "Gmail is not connected — search not run. Nothing invented."
    if rc != 0 and not out.lstrip().startswith(("{", "[")):
        return "ERROR: %s" % out[:800]
    return _summarize_gmail_json(out, maxn)


def tool_gmail_read(args, ctx):
    mid = str(args.get("id", "")).strip()
    if not mid:
        return "ERROR: 'id' (a message id from gmail_search) is required."
    rc, out = _gws(["gmail", "+read", "--id", mid, "--format", "json"])
    if _gws_offline(out):
        return "Gmail is not connected — read not run."
    try:
        d = json.loads(out)
    except Exception:
        return out[:3000] if out else "ERROR: empty response."
    subj = d.get("subject", "") if isinstance(d, dict) else ""
    frm = d.get("from", "") if isinstance(d, dict) else ""
    body = _find_text(d) or ""
    text = ("From: %s\nSubject: %s\n\n%s" % (frm, subj, body[:3000])).strip()
    return text if text else json.dumps(d)[:3000]


def tool_gmail_draft(args, ctx):
    to = args.get("to", "").strip()
    subject = args.get("subject", "").strip()
    body = args.get("body", "")
    if not to or not subject or not body:
        return "ERROR: 'to', 'subject', 'body' are required."
    cmd = ["gmail", "+draft", "--to", to, "--subject", subject, "--body", body]
    for flag, key in (("--cc", "cc"), ("--bcc", "bcc")):
        if args.get(key):
            cmd += [flag, str(args[key])]
    if args.get("html"):
        cmd.append("--html")
    rc, out = _gws(cmd)
    if _gws_offline(out):
        return "Gmail is not connected — draft NOT saved."
    if rc != 0:
        return "ERROR saving draft: %s" % out[:800]
    return ("OK: draft saved to Gmail Drafts (to=%s, subject=%s). "
            "Nothing was sent." % (to, subject))


def tool_gmail_send(args, ctx):
    if not _approved(ctx, "gmail_send"):
        return _gate_refused("gmail_send", "gmail_send")
    to = args.get("to", "").strip()
    subject = args.get("subject", "").strip()
    body = args.get("body", "")
    if not to or not subject or not body:
        return "ERROR: 'to', 'subject', 'body' are required."
    rc, out = _gws(["gmail", "+send", "--to", to, "--subject", subject,
                    "--body", body])
    if _gws_offline(out):
        return "Gmail is not connected — NOT sent."
    if rc != 0:
        return "ERROR sending: %s" % out[:800]
    return "SENT (approved for this run only): to=%s subject=%s" % (to, subject)


# ---------------------------------------------------------------- Calendar (read free, add tap-gated)

def tool_calendar_read(args, ctx):
    try:
        days = max(1, min(int(args.get("days", 7)), 30))
    except Exception:
        days = 7
    rc, out = _gws(["calendar", "+agenda", "--days", str(days), "--format", "json"])
    if _gws_offline(out):
        return ("Google Calendar is not connected — agenda not read. "
                "Nothing invented.")
    if rc != 0 and not out.lstrip().startswith(("{", "[")):
        return "ERROR: %s" % out[:800]
    return out[:3500] if out else "(no events in range)"


def tool_calendar_add(args, ctx):
    if not _approved(ctx, "calendar_add"):
        return _gate_refused("calendar_add", "calendar_add")
    summary = args.get("summary", "").strip()
    start = args.get("start", "").strip()
    if not summary or not start:
        return "ERROR: 'summary' and 'start' (RFC3339 datetime) are required."
    end = args.get("end", "").strip()
    if not end:
        try:
            dt = datetime.datetime.fromisoformat(start)
            end = (dt + datetime.timedelta(hours=1)).isoformat()
        except Exception:
            return ("ERROR: 'start' is not parseable RFC3339 "
                    "(e.g. 2026-09-23T14:00:00-05:00); pass 'end' explicitly.")
    event = {"summary": summary,
             "start": {"dateTime": start}, "end": {"dateTime": end}}
    for k in ("location", "description"):
        if args.get(k):
            event[k] = str(args[k])
    if args.get("attendees"):
        att = args["attendees"]
        att = att if isinstance(att, list) else [att]
        event["attendees"] = [{"email": str(a)} for a in att]
    rc, out = _gws(["calendar", "events", "insert",
                    "--params", json.dumps({"calendarId": "primary"}),
                    "--json", json.dumps(event)])
    if _gws_offline(out):
        return "Google Calendar is not connected — event NOT created."
    if rc != 0:
        return "ERROR creating event: %s" % out[:800]
    return "OK (approved for this run only): event '%s' at %s." % (summary, start)


# ---------------------------------------------------------------- cron (tap-gated, durable registry)

def _load_cron_registry():
    if os.path.isfile(CRON_REGISTRY):
        try:
            return json.load(open(CRON_REGISTRY))
        except Exception:
            return []
    return []


def tool_cron_add(args, ctx):
    if not _approved(ctx, "cron_add"):
        return _gate_refused("cron_add", "cron_add")
    schedule = args.get("schedule", "").strip()
    command = args.get("command", "").strip()
    note = str(args.get("note", ""))
    if not schedule or not command:
        return "ERROR: 'schedule' (5-field cron) and 'command' are required."
    if len(schedule.split()) != 5:
        return "ERROR: schedule must be a 5-field cron expression."
    for rx in BLOCKED_SHELL_RE:
        if rx.search(command):
            return "REFUSED: command matches the destructive-command blocklist."
    reg = _load_cron_registry()
    entry = {"id": "phx-cron-%d" % int(time.time()), "run_id": ctx["run_id"],
             "schedule": schedule, "command": command, "note": note,
             "created": time.strftime("%Y-%m-%d %H:%M"), "installed": False}
    try:
        cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True,
                             timeout=15)
        lines = cur.stdout.splitlines() if cur.returncode == 0 else []
        have_crontab = True
    except FileNotFoundError:
        lines, have_crontab = None, False
    except Exception:
        lines, have_crontab = None, False
    if not have_crontab:
        entry["install_note"] = ("no crontab binary on this host — entry is "
                                 "durable in the registry; the operator installs it")
    else:
        new_line = "%s %s  # phoenix %s %s" % (schedule, command, entry["id"], note)
        data = "\n".join(lines + [new_line]) + "\n"
        ins = subprocess.run(["crontab", "-"], input=data, capture_output=True,
                             text=True, timeout=15)
        entry["installed"] = (ins.returncode == 0)
        if ins.returncode != 0:
            entry["install_note"] = ins.stderr.strip()[:200]
    reg.append(entry)
    os.makedirs(os.path.dirname(CRON_REGISTRY), exist_ok=True)
    json.dump(reg, open(CRON_REGISTRY, "w"), indent=1)
    msg = ("OK (approved for this run only): cron entry %s recorded\n"
           "  %s %s\n  installed=%s" % (entry["id"], schedule, command,
                                       entry["installed"]))
    if entry.get("install_note"):
        msg += "\n  note: " + entry["install_note"]
    return msg


def tool_cron_list(args, ctx):
    reg = _load_cron_registry()
    scope = str(args.get("scope", "run"))
    items = reg if scope == "all" else [e for e in reg
                                        if e.get("run_id") == ctx["run_id"]]
    if not items:
        return "No cron entries recorded."
    return "\n".join("- %s | %s | %s | installed=%s%s" % (
        e["id"], e["schedule"], e["command"][:80], e.get("installed"),
        (" | " + e["note"][:60]) if e.get("note") else "") for e in items)


# ---------------------------------------------------------------- scheduled delivery (tap-gated queue)

def tool_schedule_delivery(args, ctx):
    if not _approved(ctx, "schedule_delivery"):
        return _gate_refused("schedule_delivery", "schedule_delivery")
    deliver_at = args.get("deliver_at", "").strip()
    channel = str(args.get("channel", "")).strip().lower()
    content = args.get("content", "").strip()
    if channel not in ("telegram", "email"):
        return "ERROR: channel must be telegram|email."
    if not deliver_at or not content:
        return "ERROR: 'deliver_at' (ISO datetime) and 'content' are required."
    qpath = os.path.join(ctx["run_dir"], "scheduled.json")
    queue = []
    if os.path.isfile(qpath):
        try:
            queue = json.load(open(qpath))
        except Exception:
            queue = []
    item = {"id": "sched-%d" % int(time.time()), "deliver_at": deliver_at,
            "channel": channel, "to": str(args.get("to", "")), "content": content,
            "status": "queued", "created": time.strftime("%Y-%m-%d %H:%M")}
    queue.append(item)
    json.dump(queue, open(qpath, "w"), indent=1)
    return ("OK (approved for this run only): delivery %s queued for %s via %s "
            "(position %d).\nNOTE: the queue is durable at %s — nothing delivers "
            "it on its own; a delivery runner must pick it up."
            % (item["id"], deliver_at, channel, len(queue),
               os.path.relpath(qpath, WORKSPACE)))


# ---------------------------------------------------------------- MCP client (minimal JSON-RPC over stdio)

class _StreamReader:
    """Blocking-readline pump: a daemon thread drains the stream into a queue.

    select() on a buffered text stream is racy — data can sit in the userspace
    buffer while select() reports 'not ready' — so we never select. The thread
    always drains; readers take lines from the queue with a timeout.
    """

    def __init__(self, stream):
        self._q = queue.Queue()
        self._t = threading.Thread(target=self._run, args=(stream,), daemon=True)
        self._t.start()

    def _run(self, stream):
        try:
            for line in stream:
                self._q.put(line)
        except Exception:
            pass
        finally:
            self._q.put(None)  # EOF marker

    def readline(self, timeout):
        try:
            line = self._q.get(timeout=max(0.1, timeout))
        except queue.Empty:
            return None
        return line  # None means EOF


def tool_mcp(args, ctx):
    command = args.get("command", "")
    method = str(args.get("method", "tools/list"))
    params = args.get("params", {})
    if not isinstance(params, dict):
        return "ERROR: 'params' must be an object."
    try:
        timeout = max(5, min(int(args.get("timeout", 30)), 120))
    except Exception:
        timeout = 30
    if isinstance(command, list):
        argv = [str(c) for c in command]
        cmd_str = " ".join(argv)
    elif isinstance(command, str) and command.strip():
        cmd_str = command.strip()
        argv = []
    else:
        return "ERROR: 'command' (MCP server launch) is required."
    if not argv:
        for rx in BLOCKED_SHELL_RE:
            if rx.search(cmd_str):
                return ("REFUSED: server command matches the "
                        "destructive-command blocklist.")
        argv = shlex.split(cmd_str)
    if not argv:
        return "ERROR: could not parse server command."
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, cwd=WORKSPACE,
                                bufsize=1)
    except Exception as e:
        return "ERROR: could not launch MCP server: %s" % e
    try:
        reader = _StreamReader(proc.stdout)

        def rpc(mid, meth, prm):
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": mid,
                                         "method": meth, "params": prm}) + "\n")
            proc.stdin.flush()

        def wait_for(mid, secs):
            end = time.time() + secs
            while time.time() < end:
                line = reader.readline(max(0.5, end - time.time()))
                if line is None:
                    return None
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except Exception:
                    continue
                if msg.get("id") == mid:
                    return msg
            return None

        rpc(1, "initialize",
            {"protocolVersion": "2024-11-05", "capabilities": {},
             "clientInfo": {"name": "phoenix-harness", "version": "1"}})
        init = wait_for(1, timeout)
        if not init or init.get("error"):
            return "ERROR: MCP initialize failed: %s" % json.dumps(init)[:500]
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method":
                                     "notifications/initialized"}) + "\n")
        proc.stdin.flush()
        rpc(2, method, params)
        resp = wait_for(2, timeout)
        if resp is None:
            return "ERROR: MCP server gave no response to '%s'." % method
        if resp.get("error"):
            return "MCP error: %s" % json.dumps(resp["error"])[:1000]
        return "MCP '%s' result:\n%s" % (method,
                                        json.dumps(resp.get("result"), indent=1)[:3000])
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


# ---------------------------------------------------------------- python_execute (persistent session)

_PY_SESSIONS = {}
_PY_SENTINEL = "<<<PHX_END>>>"


def _py_exchange(s, code, timeout=30, drain_only=False):
    proc = s["proc"]
    reader = s["reader"]
    if drain_only:
        payload = "print('%s')\n" % _PY_SENTINEL
    else:
        payload = code.rstrip("\n") + "\n\nprint('%s')\n" % _PY_SENTINEL
    try:
        proc.stdin.write(payload)
        proc.stdin.flush()
    except Exception as e:
        return None, "ERROR: session stdin broken (%s)." % e
    out, saw = [], False
    end = time.time() + timeout
    while time.time() < end:
        line = reader.readline(max(0.5, end - time.time()))
        if line is None:
            break
        if _PY_SENTINEL in line:
            saw = True
            break
        if line.strip():
            out.append(line)
    if not saw and not drain_only:
        if proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
            return None, ("ERROR: timed out waiting for output — the code may be "
                          "waiting on input(). Session killed; retry with "
                          "non-interactive code.")
        return None, "ERROR: python session died unexpectedly."
    return _scrub("".join(out)), None


def _py_get(sid):
    s = _PY_SESSIONS.get(sid)
    if s is not None and s["proc"].poll() is None:
        return s
    try:
        proc = subprocess.Popen(
            [sys.executable, "-u", "-i"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            cwd=WORKSPACE, bufsize=1)
    except Exception as e:
        return {"error": str(e)}
    s = {"proc": proc, "reader": _StreamReader(proc.stdout)}
    _PY_SESSIONS[sid] = s
    _py_exchange(s, "", drain_only=True)  # clear the startup banner
    return s


def tool_python_execute(args, ctx):
    sid = str(args.get("session", "main"))
    if args.get("reset"):
        s = _PY_SESSIONS.pop(sid, None)
        if s:
            try:
                s["proc"].kill()
            except Exception:
                pass
        return "OK: python session '%s' reset." % sid
    code = args.get("code", "")
    if not code.strip():
        return "ERROR: 'code' is required."
    s = _py_get(sid)
    if "error" in s:
        return "ERROR: could not start python: %s" % s["error"]
    if s["proc"].poll() is not None:
        _PY_SESSIONS.pop(sid, None)
        return "ERROR: python session died; retry (a fresh one starts automatically)."
    text, err = _py_exchange(s, code)
    if err:
        _PY_SESSIONS.pop(sid, None)
        return err
    text = (text or "").strip() or "(no output)"
    return "session=%s\n%s" % (sid, text[-3500:])


# ---------------------------------------------------------------- chart spec (no rendering deps)

def tool_chart(args, ctx):
    ctype = str(args.get("type", "bar")).lower()
    if ctype not in ("bar", "line", "pie"):
        return "ERROR: type must be bar|line|pie."
    labels = args.get("labels", [])
    series = args.get("series", [])
    if not isinstance(labels, list) or not isinstance(series, list) or not series:
        return "ERROR: 'labels' (list) and 'series' (non-empty list of {name, values}) are required."
    for se in series:
        if not isinstance(se, dict) or not isinstance(se.get("values"), list):
            return "ERROR: each series needs {name, values:[...]}."
        if len(se["values"]) != len(labels):
            return ("ERROR: series '%s' has %d values but there are %d labels." %
                    (se.get("name"), len(se["values"]), len(labels)))
    spec = {"chart": ctype, "title": str(args.get("title", "")),
            "labels": [str(l) for l in labels],
            "series": [{"name": str(se.get("name", "")),
                        "values": se["values"]} for se in series]}
    n = len([f for f in os.listdir(ctx["run_dir"])
             if f.startswith("chart_") and f.endswith(".json")])
    path = os.path.join(ctx["run_dir"], "chart_%d.json" % n)
    json.dump(spec, open(path, "w"), indent=1)
    return ("OK: %s chart spec written to %s — '%s', %d labels x %d series. "
            "Render it in the UI; the harness does no image rendering."
            % (ctype, os.path.relpath(path, WORKSPACE), spec["title"],
               len(labels), len(series)))


# ---------------------------------------------------------------- remaining Genesis wrappers

def tool_job_stage(args, ctx):
    title = args.get("title", "").strip()
    company = args.get("company", "").strip()
    url = args.get("url", "").strip()
    tier = str(args.get("tier", "")).strip().upper()
    if not title or not company or not url:
        return "ERROR: 'title', 'company', 'url' are required."
    if tier not in ("REMOTE", "VILLA_PARK"):
        return "ERROR: tier must be REMOTE|VILLA_PARK."
    argv = ["--title", title, "--company", company, "--url", url, "--tier", tier]
    for flag, key in (("--pay", "pay"), ("--notes", "notes"), ("--source", "source")):
        if args.get(key):
            argv += [flag, str(args[key])]
    return _run_script("stage.py", argv)


def tool_vekmem_recall(args, ctx):
    q = args.get("query", "").strip()
    if not q:
        return "ERROR: 'query' is required."
    try:
        top = str(max(1, min(int(args.get("top", 5)), 20)))
    except Exception:
        top = "5"
    return _run_script("vekmem.py", ["search", q, "--top", top])


def tool_llm_ask(args, ctx):
    prompt = args.get("prompt", "").strip()
    if not prompt:
        return "ERROR: 'prompt' is required."
    model = str(args.get("model", "gemini-3.6-flash"))
    system = str(args.get("system", ""))
    try:
        max_tokens = max(64, min(int(args.get("max_tokens", 1024)), 8192))
    except Exception:
        max_tokens = 1024
    try:
        sock = socket.create_connection(("127.0.0.1", GEMINI_PROXY_PORT), timeout=5)
        sock.close()
    except Exception:
        return ("NOT AVAILABLE: the local Gemini proxy is not listening on "
                "127.0.0.1:%d. Start it with: python3 tools/gemini_proxy.py "
                "(from genesis-os/). I will not fake the answer." % GEMINI_PROXY_PORT)
    msgs = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    body = json.dumps({"model": model, "messages": msgs,
                       "max_tokens": max_tokens}).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:%d/v1/chat/completions" % GEMINI_PROXY_PORT,
        data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            d = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return "ERROR: proxy HTTP %s: %s" % (e.code, e.read().decode("utf-8", "replace")[:300])
    except Exception as e:
        return "ERROR: %s" % e
    try:
        text = d["choices"][0]["message"]["content"]
    except Exception:
        return "ERROR: unexpected proxy response shape."
    return str(text)[:4000]
