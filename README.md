# Phoenix Harness v1

The body around the Phoenix brain. A stdlib-only ReAct loop
(think → act → observe) that executes tools the model proposes.
**The model proposes; the harness disposes.** All safety gates are enforced
in this code — never in the model.

Design: `../PHOENIX_HARNESS.md` §4 (OpenManus loop + open-Jarvis feature map).

## Files

- `phoenix.py` — the ReAct loop + CLI. `MAX_STEPS=20`, `MAX_OBSERVE=4000`.
- `tools.py` — the tool registry: real tools, tap-gated tools, and stubs.
- `.selftest_fixture.txt` — fixture used by `--self-test`.

## Tool-call protocol

The model emits exactly one tool call per reply, as a fenced block:

````tool:{"name":"web_search","args":{"query":"Walgreens Villa Park hiring"}} ````

No native function-calling is required — this is the plain-text protocol from
the minimal-Jarvis design, which is what Phoenix v2 will be trained on
(see `PHOENIX_HARNESS.md` §5 for the 42 training-pair topics).

## Running

```bash
# 3-step dry run (calc -> file_read -> terminate), prints PASS/FAIL
python3 phoenix.py --self-test

# a real task with canned model replies (one reply per step,
# steps separated by a line that is exactly "===STEP===")
python3 phoenix.py "check the weather in Villa Park" \
    --model-output-file replies.txt

# task from file, custom run id
python3 phoenix.py --task-file task.txt --model-output-file replies.txt \
    --run-id myrun-01
```

Every run logs to `genesis-os/state/phoenix_runs/<run_id>/transcript.jsonl`
(tool calls + observations + stops). `ask_brandon` writes the question to
`ask_brandon.txt` in the run dir and **stops the run** — Brandon's answer is
never fabricated.

## Tools (43 total)

Real now: `web_search` (Bing RSS via proxy curl), `web_fetch` / `web_shot`
(via `tools/webcrawl.py`), `weather` (Open-Meteo, no key, defaults to
Villa Park IL), `shell`, `file_read`, `file_write`, `file_edit`, `calc`,
`memory_search` (MEMORY.md + daily notes), `plan` (JSON-backed multi-step
plans), `job_scan`, `job_stage` (wraps `tools/stage.py`), `sprint` (read),
`money_log` (read), `growth` (read), `dragon` (read), `kaggle_run` (status only),
`image_search`, `image_generate` (via `media-generation` CLI),
`gmail_search`, `gmail_read`, `gmail_draft` (saves to Drafts, never sends),
`calendar_read`, `vekmem_recall` (wraps `tools/vekmem.py`), `tts_speak`
(via `tts` CLI, MP3 into the run dir), `stt_transcribe` (honest interface —
no offline model installed, never fakes), `llm_ask` (via the local Gemini
proxy when it's up, honest when it's down), `mcp` (minimal JSON-RPC stdio
client), `python_execute` (persistent `python3 -i` session, cwd-jailed),
`chart` (chart-spec JSON for the UI), `cron_list`, `ask_brandon`, `terminate`.

Tap-gated (refuse without `approvals/<gate>.approved`, real when approved):
`gmail_send`, `calendar_add`, `cron_add` (durable registry +
real `crontab` install when the binary exists), `schedule_delivery`
(durable per-run queue — a delivery runner must pick it up),
plus write sub-actions: `sprint done`, `money_log add`, `growth arm/tap`,
`dragon arm/tap`, `kaggle_run push`.

Always-refuse (the machine never does these on its own): `application_submit`,
`outreach_send`, `engine_arm`, `telegram_send`.

Honest stubs left: `delegate` (spawning subagents is a parent-agent
capability, not something the harness can do from inside a run).

## Hard gates (in code, not the model)

1. These tools **always refuse** unless the operator creates the per-run flag
   `state/phoenix_runs/<run_id>/approvals/<tool>.approved`:
   `gmail_send`, `application_submit`, `outreach_send`, `engine_arm`,
   `gpu_run`, `cron_add`, `telegram_send` — plus write sub-actions:
   `sprint done`, `money_log add`, `growth arm/tap`, `dragon arm/tap`,
   `kaggle_run push`. The machine never self-approves.
2. `file_*` tools are jailed to `~/workspace` (realpath-checked).
3. `shell`: cwd-jailed to `~/workspace`, 60s timeout, destructive-command
   blocklist (`rm -rf /`, `mkfs`, pipe-to-shell, …), `cd` escapes rejected,
   secrets scrubbed from output.
4. Nothing is ever deleted by the model — archive/void only, per standing rules.

## No model wired yet (by design)

`--model-output-file` feeds canned replies. To connect a real backend later,
implement the `ModelBackend.generate(messages)` interface in `phoenix.py`
(e.g. local Phoenix v2 inference or an OpenAI-compatible endpoint) and pass
the system prompt + tool specs already assembled in `run_loop`.

Phoenix v1 (training on Kaggle as of 2026-09-21) is chat-only and cannot use
this harness. Tool use needs the v2 fine-tune with the tool-use pairs —
the harness is ready and waiting for it.
