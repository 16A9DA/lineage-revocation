# Measurement Pipeline Status

Milestone 1 (trustworthy measurement pipeline) per frozen spec §19/§20:
trace schema + parser + topology/distribution analysis + reproducible
histogram output. No revocation benchmarks yet (§20: do not tune synthetic
workloads before real-agent topology measurement is collected).

## Built

- `measurement/traces/schema.py` — `DelegationEvent`, `ToolCallEvent`, `Trace`.
- `measurement/traces/jsonl.py` — JSONL trace parser, one task's events per line,
  grouped by `task_id`. Event types: `delegation`, `tool_call`, `task_start`,
  `task_end`.
- `measurement/analysis/topology.py` — per-task `TraceMetrics`: num_agents,
  delegation_count, max_depth, fanout, tool_call_count,
  num_tool_participants, task_duration. Rejects multi-root and cyclic traces.
- `measurement/analysis/distributions.py` — `summarize()`: n, mean,
  p50/p95/p99, min, max (linear-interpolation percentiles, matches spec §19's
  P50/P95/P99 metric convention).
- `measurement/plots/histograms.py` — stdlib-only fixed-width-bin histogram,
  CSV export + text bar chart. No plotting dependency added.
- `measurement/report.py` — CLI: `python -m measurement.report <trace.jsonl> [--out-dir DIR]`.
- `tests/test_measurement.py` + `tests/fixtures/sample_trace.jsonl` — parser
  and analysis tests against a synthetic fixture (explicitly not a real
  measurement; used only to exercise the code paths).

## Not built yet

- `measurement/collectors/` — left empty. No live agent system is currently
  instrumented; building a collector without something to collect from would
  be speculative.
- Real trace ingestion — no real agent workload traces have been supplied
  yet. Every number this pipeline can currently produce is derived from the
  synthetic test fixture and must not be reported as a real measurement.
- Revocation benchmark harness (§19's actual sweep) — explicitly deferred
  until real topology parameters exist.

## Collection Plan v2 status (docs/collection-plan-v2.md)

- `manager_multi_specialist` tasks 0, 4, 5: retried 2026-08-23 via
  `python -m experiments.runners.collect manager_multi_specialist` (new
  `sys.argv` workload-id filter added to `collect.py main()`, scoped to this
  workload only so the still-unrun v2 cells couldn't fire by accident).
  Result, one attempt each recorded below (not the old "stopped, not
  retried" state — that line was stale as of this run):
  - Task 0 (France population): **SUCCESS**. New raw trace
    `manager_multi_specialist_00_1787459909.json`.
  - Task 4 (marathon world record): **FAILED**, 3/3 attempts,
    `AgentGenerationError`. Root cause confirmed directly: Groq returned
    `429 rate_limit_exceeded` — "tokens per day (TPD): Limit 200000, Used
    199624, Requested 2642" — i.e. task 0's run plus prior traffic exhausted
    the account's daily token quota mid-workload. New failure record
    `artifacts/raw_traces/failed/manager_multi_specialist_04_1787461492.json`.
  - Task 5 (Eiffel Tower height): **STOPPED**, not failed-out. Its first
    attempt was mid-flight against the same exhausted TPD quota when the
    run was deliberately killed (`kill`, exit 144) rather than burning two
    more guaranteed-429 attempts. No new raw or failed file was written for
    task 5 this run; the pre-existing
    `manager_multi_specialist_05_1787458507.json` failure record (from an
    earlier attempt, same connection-error signature) is untouched.
  - Independent confirmation the quota (not the model/key) is the blocker: a
    bare `curl` to `api.groq.com/v1/chat/completions` outside the collector
    returned `HTTP 200` at the same time task 4/5 were 429ing.
  - **Next run**: wait for the Groq TPD window to reset (429 body reported
    "try again in 16m18.912s" as of 2026-08-23 ~ time of the task-4
    failure) or for the next daily quota window, then rerun
    `python -m experiments.runners.collect manager_multi_specialist` — the
    workload-id filter makes this safe to rerun repeatedly; it skips any
    index that already has a non-`failed/` raw trace (task 0 will be
    skipped; only tasks 4 and 5 will attempt).
  The validated 33-trace dataset and pre-existing raw/failed logs are
  otherwise untouched. Tasks 0, 1, 2, 3 are now real `manager_multi_specialist`
  traces; 4 and 5 remain outstanding pending quota reset.
- Cell C smoke test (`ToolCallingAgent`, fanout axis) run 2026-08-23 via
  `experiments/runners/smoke_toolcalling.py` — one task, 2 managed specialists
  (`research_agent`, `math_agent`) rather than the full `manager_4` topology,
  scoped down per the smoke test's own purpose (governance/plumbing check,
  not a fanout=4 measurement). Result: `ToolCallingAgent` completed, both
  specialists were called, delegation events validated and
  `compute_metrics()` reported `fanout=[2]`, `max_depth=1` — but the two
  delegations were two separate single-tool-call turns (steps 1 and 2 of
  `manager_agent`), not one turn with 2+ tool calls. qwen/qwen3.6-27b on Groq
  did not exhibit parallel tool calling in this run; it used
  `ToolCallingAgent`'s JSON schema but called specialists one at a time, same
  as `CodeAgent` would. New adapter:
  `measurement/adapters/smolagents_toolcalling_adapter.py` (tool name ==
  registered agent name is delegation; existing `smolagents_adapter.py`'s
  substring-on-code-string match doesn't apply to this trace shape, per the
  plan). Full `manager_4`/n=6 collection under cell C not started — needs a
  decision on whether single-turn-only delegation is still worth collecting
  before spending real runs on it, since it wouldn't add depth/fanout data
  beyond what CodeAgent topologies already produce.
- Parallelism capability probe run 2026-08-23 via
  `experiments/runners/probe_toolcalling_parallelism.py` — 3 tasks using
  *independent* facts (no research->math data dependency, unlike the smoke
  test's task), to remove any structural reason for sequential ordering.
  Decisive finding from `probe_00_neutral` ("Eiffel Tower height" +
  "15 percent of 2000"): the model's raw `failed_generation` payload
  contained two consecutive `Action:` tool-call blocks in one generation —
  one for `research_agent`, one for `math_agent` — i.e. qwen/qwen3.6-27b
  does attempt same-turn multi-agent calls. Groq's tool-calling endpoint
  rejected it as malformed (`400 tool_use_failed`, "Failed to call a
  function"), and the whole task run failed with `AgentGenerationError`
  rather than falling back to one tool call. `probe_02_forced_multi_lookup`
  (boiling point + sqrt(144), from the earlier run) completed but with
  `delegation_count=0` — the manager answered both directly, including the
  arithmetic, without invoking `math_agent` at all. `probe_01` is
  inconclusive: killed by a local shell timeout mid-retry, not by a model or
  provider result; not rerun (see decision below on why not).
  **Decision: B.** Same-turn multi-agent calls are not usable with this
  model/provider configuration. Not "never attempted" (probe_00 shows the
  model does try) but "attempting it is worse than not delegating" — it
  produces a hard task failure instead of either parallel execution or a
  sequential fallback. Collecting `manager_4`/`ToolCallingAgent` traffic
  hoping for fanout>1 would mostly collect failed runs, not data. Proceeding
  with v2's fanout/depth collection (cells A/B, `CodeAgent`) using the
  topology this setup actually supports: sequential delegation, fanout
  capped by managed-agent count, no same-turn concurrency. Cell C (`manager_4`
  `ToolCallingAgent`, n=6) stays not started; worth revisiting only if a
  different model/provider is swapped in, not by retrying this one.
