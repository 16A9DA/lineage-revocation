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

- `manager_multi_specialist` tasks 0, 4, 5: collection stalled (see
  `docs/duration-outlier-investigation.md`'s `manager_multi_specialist_02`
  entry — 8508s of that run's 8655s was API-side wait, same failure mode).
  Stopped 2026-08-23, not retried, no new traces produced for these three.
  The validated 33-trace dataset and existing raw/failed logs are untouched.
  Tasks 1, 2, 3 remain the only real `manager_multi_specialist` traces.
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
