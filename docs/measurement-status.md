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
