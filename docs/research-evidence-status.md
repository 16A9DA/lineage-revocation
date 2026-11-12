# Research Evidence Status

Date: 2026-11-12. Scope: real-agent measurement evidence only. No controlled benchmark exists or has been run; none is implemented until the supervisor approves the methodology in `docs/controlled-benchmark-design-v1.md`. Nothing below is estimated; items not measured are listed as outstanding.

Regenerate every number here with:
`python scripts/count_traces.py` (writes `artifacts/validation/trace-counts.json`) and `python scripts/refresh_corroboration.py` (writes `artifacts/validation/delegation-corroboration-refresh.json` and `docs/delegation-corroboration-refresh.md`).

## 1. Exact current trace counts

Verbatim output of `python scripts/count_traces.py`. Groq and Haiku are separate datasets and are never summed.

```
=== GROQ (groq; model: NOT RECORDED IN TRACES; see model_provenance) ===
raw artifacts/raw_traces: 34 files, 34 valid JSON, 0 invalid
normalized experiments/traces/normalized: 34 files, 34 valid, 0 invalid
failed records: 5 (0 invalid JSON)
raw without normalized: []  normalized without raw: []
model provenance (trace epoch vs swap commit): {'collected_after_swap_commit (consistent with qwen/qwen3.6-27b)': 1, 'collected_before_swap_commit (model unverified)': 33}
  condition manager_1/unaudited: 18
  condition manager_2/unaudited: 4
  condition solo/none: 12
  document_technical_analysis [manager_1] raw=6 present=[0, 1, 2, 3, 4, 5] missing=[] first_run=0 dup=[] failed=[] retry=[]
  manager_multi_specialist [manager_2] raw=4 present=[0, 1, 2, 3] missing=[4, 5] first_run=0 dup=[] failed=['0', '4', '5'] retry=[0]
  manager_specialist_delegation [manager_1] raw=6 present=[0, 1, 2, 3, 4] missing=[5] first_run=1 dup=[] failed=['3'] retry=[3]
      MISMATCH manager_specialist_delegation_first_run_1786944911.json: task text not in current workloads.py
  multi_step_research [solo] raw=6 present=[0, 1, 2, 3, 4, 5] missing=[] first_run=0 dup=[] failed=[] retry=[]
  simple_research [solo] raw=6 present=[0, 1, 2, 3, 4, 5] missing=[] first_run=0 dup=[] failed=[] retry=[]
  technology_comparison [manager_1] raw=6 present=[0, 1, 2, 3, 4, 5] missing=[] first_run=0 dup=[] failed=[] retry=[]
  exclusions: failed/ records x5 (attempts exhausted with provider errors; not traces; kept as evidence); stall_annotations.json x2 (NOT excluded; duration-only flag (API-wait stall lower bounds))

=== HAIKU (anthropic (OpenAI-compatible endpoint); model: claude-haiku-5-5) ===
raw artifacts/raw_traces_haiku: 12 files, 12 valid JSON, 0 invalid
normalized experiments/traces/normalized_haiku: 12 files, 12 valid, 0 invalid
failed records: 0 (0 invalid JSON)
raw without normalized: []  normalized without raw: []
  condition chained_2/elicited-by-topology: 6
  condition manager_4/elicited-by-prompt: 6
  forced_multi_lookup [manager_4] raw=6 present=[0, 1, 2, 3, 4, 5] missing=[] first_run=0 dup=[] failed=[] retry=[]
  manager_specialist_delegation_chained_2 [chained_2] raw=6 present=[0, 1, 2, 3, 4, 5] missing=[] first_run=0 dup=[] failed=[] retry=[]
  exclusions: failed/ records x0 (attempts exhausted with provider errors; not traces; kept as evidence)

=== SMOKE/PROBE (separate, not pooled) === 4 json (4 valid), 4 jsonl (4 valid)
Datasets are reported separately; no cross-dataset total is computed.

JSON: artifacts/validation/trace-counts.json
```

Reading notes (all from that output):
- Groq: 34 raw, 34 normalized, 5 failed records, 0 invalid JSON. `manager_multi_specialist` has indices 0 to 3 (missing 4, 5). `manager_specialist_delegation` has indices 0 to 4 plus one `first_run` file whose task text is not in `workloads.py` (missing index 5).
- Haiku: 12 raw, 12 normalized, 0 failed records, 0 invalid JSON, no missing indices.
- Duplicates: no index has more than one raw trace. Retries after a failure record: Groq `manager_multi_specialist` index 0 and `manager_specialist_delegation` index 3.
- The earlier documents' "33" is the historical set; the disk now holds 34 Groq files (the extra one is `manager_multi_specialist_00_1787459909`).

## 2. Verified evidence

| item | result | source |
|---|---|---|
| Adapter corroboration, Groq original 33 | 33 processed, 33 valid, 21 delegation events, 21 corroborated, 0 failures; reproduces the stored historical JSON | `docs/delegation-corroboration-refresh.md` |
| Adapter corroboration, Groq current 34 | 34 / 34, 23 events, 23 corroborated, 0 failures | same |
| Adapter corroboration, Haiku 12 | 12 / 12, 36 events, 36 corroborated, 0 failures; 11 of 12 topology-scorable | same |
| Delegation depth, Groq | max depth 0 in 22 traces, 1 in 12; never above 1 | refresh JSON |
| Delegation depth, Haiku `chained_2` | max depth 2 in 5 scorable traces; trace 02 unscorable | refresh JSON; `docs/chained2-trace02-investigation.md` |
| Delegation breadth, Haiku `forced_multi_lookup` | depth 1; at most 2 distinct children; sequential | refresh JSON |
| Failure records preserved | 5 Groq records, 0 Haiku | `trace-counts.json` |
| Tests | see section 8 | pytest |

"Corroborated" means the child agent has timed activity in the raw trace. It does not say the delegation was useful or well-formed.

## 3. Outstanding experiments (not done)

- `manager_multi_specialist` indices 4 and 5 (Groq): no successful trace. Not retried since 2026-08-23. A retry on Haiku would be a different cell, not a completion of this one.
- `manager_specialist_delegation` index 5 (Groq): missing; a `first_run` trace with a different prompt exists but does not replace it.
- Haiku `chained_2` rerun with per-invocation memory capture, needed to confirm the trace 02 mechanism. Not run.
- F-par (genuine parallel fanout): no smoke test passed on any provider. See section 7.
- Natural-delegation audit of the Groq `manager_*` prompts. Not done.
- Controlled benchmark: blocked on supervisor approval of the five decisions in `docs/controlled-benchmark-design-review.md` section 3. No code written.

## 4. Missing artifacts

- Per-trace provider/model. Raw traces do not record it. Per `trace-counts.json`, 33 of 34 Groq traces have a filename epoch earlier than commit `58cd04b` (collector changed from `openai/gpt-oss-120b` to `qwen/qwen3.6-27b`); the first trace came from a runner naming `llama-3.3-70b-versatile`. Commit time is not collection time, so this is a bound, not proof. Earlier documents that call the whole Groq corpus `qwen/qwen3.6-27b` are not supported by trace data. Resolving this needs the original collection logs or environment of those runs; not available in the repository.
- Per-workload natural-versus-elicited metadata. The `ELICITATION` table in `scripts/count_traces.py` is a researcher label, not stored with the traces.
- `docs/measurement-status.md`: deleted from tracking in `c75be4e`; recoverable from git history; not restored.
- `docs/` is gitignored, so all documents here (and these new ones) are local only. `scripts/`, `artifacts/validation/*.json` and `tests/test_count_traces.py` are untracked and uncommitted until the supervisor or user decides.
- Haiku duration annotations. `experiments/traces/stall_annotations.json` covers two Groq traces only. Haiku `chained_2` traces 00 to 03 were collected before the timeout fix and have unreliable durations (trace 03 about 10134 s, trace 02 about 1672 s).
- Spec check: whether the spec requires a signature on the status artifact (the code has none). Flagged in the design review, not checked.
- `docs/instrumentation-validity-evidence.md` still quotes 33 traces and 53 passing tests and points at a scratchpad script. Left unmodified as historical evidence; superseded by this file for counts and tests.

## 5. Instrumentation limitations

- Memory reset (OBSERVED in smolagents 1.26.0 source): `MultiStepAgent.run` resets memory by default, and the collector serializes memory once after the run. If a managed agent is invoked twice, only the last invocation is recorded. This caused or contributed to the missing mid -> leaf link in `chained_2` trace 02 and means step and delegation counts for repeatedly invoked managed agents are lower bounds. See `docs/chained2-trace02-investigation.md`.
- The `CodeAgent` adapter detects delegation by the substring `agent_name(` in generated code, then requires timed child activity. It can miss calls whose code does not contain that literal, and cannot see calls lost to the reset above.
- `CodeAgent` executes generated code synchronously; same-code-block calls to two children are sequential, not parallel evidence.
- smolagents caps code execution at 30 s; several manager steps record that error, then re-invoke the child.
- Provider/model is not stored in traces (section 4).

## 6. Natural versus elicited

| evidence | class | what it can support |
|---|---|---|
| Groq `simple_research`, `multi_step_research` | solo agent, no delegation possible | zero-delegation baseline |
| Groq `technology_comparison`, `document_technical_analysis`, `manager_specialist_delegation` | prompts not audited | prompt-dependent delegation rate (documented 1/6, 1/6 and 6/6 in `docs/instrumentation-validity-evidence.md`); not shown to be natural |
| Groq `manager_multi_specialist` | prompts ask for lookup then compute; not audited | sequential use of two named specialists, depth 0/1; incomplete (4 of 6) |
| Haiku `chained_2` | **elicited by topology** (manager's only agent is mid; mid's only agent is leaf; prompts identical to `manager_specialist_delegation`) | depth 2 is reachable and observable when the structure forces it |
| Haiku `forced_multi_lookup` | **elicited by prompt** (prompt lists the lookup/convert/combine steps) | sequential breadth up to 2 distinct children |

Supported statement: "Real agent stacks produce depth-2 delegation when the topology and task demand it." Not supported: that ordinary workloads commonly reach depth 2, or that any measured delegation rate is the natural propensity of a model. Groq and Haiku are different models and providers; no cross-dataset comparison is made.

## 7. Parallel fanout status

No real trace shows same-step parallel delegation. Groq `probe_00_neutral` ended in HTTP 400 `tool_use_failed` after generating two tool-call blocks. The preserved ToolCallingAgent smoke trace has `fanout=[2]` from two separate manager turns. Haiku has never been smoke-tested for same-step multi-tool calls; the probe and smoke runners now point at Haiku (commit `375b5fc`) but were not rerun. F-par remains a gated, unexecuted plan item.

## 8. Test results

- 2026-11-12: `python -m pytest -q` in `.venv` (Python 3.12.2, smolagents 1.26.0): **61 passed in 19.64s**. This is the earlier 60 plus the new `tests/test_count_traces.py`. The "53 passed" in `docs/instrumentation-validity-evidence.md` and the 60 at commit `375b5fc` are older runs.
- `src/lineage_revocation/`: no files modified (see validation output in the session report; `git diff --stat -- src/lineage_revocation/` empty).
