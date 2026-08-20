# Instrumentation Validity Evidence Package

Scope: 33 real traces already collected. No new traces, no synthetic data, no protocol change, no depth/fanout sweep. This doc exists to answer one question before the controlled benchmark proceeds: is `max_depth <= 1` / `fanout <= 1` a real property of the collected agent workloads, or an artifact of the smolagents tracer?

## 1. Dataset

33 real traces, smolagents + Groq (`qwen/qwen3.6-27b`) + web_search/python_interpreter tools. 6 workload groups. Per-workload counts (measured, not designed — `manager_multi_specialist` only ran 3 of its 6 defined tasks before collection was stopped at 33):

| workload | topology | managed agents | n collected |
|---|---|---|---|
| simple_research | solo | 0 | 6 |
| multi_step_research | solo | 0 | 6 |
| technology_comparison | manager_1 | 1 (research_agent) | 6 |
| document_technical_analysis | manager_1 | 1 (research_agent) | 6 |
| manager_specialist_delegation | manager_1 | 1 (research_agent) | 6 |
| manager_multi_specialist | manager_2 | 2 (research_agent, math_agent) | 3 |

`solo` topology: single agent, no managed agents registered, delegation structurally impossible. `manager_1`: one managed agent registered, so any delegation from the manager has a structural fanout ceiling of 1 regardless of what the model does. `manager_2`: two managed agents registered, structural fanout ceiling of 2 — this is the only topology in the dataset where fanout > 1 was even possible.

## 2. Operational definition of a delegation edge (current instrumentation)

Source: `measurement/adapters/smolagents_adapter.py:15-40`.

A `tool_call` step is classified as a **delegation** edge, not a tool call, iff the raw code-execution string for that step (`tc["arguments"]`) contains the substring `"{other_agent_name}("` for some other agent name known to be registered in that trace (`raw["agents"].keys()`). If it matches, one `delegation` event is emitted, `parent_agent_id` = the executing agent, `agent_id` = the matched name. If no agent name is found in the code string, the step is emitted as a plain `tool_call` instead.

This is a **static substring match on the executed Python code of a CodeAgent step**, not an execution-trace-confirmed handoff. It fires on `agent_name(...)` appearing anywhere in the code string the step ran, including inside a comment, a string literal, or dead code that never actually executed a call. It has no negative case: it cannot represent "manager considered delegating and didn't."

## 3. What is and is not being measured

This pipeline measures **task-delegation structure** in a smolagents `CodeAgent` hierarchy: which agent's code, in which step, referenced which other agent's callable name. It does **not** measure credential-bearing authority transfer. No token, capability, credential, or lineage-key handoff is recorded or implied by a `delegation` event — the raw traces contain no such data, and the frozen protocol's revocation objects are not present anywhere in this measurement layer. Any use of this data as a proxy for lineage depth/fanout in the protocol's sense is an analogy, not a measurement of the protocol itself.

## 4. What the current tracer can and cannot observe

Can observe:
- One delegation edge per tool-call step, keyed on the first agent name matched in that step's code string.
- Sequential ordering of steps within a single agent (steps are already time-ordered in the raw trace).
- Repeated delegation from the same parent to the same child across separate steps (now correctly deduped into one edge with `delegation_count` > `len(fanout distinct children)`, per the topology fix already applied — see `manager_specialist_delegation_01..04`, all `delegation_count=2`, `fanout=[1]`, both edges to the same child).

Cannot observe:
1. **Concurrent/sibling delegation within one step.** `adapt()` uses `next(...)` to take the *first* matching agent name in a step's code string and stops (`smolagents_adapter.py:25-28`). If a single code block called two different managed agents (e.g. `research_agent(...)` then `math_agent(...)` in the same Python cell), only the first would be recorded as a delegation; the second reference would be silently dropped — not recorded as a second delegation, not recorded as a tool call, not recorded at all. Checked directly: grepped all 33 raw traces for any single tool-call step whose code string matches more than one registered agent name — **zero occurrences**. This limitation exists in the adapter but was not triggered by this dataset.
2. **True concurrency.** smolagents' `CodeAgent` executes one step at a time and each step's code runs synchronously; there is no async/parallel tool-call execution in this framework to instrument in the first place. "Sibling" delegation, if it occurred, would show up as two sequential events with distinct timestamps, not concurrent ones — moot here given (1) also found nothing.
3. **Downstream MCP/service activity.** `ToolCallEvent.server` (`measurement/traces/schema.py`) is never set by the adapter — every tool call is recorded with a `tool` name and timestamp only, never which downstream server/API/MCP endpoint it actually hit. `num_tool_participants` in the current dataset is therefore just `{(agent_id, None)}` deduped, i.e. it currently degenerates to counting distinct *agents* that made tool calls, not distinct downstream services. This is a real blind spot for anything below the agent layer.
4. **Delegation the model considered but didn't execute**, and any handoff that isn't expressed as a Python call syntactically matching `name(` (e.g. natural-language delegation, delegation via return value inspection, or any non-smolagents delegation mechanism) — not applicable to this framework/dataset but worth stating as a boundary of the operational definition.

## 5. Is fanout <= 1 genuine, or an instrumentation ceiling?

Two separate ceilings are in play, and they need to be told apart:

**Structural ceiling (topology, not instrumentation):** 30 of 33 traces come from `solo` or `manager_1` topologies, where fanout > 1 is *impossible by construction* — there's only zero or one managed agent registered. This is not something the tracer could ever have shown differently; it's a workload-design property, already stated in `experiments/configs/workloads.py`.

**Behavioral ceiling (the only place fanout > 1 could show up):** `manager_2` (`manager_multi_specialist`, n=3) is the only topology with two managed agents (`research_agent`, `math_agent`). Checked all 3 raw traces directly:

- `math_agent(` — 0 occurrences in any of the 3 traces.
- `"math_agent"` as a bare substring (i.e. even mentioned in an f-string, comment, or elsewhere) — exactly 1 occurrence per trace, consistent with it appearing only once in the manager's system/tool listing, not in any executed call.
- Manually inspected the step content: in `manager_multi_specialist_02`, the arithmetic that `math_agent` exists to do (light-travel-time from a distance in km) was instead computed by the manager itself, inline, in its own Python (`distance_km / 299_792.458 * ...`), rather than delegated.

So for these 3 traces, `math_agent` was registered and available every time, and never called — confirmed at the raw-trace level, not inferred from the adapter's output. The absence of fanout > 1 in this dataset is genuine model behavior (the manager chose to do the math itself), not the adapter dropping a second delegation edge that the model actually attempted. Given the earlier substring-match check in §4.1 also found no step with two agent-name matches, there's no dropped edge anywhere in the 33-trace dataset.

**Caveat:** n=3 for the only topology where this could have gone differently is a thin base for a general claim. This says "not observed in these 3," not "impossible in `manager_2` generally."

## 6. Delegation propensity is also lower than topology alone predicts

A second, independent finding, not about the tracer: even within `manager_1` workloads (fanout ceiling = 1, so this isn't a fanout question, it's a depth/delegation-frequency one), the manager frequently chose not to delegate at all, despite a managed agent being available every run:

| workload | delegated | did not delegate |
|---|---|---|
| document_technical_analysis | 1/6 | 5/6 |
| technology_comparison | 1/6 | 5/6 |
| manager_specialist_delegation | 6/6 | 0/6 |
| manager_multi_specialist | 3/3 | 0/3 |

Same `manager_1` topology, wildly different delegation rates by workload prompt (`document_technical_analysis`/`technology_comparison` vs `manager_specialist_delegation`). This is a prompt-design effect on model behavior, not a topology or instrumentation effect — flagging it because it's directly relevant to how "representative" any of these depth/fanout numbers are of anything beyond this specific set of 24 task prompts.

## 7. Full per-trace breakdown (33/33)

All 33 traces are scorable under the current (fixed) topology code — 0 excluded, 0 `TopologyError`, confirmed by both the standalone metrics script and by running `measurement.report` as a CLI over each workload group (§8) with no exceptions raised.

```
document_technical_analysis_00  agents=1 deleg=0 depth=0 fanout=[]  tool_calls=3 duration=25.33s
document_technical_analysis_01  agents=1 deleg=0 depth=0 fanout=[]  tool_calls=2 duration=30.87s
document_technical_analysis_02  agents=1 deleg=0 depth=0 fanout=[]  tool_calls=2 duration=23.91s
document_technical_analysis_03  agents=1 deleg=0 depth=0 fanout=[]  tool_calls=2 duration=2799.86s
document_technical_analysis_04  agents=2 deleg=1 depth=1 fanout=[1] tool_calls=4 duration=236.79s
document_technical_analysis_05  agents=1 deleg=0 depth=0 fanout=[]  tool_calls=2 duration=1.78s

manager_multi_specialist_01     agents=2 deleg=4 depth=1 fanout=[1] tool_calls=7 duration=816.10s
manager_multi_specialist_02     agents=2 deleg=3 depth=1 fanout=[1] tool_calls=2 duration=8655.29s
manager_multi_specialist_03     agents=2 deleg=2 depth=1 fanout=[1] tool_calls=4 duration=1482.89s

manager_specialist_delegation_00        agents=2 deleg=1 depth=1 fanout=[1] tool_calls=4 duration=56.82s
manager_specialist_delegation_01        agents=2 deleg=2 depth=1 fanout=[1] tool_calls=6 duration=404.59s
manager_specialist_delegation_02        agents=2 deleg=2 depth=1 fanout=[1] tool_calls=8 duration=357.80s
manager_specialist_delegation_03        agents=2 deleg=2 depth=1 fanout=[1] tool_calls=7 duration=429.80s
manager_specialist_delegation_04        agents=2 deleg=2 depth=1 fanout=[1] tool_calls=4 duration=151.70s
manager_specialist_delegation_first_run agents=2 deleg=1 depth=1 fanout=[1] tool_calls=5 duration=14.30s

multi_step_research_00  agents=1 deleg=0 depth=0 fanout=[] tool_calls=3 duration=28.74s
multi_step_research_01  agents=1 deleg=0 depth=0 fanout=[] tool_calls=3 duration=4.38s
multi_step_research_02  agents=1 deleg=0 depth=0 fanout=[] tool_calls=1 duration=1.29s
multi_step_research_03  agents=1 deleg=0 depth=0 fanout=[] tool_calls=2 duration=18.53s
multi_step_research_04  agents=1 deleg=0 depth=0 fanout=[] tool_calls=3 duration=31.97s
multi_step_research_05  agents=1 deleg=0 depth=0 fanout=[] tool_calls=1 duration=1.05s

simple_research_00  agents=1 deleg=0 depth=0 fanout=[] tool_calls=2 duration=2.19s
simple_research_01  agents=1 deleg=0 depth=0 fanout=[] tool_calls=2 duration=1.91s
simple_research_02  agents=1 deleg=0 depth=0 fanout=[] tool_calls=2 duration=1.88s
simple_research_03  agents=1 deleg=0 depth=0 fanout=[] tool_calls=2 duration=3.44s
simple_research_04  agents=1 deleg=0 depth=0 fanout=[] tool_calls=2 duration=2.31s
simple_research_05  agents=1 deleg=0 depth=0 fanout=[] tool_calls=3 duration=35.83s

technology_comparison_00  agents=2 deleg=1 depth=1 fanout=[1] tool_calls=3 duration=48.98s
technology_comparison_01  agents=1 deleg=0 depth=0 fanout=[] tool_calls=3 duration=44.84s
technology_comparison_02  agents=1 deleg=0 depth=0 fanout=[] tool_calls=3 duration=43.34s
technology_comparison_03  agents=1 deleg=0 depth=0 fanout=[] tool_calls=3 duration=42.39s
technology_comparison_04  agents=1 deleg=0 depth=0 fanout=[] tool_calls=3 duration=37.42s
technology_comparison_05  agents=1 deleg=0 depth=0 fanout=[] tool_calls=1 duration=32.45s
```

Full machine-readable version: `workload_table.json` (scratchpad, listed in §8 — not committed, regenerable from `experiments/traces/normalized/*.jsonl` via `measurement.analysis.topology.compute_metrics`).

## 8. Histograms and CSV outputs

Generated with the existing, unmodified `measurement.report` CLI (`python -m measurement.report <combined.jsonl> --out-dir <dir>`), run once over all 33 traces combined and once per workload group. All 7 runs completed with no `TopologyError`.

Location (scratchpad, not committed — regenerate anytime from `experiments/traces/normalized/`, script at `scratchpad/build_combined.py`):
```
evidence_package/csv/all_33/{max_depth,delegation_count,num_agents,tool_call_count,num_tool_participants,task_duration,fanout}.csv
evidence_package/csv/document_technical_analysis/...
evidence_package/csv/manager_multi_specialist/...
evidence_package/csv/manager_specialist_delegation/...
evidence_package/csv/multi_step_research/...        (no fanout.csv — 0 delegations, solo topology)
evidence_package/csv/simple_research/...             (no fanout.csv — 0 delegations, solo topology)
evidence_package/csv/technology_comparison/...
```

## 9. Real vs. synthetic

Everything in this doc is derived from the 33 already-collected real traces (`artifacts/raw_traces/`, `experiments/traces/normalized/`). No synthetic trace, no controlled benchmark run, no depth/fanout sweep was generated or executed for this package. The controlled benchmark stays parked pending review of this evidence.

## 10. Verification

- Protocol implementation untouched: `git diff --stat -- src/lineage_revocation/` → empty.
- Full test suite: `pytest -q` → 53 passed, 0 failed.
- Dataset: 33/33 traces scorable (0 `TopologyError`), independently confirmed via `measurement.report` CLI and via direct `compute_metrics` calls.

## Summary

- `max_depth <= 1` and `fanout <= 1` in this dataset are correctly measured given the current instrumentation, not an artifact of a bug or of the (real but untriggered) single-match adapter limitation.
- They are however largely a **structural** ceiling: 30/33 traces come from topologies where fanout > 1 is impossible by construction (`solo`, `manager_1`).
- Of the 3 traces where fanout > 1 was structurally possible (`manager_2`), it was **behaviorally** never exercised — `math_agent` was available and unused in all 3, confirmed at the raw-trace level.
- Depth itself was also frequently 0 even where delegation was possible (`manager_1` workloads), driven by prompt design, not topology or tracer limits.
- Real instrumentation gaps that exist but were not triggered by this specific dataset: same-step multi-agent delegation (silently drops the second edge), and downstream service/MCP-level visibility (`server` field never populated).
- Given all of this, the current 33-trace real dataset supports depth/fanout values as a *documented floor*, not as evidence that depth/fanout can't go higher — which is exactly why a controlled benchmark (separate, synthetic, clearly labeled, not yet started) is still the right next step once this package is reviewed.
