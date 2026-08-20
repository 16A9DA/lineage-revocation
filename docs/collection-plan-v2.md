# Collection Plan v2

Covers what to collect next, if/when more real-trace collection is authorized. This is a plan, not a collection run — nothing here has been executed. It exists to fix the structural gap found in `docs/instrumentation-validity-evidence.md`: the current 33-trace dataset cannot show `max_depth > 1` or `fanout > 1` no matter what the model does, because every collected topology (`solo`, `manager_1`, `manager_2`) structurally caps them there.

## What each current cell can and can't inform

| workload group | topology | framework | model | n | can inform | cannot inform |
|---|---|---|---|---|---|---|
| simple_research, multi_step_research | solo | smolagents CodeAgent | qwen/qwen3.6-27b | 6 each | zero-delegation baseline | depth, fanout (0 managed agents, structurally) |
| technology_comparison, document_technical_analysis, manager_specialist_delegation | manager_1 | smolagents CodeAgent | qwen/qwen3.6-27b | 6 each | depth<=1, delegation propensity by prompt | fanout>1 (1 managed agent, structurally) |
| manager_multi_specialist | manager_2 | smolagents CodeAgent | qwen/qwen3.6-27b | 3 (6 planned, 3 pending — item 4) | fanout in {0,1,2} | depth>1; fanout>1 never observed behaviorally either (§5 of evidence package) |

No cell in the current plan can produce depth > 1 or fanout > 2 no matter how much more is collected under the same three topologies. v2 adds the topologies and one framework needed to actually reach those cells.

## New topologies (same framework: smolagents CodeAgent)

Both are direct extensions of the existing `_build(topology, model)` pattern in `experiments/runners/collect.py` — no new dependency, reuses the existing manager/CodeAgent scaffolding.

- **`chained_2`** (depth axis): manager -> mid_agent -> leaf_agent, three levels, one managed agent at each level. Structural depth ceiling = 2. Needed because every current topology structurally caps depth at 1.
- **`manager_4`** (fanout axis, CodeAgent): one manager, four managed leaf agents (research_agent, math_agent, unit_agent, lookup_agent). Structural fanout ceiling = 4. Still subject to the same behavioral risk found in `manager_multi_specialist` (§5 of the evidence package: registering more specialists doesn't mean the model calls them) — prompts must force multi-specialist use, see below.

## New framework: smolagents `ToolCallingAgent` (fanout axis, genuine parallel delegation)

Already installed (same `smolagents` package, different agent class — `CodeAgent` generates Python that calls managed agents sequentially in code; `ToolCallingAgent` uses native JSON tool-calling, where a single model turn can request multiple tool calls at once if the underlying model/provider supports parallel tool calls). Exposing managed agents as tools to a `ToolCallingAgent` manager and observing a single turn requesting 2+ managed-agent tool calls is a structurally different delegation mechanism than the current substring-match-on-generated-code approach, and is the one candidate here for **genuinely concurrent, model-decided multi-child delegation** rather than sequential Python calls.

This needs its own adapter path (a `ToolCallingAgent` raw trace records tool calls as structured JSON per turn, not as a Python code string — the current `smolagents_adapter.py`'s substring-match logic doesn't apply and shouldn't be forced to). Not built yet; scoped as its own implementation item, not bundled into this plan silently.

Before any real collection on this path: **smoke-test whether the selected model actually emits parallel tool calls on Groq at all.** This is the same category of risk that caused the `gpt-oss-120b` swap — not every model/provider combination reliably supports `parallel_tool_calls`, and finding that out mid-collection wastes a run. One task, `manager_4` topology via `ToolCallingAgent`, checked by hand before any n>1 collection.

## Prompt families

The evidence package (§6) found delegation propensity is prompt-driven far more than topology-driven — same `manager_1` topology, 1/6 vs 6/6 delegation rate depending on wording. v2 adds a prompt family designed against that finding, instead of hoping more managed agents alone produces more delegation:

- **`forced_multi_lookup`** (new): explicitly asks for N independently-sourced facts to be combined ("look up X, look up Y, look up Z, then combine them"), matching the phrasing style of `manager_specialist_delegation` (the one prompt family that got 6/6 delegation) rather than `document_technical_analysis`/`technology_comparison` (1/6 each). Used for both `manager_4`/CodeAgent and the `ToolCallingAgent` fanout cells. 6 prompts, mirroring the existing per-workload convention.
- Existing prompt families (`simple_research`, `multi_step_research`, `technology_comparison`, `document_technical_analysis`, `manager_specialist_delegation`, `manager_multi_specialist`) carry over unchanged for `chained_2` where relevant — reuse existing wording rather than inventing new tasks for a topology change alone.

## Proposed matrix (not yet run)

| cell | framework | topology | model | prompt family | target n | axis |
|---|---|---|---|---|---|---|
| A | CodeAgent | chained_2 | qwen/qwen3.6-27b | manager_specialist_delegation wording, adapted to 2-hop | 6 | depth |
| B | CodeAgent | manager_4 | qwen/qwen3.6-27b | forced_multi_lookup | 6 | fanout |
| C | ToolCallingAgent | manager_4 | qwen/qwen3.6-27b (pending smoke test) | forced_multi_lookup | 1 smoke test, then 6 | fanout, concurrency |

n=6 per cell follows the existing per-workload-group convention already used for all 33 collected traces, not a new invented number.

## Explicitly out of scope for this plan

- No new external framework/dependency (LangGraph, CrewAI, AutoGen, etc.) — `ToolCallingAgent` already covers the "genuine parallel delegation" requirement from within the installed `smolagents` package.
- No collection against `src/lineage_revocation/` — this plan is entirely about the smolagents measurement layer, same boundary as everything else in this dataset.
- No execution of this matrix yet. Only the 3 missing `manager_multi_specialist` tasks (item 4, existing `manager_2` topology, no new code needed) are authorized right now.
