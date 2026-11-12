# Collection Plan v2

> **Corrected 2026-11-12.** The pre-correction text is preserved unchanged in `docs/collection-plan-v2.original-2026-08.md`. Counts below come from `scripts/count_traces.py` (`artifacts/validation/trace-counts.json`) and `scripts/refresh_corroboration.py` (`docs/delegation-corroboration-refresh.md`); do not maintain counts by hand.
>
> | # | earlier statement | corrected statement | evidence |
> |---|---|---|---|
> | 1 | "33 traces collected with ... Groq `qwen/qwen3.6-27b`" | 34 Groq raw traces. The model is **not recorded in any trace file**. 33 of 34 have a filename epoch earlier than commit `58cd04b`, which changed the collector from `openai/gpt-oss-120b` to `qwen/qwen3.6-27b`; the first trace came from a runner that named `llama-3.3-70b-versatile`. Commit `181b408` labels two of them qwen. Model per trace is therefore **unverified** for most of the Groq corpus. | `trace-counts.json` `model_provenance`; `git show 58cd04b`, `87f188d`, `7726f33` |
> | 2 | D2 (`chained_2`) uses Groq `qwen/qwen3.6-27b` | D2 was executed with `claude-haiku-5-5` via Anthropic's OpenAI-compatible endpoint: 6 raw traces in `artifacts/raw_traces_haiku/`, 0 failed attempts | `collect.py` at `375b5fc`; trace counts |
> | 3 | B-seq (`forced_multi_lookup`) uses Groq, "planned, not runnable" | Executed with `claude-haiku-5-5`: 6 raw traces, 0 failed attempts | same |
> | 4 | `manager_4` has no collector branch | Branch exists (commit `0089e5d`, `collect.py` `_build`); all 6 Haiku traces contain the 5 agents `manager_agent`, `research_agent`, `math_agent`, `lookup_agent`, `unit_agent` | raw trace `agents` keys |
> | 5 | `manager_multi_specialist`: 3 historical, 3 pending | **Incomplete: 4 of 6** Groq traces (indices 0 to 3). Indices 4 and 5 have no successful trace. 4 failure records for this workload (connection errors for 00, 04, 05; index 04's second record shows two wall-clock timeouts then HTTP 429). Index 00 later succeeded (`..._00_1787459909`, a retry after failure). Not run on Haiku. | `trace-counts.json` |
> | 6 | D2 prompts "rewritten ... to require" mid-then-leaf | Prompts are **identical** to `manager_specialist_delegation`; depth 2 is imposed by topology (the manager's only agent is `mid_agent`, whose only agent is the leaf). | `experiments/configs/workloads.py` |
> | 7 | (not stated) | `manager_specialist_delegation` (Groq) has 5 indexed traces (0 to 4) plus `first_run`, whose task ("What is the current version of the Python programming language?") is not in `workloads.py`; index 5 is **missing**. It is not 6 complete. | `trace-counts.json` |
> | 8 | (not stated) | Depth-2 and breadth results below are **elicited**, not natural delegation propensity. See "Natural versus elicited". | this document |
>
> **Haiku results so far (all elicited, claude-haiku-5-5, adapter-corroborated; see refresh doc):**
> - `chained_2`: 6 traces, 6/6 pass corroboration, 5 of 6 topology-scorable at max depth 2. Trace 02 is unscorable (missing mid -> leaf link); cause analysed in `docs/chained2-trace02-investigation.md` (best-supported: timeout-driven mid re-invocation plus post-run memory snapshot; first mid invocation unrecorded; not fully confirmed). Traces 00 to 03 were collected before the timeout fix, so their durations are unreliable.
> - `forced_multi_lookup`: 6 traces, 6/6 corroborated, all scorable, max depth 1, 1 to 4 delegation events per trace, at most 2 distinct children (`research_agent`, `lookup_agent`; `math_agent` and `unit_agent` were never delegated to), `fanout` [1] or [2]. `CodeAgent` executes synchronously. In trace 03 one code block called two children; their recorded step windows do not overlap. No parallel-fanout evidence.
>
> **Natural versus elicited.** No cell in this plan measures natural depth-2 delegation in ordinary workloads. Haiku `chained_2` forces depth by topology; Haiku `forced_multi_lookup` forces breadth by prompt wording. Groq `manager_*` workloads were never audited for natural versus elicited delegation (their prompts ask for lookup plus compute), so no Groq workload is labelled "natural" here either. Groq delegation rates differ by prompt (documented in `docs/instrumentation-validity-evidence.md` section 6).

## Purpose and evidence boundary

This plan separates two evidence streams:

1. **Measured real traces.** Agent runs against a live model/provider. They can describe behavior of that exact configuration only.
2. **Controlled synthetic benchmarks.** Deterministic delegation trees exercised against the frozen protocol. They measure protocol cost and correctness over depth/fanout cells; they cannot establish real-world agent delegation distributions.

The existing Groq real-trace corpus has 34 traces collected with smolagents on Groq (model per trace unverified; see correction 1). It establishes a measured floor, not a maximum: current `solo`, `manager_1`, and `manager_2` topologies structurally cap depth at 0/1 and supply at most two direct specialists. See `docs/instrumentation-validity-evidence.md`.

No collection configuration changes `src/lineage_revocation/`. New real traces remain separate from the Groq corpus (the 33 historical traces are now 34 files). Controlled traces remain in a separate controlled-results location and are never pooled with real traces.

## Existing cells: valid uses and limits

| workload group | topology | framework/provider/model | observed n | may inform | cannot inform |
|---|---|---|---:|---|---|
| simple_research, multi_step_research | solo | ToolCallingAgent, Groq (model unverified) | 6 each | zero-delegation baseline | delegation depth or fanout |
| technology_comparison, document_technical_analysis, manager_specialist_delegation | manager_1 | CodeAgent manager, Groq (model unverified) | 6 each, except `manager_specialist_delegation`: 5 indexed + 1 `first_run`, index 5 missing | prompt-dependent delegation rates and depth 0/1 (not shown natural) | breadth above one child; depth above one hop |
| manager_multi_specialist | manager_2 | CodeAgent manager, Groq (model unverified) | 4 of 6 (indices 4, 5 missing, not retried) | sequential use of named specialists; depth 0/1 | concurrent fanout; depth above one hop |

`CodeAgent` executes generated Python synchronously. Registering four specialists does not make it a genuine parallel-fanout executor. It may provide an exploratory measurement of sequential, distinct-child delegation only when the raw trace shows those calls; it must not be labelled as evidence of concurrent/model-parallel fanout.

## Preserved ToolCallingAgent observation

`experiments/traces/smoke/smoke_toolcalling_manager2spec_00.jsonl` is real measured data. Its `ToolCallingAgent` manager invoked both `research_agent` and `math_agent`; metrics are `num_agents=3`, `delegation_count=2`, `max_depth=1`, and `fanout=[2]`. Preserve it as a valid observed breadth measurement.

The two delegations occurred in separate manager turns, so this run is not evidence of same-turn parallel execution. A separate probe (`probe_00_neutral`) captured a same-turn two-tool-call generation, but Groq returned `400 tool_use_failed`; it is evidence that the model attempted the form, not that parallel execution completed. Therefore, do not discard `ToolCallingAgent` and do not infer that the model cannot parallelize. The supported conclusion is narrower: same-turn multi-tool calls are unreliable for this Groq/model configuration.

## Real-trace collection configurations

### Depth configuration: D2

- Framework: smolagents `CodeAgent` hierarchy.
- Topology: `manager_agent` delegates to `mid_agent`, which delegates to `leaf_research_agent` (`chained_2`).
- Provider/model: **executed on `claude-haiku-5-5`** (Anthropic OpenAI-compatible endpoint), not Groq. Separate dataset `artifacts/raw_traces_haiku/`.
- Topology as built: `manager_agent` (CodeAgent) holds only `mid_agent` (CodeAgent), which holds only `leaf_research_agent` (ToolCallingAgent with web search). Depth 2 is imposed by this structure.
- Prompt family: the six `manager_specialist_delegation` prompts, **unchanged** (no rewrite requiring the two hops).
- Status: 6 traces, 0 failed attempts, 6/6 corroborated, 5/6 topology-scorable (trace 02: see `docs/chained2-trace02-investigation.md`). Durations of traces 00 to 03 predate the timeout fix and are unreliable.
- Axis claim: **elicited** depth-2 behavior when topology forces it. It does not show that ordinary workloads reach depth 2, and does not inform parallel fanout.

### Sequential-breadth diagnostic: B-seq

- Framework: smolagents `CodeAgent` hierarchy.
- Topology: `manager_4`: one manager with four named specialists (`research_agent`, `math_agent`, `lookup_agent`, `unit_agent`); all five agents appear in every trace file.
- Repository state: the `manager_4` branch exists in `collect.py` (commit `0089e5d`). The cell was **executed**: 6 traces, 0 failed attempts, 6/6 corroborated.
- Provider/model: **`claude-haiku-5-5`**, not Groq.
- Prompt family: `forced_multi_lookup`, six independent fact pairs plus combination work; each prompt names the required specialist outputs.
- Observed: max depth 1; 1 to 4 delegation events; at most 2 distinct children; `math_agent`/`unit_agent` never called. Prompt wording spells out the lookup/convert/combine steps, so this is **elicited** breadth.
- Axis claim: exploratory sequential distinct-child breadth only. It can inform whether prompts induce multiple registered-child calls. It cannot be used as a genuine fanout/concurrency result because CodeAgent's executor is synchronous.

### Genuine fanout configuration: F-par

- Framework: smolagents `ToolCallingAgent` manager with four managed specialist tools (`manager_4`). Its structured tool-call trace is adapted by `measurement.adapters.smolagents_toolcalling_adapter`, not by the CodeAgent substring adapter.
- Current repository state: no ToolCallingAgent `manager_4` construction exists in the live collector. F-par remains a gated plan item, not an executed configuration.
- Candidate provider/model: a provider/model with documented and demonstrated multi-tool-call support. Initial acceptance candidates are a non-Groq OpenAI-compatible provider/model or local Ollama model/runtime with parallel tool-call support. Selection is empirical, not assumed.
- Prompt family: `forced_multi_lookup` with at least two independent specialist requests and no data dependency between them. Include an explicit same-turn instruction plus a neutral counterpart to distinguish prompt forcing from capability.
- Gate before collection: one smoke trace must complete with two or more registered-agent tool calls in one manager step. Save raw structured tool calls, provider/model/version, runtime concurrency setting, and wall-clock overlap. A failed provider request is a failed smoke result, not fanout.
- Target after gate: `n=6` successful traces for each chosen provider/model cell, plus all failed/timeout attempts. If smoke never passes, record F-par as unavailable for that provider/model and do not substitute CodeAgent results.
- Axis claim: genuine observed fanout only for completed same-turn multi-agent calls. Sequential ToolCallingAgent calls remain valid breadth observations, including the preserved `fanout=[2]` smoke trace, but are not parallelism evidence.

### Path to an alternate provider or local Ollama

1. Run a bounded capability smoke with same `ToolCallingAgent` topology and prompt on one alternate provider/model or local Ollama runtime.
2. Verify raw step contains two or more registered-agent tool calls in one manager step and that requests complete. For local Ollama, record model tag, Ollama version, host concurrency settings, and tool-calling template.
3. If accepted, freeze that provider/model/runtime for all six F-par runs. If rejected, retain raw failure evidence and test the next candidate. Do not repeatedly retry Groq `qwen/qwen3.6-27b` as a substitute for a fanout-capable cell.
4. Report provider behavior as a configuration limitation, never as a general limitation of agent parallelism.

## Matrix and interpretation

| cell | evidence type | framework/topology | provider/model | prompt family | target | primary axis | interpretation limit |
|---|---|---|---|---|---:|---|---|
| D2 | real measured, elicited (topology) | CodeAgent `chained_2` | `claude-haiku-5-5` | two-hop version lookup (same prompts as manager_specialist_delegation) | executed: 6 traces, 5 scorable | depth | no natural-depth claim; no parallel fanout claim |
| B-seq | real measured diagnostic, elicited (prompt) | CodeAgent `manager_4` | `claude-haiku-5-5` | forced_multi_lookup | executed: 6 traces, 6 scorable | sequential breadth | not genuine fanout/concurrency |
| F-par | real measured, gated | ToolCallingAgent `manager_4` | accepted alternate provider/model or local Ollama | forced_multi_lookup | 6 successful/provider | genuine fanout | only after same-step multi-call smoke passes |
| C-depth/fanout | controlled synthetic | frozen protocol tree generator | local deterministic harness | generated topology cells | see below | verifier/revocation scaling | not real-agent behavior |

## Controlled benchmark, separate from real traces

Begin independently of real-trace collection. Use the frozen protocol unchanged. Sweep a fixed grid that isolates both axes, for example depth `{0, 1, 2, 4, 8}` and fanout `{1, 2, 4, 8}` where valid. Run at least 30 repetitions per cell after a warmup, with deterministic tree generation and recorded software/hardware metadata.

For every cell, record verifier-side latency/cost metrics already exposed by the harness, revocation propagation latency/cost when exposed, and revocation correctness. Run the TTL-only baseline under the same controlled topology and workload when the harness supports it. If the baseline or a metric is unsupported, record it as unavailable; do not create a proxy silently. Report crossover findings as controlled/projected protocol results, not observed real-world agent behavior.

## Provider limitations and reporting rules

- Groq `qwen/qwen3.6-27b` (smoke and probe runners at commits `823ccd3`/`fbbdb61` name this model; the smoke files themselves do not record it. The runners now name `claude-haiku-5-5` since `375b5fc`, so rerunning them would test Haiku, which has not been smoke-tested): sequential `ToolCallingAgent` breadth observed; same-turn multi-tool generation can fail with `400 tool_use_failed`. It is unsuitable for F-par until a successful smoke disproves that limitation.
- Prompt wording materially changes delegation propensity. Report prompt family, topology, registered-agent count, and provider/model beside each result.
- Raw traces are authoritative for executed calls. Adapter-derived events must be corroborated against raw call records before aggregation.
- Preserve every timeout, provider error, retry, and incomplete run as evidence. Do not overwrite the 33 historical traces, alter schemas, or merge synthetic and real samples.
