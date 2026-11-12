# Collection Plan v2

## Purpose and evidence boundary

This plan separates two evidence streams:

1. **Measured real traces.** Agent runs against a live model/provider. They can describe behavior of that exact configuration only.
2. **Controlled synthetic benchmarks.** Deterministic delegation trees exercised against the frozen protocol. They measure protocol cost and correctness over depth/fanout cells; they cannot establish real-world agent delegation distributions.

The existing real-trace corpus has 33 traces collected with smolagents and Groq `qwen/qwen3.6-27b`. It establishes a measured floor, not a maximum: current `solo`, `manager_1`, and `manager_2` topologies structurally cap depth at 0/1 and supply at most two direct specialists. See `docs/instrumentation-validity-evidence.md`.

No collection configuration changes `src/lineage_revocation/`. New real traces remain separate from the 33 historical traces. Controlled traces remain in a separate controlled-results location and are never pooled with real traces.

## Existing cells: valid uses and limits

| workload group | topology | framework/provider/model | observed n | may inform | cannot inform |
|---|---|---|---:|---|---|
| simple_research, multi_step_research | solo | ToolCallingAgent, Groq `qwen/qwen3.6-27b` | 6 each | zero-delegation baseline | delegation depth or fanout |
| technology_comparison, document_technical_analysis, manager_specialist_delegation | manager_1 | CodeAgent manager, Groq `qwen/qwen3.6-27b` | 6 each | delegation propensity and depth 0/1 | breadth above one child; depth above one hop |
| manager_multi_specialist | manager_2 | CodeAgent manager, Groq `qwen/qwen3.6-27b` | 3 historical, 3 pending | sequential use of named specialists; depth 0/1 | concurrent fanout; depth above one hop |

`CodeAgent` executes generated Python synchronously. Registering four specialists does not make it a genuine parallel-fanout executor. It may provide an exploratory measurement of sequential, distinct-child delegation only when the raw trace shows those calls; it must not be labelled as evidence of concurrent/model-parallel fanout.

## Preserved ToolCallingAgent observation

`experiments/traces/smoke/smoke_toolcalling_manager2spec_00.jsonl` is real measured data. Its `ToolCallingAgent` manager invoked both `research_agent` and `math_agent`; metrics are `num_agents=3`, `delegation_count=2`, `max_depth=1`, and `fanout=[2]`. Preserve it as a valid observed breadth measurement.

The two delegations occurred in separate manager turns, so this run is not evidence of same-turn parallel execution. A separate probe (`probe_00_neutral`) captured a same-turn two-tool-call generation, but Groq returned `400 tool_use_failed`; it is evidence that the model attempted the form, not that parallel execution completed. Therefore, do not discard `ToolCallingAgent` and do not infer that the model cannot parallelize. The supported conclusion is narrower: same-turn multi-tool calls are unreliable for this Groq/model configuration.

## Real-trace collection configurations

### Depth configuration: D2

- Framework: smolagents `CodeAgent` hierarchy.
- Topology: `manager_agent` delegates to `mid_agent`, which delegates to `leaf_research_agent` (`chained_2`).
- Provider/model: Groq `qwen/qwen3.6-27b`, continuing the historical configuration.
- Prompt family: six current-version lookup prompts from `manager_specialist_delegation`, rewritten only to require the manager to obtain its answer through the mid agent and the mid agent to obtain cited facts through the leaf.
- Target: `n=6` successful traces. Record attempts and failures separately; never replace failed evidence with an unmarked retry.
- Axis claim: real, measured depth behavior up to two delegation hops. It does not inform genuine parallel fanout.

### Sequential-breadth diagnostic: B-seq

- Framework: smolagents `CodeAgent` hierarchy.
- Topology: one manager with four named leaf specialists (`manager_4`) only after implementation is verified to register all four.
- Current repository state: `forced_multi_lookup` declares `manager_4`, but `experiments/runners/collect.py` has no `manager_4` branch. This cell is planned, not runnable; do not collect it until that mismatch is resolved and tested.
- Provider/model: Groq `qwen/qwen3.6-27b`.
- Prompt family: `forced_multi_lookup`, six independent fact pairs plus combination work; each prompt names the required specialist outputs.
- Target: `n=6` attempted tasks, with successful, failed, and skipped counts reported separately.
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
| D2 | real measured | CodeAgent `chained_2` | Groq `qwen/qwen3.6-27b` | two-hop version lookup | 6 successful | depth | no parallel fanout claim |
| B-seq | real measured diagnostic | CodeAgent `manager_4` | Groq `qwen/qwen3.6-27b` | forced_multi_lookup | 6 attempted | sequential breadth | not genuine fanout/concurrency |
| F-par | real measured, gated | ToolCallingAgent `manager_4` | accepted alternate provider/model or local Ollama | forced_multi_lookup | 6 successful/provider | genuine fanout | only after same-step multi-call smoke passes |
| C-depth/fanout | controlled synthetic | frozen protocol tree generator | local deterministic harness | generated topology cells | see below | verifier/revocation scaling | not real-agent behavior |

## Controlled benchmark, separate from real traces

Begin independently of real-trace collection. Use the frozen protocol unchanged. Sweep a fixed grid that isolates both axes, for example depth `{0, 1, 2, 4, 8}` and fanout `{1, 2, 4, 8}` where valid. Run at least 30 repetitions per cell after a warmup, with deterministic tree generation and recorded software/hardware metadata.

For every cell, record verifier-side latency/cost metrics already exposed by the harness, revocation propagation latency/cost when exposed, and revocation correctness. Run the TTL-only baseline under the same controlled topology and workload when the harness supports it. If the baseline or a metric is unsupported, record it as unavailable; do not create a proxy silently. Report crossover findings as controlled/projected protocol results, not observed real-world agent behavior.

## Provider limitations and reporting rules

- Groq `qwen/qwen3.6-27b`: sequential `ToolCallingAgent` breadth observed; same-turn multi-tool generation can fail with `400 tool_use_failed`. It is unsuitable for F-par until a successful smoke disproves that limitation.
- Prompt wording materially changes delegation propensity. Report prompt family, topology, registered-agent count, and provider/model beside each result.
- Raw traces are authoritative for executed calls. Adapter-derived events must be corroborated against raw call records before aggregation.
- Preserve every timeout, provider error, retry, and incomplete run as evidence. Do not overwrite the 33 historical traces, alter schemas, or merge synthetic and real samples.
