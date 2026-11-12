# Controlled Benchmark Design: Review

Review of `docs/controlled-benchmark-design-v1.md`. Labels used throughout: **VERIFIED** (checked against repository files or by running existing code this session), **PROPOSED** (a recommendation, not approved), **APPROVED** (none exist yet). No controlled benchmark has been run. No benchmark code has been written.

## 1. Existing facts verified against repository evidence

### 1.1 Protocol and tests

- **VERIFIED** `src/lineage_revocation/` has `canonical`, `keys`, `nodes`, `lineage`, `revocation`, `status`, `verifier`. No commit made this session touched it.
- **VERIFIED** Test suite: 60 passed in the run at commit `375b5fc` (the earlier run needed `pythonpath = ["src"]` in `pyproject.toml`, added in that commit). Not re-run after the later trace commit. `instrumentation-validity-evidence.md` quotes 53 passed, so that figure is stale.
- **VERIFIED** The repository has no controlled benchmark harness, topology generator, TTL baseline or timing code. `controlled-benchmark-blocker-evidence.md` is accurate on this point (tracked file list contains none).
- **VERIFIED** API facts that shape the design: no propagation or fetch/cache function; `StatusArtifact` has no serializer or signature field; `authorize()` checks only the leaf's `expires_at`; a repeated artifact version raises `StaleStatusArtifact`; `now` is always injected. Details in v1 section 0.

### 1.2 Real-agent traces (three categories, never pooled)

**Category 1: Groq `qwen/qwen3.6-27b` workload measurements (`artifacts/raw_traces/`).**

- **VERIFIED** 34 raw trace files, 34 normalized files, 5 failure records in `failed/`.
- **VERIFIED** Counts per workload: simple_research 6, multi_step_research 6, technology_comparison 6, document_technical_analysis 6, manager_specialist_delegation 6 (five numbered plus `first_run`), manager_multi_specialist 4 of 6.
- **VERIFIED** Documents say 33; files say 34. The difference is `manager_multi_specialist_00_1787459909.json`, a later retry. Both `delegation-corroboration-33.*` and `instrumentation-validity-evidence.md` describe 33 and were not updated.
- **VERIFIED (recomputed this session, not stored anywhere)** `adapt_file` over all 34 Groq raw traces: 0 validation failures, 23 delegation events (the 33-trace JSON records 21).
- **VERIFIED** `manager_multi_specialist` is **not complete**: indices 04 and 05 have no successful trace. Failure records show connection errors (index 00 once, 04 once, 05 once) and an HTTP 429 (index 04 second attempt). Index 00 later succeeded as the retry file. `collection-plan-v2.md` says "3 historical, 3 pending", which does not match 4 files.
- **VERIFIED** Documented delegation propensity depends on the prompt: 1 of 6 delegated in two `manager_1` workloads and 6 of 6 in a third (`instrumentation-validity-evidence.md` section 6). I did not audit prompt wording to decide which Groq workloads count as "natural" versus delegation-eliciting. The two `manager_*` workloads use lookup-plus-compute prompts that call for a specialist, so treating the whole Groq corpus as "natural" would be a claim I cannot support.

**Category 2: Haiku `chained_2` elicitation (`artifacts/raw_traces_haiku/`).**

- **VERIFIED** 6 raw and 6 normalized traces, model `claude-haiku-5-5` via the Anthropic OpenAI-compatible endpoint, 0 failed attempts. Topology: manager with `mid_agent` only, `mid_agent` with `leaf_research_agent` only. All 6 pass the corroboration adapter.
- **VERIFIED** Of the 6, 5 are scorable by `measurement.report` and each shows max depth 2. Trace 02 fails the topology check: the leaf agent has 8 recorded steps but `mid_agent`'s four steps never name it, so the report sees two root agents (`manager_agent` and `leaf_research_agent`).
- **UNRESOLVED** Cause of trace 02. Not diagnosed. It remains an open instrumentation issue and must not be described as explained.
- **VERIFIED** Provenance caveat: traces 00 to 03 were collected before the timeout fix (`TaskTimeout` was an `Exception` subclass that smolagents could swallow); 04 and 05 after. Early durations (one task took about 2h50m) are unreliable and, unlike two Groq traces, have no stall annotation.
- **VERIFIED** Prompt discrepancy: `collection-plan-v2.md` says the prompts were "rewritten to require" the manager to go through mid and leaf; `experiments/configs/workloads.py` says the wording is the same as `manager_specialist_delegation` and that the topology forces the two hops. Depth 2 here is imposed by topology (the manager has no other agent to call), not discovered.

**Category 3: Haiku `forced_multi_lookup` elicitation.**

- **VERIFIED** 6 raw and 6 normalized traces, 0 failed attempts, topology `manager_4` (CodeAgent), prompts spell out look-up-then-combine steps. All 6 pass the adapter; all 6 scorable. Observed: max depth 1, 1 to 4 delegation events per trace, up to 2 distinct children per trace, calls made one after another.
- **VERIFIED** 36 delegation events across the 12 Haiku traces, 0 corroboration failures (recomputed this session, not stored anywhere).

**Accurate wording of the depth-2 finding (PROPOSED):** "Real agent stacks produce depth-2 delegation when the topology and task demand it." It does **not** show that ordinary workloads commonly reach depth 2. The Groq corpus never exceeded depth 1, and those topologies capped it.

**Parallel fanout.** **VERIFIED** no real trace shows same-step parallel delegation. In `experiments/traces/smoke/`, `probe_00_neutral` ended in a Groq 400 error after the model generated two tool-call blocks in one turn, and no probe trace has a step with more than one recorded tool call. Commit `fbbdb61` records the decision not to collect a ToolCallingAgent fanout cell with Groq. Haiku was never smoke-tested for same-step multi-tool calls.

## 2. Proposed methodology (summary of v1)

All **PROPOSED**; see v1 for detail.

- Grid depth {0..5} x fanout {1,2,4,8}, 21 meaningful cells; `d=0` run once; `f=1` has no sibling test; `real`/`projected` labels on every row.
- Deterministic seeded keys; node ids from `compute_node_id`; three revocation scenarios (root, intermediate, leaf) with a structural oracle for sibling isolation.
- Timing: `authorize()` on parsed nodes as primary; parse and wire cost separate; cold start in subprocesses; fresh artifact version per call; cached-statements path only as a labelled harness composition.
- Cost: primary Ed25519 verifications per authorization; co-primary artifact bytes; no "propagation" metric because no propagation operation exists.
- Baseline: chain-minimum TTL (B1) as primary, frozen leaf-only expiry (B2) as an observation; renewal models T-active and T-full; TTL grid 30 s to 1 h kept; equal-exposure rule `L = R`.
- JSONL schema with raw, summary and report layers under `artifacts/controlled/<experiment_id>/`.
- Correctness gate before any timing is accepted.

## 3. Five decisions requiring supervisor approval

None is approved. Each needs an explicit yes, no, or change.

1. **Topology and revocation targets.** PROPOSED: the 21-cell grid, depth defined as hops (lineage length `d+1`), uniform fanout, three revocation scenarios, oracle-based sibling isolation. Question: accept the depth mapping as an analogy to the measurement layer, and the grid size?
2. **Latency methodology.** PROPOSED: `authorize()` on parsed nodes as primary, parse and wire reported separately, cold start separate, fresh artifact version per call. Question: is the "no cache-hit path in the frozen API" limitation acceptable, or should a cache be specified in a design revision first?
3. **Revocation cost.** PROPOSED: `verify_ops` primary, artifact bytes co-primary, call it "enforcement cost" not "propagation cost". Question: agree no propagation latency is claimed?
4. **TTL baseline.** PROPOSED: chain-minimum TTL (B1) as the primary baseline, because the frozen verifier's leaf-only expiry check would not bound exposure from a compromised intermediary; renewal models T-active and T-full; grid {30 s, 1 min, 5 min, 15 min, 1 h}; `L = R`. Question: does the spec intend expiry nesting, and is B1 an acceptable fair baseline?
5. **Schema and storage.** PROPOSED: JSONL schema and the `artifacts/controlled/<experiment_id>/{raw,summaries,reports}` layout, `experiments/controlled/` for code. Question: accept, and should controlled results be committed or ignored like `docs/`?

## 4. Risks and limitations

- **Environment timing noise.** First reads of files in the venv took about 1.2 s each on this machine, which stalled earlier runs. Benchmark timing must warm files and record environment details, or results may reflect I/O, not protocol cost.
- **The disk write is inside `accept_status_artifact`.** It cannot be removed without editing frozen code, so the high-water-mark write will probably dominate the pull path's latency. Components are timed separately so this is visible.
- **No cache path in the frozen API.** "Steady-state with cached artifact" is only available as a harness composition.
- **Baseline validity.** If B2 (leaf-only expiry) were used as "the TTL baseline", TTL would look unbounded against a compromised intermediary. If B1 were not labelled harness-side, it would look like a frozen-verifier property.
- **Possible spec mismatch.** `StatusArtifact` carries no signature, while the spec pseudocode has a `verify_status_artifact` step. I did not check the full spec text for an artifact-level signature requirement. Flagged, not concluded.
- **Single machine, no real network, Ed25519 via the installed `cryptography` library.** Absolute numbers will not transfer; scaling shape and ratios are the intended output.
- **Depth above 2 and fanout above 2 are projected.** Real traces do not reach them except by construction.
- **Corrections to my earlier scratch draft** (`docs/controlled-benchmark-design.md`, now superseded): it said TTL-only is "the same call with `status_artifact=None`", which is wrong as a fair baseline because of the leaf-only expiry check; it described real task duration "median about 34 s" as solo-workload data, but 34 s is the p50 over all 34 Groq traces; it listed depths up to 8, beyond your candidate grid; it did not mention the repeated-version rejection or the missing artifact serializer.
- **Correctness-test coverage is name-level.** I checked that matching tests exist; I did not audit each assertion against the spec.

## 5. Missing evidence (state at time of review)

| item | state |
|---|---|
| Authoritative trace-count script | **Missing.** No tracked script. `instrumentation-validity-evidence.md` points at an uncommitted scratchpad script. The counts in section 1 came from ad hoc commands this session. |
| Corroboration across the original 33 | **Exists** (`delegation-corroboration-33.md/.json`, 21 of 21) but **stale**: the corpus is now 34 files, and my recomputation (23 events, 0 failures) is not saved as an artifact. No stored Haiku corroboration artifact either. |
| Duration-outlier investigation | **Exists** (`duration-outlier-investigation.md`, `experiments/traces/stall_annotations.json`). Covers two Groq traces only. Haiku early-trace durations are unannotated. |
| Adapter-fix diff | **Exists** in `adapter-fix-evidence.md`; commit `eff0fb9` is in history. I did not re-diff the document against git. |
| Collection Plan v2 | **Exists but stale.** Says D2 and B-seq use Groq (they ran on Haiku); says `manager_4` is not runnable (collector branch added in `0089e5d`); says `manager_multi_specialist` is 3 done (it is 4); wording of the `chained_2` prompts disagrees with `workloads.py`. |
| Genuine parallel-fanout-capable configuration | **Not available.** Groq failed the probe; no alternate provider or Ollama candidate has been smoke-tested; Haiku not tested. F-par is still a gated plan item. |
| Remaining `manager_multi_specialist` traces | **Missing** (indices 04 and 05, failed on connection errors and a 429). Not retried. Any retry on Haiku would be a different cell. |
| `chained_2` trace 02 missing-parent | **Unresolved**, undiagnosed. |
| `docs/measurement-status.md` | **Missing locally.** Referenced by the blocker document; it was deleted from git tracking in `c75be4e` and is recoverable from git history. |
| Real-versus-elicited labelling in the corpus | **Missing.** No per-workload metadata marks natural versus elicited prompts. |
| Docs under version control | **Not tracked.** `docs/` is in `.gitignore`; the design documents are local files only. |

## 6. Recommended next steps (all PROPOSED)

1. Supervisor reviews `controlled-benchmark-design-v1.md` and answers the five decisions in section 3. No benchmark code is written before then.
2. Independently of approval, close the evidence gaps that would otherwise undercut the real-trace side: commit a trace-count script, regenerate the corroboration artifact for 34 Groq traces and for the 12 Haiku traces, and update Collection Plan v2 to match what actually ran.
3. Diagnose `chained_2` trace 02 and the possible artifact-signature mismatch with the spec, separately from the benchmark.
4. Decide whether to retry `manager_multi_specialist` 04 and 05 and whether to smoke-test an alternate provider for parallel fanout. Both are optional for the controlled benchmark.
5. Only after step 1: write the harness under `experiments/controlled/`, run the topology validation and correctness gate first, and only then collect timing.
