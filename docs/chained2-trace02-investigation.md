# Investigation: Haiku chained_2 trace 02 (missing mid -> leaf link)

Trace: `artifacts/raw_traces_haiku/manager_specialist_delegation_chained_2_02_1794426465.json`
Normalized: `experiments/traces/normalized_haiku/manager_specialist_delegation_chained_2_02_1794426465.jsonl`
Reproduce: `python scripts/chained2_timeline.py` (read-only). Date of investigation: 2026-11-12.

Labels: **OBSERVED** (read from files or by running code), **INFERRED** (follows from observations plus code reading, not directly seen), **UNRESOLVED**.

## Symptom (OBSERVED)

`python -m measurement.report` style scoring (`compute_metrics`) rejects this trace: `expected exactly one root agent, found ['leaf_research_agent', 'manager_agent']`. The adapter emits `manager_agent -> mid_agent` (x2) and no `mid_agent -> leaf_research_agent`, although `leaf_research_agent` has 7 timed steps (8 entries including the TaskStep) in the raw file. The five other chained_2 traces each have an adapter edge `mid_agent -> leaf_research_agent` and score at depth 2.

## Evidence

| fact | trace 02 | other five |
|---|---|---|
| manager steps that call `mid_agent(` | steps 1 and 2 | steps 1 and 2 (all five) |
| manager step 1 error | `Code execution exceeded the maximum execution time of 30 seconds` | same error in step 1 of 00, 01, 02, 04, 05; trace 03 has `task exceeded wall-clock budget` |
| serialized mid steps that call `leaf_research_agent(` | none | 1 to 3 steps each |
| leaf steps lying inside a serialized mid step window | **0 of 7** | all (7/7 or 8/8) |
| seconds from manager start: manager step 1 | 0.0 to 44.0 | e.g. 00: 0 to 504.8 |
| seconds: leaf steps | 8.1 to 29.1 (inside manager step 1) | start after the first serialized mid step begins |
| seconds: first serialized mid step | 46.5 (2.5 s after manager step 1 ended, i.e. inside manager step 2) | 2.2 to 2.8 s after manager step 1 ended in 00, 01, 04, 05 (trace 03 differs, see below) |
| mid steps serialized | 3 (two ended in `InterpreterError`: `import json` not allowed; `visit_webpage` forbidden) | 2 to 5 |
| adapter output equals stored normalized file | true | true |

Code facts (OBSERVED by reading and running):
- `experiments/runners/collect.py` `run_one` serializes `agent.memory.steps` once, after `agents[root_name].run(task)` returns.
- smolagents 1.26.0 `MultiStepAgent.run` contains `if reset: self.memory.reset()` with `reset: bool = True`, and a managed agent's `__call__` calls `self.run(full_task, **kwargs)` without passing `reset`. So each invocation of `mid_agent` by the manager clears `mid_agent`'s memory.
- In `_build("chained_2")` only `mid_agent` has `leaf_research_agent` in `managed_agents`. The manager holds only `mid_agent`.

## Reading of the evidence

1. **Agent execution behavior (OBSERVED).** In every chained_2 trace the manager invoked `mid_agent` twice, because its first code execution hit the 30 s cap (or the wall-clock alarm in trace 03). That re-invocation is real behavior, recorded in the manager's own steps.
2. **Serialization / instrumentation (INFERRED, strongly supported).** Because memory is reset on each `run` and the collector snapshots only post-run memory, the first `mid_agent` invocation is not in the file. The retained mid steps in trace 02 start at 46.5 s, after manager step 1 ended at 44.0 s, so they belong to the second invocation. The leaf's 7 steps (8.1 s to 29.1 s) fall inside manager step 1, i.e. inside the first, unrecorded mid invocation. Only `mid_agent` can call the leaf, so the first mid invocation must have called it. The second invocation never did: it hit forbidden-import and forbidden-function errors, then ran from 48.4 s until 1666.6 s (one step of about 27 minutes) before `final_answer`.
3. **Adapter parsing (not supported as cause).** The adapter only sees serialized steps and correctly finds no `leaf_research_agent(` in the retained mid code. The raw file, the fresh adapter output and the stored normalized file agree (`adapter_output_equals_stored_normalized: true`). The substring rule `f"{o}("` is not implicated, but it cannot be tested on code that was never serialized.
4. **JSON serialization defects (not supported).** The raw file is valid JSON and complete for what it contains; nothing was truncated.

## Conclusion

The missing link is not an adapter bug. Best-supported cause: **agent execution behavior (timeout-driven re-invocation of mid_agent, whose second run did not delegate) combined with an instrumentation limitation (post-run snapshot of memory that smolagents resets on every `run`).** The leaf's work was real; the raw artifact lost the mid-side record of the call that triggered it.

## What stays UNRESOLVED

- The exact code the first `mid_agent` invocation executed is not in any artifact. "Mid called the leaf in invocation 1" is inferred from topology and timing, not read from a record.
- Whether the same loss occurred in the other five chained_2 traces. By the same reset semantics each of them also lost the first mid invocation (and possibly leaf steps from it), so their delegation counts and mid/leaf step counts are lower bounds. Not measured.
- Trace 03 shows overlapping mid step windows (e.g. step 4 spanning 1898.5 s to 10110.6 s while steps 1 to 3 fall inside that span). That is not explained by the reset mechanism and is not investigated here.
- Direct confirmation needs per-invocation capture (for example a `step_callbacks` hook, or `reset=False` managed runs, or serializing memory before each re-invocation) and a rerun. No rerun was done; it costs API spend and was outside this task.

## Consequence for evidence use

Trace 02 is kept, not excluded, and is flagged as a topology-unscorable trace in `docs/delegation-corroboration-refresh.md`. The depth-2 figure is 5 scorable traces out of 6. The same instrumentation limitation applies to every `CodeAgent` manager trace in both corpora whenever a managed agent is invoked more than once in a run; this is a limitation of the existing collector, not something this task changed.
