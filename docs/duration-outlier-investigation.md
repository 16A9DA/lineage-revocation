# Duration Outlier Investigation

Two traces in the 33-trace real dataset have task_duration far above the rest: `document_technical_analysis_03` (~2799.86s) and `manager_multi_specialist_02` (~8655.29s), against a dataset p95 of ~2010s and a typical (non-outlier) range of 1-50s. Not deleted, not excluded. Cause investigated at the raw per-step timing level.

## Ground truth used

smolagents enforces a hard 30-second cap on local sandboxed code execution per step. This is not assumed — it is quoted verbatim from a real error recorded in `manager_multi_specialist_02_1786970824.json`:

> `Code execution exceeded the maximum execution time of 30 seconds`

This gives a defensible, non-invented lower bound: for any `python_interpreter` step, code-execution time is at most 30s, so `step_duration - 30s` is a lower bound on time spent outside code execution (LLM generation / API wait) for that step. It is a lower bound, not an exact split — smolagents' raw trace format records only step-level `start_time`/`end_time`, not per-phase (generation vs. execution) timestamps or HTTP-level retry/attempt counts. That granularity does not exist in the current instrumentation; this is stated as a limitation, not worked around with an invented number.

## document_technical_analysis_03

Task: "Summarize the CAP theorem in distributed systems." (`solo`-equivalent single-manager step sequence, `document_technical_analysis_03` is a `manager_1` workload but this run never delegated — see step trace.)

| step | agent | duration | tool | error |
|---|---|---|---|---|
| 1 | manager_agent | 12.98s | python_interpreter | none |
| 2 | manager_agent | **2786.88s** | python_interpreter | none |

Step 2 succeeded (no error), so the 30s execution cap was never hit — meaning the entire 2786.88s minus at most 30s of code execution (≥2756.88s, 98.9% of the step) was spent before code ran at all, i.e. waiting on the Groq completion API to return a response for that step.

## manager_multi_specialist_02

Task: "Find the distance from Earth to the Moon in kilometers, then compute how many hours light takes to cover it."

| step | agent | duration | tool | error |
|---|---|---|---|---|
| 1 | manager_agent | 2881.86s | python_interpreter | `exceeded max execution time of 30 seconds` |
| 2 | manager_agent | 2.30s | python_interpreter | `InterpreterError: globals not allowed` |
| 3 | manager_agent | 813.76s | python_interpreter | `AgentGenerationError: tool 'answer' not in request.tools` (400 from Groq) |
| 4 | research_agent | 796.31s | web_search | none (nested inside manager's step 3 window — a managed-agent call blocks the parent's step) |
| 5 | manager_agent | **4957.37s** | python_interpreter | none |

- Step 1: code execution itself hit the 30s cap and was killed, but the step's total wall time was 2881.86s — so ≥2851.86s was spent before code execution started, again API-wait.
- Step 3: errored on tool-call validation (malformed generation), not on code timeout, so essentially none of its 813.76s is code execution — almost all of it is API-side (Groq generating, and Groq rejecting the malformed call).
- Step 4 (research_agent, `web_search`, no error): the 30s code-exec cap doesn't apply to this tool call (that cap is specifically documented for `python_interpreter` code execution, not web_search), so this number isn't decomposable the same way. 796s for one search call is still far outside the normal range seen elsewhere in the dataset for the same tool (single-digit to low tens of seconds), and is reported as-is without a fabricated execution/stall split.
- Step 5: succeeded, no error, 4957.37s with the same 30s execution ceiling reasoning as step 2 above → ≥4927.37s API-side.

## Conclusion

Both outliers are dominated by time spent outside actual code/tool execution — consistent with the completion API (Groq) taking minutes to respond to individual requests on these two runs, not with retries exhausting (client is configured `max_retries=2`, `timeout=60.0`s, which would surface as a raised error within roughly 2-3 minutes if genuinely stuck, not silently succeed after 45-140 minutes) and not with actual heavy computation (the tasks themselves are trivial arithmetic/summarization). The raw trace format cannot distinguish "one very slow request" from "several silently-retried slow requests" beyond the OpenAI SDK's own retry count, because no HTTP-level attempt log is captured — flagged as a genuine instrumentation gap, not resolved by guessing.

## Disposition

Both traces stay in the dataset — the delegation/depth/fanout structure they contain is real and correctly measured; only `task_duration` for these two is unreliable as a measure of "real work time." Annotated (not modified/excluded) in `experiments/traces/stall_annotations.json`: each entry names the task_id and the lower-bound stall time in seconds, for any downstream analysis that wants to exclude or footnote these two from duration-specific conclusions. `max_depth`, `fanout`, `delegation_count`, `num_agents`, `tool_call_count` are unaffected by this and require no annotation.
