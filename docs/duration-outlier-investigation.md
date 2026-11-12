# Duration Outlier Investigation

Two traces in the 33-trace real dataset have task_duration far above the rest: `document_technical_analysis_03` (~2799.86s) and `manager_multi_specialist_02` (~8655.29s), against a dataset p95 of ~2010s and a typical (non-outlier) range of 1-50s. Not deleted, not excluded. Cause investigated at the raw per-step timing level.

## Ground truth used

smolagents enforces a hard 30-second cap on local sandboxed code execution per step. This is not assumed — it is quoted verbatim from a real error recorded in `manager_multi_specialist_02_1786970824.json`:

> `Code execution exceeded the maximum execution time of 30 seconds`

This gives a defensible, non-invented lower bound: for any `python_interpreter` step, code-execution time is at most 30s, so `step_duration - 30s` is a lower bound on time spent outside code execution. For Python-only steps, that exterior time is model/provider-facing wait before execution, plus negligible local orchestration; it is not actual Python execution. It is a lower bound, not an exact split: raw traces record only step-level `start_time`/`end_time`, not per-phase timestamps or HTTP retry/attempt logs. No captured artifact distinguishes one slow completion from retries.

## document_technical_analysis_03

Task: "Summarize the CAP theorem in distributed systems." (`solo`-equivalent single-manager step sequence, `document_technical_analysis_03` is a `manager_1` workload but this run never delegated — see step trace.)

| step | agent | duration | tool | error |
|---|---|---|---|---|
| 1 | manager_agent | 12.98s | python_interpreter | none |
| 2 | manager_agent | **2786.88s** | python_interpreter | none |

Step 2 succeeded with only a local `python_interpreter` call and no nested agent/tool. The 30s execution cap was not hit. Therefore at least 2756.88s of 2786.88s (98.9%) was outside Python execution: model/provider-facing completion wait before execution, not arithmetic or code runtime. The raw trace does not establish whether this was one delayed Groq completion or retries.

## manager_multi_specialist_02

Task: "Find the distance from Earth to the Moon in kilometers, then compute how many hours light takes to cover it."

| step | agent | duration | tool | error |
|---|---|---|---|---|
| 1 | manager_agent | 2881.86s | python_interpreter | `exceeded max execution time of 30 seconds` |
| 2 | manager_agent | 2.30s | python_interpreter | `InterpreterError: globals not allowed` |
| 3 | manager_agent | 813.76s | python_interpreter | `AgentGenerationError: tool 'answer' not in request.tools` (400 from Groq) |
| 4 | research_agent | 796.31s | web_search | none (nested inside manager's step 3 window — a managed-agent call blocks the parent's step) |
| 5 | manager_agent | **4957.37s** | python_interpreter | none |

- Step 1: code execution hit the 30s cap and was killed, but total wall time was 2881.86s. At least 2851.86s was outside Python execution. The tool body requested `research_agent`, but the raw `research_agent` action begins only after this manager step ends; this step's split cannot be refined beyond the lower bound.
- Step 3: errored on Groq tool-call validation after the nested `research_agent` ran. Its 813.76s window contains the complete 796.31s `research_agent` web-search step (timestamps overlap from 1786973724.659654 to 1786974520.968470), then the 400 response. Thus this delay is chiefly nested-agent/tool completion wait, not local Python execution; the raw trace cannot split web search from its model completion.
- Step 4 (research_agent, `web_search`, no error): the 30s code-exec cap doesn't apply to this tool call (that cap is specifically documented for `python_interpreter` code execution, not web_search), so this number isn't decomposable the same way. 796s for one search call is still far outside the normal range seen elsewhere in the dataset for the same tool (single-digit to low tens of seconds), and is reported as-is without a fabricated execution/stall split.
- Step 5: succeeded with only local arithmetic in `python_interpreter`, no nested agent/tool. At least 4927.37s of 4957.37s was model/provider-facing completion wait rather than Python execution.

## Conclusion

`document_technical_analysis_03` is dominated by model/provider-facing completion delay, with a measured lower bound of 2756.88s. `manager_multi_specialist_02` combines that same delay pattern in manager Python-only steps (at least 2851.86s in step 1 and 4927.37s in step 5) with one 796.31s nested web-search/agent call and a subsequent Groq 400 tool-validation failure. Neither trace supports a claim of heavy local computation.

The collection source archived with these runs configures Groq/OpenAI client `timeout=60.0`, `max_retries=2`, 15s HTTP web-search timeouts, and a 150s outer alarm. The observed multi-hour raw step durations show that those controls did not bound these historical runs end-to-end; they cannot be used to rule out retries or provider queuing. Because no HTTP attempt log was retained, the evidence cannot distinguish one extremely slow completion from repeated slow/retried requests. This is an instrumentation limitation, not a basis to assign an unobserved cause.

## Disposition

Both traces stay in the dataset — the delegation/depth/fanout structure they contain is real and correctly measured; only `task_duration` for these two is unreliable as a measure of "real work time." Annotated (not modified/excluded) in `experiments/traces/stall_annotations.json`: each entry names the task_id and the lower-bound stall time in seconds, for any downstream analysis that wants to exclude or footnote these two from duration-specific conclusions. `max_depth`, `fanout`, `delegation_count`, `num_agents`, `tool_call_count` are unaffected by this and require no annotation.
