from __future__ import annotations

# One-off smoke test for Collection Plan v2 cell C (docs/collection-plan-v2.md):
# does qwen/qwen3.6-27b on Groq, via smolagents ToolCallingAgent, ever call two
# different managed-agent tools from one manager? Not part of the collect.py
# pipeline: writes to its own directory, never touches artifacts/raw_traces or
# experiments/traces/normalized (the real 33-trace dataset).

import json
import os
import signal
import sys
from pathlib import Path

from smolagents import CodeAgent, OpenAIServerModel, ToolCallingAgent

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from experiments.runners.collect import TaskTimeout, TimedWebSearchTool, _alarm, _step_to_dict
from measurement.adapters.smolagents_toolcalling_adapter import adapt
from measurement.analysis.topology import compute_metrics
from measurement.traces.jsonl import parse_lines

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "experiments" / "traces" / "smoke"
TASK_ID = "smoke_toolcalling_manager2spec_00"
# reuses manager_multi_specialist's first prompt verbatim (experiments/configs/workloads.py)
TASK = "Find the current population of France, then compute what 10 percent of it is."


def build_manager(model) -> tuple[str, dict]:
    research_agent = ToolCallingAgent(
        tools=[TimedWebSearchTool(engine="bing")], model=model, name="research_agent", max_steps=6,
        description="Searches the web and returns findings for a given question.",
    )
    math_agent = CodeAgent(
        tools=[], model=model, name="math_agent", max_steps=6,
        description="Performs numeric calculations given the needed numbers.",
    )
    manager = ToolCallingAgent(
        tools=[], model=model, managed_agents=[research_agent, math_agent], max_steps=6,
        name="manager_agent", description="Delegates to specialists as needed.",
    )
    agents = {"manager_agent": manager, "research_agent": research_agent, "math_agent": math_agent}
    return "manager_agent", agents


def main() -> None:
    model = OpenAIServerModel(
        model_id="qwen/qwen3.6-27b",
        api_base="https://api.groq.com/openai/v1",
        api_key=os.environ["GROQ_API_KEY"],
        client_kwargs={"timeout": 60.0, "max_retries": 2},
    )

    root_name, agents = build_manager(model)

    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(300)
    run_error = None
    try:
        agents[root_name].run(TASK)
    except TaskTimeout as exc:
        run_error = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # model/provider/tool-calling failure, report don't crash
        run_error = f"{type(exc).__name__}: {exc}"
    finally:
        signal.alarm(0)

    raw = {
        "workload_id": "smoke_toolcalling", "run_id": "00", "task": TASK,
        "root_agent": root_name,
        "agents": {
            name: {"steps": [_step_to_dict(s) for s in agent.memory.steps]}
            for name, agent in agents.items()
        },
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    raw_path = OUT_DIR / f"{TASK_ID}.json"
    raw_path.write_text(json.dumps(raw, indent=2, default=str))

    print(f"ToolCallingAgent run completed: {run_error is None}")
    if run_error:
        print(f"run error: {run_error}")

    try:
        events = adapt(raw, TASK_ID)
    except Exception as exc:
        print(f"adapt/validation FAILED: {type(exc).__name__}: {exc}")
        return

    norm_path = OUT_DIR / f"{TASK_ID}.jsonl"
    norm_path.write_text("\n".join(json.dumps(e) for e in events) + "\n")

    delegations = [e for e in events if e["event"] == "delegation"]
    called = {d["agent_id"] for d in delegations}
    print(f"delegation events: {delegations}")
    print(f"specialists called: {sorted(called)} (both: {called == {'research_agent', 'math_agent'}})")

    traces = parse_lines([json.dumps(e) for e in events])
    m = compute_metrics(traces[TASK_ID])
    print(f"compute_metrics: {m}")
    print(f"normalized trace written: {norm_path}")


if __name__ == "__main__":
    main()
