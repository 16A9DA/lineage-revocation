from __future__ import annotations

# Parallelism capability probe for Collection Plan v2 cell C
# (docs/collection-plan-v2.md). The prior smoke test used a *dependent* task
# (percent of a looked-up number), which forces research_agent -> math_agent
# ordering regardless of the model's parallel tool-calling ability. These
# probes use independent facts instead, so nothing stops the manager from
# calling both specialists in the same turn if the model/provider supports
# it. Same safe/controlled mechanism as smoke_toolcalling.py: reuses
# build_manager (TimedWebSearchTool, safe-search locked) and writes only to
# experiments/traces/smoke/, never touching the real dataset dirs.

import json
import os
import signal
import sys
from pathlib import Path

from smolagents import OpenAIServerModel

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from experiments.runners.collect import TaskTimeout, _alarm, _step_to_dict
from experiments.runners.smoke_toolcalling import build_manager
from measurement.adapters.smolagents_toolcalling_adapter import adapt
from measurement.analysis.topology import compute_metrics
from measurement.traces.jsonl import parse_lines

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "experiments" / "traces" / "smoke"

PROBES = [
    ("probe_00_neutral",
     "Look up the height of the Eiffel Tower in meters, and separately calculate "
     "15 percent of 2000. These two things are unrelated to each other."),
    ("probe_01_explicit_parallel",
     "Do these two independent tasks at the same time: (1) look up the current "
     "speed of light in kilometers per second, (2) calculate 37 multiplied by 89. "
     "Neither task depends on the other."),
    ("probe_02_forced_multi_lookup",
     "Look up the boiling point of water in Celsius at sea level, and compute the "
     "square root of 144. Handle both of these."),
]


def _same_turn_multi_delegation(raw: dict, root_name: str) -> bool:
    agent_names = set(raw["agents"])
    for step in raw["agents"][root_name]["steps"]:
        targets = {tc["name"] for tc in step.get("tool_calls", []) if tc["name"] in agent_names}
        if len(targets) > 1:
            return True
    return False


def run_probe(model, task_id: str, task: str) -> None:
    root_name, agents = build_manager(model)

    signal.alarm(300)
    run_error = None
    try:
        agents[root_name].run(task)
    except TaskTimeout as exc:
        run_error = f"{type(exc).__name__}: {exc}"
    except Exception as exc:
        run_error = f"{type(exc).__name__}: {exc}"
    finally:
        signal.alarm(0)

    raw = {
        "workload_id": "probe_toolcalling_parallelism", "run_id": task_id, "task": task,
        "root_agent": root_name, "run_error": run_error,
        "agents": {
            name: {"steps": [_step_to_dict(s) for s in agent.memory.steps]}
            for name, agent in agents.items()
        },
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / f"{task_id}.json").write_text(json.dumps(raw, indent=2, default=str))

    print(f"\n=== {task_id} ===")
    print(f"completed: {run_error is None}" + (f" ({run_error})" if run_error else ""))

    try:
        events = adapt(raw, task_id)
    except Exception as exc:
        print(f"adapt/validation FAILED: {type(exc).__name__}: {exc}")
        return
    (OUT_DIR / f"{task_id}.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n")

    delegations = [e for e in events if e["event"] == "delegation"]
    called = {d["agent_id"] for d in delegations}
    traces = parse_lines([json.dumps(e) for e in events])
    m = compute_metrics(traces[task_id])

    print(f"called research_agent: {'research_agent' in called}")
    print(f"called math_agent: {'math_agent' in called}")
    print(f"same-turn multi-agent call: {_same_turn_multi_delegation(raw, root_name)}")
    print(f"delegation_count: {m.delegation_count}  fanout: {m.fanout}  max_depth: {m.max_depth}")
    print(f"validation+compute_metrics: OK")


def main() -> None:
    model = OpenAIServerModel(
        model_id="qwen/qwen3.6-27b",
        api_base="https://api.groq.com/openai/v1",
        api_key=os.environ["GROQ_API_KEY"],
        client_kwargs={"timeout": 60.0, "max_retries": 2},
    )
    signal.signal(signal.SIGALRM, _alarm)
    wanted = set(sys.argv[1:]) or None
    for task_id, task in PROBES:
        if wanted and task_id not in wanted:
            continue
        run_probe(model, task_id, task)


if __name__ == "__main__":
    main()
