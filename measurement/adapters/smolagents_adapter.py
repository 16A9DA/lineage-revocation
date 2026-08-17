# Adapts a raw smolagents trace (as written by
# experiments/runners/groq_manager_research.py) into the normalized JSONL
# schema (task_start/delegation/tool_call/task_end). A tool_call whose code
# invokes a managed agent by name is recorded as delegation, not tool_call,
# since that is what it structurally is in a smolagents CodeAgent.
from __future__ import annotations

import json
from pathlib import Path


def adapt(raw: dict, task_id: str) -> list[dict]:
    manager_name = raw["manager"]["name"]
    managed_name = raw["research_agent"]["name"]

    events: list[dict] = []
    starts: list[float] = []
    ends: list[float] = []

    def handle_steps(agent_name: str, steps: list[dict]) -> None:
        for step in steps:
            timing = step.get("timing")
            if not timing:
                continue
            ts = timing["start_time"]
            starts.append(ts)
            ends.append(timing["end_time"])
            for tc in step.get("tool_calls", []):
                args = tc.get("arguments")
                if isinstance(args, str) and f"{managed_name}(" in args:
                    events.append({
                        "event": "delegation", "task_id": task_id,
                        "parent_agent_id": agent_name, "agent_id": managed_name,
                        "timestamp": ts,
                    })
                else:
                    events.append({
                        "event": "tool_call", "task_id": task_id,
                        "agent_id": agent_name, "tool": tc["name"],
                        "timestamp": ts,
                    })

    handle_steps(manager_name, raw["manager"]["steps"])
    handle_steps(managed_name, raw["research_agent"]["steps"])

    out = [{"event": "task_start", "task_id": task_id, "timestamp": min(starts)}]
    out.extend(events)
    out.append({"event": "task_end", "task_id": task_id, "timestamp": max(ends)})
    return out


def adapt_file(raw_path: Path, task_id: str) -> list[dict]:
    return adapt(json.loads(raw_path.read_text()), task_id)


if __name__ == "__main__":
    import sys

    raw_path = Path(sys.argv[1])
    task_id = raw_path.stem
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else (
        Path(__file__).resolve().parents[2] / "experiments" / "traces" / "normalized" / f"{task_id}.jsonl"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(e) for e in adapt_file(raw_path, task_id)]
    out_path.write_text("\n".join(lines) + "\n")
    print(f"normalized trace written: {out_path}")
