from __future__ import annotations

import json
from pathlib import Path


def adapt(raw: dict, task_id: str) -> list[dict]:
    # A tool_call whose code invokes another known agent by name is
    # delegation, not tool use, in a smolagents CodeAgent.
    agent_names = set(raw["agents"])
    events: list[dict] = []
    starts: list[float] = []
    ends: list[float] = []

    for agent_name, data in raw["agents"].items():
        for step in data["steps"]:
            timing = step.get("timing")
            if not timing:
                continue
            ts = timing["start_time"]
            starts.append(ts)
            ends.append(timing.get("end_time", ts))
            for tc in step.get("tool_calls", []):
                args = tc.get("arguments")
                target = next(
                    (o for o in agent_names if o != agent_name and isinstance(args, str) and f"{o}(" in args),
                    None,
                )
                if target:
                    events.append({
                        "event": "delegation", "task_id": task_id,
                        "parent_agent_id": agent_name, "agent_id": target,
                        "timestamp": ts,
                    })
                else:
                    events.append({
                        "event": "tool_call", "task_id": task_id,
                        "agent_id": agent_name, "tool": tc["name"],
                        "timestamp": ts,
                    })

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
