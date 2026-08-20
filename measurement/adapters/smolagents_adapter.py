from __future__ import annotations

import json
from pathlib import Path


class DelegationValidationError(Exception):
    pass


def _agent_has_activity(raw: dict, agent_name: str) -> bool:
    # A registered agent "did something" only if at least one of its steps
    # actually ran (non-null timing). A TaskStep placeholder alone means the
    # agent was registered but never invoked.
    steps = raw["agents"].get(agent_name, {}).get("steps", [])
    return any(step.get("timing") for step in steps)


def adapt(raw: dict, task_id: str) -> list[dict]:
    # A tool_call whose code invokes another known agent by name is
    # delegation, not tool use, in a smolagents CodeAgent. A single code
    # block can call more than one managed agent, so every registered
    # agent name found in the code is its own delegation, not just the
    # first one matched.
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
                targets = []
                if isinstance(args, str):
                    targets = sorted(
                        (o for o in agent_names if o != agent_name and f"{o}(" in args),
                        key=lambda o: args.find(f"{o}("),
                    )
                if targets:
                    for target in targets:
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

    for e in events:
        if e["event"] != "delegation":
            continue
        child = e["agent_id"]
        if not _agent_has_activity(raw, child):
            raise DelegationValidationError(
                f"task {task_id}: delegation {e['parent_agent_id']!r} -> {child!r} has no "
                f"corroborating activity from {child!r} in the raw trace (likely a comment, "
                f"string, or dead-code match on the agent's name rather than a real call)"
            )

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
