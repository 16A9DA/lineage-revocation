from __future__ import annotations

import json
from pathlib import Path

from .smolagents_adapter import DelegationValidationError, _agent_has_activity


def adapt(raw: dict, task_id: str) -> list[dict]:
    # ToolCallingAgent records each tool call as structured JSON
    # ({"name": ..., "arguments": {...}}), not a Python code string, so
    # unlike smolagents_adapter.adapt (CodeAgent) there is no substring
    # search: a managed agent is exposed to the model as a tool whose name
    # equals the agent's name, so a call is delegation iff its tool name is
    # a *different* registered agent's name.
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
                name = tc["name"]
                if name in agent_names and name != agent_name:
                    events.append({
                        "event": "delegation", "task_id": task_id,
                        "parent_agent_id": agent_name, "agent_id": name,
                        "timestamp": ts,
                    })
                else:
                    events.append({
                        "event": "tool_call", "task_id": task_id,
                        "agent_id": agent_name, "tool": name,
                        "timestamp": ts,
                    })

    for e in events:
        if e["event"] != "delegation":
            continue
        child = e["agent_id"]
        if not _agent_has_activity(raw, child):
            raise DelegationValidationError(
                f"task {task_id}: delegation {e['parent_agent_id']!r} -> {child!r} has no "
                f"corroborating activity from {child!r} in the raw trace"
            )

    out = [{"event": "task_start", "task_id": task_id, "timestamp": min(starts)}]
    out.extend(events)
    out.append({"event": "task_end", "task_id": task_id, "timestamp": max(ends)})
    return out


def adapt_file(raw_path: Path, task_id: str) -> list[dict]:
    return adapt(json.loads(raw_path.read_text()), task_id)
