from __future__ import annotations

import json
from pathlib import Path

from .schema import DelegationEvent, Trace, ToolCallEvent


class TraceParseError(Exception):
    pass


def parse_jsonl(path: Path) -> dict[str, Trace]:
    return parse_lines(path.read_text().splitlines())


def parse_lines(lines: list[str]) -> dict[str, Trace]:
    delegations: dict[str, list[DelegationEvent]] = {}
    tool_calls: dict[str, list[ToolCallEvent]] = {}
    starts: dict[str, float | None] = {}
    ends: dict[str, float | None] = {}

    for i, raw in enumerate(lines):
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TraceParseError(f"line {i}: invalid JSON") from exc

        event = rec.get("event")
        task_id = rec.get("task_id")
        if task_id is None:
            raise TraceParseError(f"line {i}: missing task_id")

        if event == "delegation":
            delegations.setdefault(task_id, []).append(DelegationEvent(
                task_id=task_id,
                parent_agent_id=rec["parent_agent_id"],
                agent_id=rec["agent_id"],
                timestamp=rec.get("timestamp"),
            ))
        elif event == "tool_call":
            tool_calls.setdefault(task_id, []).append(ToolCallEvent(
                task_id=task_id,
                agent_id=rec["agent_id"],
                tool=rec["tool"],
                timestamp=rec.get("timestamp"),
                server=rec.get("server"),
            ))
        elif event == "task_start":
            starts[task_id] = rec.get("timestamp")
        elif event == "task_end":
            ends[task_id] = rec.get("timestamp")
        else:
            raise TraceParseError(f"line {i}: unknown event {event!r}")

    task_ids = set(delegations) | set(tool_calls) | set(starts) | set(ends)
    return {
        task_id: Trace(
            task_id=task_id,
            delegations=delegations.get(task_id, []),
            tool_calls=tool_calls.get(task_id, []),
            start_time=starts.get(task_id),
            end_time=ends.get(task_id),
        )
        for task_id in task_ids
    }
