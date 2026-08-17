from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DelegationEvent:
    task_id: str
    parent_agent_id: str
    agent_id: str
    timestamp: float | None = None


@dataclass(frozen=True)
class ToolCallEvent:
    task_id: str
    agent_id: str
    tool: str
    timestamp: float | None = None
    server: str | None = None


@dataclass(frozen=True)
class Trace:
    task_id: str
    delegations: list[DelegationEvent]
    tool_calls: list[ToolCallEvent]
    start_time: float | None = None
    end_time: float | None = None

    def duration(self) -> float | None:
        if self.start_time is None or self.end_time is None:
            return None
        return self.end_time - self.start_time
