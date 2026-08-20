from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from ..traces.schema import Trace


class TopologyError(Exception):
    pass


@dataclass(frozen=True)
class TraceMetrics:
    task_id: str
    num_agents: int
    delegation_count: int
    max_depth: int
    fanout: list[int]  # child count per delegating agent
    tool_call_count: int
    num_tool_participants: int
    task_duration: float | None


def compute_metrics(trace: Trace) -> TraceMetrics:
    children: dict[str, list[str]] = defaultdict(list)
    all_agents: set[str] = set()
    created: set[str] = set()

    for d in trace.delegations:
        # A parent may legitimately delegate to the same child more than once
        # (e.g. retrying a specialist with a refined query). That's a repeated
        # edge, not a second edge, so dedupe here rather than let the BFS below
        # mistake a revisited-via-duplicate-edge child for a cycle.
        if d.agent_id not in children[d.parent_agent_id]:
            children[d.parent_agent_id].append(d.agent_id)
        all_agents.add(d.parent_agent_id)
        all_agents.add(d.agent_id)
        created.add(d.agent_id)

    for t in trace.tool_calls:
        all_agents.add(t.agent_id)

    roots = all_agents - created
    max_depth = 0
    if trace.delegations:
        if len(roots) != 1:
            raise TopologyError(
                f"task {trace.task_id}: expected exactly one root agent, found {sorted(roots)}"
            )
        root = next(iter(roots))
        queue = deque([(root, 0)])
        seen = {root}
        while queue:
            agent, depth = queue.popleft()
            max_depth = max(max_depth, depth)
            for child in children.get(agent, []):
                if child in seen:
                    raise TopologyError(f"task {trace.task_id}: cycle at agent {child!r}")
                seen.add(child)
                queue.append((child, depth + 1))

    fanout = [len(kids) for kids in children.values()]
    tool_participants = {(t.agent_id, t.server) for t in trace.tool_calls}

    return TraceMetrics(
        task_id=trace.task_id,
        num_agents=len(all_agents),
        delegation_count=len(trace.delegations),
        max_depth=max_depth,
        fanout=fanout,
        tool_call_count=len(trace.tool_calls),
        num_tool_participants=len(tool_participants),
        task_duration=trace.duration(),
    )


def compute_all(traces: dict[str, Trace]) -> list[TraceMetrics]:
    return [compute_metrics(t) for t in traces.values()]
