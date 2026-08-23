import json

import pytest

from measurement.adapters.smolagents_toolcalling_adapter import DelegationValidationError, adapt
from measurement.analysis.topology import compute_metrics
from measurement.traces.jsonl import parse_lines


def _corroborated_agent(start: float, end: float, tool: str = "web_search") -> dict:
    return {"steps": [
        {"step_type": "ActionStep", "timing": {"start_time": start, "end_time": end}, "tool_calls": [
            {"name": tool, "arguments": {}},
        ], "error": None},
    ]}


def test_single_step_calling_two_agents_yields_two_delegations():
    # a ToolCallingAgent step can carry more than one tool_call entry when the
    # model requests parallel tool calls in a single turn
    raw = {
        "agents": {
            "manager": {"steps": [
                {"step_type": "ActionStep", "timing": {"start_time": 0.0, "end_time": 1.0}, "tool_calls": [
                    {"name": "research_agent", "arguments": {"task": "a"}},
                    {"name": "math_agent", "arguments": {"task": "b"}},
                ], "error": None},
            ]},
            "research_agent": _corroborated_agent(0.2, 0.4),
            "math_agent": _corroborated_agent(0.5, 0.7),
        },
    }
    events = adapt(raw, task_id="multi")
    lines = [json.dumps(e) for e in events]
    traces = parse_lines(lines)
    m = compute_metrics(traces["multi"])
    assert m.num_agents == 3
    assert m.delegation_count == 2
    assert m.fanout == [2]
    assert m.max_depth == 1


def test_delegation_without_child_activity_fails_validation():
    raw = {
        "agents": {
            "manager": {"steps": [
                {"step_type": "ActionStep", "timing": {"start_time": 0.0, "end_time": 1.0}, "tool_calls": [
                    {"name": "research_agent", "arguments": {"task": "a"}},
                ], "error": None},
            ]},
            "research_agent": {"steps": [
                {"step_type": "TaskStep", "step_number": None, "timing": None, "tool_calls": [], "error": None},
            ]},
        },
    }
    with pytest.raises(DelegationValidationError):
        adapt(raw, task_id="false_positive")


def test_real_tool_call_not_mistaken_for_delegation():
    raw = {
        "agents": {
            "research_agent": {"steps": [
                {"step_type": "ActionStep", "timing": {"start_time": 0.0, "end_time": 1.0}, "tool_calls": [
                    {"name": "web_search", "arguments": {"query": "x"}},
                ], "error": None},
            ]},
        },
    }
    events = adapt(raw, task_id="solo")
    lines = [json.dumps(e) for e in events]
    traces = parse_lines(lines)
    m = compute_metrics(traces["solo"])
    assert m.delegation_count == 0
    assert m.tool_call_count == 1
