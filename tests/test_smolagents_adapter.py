import json
from pathlib import Path

import pytest

from measurement.adapters.smolagents_adapter import DelegationValidationError, adapt, adapt_file
from measurement.analysis.topology import compute_metrics
from measurement.traces.jsonl import parse_lines

FIXTURE = Path(__file__).parent / "fixtures" / "groq_manager_research_raw.json"


def test_adapt_produces_one_delegation_and_valid_topology():
    # fixture is a real captured smolagents trace on Groq, not synthetic
    events = adapt_file(FIXTURE, task_id="t")
    lines = [json.dumps(e) for e in events]
    traces = parse_lines(lines)
    m = compute_metrics(traces["t"])
    assert m.num_agents == 2
    assert m.delegation_count == 1
    assert m.max_depth == 1
    assert m.tool_call_count == 5  # 3 manager python_interpreter + research web_search + final_answer


def _corroborated_agent(start: float, end: float, tool: str = "web_search") -> dict:
    return {"steps": [
        {"step_type": "ActionStep", "timing": {"start_time": start, "end_time": end}, "tool_calls": [
            {"name": tool, "arguments": {}},
        ], "error": None},
    ]}


def test_single_step_calling_two_agents_yields_two_delegations():
    raw = {
        "agents": {
            "manager": {"steps": [
                {"step_type": "ActionStep", "timing": {"start_time": 0.0, "end_time": 1.0}, "tool_calls": [
                    {"name": "python_interpreter",
                     "arguments": "research_agent(task='a')\nmath_agent(task='b')"},
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

    delegations = [e for e in events if e["event"] == "delegation"]
    # order follows position of the call in the code, research_agent( comes first
    assert [d["agent_id"] for d in delegations] == ["research_agent", "math_agent"]


def test_delegation_without_child_activity_fails_validation():
    raw = {
        "agents": {
            "manager": {"steps": [
                {"step_type": "ActionStep", "timing": {"start_time": 0.0, "end_time": 1.0}, "tool_calls": [
                    {"name": "python_interpreter",
                     "arguments": "# call research_agent(task) once this is ready\nprint('todo')"},
                ], "error": None},
            ]},
            # registered, but never actually ran: only the placeholder TaskStep, timing is None
            "research_agent": {"steps": [
                {"step_type": "TaskStep", "step_number": None, "timing": None, "tool_calls": [], "error": None},
            ]},
        },
    }
    with pytest.raises(DelegationValidationError):
        adapt(raw, task_id="false_positive")
