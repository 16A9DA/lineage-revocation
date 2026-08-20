# tests/fixtures/sample_trace.jsonl is a synthetic fixture for exercising the
# parser/analysis code paths. It is not a real agent workload measurement.
from pathlib import Path

import pytest

from measurement.analysis.distributions import summarize
from measurement.analysis.topology import TopologyError, compute_metrics
from measurement.plots.histograms import histogram_bins
from measurement.traces.jsonl import TraceParseError, parse_jsonl, parse_lines
from measurement.traces.schema import DelegationEvent, Trace

FIXTURE = Path(__file__).parent / "fixtures" / "sample_trace.jsonl"


def test_parse_jsonl_splits_by_task():
    traces = parse_jsonl(FIXTURE)
    assert set(traces) == {"t1", "t2"}


def test_t1_metrics():
    traces = parse_jsonl(FIXTURE)
    m = compute_metrics(traces["t1"])
    assert m.num_agents == 4  # root, a, b, c
    assert m.delegation_count == 3
    assert m.max_depth == 2  # root -> a -> {b, c}
    assert sorted(m.fanout) == [1, 2]  # root->a (1), a->{b,c} (2)
    assert m.tool_call_count == 2
    assert m.num_tool_participants == 2  # (root, local), (b, local)
    assert m.task_duration == 50


def test_t2_metrics():
    traces = parse_jsonl(FIXTURE)
    m = compute_metrics(traces["t2"])
    assert m.num_agents == 2
    assert m.max_depth == 1
    assert m.fanout == [1]
    assert m.tool_call_count == 0
    assert m.task_duration == 20


def test_unknown_event_rejected():
    with pytest.raises(TraceParseError):
        parse_lines(['{"event": "bogus", "task_id": "t1"}'])


def test_invalid_json_rejected():
    with pytest.raises(TraceParseError):
        parse_lines(["not json"])


def test_cycle_detected():
    trace = Trace(
        task_id="cyclic",
        delegations=[
            DelegationEvent(task_id="cyclic", parent_agent_id="a", agent_id="b"),
            DelegationEvent(task_id="cyclic", parent_agent_id="b", agent_id="a"),
        ],
        tool_calls=[],
    )
    with pytest.raises(TopologyError):
        compute_metrics(trace)


def test_repeated_delegation_to_same_child_accepted():
    trace = Trace(
        task_id="retry",
        delegations=[
            DelegationEvent(task_id="retry", parent_agent_id="manager", agent_id="research"),
            DelegationEvent(task_id="retry", parent_agent_id="manager", agent_id="research"),
        ],
        tool_calls=[],
    )
    m = compute_metrics(trace)
    assert m.num_agents == 2
    assert m.delegation_count == 2  # both retry events still counted
    assert m.max_depth == 1
    assert m.fanout == [1]  # one distinct child, not two


def test_multiple_roots_rejected():
    trace = Trace(
        task_id="split",
        delegations=[
            DelegationEvent(task_id="split", parent_agent_id="root1", agent_id="a"),
            DelegationEvent(task_id="split", parent_agent_id="root2", agent_id="b"),
        ],
        tool_calls=[],
    )
    with pytest.raises(TopologyError):
        compute_metrics(trace)


def test_summarize_percentiles():
    s = summarize([1.0, 2.0, 3.0, 4.0, 5.0])
    assert s.n == 5
    assert s.min == 1.0
    assert s.max == 5.0
    assert s.p50 == 3.0


def test_summarize_empty_raises():
    with pytest.raises(ValueError):
        summarize([])


def test_histogram_bins_cover_all_values():
    bins = histogram_bins([1.0, 2.0, 3.0, 10.0], bin_count=3)
    assert sum(count for _, _, count in bins) == 4
