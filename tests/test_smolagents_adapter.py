# tests/fixtures/groq_manager_research_raw.json is a real captured smolagents
# trace (manager_agent -> research_agent -> web_search, on Groq), not synthetic.
import json
from pathlib import Path

from measurement.adapters.smolagents_adapter import adapt_file
from measurement.analysis.topology import compute_metrics
from measurement.traces.jsonl import parse_lines

FIXTURE = Path(__file__).parent / "fixtures" / "groq_manager_research_raw.json"


def test_adapt_produces_one_delegation_and_valid_topology():
    events = adapt_file(FIXTURE, task_id="t")
    lines = [json.dumps(e) for e in events]
    traces = parse_lines(lines)
    m = compute_metrics(traces["t"])
    assert m.num_agents == 2
    assert m.delegation_count == 1
    assert m.max_depth == 1
    assert m.tool_call_count == 5  # 3 manager python_interpreter + research web_search + final_answer
