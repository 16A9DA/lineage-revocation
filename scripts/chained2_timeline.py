from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from measurement.adapters.smolagents_adapter import adapt  # noqa: E402

RAW = ROOT / "artifacts/raw_traces_haiku"
NORM = ROOT / "experiments/traces/normalized_haiku"


def windows(steps):
    return [(s["step_number"], s["timing"]["start_time"], s["timing"]["end_time"]) for s in steps if s.get("timing")]


def main() -> None:
    out = {}
    for p in sorted(RAW.glob("manager_specialist_delegation_chained_2_*.json")):
        d = json.loads(p.read_text())
        A = d["agents"]
        mgr, mid, leaf = (windows(A[a]["steps"]) for a in ("manager_agent", "mid_agent", "leaf_research_agent"))
        t0 = min(w[1] for w in mgr)
        rel = lambda ws: [(n, round(s - t0, 1), round(e - t0, 1)) for n, s, e in ws]  # noqa: E731
        calls = lambda a, tgt: [s["step_number"] for s in A[a]["steps"]  # noqa: E731
                                for c in s["tool_calls"] if f"{tgt}(" in str(c["arguments"])]
        inside = [w for w in leaf if any(m[1] <= w[1] and w[2] <= m[2] for m in mid)]
        events = adapt(d, p.stem)
        stored = [json.loads(line) for line in (NORM / f"{p.stem}.jsonl").read_text().splitlines() if line.strip()]
        out[p.stem] = {
            "seconds_relative_to_manager_start": {"manager": rel(mgr), "mid": rel(mid), "leaf_first_last": rel([leaf[0], leaf[-1]])},
            "manager_steps_calling_mid": calls("manager_agent", "mid_agent"),
            "mid_steps_calling_leaf_in_serialized_trace": calls("mid_agent", "leaf_research_agent"),
            "leaf_steps_total": len(leaf),
            "leaf_steps_inside_a_retained_mid_step_window": len(inside),
            "manager_step_errors": [(s["step_number"], (s["error"] or "")[:60]) for s in A["manager_agent"]["steps"] if s["error"]],
            "adapter_edges": sorted({(e["parent_agent_id"], e["agent_id"]) for e in events if e["event"] == "delegation"}),
            "adapter_output_equals_stored_normalized": events == stored,
        }
    from smolagents.agents import MultiStepAgent
    out["smolagents_run_resets_memory"] = [ln.strip() for ln in inspect.getsource(MultiStepAgent.run).splitlines() if "reset" in ln]
    out["collector_serializes_post_run_memory"] = [
        ln.strip() for ln in (ROOT / "experiments/runners/collect.py").read_text().splitlines() if "agent.memory.steps" in ln]
    print(json.dumps(out, indent=2, default=list))


if __name__ == "__main__":
    main()
