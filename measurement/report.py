from __future__ import annotations

import argparse
from pathlib import Path

from .analysis.distributions import summarize
from .analysis.topology import compute_all
from .plots.histograms import render_text_histogram, write_histogram_csv
from .traces.jsonl import parse_jsonl

SCALAR_METRICS = [
    "max_depth", "delegation_count", "num_agents",
    "tool_call_count", "num_tool_participants", "task_duration",
]


def _report_metric(name: str, values: list[float], out_dir: Path | None) -> None:
    if not values:
        print(f"{name}: no data")
        return
    s = summarize(values)
    print(f"{name}: n={s.n} mean={s.mean:.2f} p50={s.p50:.2f} p95={s.p95:.2f} p99={s.p99:.2f}")
    print(render_text_histogram(values))
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        write_histogram_csv(values, out_dir / f"{name}.csv")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Summarize agent delegation traces (JSONL).")
    parser.add_argument("trace_file", type=Path)
    parser.add_argument("--out-dir", type=Path, default=None, help="write histogram CSVs here")
    args = parser.parse_args(argv)

    traces = parse_jsonl(args.trace_file)
    metrics = compute_all(traces)

    for name in SCALAR_METRICS:
        values = [float(v) for m in metrics if (v := getattr(m, name)) is not None]
        _report_metric(name, values, args.out_dir)

    fanout_values = [float(f) for m in metrics for f in m.fanout]
    _report_metric("fanout", fanout_values, args.out_dir)


if __name__ == "__main__":
    main()
