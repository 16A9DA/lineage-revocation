from __future__ import annotations

import statistics
from dataclasses import dataclass


@dataclass(frozen=True)
class Summary:
    n: int
    mean: float
    p50: float
    p95: float
    p99: float
    min: float
    max: float


def summarize(values: list[float]) -> Summary:
    if not values:
        raise ValueError("cannot summarize empty distribution")
    ordered = sorted(values)
    return Summary(
        n=len(ordered),
        mean=statistics.fmean(ordered),
        p50=_percentile(ordered, 0.50),
        p95=_percentile(ordered, 0.95),
        p99=_percentile(ordered, 0.99),
        min=ordered[0],
        max=ordered[-1],
    )


def _percentile(ordered: list[float], p: float) -> float:
    # linear interpolation between closest ranks, per spec §19's P50/P95/P99 convention.
    if len(ordered) == 1:
        return ordered[0]
    k = p * (len(ordered) - 1)
    f, c = int(k), min(int(k) + 1, len(ordered) - 1)
    if f == c:
        return ordered[f]
    return ordered[f] + (ordered[c] - ordered[f]) * (k - f)
