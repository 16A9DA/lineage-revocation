from __future__ import annotations

import csv
from pathlib import Path


def histogram_bins(values: list[float], bin_count: int = 10) -> list[tuple[float, float, int]]:
    if not values:
        return []
    lo, hi = min(values), max(values)
    if lo == hi:
        return [(lo, hi, len(values))]
    width = (hi - lo) / bin_count
    bins = [[lo + i * width, lo + (i + 1) * width, 0] for i in range(bin_count)]
    for v in values:
        idx = min(int((v - lo) / width), bin_count - 1)
        bins[idx][2] += 1
    return [(b[0], b[1], b[2]) for b in bins]


def write_histogram_csv(values: list[float], out_path: Path, bin_count: int = 10) -> None:
    bins = histogram_bins(values, bin_count)
    with out_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["bin_start", "bin_end", "count"])
        writer.writerows(bins)


def render_text_histogram(values: list[float], bin_count: int = 10, width: int = 40) -> str:
    bins = histogram_bins(values, bin_count)
    if not bins:
        return "(no data)"
    max_count = max(c for _, _, c in bins) or 1
    lines = []
    for lo, hi, count in bins:
        bar = "#" * max(1, round(count / max_count * width)) if count else ""
        lines.append(f"{lo:10.2f} - {hi:10.2f} | {bar} {count}")
    return "\n".join(lines)
