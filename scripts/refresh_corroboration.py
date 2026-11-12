from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from measurement.adapters.smolagents_adapter import adapt  # noqa: E402
from measurement.analysis.topology import compute_metrics  # noqa: E402
from measurement.traces.jsonl import parse_lines  # noqa: E402

ORIGINAL_COMMIT = "0a69575"
OUT_JSON = ROOT / "artifacts/validation/delegation-corroboration-refresh.json"
OUT_MD = ROOT / "docs/delegation-corroboration-refresh.md"


def _git_original_33() -> list[str]:
    out = subprocess.run(["git", "ls-tree", "-r", "--name-only", ORIGINAL_COMMIT, "artifacts/raw_traces"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    return sorted(Path(p).name for p in out if p.endswith(".json") and "/failed/" not in p)


def _stored_events(norm_dir: Path, stem: str) -> int | None:
    p = norm_dir / f"{stem}.jsonl"
    if not p.exists():
        return None
    return sum(json.loads(line)["event"] == "delegation" for line in p.read_text().splitlines() if line.strip())


def check(raw_dir: Path, norm_dir: Path, names: list[str]) -> dict:
    events = corrob = valid = 0
    failures, norm_mismatch, topo_errors = {}, {}, {}
    depths: Counter = Counter()
    per_trace = {}
    for n in names:
        stem = n[:-5]
        try:
            ev = adapt(json.loads((raw_dir / n).read_text()), stem)
        except Exception as exc:  # DelegationValidationError, KeyError (schema), JSON errors
            failures[n] = f"{type(exc).__name__}: {exc}"
            continue
        valid += 1
        d = [e for e in ev if e["event"] == "delegation"]
        events += len(d)
        corrob += len(d)  # adapt() raises unless every delegation has child activity, so valid => all corroborated
        stored = _stored_events(norm_dir, stem)
        if stored != len(d):
            norm_mismatch[n] = {"fresh": len(d), "stored_normalized": stored}
        try:
            m = compute_metrics(parse_lines([json.dumps(e) for e in ev])[stem])
            depths[m.max_depth] += 1
            per_trace[n] = {"delegations": m.delegation_count, "max_depth": m.max_depth,
                            "distinct_children": len({e["agent_id"] for e in d}), "fanout": m.fanout}
        except Exception as exc:
            topo_errors[n] = f"{type(exc).__name__}: {exc}"
            per_trace[n] = {"delegations": len(d), "topology_error": str(exc)}
    return {
        "traces_processed": len(names), "valid_traces": valid,
        "delegation_events": events, "corroborated_delegation_events": corrob,
        "uncorroborated_delegation_events": events - corrob,
        "validation_failures": failures,
        "events_in_failed_traces": "not enumerable (adapter raises before returning events)" if failures else 0,
        "topology_scorable_traces": valid - len(topo_errors), "topology_errors": topo_errors,
        "max_depth_distribution": {str(k): v for k, v in sorted(depths.items())},
        "stored_normalized_vs_fresh_event_mismatch": norm_mismatch,
        "per_trace": per_trace,
    }


def main() -> None:
    groq_raw, groq_norm = ROOT / "artifacts/raw_traces", ROOT / "experiments/traces/normalized"
    hk_raw, hk_norm = ROOT / "artifacts/raw_traces_haiku", ROOT / "experiments/traces/normalized_haiku"
    orig = _git_original_33()
    cur = sorted(p.name for p in groq_raw.glob("*.json"))
    hk = sorted(p.name for p in hk_raw.glob("*.json"))
    res = {
        "method": "measurement.adapters.smolagents_adapter.adapt over each raw trace; corroborated = child agent has timed activity",
        "datasets_not_pooled": True,
        "groq_original_33": {
            "source": f"files tracked under artifacts/raw_traces/ at git commit {ORIGINAL_COMMIT}; run with CURRENT adapter",
            "provider_model": "groq; model NOT recorded in traces (see trace-counts.json model_provenance)",
            **check(groq_raw, groq_norm, orig),
            "excluded": {"artifacts/raw_traces/failed/*": "failure records, not traces", "smoke/probe traces": "separate dataset"},
        },
        "groq_current_34": {
            "source": "artifacts/raw_traces/*.json on disk now",
            "added_vs_original_33": sorted(set(cur) - set(orig)), "missing_vs_original_33": sorted(set(orig) - set(cur)),
            "provider_model": "groq; model NOT recorded in traces (see trace-counts.json model_provenance)",
            **check(groq_raw, groq_norm, cur),
            "excluded": {"artifacts/raw_traces/failed/*": "5 failure records, not traces", "smoke/probe traces": "separate dataset"},
        },
        "haiku_12": {
            "source": "artifacts/raw_traces_haiku/*.json", "provider_model": "anthropic OpenAI-compatible endpoint, claude-haiku-5-5",
            **check(hk_raw, hk_norm, hk),
            "excluded": {"none": "no failure records, no exclusions"},
        },
    }
    hist = ROOT / "artifacts/validation/delegation-corroboration-33.json"
    h = json.loads(hist.read_text())
    res["historical_33_reproduction"] = {
        "stored": {"traces": h["trace_count"], "events": h["delegation_events"]["total"]},
        "recomputed_now": {"traces": res["groq_original_33"]["traces_processed"], "events": res["groq_original_33"]["delegation_events"]},
        "matches_stored": h["trace_count"] == res["groq_original_33"]["traces_processed"]
        and h["delegation_events"]["total"] == res["groq_original_33"]["delegation_events"],
    }
    OUT_JSON.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")

    rows = ["| dataset | processed | valid | delegation events | corroborated | validation failures | topology-scorable | max-depth dist. |", "|---|---:|---:|---:|---:|---:|---:|---|"]
    for k in ("groq_original_33", "groq_current_34", "haiku_12"):
        r = res[k]
        rows.append(f"| {k} | {r['traces_processed']} | {r['valid_traces']} | {r['delegation_events']} | {r['corroborated_delegation_events']} | "
                    f"{len(r['validation_failures'])} | {r['topology_scorable_traces']} | {r['max_depth_distribution']} |")
    md = [
        "# Delegation Corroboration: Refresh",
        "",
        "Generated by `scripts/refresh_corroboration.py`; machine-readable twin: `artifacts/validation/delegation-corroboration-refresh.json`.",
        "This does **not** replace `docs/delegation-corroboration-33.md` (historical, kept unchanged). Datasets are never pooled.",
        "",
        "Corroborated means the adapter found timed activity by the child agent in the raw trace. It checks that a call happened, not that the call was useful.",
        "Topology-scorable means `measurement.analysis.topology.compute_metrics` accepts the adapted trace (exactly one root agent).",
        "",
        *rows,
        "",
        f"Historical reproduction: stored {res['historical_33_reproduction']['stored']}, recomputed {res['historical_33_reproduction']['recomputed_now']}, "
        f"matches = {res['historical_33_reproduction']['matches_stored']}.",
        f"Original-33 set = files tracked at commit `{ORIGINAL_COMMIT}`. Current-34 adds: {res['groq_current_34']['added_vs_original_33']}; missing: {res['groq_current_34']['missing_vs_original_33']}.",
        "",
        "## Excluded",
        "- `artifacts/raw_traces/failed/*` (5 records): failure records, not traces. None under `raw_traces_haiku/`.",
        "- `experiments/traces/smoke/*`: probe/smoke runs, separate dataset.",
        "- No trace was excluded for validation failure.",
        "",
        "## Validation failures and topology errors",
    ]
    for k in ("groq_original_33", "groq_current_34", "haiku_12"):
        r = res[k]
        md.append(f"- {k}: validation failures {r['validation_failures'] or 'none'}; topology errors {r['topology_errors'] or 'none'}; "
                  f"stored-normalized vs fresh event mismatches {r['stored_normalized_vs_fresh_event_mismatch'] or 'none'}")
    md += ["", "## Provider/model", "- Groq sets: model is not recorded inside the traces. See `artifacts/validation/trace-counts.json` (`model_provenance`): 33 of 34 traces predate the commit that changed the collector model.",
           "- Haiku: `claude-haiku-5-5` per collector at commit `375b5fc`; not recorded in the traces either.",
           "", "## Haiku per-trace (depth, children)", "| trace | delegations | max depth | distinct children | fanout |", "|---|---:|---:|---:|---|"]
    for n, t in res["haiku_12"]["per_trace"].items():
        md.append(f"| {n[:-5]} | {t['delegations']} | {t.get('max_depth', 'n/a: ' + t.get('topology_error', ''))} | {t.get('distinct_children', '')} | {t.get('fanout', '')} |")
    OUT_MD.write_text("\n".join(md) + "\n")
    print("\n".join(rows))
    print("historical reproduction:", res["historical_33_reproduction"])


if __name__ == "__main__":
    main()
