from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.configs.workloads import WORKLOADS  # noqa: E402

# Raw traces store NO provider/model. Labels below come from git history of the collector
# (see MODEL_EVIDENCE) plus directory, never from the trace files themselves.
DATASETS = {
    "groq": {
        "raw": "artifacts/raw_traces", "norm": "experiments/traces/normalized",
        "failed": "artifacts/raw_traces/failed", "provider": "groq",
    },
    "haiku": {
        "raw": "artifacts/raw_traces_haiku", "norm": "experiments/traces/normalized_haiku",
        "failed": "artifacts/raw_traces_haiku/failed",
        "provider": "anthropic (OpenAI-compatible endpoint)", "model": "claude-haiku-5-5",
    },
}
SMOKE_DIR = "experiments/traces/smoke"

# Collector model_id by commit (git show <c>:experiments/runners/collect.py), commit epoch (UTC).
MODEL_EVIDENCE = {
    "swap_commit_58cd04b_epoch": 1787186734,  # 2026-08-20T00:45:34Z: gpt-oss-120b -> qwen/qwen3.6-27b
    "collector_model_before_swap": "openai/gpt-oss-120b (collect.py at 87f188d, 42076b9, 9e6f44e)",
    "collector_model_after_swap": "qwen/qwen3.6-27b (collect.py at 58cd04b..0089e5d)",
    "first_runner_model": "llama-3.3-70b-versatile (groq_manager_research.py at 7726f33)",
    "note": "Commit time is not collection time. Trace epoch vs swap epoch is a bound, not proof.",
}

# Elicitation class per workload. Only config-documented classes are asserted; the rest are
# "unaudited": the Groq manager_* prompts were never audited for natural vs elicited delegation.
ELICITATION = {
    "simple_research": "none (solo, no managed agents)",
    "multi_step_research": "none (solo, no managed agents)",
    "technology_comparison": "unaudited",
    "document_technical_analysis": "unaudited",
    "manager_specialist_delegation": "unaudited",
    "manager_multi_specialist": "unaudited (prompt asks lookup then compute)",
    "manager_specialist_delegation_chained_2": "elicited-by-topology (manager's only agent is mid; mid's only agent is leaf)",
    "forced_multi_lookup": "elicited-by-prompt (prompt spells out lookup/convert/combine steps)",
}
NAME_RE = re.compile(r"^(?P<w>.+)_(?P<i>\d{2}|first_run)_(?P<ts>\d+)$")


def _load(path: Path):
    try:
        return json.loads(path.read_text()), None
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _jsonl_ok(path: Path) -> str | None:
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if line.strip():
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                return f"line {n}: {exc}"
    return None


def _digest(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(p.relative_to(ROOT).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def count_dataset(name: str, cfg: dict) -> dict:
    raw_dir, norm_dir, fail_dir = (ROOT / cfg[k] for k in ("raw", "norm", "failed"))
    raw = sorted(raw_dir.glob("*.json")) if raw_dir.is_dir() else []
    norm = sorted(norm_dir.glob("*.jsonl")) if norm_dir.is_dir() else []
    fail = sorted(fail_dir.glob("*.json")) if fail_dir.is_dir() else []
    cfg_w = {w: (topo, tasks) for w, topo, tasks in WORKLOADS}

    invalid_raw, invalid_norm, invalid_fail = {}, {}, {}
    by_wl: dict[str, dict] = defaultdict(lambda: {"raw_files": [], "indices": defaultdict(list), "failed": defaultdict(list),
                                                  "unindexed": [], "task_mismatch": [], "topology": None})
    unparsed = []
    swap = MODEL_EVIDENCE["swap_commit_58cd04b_epoch"]
    buckets: Counter = Counter()

    for p in raw:
        data, err = _load(p)
        if err:
            invalid_raw[p.name] = err
        m = NAME_RE.match(p.stem)
        if not m:
            unparsed.append(p.name)
            continue
        w, i, ts = m["w"], m["i"], int(m["ts"])
        rec = by_wl[w]
        rec["raw_files"].append(p.name)
        topo, tasks = cfg_w.get(w, (None, []))
        rec["topology"] = topo
        idx = None
        if i != "first_run":
            idx = int(i)
        if data is not None and tasks:
            if data.get("task") in tasks:
                text_idx = tasks.index(data["task"])
                if idx is None:
                    idx = text_idx  # first_run: index recovered from task text
                elif idx != text_idx:
                    rec["task_mismatch"].append(f"{p.name}: filename idx {idx}, task text matches idx {text_idx}")
            else:
                rec["task_mismatch"].append(f"{p.name}: task text not in current workloads.py")
        if i == "first_run":
            rec["unindexed"].append(p.name)
        if idx is not None:
            rec["indices"][idx].append(p.name)
        if name == "groq":
            buckets["collected_before_swap_commit (model unverified)" if ts < swap
                    else "collected_after_swap_commit (consistent with qwen/qwen3.6-27b)"] += 1

    fail_reasons: Counter = Counter()
    for p in fail:
        data, err = _load(p)
        if err or data is None:
            invalid_fail[p.name] = err or "empty"
            continue
        by_wl[data["workload_id"]]["failed"][data["index"]].append(p.name)
        for a in data.get("attempts", []):
            last = (a.get("error", "").splitlines() or [""])[-1]
            fail_reasons[a.get("error_type", "?") + ": " + last[:60]] += 1

    for p in norm:
        err = _jsonl_ok(p)
        if err:
            invalid_norm[p.name] = err

    workloads = {}
    for w in sorted(set(by_wl) | set(cfg_w)):
        rec = by_wl[w]
        topo, tasks = cfg_w.get(w, (None, []))
        expected = list(range(len(tasks)))
        present = sorted(rec["indices"])
        if not rec["raw_files"] and not rec["failed"]:
            continue  # workload not collected in this dataset
        workloads[w] = {
            "topology": topo,
            "framework": "smolagents (ToolCallingAgent solo)" if topo == "solo" else "smolagents (CodeAgent manager)" if topo else None,
            "elicitation": ELICITATION.get(w, "unknown workload"),
            "condition": f"{topo}/{ELICITATION.get(w, 'unknown').split(' ')[0]}",
            "raw_trace_files": len(rec["raw_files"]),
            "expected_indices": expected,
            "present_indices": present,
            "missing_indices": [i for i in expected if i not in present],
            "unindexed_first_run_files": rec["unindexed"],
            "duplicate_indices": {str(i): f for i, f in sorted(rec["indices"].items()) if len(f) > 1},
            "failed_records": {str(i): f for i, f in sorted(rec["failed"].items())},
            "retry_after_failure_indices": [i for i in present if i in rec["failed"]],
            "task_mismatches": rec["task_mismatch"],
        }

    raw_stems = {p.stem for p in raw}
    norm_stems = {p.stem for p in norm}
    out = {
        "provider": cfg["provider"],
        "model": cfg.get("model", "NOT RECORDED IN TRACES; see model_provenance"),
        "paths": {k: cfg[k] for k in ("raw", "norm", "failed")},
        "raw_trace_files": len(raw),
        "raw_valid_json": len(raw) - len(invalid_raw),
        "raw_invalid_json": invalid_raw,
        "normalized_trace_files": len(norm),
        "normalized_valid_jsonl": len(norm) - len(invalid_norm),
        "normalized_invalid_jsonl": invalid_norm,
        "raw_without_normalized": sorted(raw_stems - norm_stems),
        "normalized_without_raw": sorted(norm_stems - raw_stems),
        "unparsable_filenames": unparsed,
        "failed_records": len(fail),
        "failed_records_invalid_json": invalid_fail,
        "failed_attempt_reasons": dict(sorted(fail_reasons.items())),
        "by_workload": workloads,
        "by_topology": dict(sorted(Counter(v["topology"] for v in workloads.values() for _ in range(v["raw_trace_files"])).items())),
        "by_condition": dict(sorted(Counter(v["condition"] for v in workloads.values() for _ in range(v["raw_trace_files"])).items())),
        "sha256_raw_dir_files": _digest(raw),
        "sha256_normalized_dir_files": _digest(norm),
        "documented_exclusions": [
            {"what": "failed/ records", "count": len(fail), "reason": "attempts exhausted with provider errors; not traces; kept as evidence"},
        ],
    }
    if name == "groq":
        out["model_provenance"] = {"collected_relative_to_swap_commit": dict(sorted(buckets.items())), **MODEL_EVIDENCE}
        ann = ROOT / "experiments/traces/stall_annotations.json"
        if ann.exists():
            keys = sorted(k for k in json.loads(ann.read_text()) if not k.startswith("_"))
            out["documented_exclusions"].append({
                "what": "stall_annotations.json", "count": len(keys), "traces": keys,
                "reason": "NOT excluded; duration-only flag (API-wait stall lower bounds)"})
    return out


def count_smoke() -> dict:
    d = ROOT / SMOKE_DIR
    js, jl = sorted(d.glob("*.json")), sorted(d.glob("*.jsonl"))
    return {
        "path": SMOKE_DIR, "raw_json_files": len(js), "raw_valid_json": sum(_load(p)[1] is None for p in js),
        "normalized_jsonl_files": len(jl), "normalized_valid_jsonl": sum(_jsonl_ok(p) is None for p in jl),
        "files": [p.name for p in js],
        "note": "probe/smoke runs; excluded from both corpora; provider/model not recorded in files",
    }


def render(res: dict) -> str:
    L = []
    for name in ("groq", "haiku"):
        r = res[name]
        L += [f"=== {name.upper()} ({r['provider']}; model: {r['model']}) ===",
              f"raw {r['paths']['raw']}: {r['raw_trace_files']} files, {r['raw_valid_json']} valid JSON, {len(r['raw_invalid_json'])} invalid",
              f"normalized {r['paths']['norm']}: {r['normalized_trace_files']} files, {r['normalized_valid_jsonl']} valid, {len(r['normalized_invalid_jsonl'])} invalid",
              f"failed records: {r['failed_records']} ({len(r['failed_records_invalid_json'])} invalid JSON)",
              f"raw without normalized: {r['raw_without_normalized']}  normalized without raw: {r['normalized_without_raw']}"]
        if "model_provenance" in r:
            L.append(f"model provenance (trace epoch vs swap commit): {r['model_provenance']['collected_relative_to_swap_commit']}")
        for k, v in r["by_condition"].items():
            L.append(f"  condition {k}: {v}")
        for w, v in r["by_workload"].items():
            L.append(f"  {w} [{v['topology']}] raw={v['raw_trace_files']} present={v['present_indices']} missing={v['missing_indices']}"
                     f" first_run={len(v['unindexed_first_run_files'])} dup={list(v['duplicate_indices'])} failed={list(v['failed_records'])}"
                     f" retry={v['retry_after_failure_indices']}")
            L += [f"      MISMATCH {m}" for m in v["task_mismatches"]]
        L.append("  exclusions: " + "; ".join(f"{e['what']} x{e['count']} ({e['reason']})" for e in r["documented_exclusions"]))
        L.append("")
    s = res["smoke"]
    L.append(f"=== SMOKE/PROBE (separate, not pooled) === {s['raw_json_files']} json ({s['raw_valid_json']} valid), {s['normalized_jsonl_files']} jsonl ({s['normalized_valid_jsonl']} valid)")
    L.append("Datasets are reported separately; no cross-dataset total is computed.")
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path, default=ROOT / "artifacts/validation/trace-counts.json")
    args = ap.parse_args()
    res = {n: count_dataset(n, c) for n, c in DATASETS.items()}
    res["smoke"] = count_smoke()
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    print(render(res))
    print(f"\nJSON: {args.json.relative_to(ROOT) if args.json.is_relative_to(ROOT) else args.json}")


if __name__ == "__main__":
    main()
