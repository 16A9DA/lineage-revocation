# Controlled Benchmark Blocker Evidence

## Scope checked

Checked repository sources outside `src/lineage_revocation/` for an executable controlled benchmark, a deterministic tree generator, a TTL-only baseline, and benchmark metric collectors. The only executable experiment runners are:

- `experiments/runners/collect.py`: live smolagents real-trace collection.
- `experiments/runners/smoke_toolcalling.py`: live provider smoke run.
- `experiments/runners/probe_toolcalling_parallelism.py`: live provider capability probe.
- `measurement/report.py`: parser and descriptive report for already-written JSONL traces.

None generates protocol lineages, sweeps depth or fanout, measures verifier latency, measures propagation, or implements a TTL-only comparator.

## Existing protocol evidence

The frozen implementation has correctness tests in `tests/test_root_binding.py`, `tests/test_revocation_correctness.py`, and `tests/test_leaf_status_redirect.py`. Those tests exercise fixed example lineages and revocation decisions. They are not a timed benchmark harness and do not contain a TTL-only baseline.

`docs/measurement-status.md` also records that the "Revocation benchmark harness" was deferred. No later harness is present in the repository.

## Result

No controlled benchmark was run. Starting a depth/fanout sweep now would require introducing a new synthetic-lineage generator, timing methodology, result schema, and TTL baseline definition. Those choices determine reported cost and any crossover result, so they are research-significant methodology rather than an invocation of an existing harness.

The controlled benchmark remains blocked pending an approved benchmark design. This finding does not alter the frozen protocol or any real trace. It does not imply any controlled or real-world crossover result.

## Required design decisions before execution

1. Define deterministic topology generation and which revocation target(s) are tested per depth/fanout cell.
2. Define latency clock, warmup/repetition count, hardware metadata, and aggregation statistics.
3. Define revocation-propagation operation and cost metric, if protocol API exposes one.
4. Define TTL-only semantics and implementation boundary so its comparison is valid.
5. Define controlled-only result schema/location and correctness invariants.
