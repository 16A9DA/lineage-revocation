# Controlled Benchmark Design (DRAFT, needs approval)

Status: proposal. Nothing here is implemented. Answers the five decisions listed in `controlled-benchmark-blocker-evidence.md`. Evidence type: **controlled synthetic**. Never pooled with real traces. `src/lineage_revocation/` stays frozen; the harness only calls its public API.

## 0. Constraints this design obeys

- Spec §19: first experiment compares the pull design against short-lived credentials. Artifact size growth (revocations x chain depth) MUST be measured and reported.
- Spec §20: do not tune synthetic workloads before real topology is measured. Real data now exists (below), so the grid is anchored to it.
- Design §18: report P50/P95/P99 with confidence intervals; exposure = revocation decision to first denied request; check sibling preservation and descendant containment.
- Collection plan v2: synthetic results are protocol cost and correctness only. They say nothing about how real agents behave.

## 1. Real-data anchor

| quantity | measured (real) | source |
|---|---|---|
| delegation depth | 0 to 2 | Groq 0/1, Haiku `chained_2` = 2 |
| fanout | 1 to 2, sequential only | Haiku `forced_multi_lookup` |
| task duration | about 1s to 2000s, median about 34s (solo) | Groq corpus, annotated outliers excluded |
| tool calls per task | 1 to 22, median about 3 | both |

Grid points inside this range are labelled **real-anchored**. Points beyond it are labelled **projected**. Reports must keep that label on every row and plot.

## 2. Decision 1: topology generation and revocation targets

**Key observation.** `authorize()` verifies one lineage chain (`lineage: list[Node]`), not a tree. Single-request cost depends on depth only. Fanout enters through (a) how many sibling branches exist for sibling-preservation checks and (b) how many revocation statements sit in the status artifact. A full tree at depth 8, fanout 8 has about 19 million nodes, so it must not be built eagerly.

Design:
- Grid: depth `d` in {0, 1, 2, 4, 8} x fanout `f` in {1, 2, 4, 8}. Depth 0 means root only, so `f` is not meaningful there; run it once.
- Tree is generated lazily and deterministically. Node keys derive from `sha256(seed || path)` via `load_private_key_from_raw`. Same seed gives byte-identical nodes.
- Per cell, materialize only: the target chain (length d+1), one sibling chain per level, and enough decoy statements to reach the artifact size under test.
- Revocation targets per cell (three scenarios): **R-root-child** (revoke depth 1, whole subtree), **R-mid** (revoke depth d/2), **R-leaf** (revoke only the leaf). Each is issued by the legitimate parent, as the spec requires.

## 3. Decision 2: timing methodology

- Clock: `time.perf_counter_ns()` around the call. No sleeping. `authorize()` takes `now` as a parameter, so protocol time is simulated and runs are deterministic.
- `gc.disable()` inside the timed region; `gc.collect()` between repetitions.
- Per cell: 200 warmup calls (discarded), then 30 repetitions of 500 calls each. Report p50, p95, p99 over repetitions plus a 95% bootstrap CI (10,000 resamples).
- Components timed separately (Design §15): `verify_lineage`, `accept_status_artifact` (cache/freshness/high-water mark), `is_target_revoked`, and end-to-end `authorize`.
- High-water-mark file: `accept_status_artifact` writes a JSON file on every accepted artifact. Report with the write (spec-mandated durable persistence) and note that disk I/O will dominate; do not hide it.
- Metadata recorded once per run: CPU model, core count, OS, Python and `cryptography` versions, git commit of the repo, seed.
- Single process, single thread. Concurrency is out of scope for the first readout.

## 4. Decision 3: metrics

| id | metric | how |
|---|---|---|
| M1 | verifier latency per component and end-to-end | section 3 |
| M2 | status artifact size in bytes | harness-side CBOR serialization of statements plus their `target_lineage` nodes; vary revocation count K in {0, 1, 10, 100, 1000} x depth |
| M3 | post-revocation exposure | simulated: revoke at `effective_at`, attacker sends one request per `1/r` seconds, verifier refreshes every `R` seconds; exposure = first DENY time minus `effective_at` |
| M4 | correctness | invariants in section 6, asserted on every cell |

Propagation cost: the protocol exposes no push or propagation API (pull design). So there is no propagation latency metric; exposure (M3) is the observable. If the status service gets a fetch latency, that is a network parameter, and the first readout uses a fixed set {0, 50, 500 ms} simulated, not real network.

## 5. Decision 4: TTL-only baseline

Definition: no status artifact, no revocation statements. Revocation takes effect only when the credential expires. Same lineage and the same `authorize()` call with `status_artifact=None`, so no new baseline code is needed. Credential lifetime `L` is the only knob.

Comparison at **equal worst-case exposure**, otherwise the numbers are not comparable:
- Pull design exposure bound is about `R` (refresh interval, via `max_staleness`).
- TTL exposure bound is `L`. To match, set `L = R`.
- Cost at equal exposure per node per hop:
  - Pull: per-request verify cost (M1) plus fetch/ingest of one artifact per `R`.
  - TTL: per-request verify cost with no status step, plus **reissue cost**: `d` signatures per credential rotation every `L` seconds.
- `R = L` is swept over {5, 30, 300, 3600} seconds, chosen from the measured task duration range (median 34s, long tail near 2000s).
- Output: the crossover, if any, as a function of (d, request rate, R). Reported as controlled/projected, never as real agent behavior. A cell where TTL wins is a valid result (Design §24).

Design §16 lists four baselines; this first readout does TTL-only per spec §19. The others are later work.

## 6. Correctness invariants (checked in every cell, from spec §18)

1. Before `effective_at`: ALLOW. At and after: DENY.
2. Revoked node denies all of its descendants.
3. Sibling branches stay ALLOW.
4. Statement signed by a non-ancestor is ignored (no DENY).
5. Artifact with a lower version than the high-water mark is rejected.
6. Expired artifact follows the configured stale policy.

A cell with any invariant failure is reported as a failure, never timed and averaged in.

## 7. Decision 5: schema and location

- Code: `experiments/controlled/` (`tree.py`, `scenarios.py`, `run.py`). No edits under `src/`.
- Results: `artifacts/controlled/results.jsonl`, one row per (cell, scenario, repetition). Fields: `evidence_type="controlled_synthetic"`, `anchor` ("real" or "projected"), `depth`, `fanout`, `scenario`, `K`, `R`, `L`, per-component ns, artifact bytes, exposure seconds, invariants passed, seed, commit.
- A separate `artifacts/controlled/metadata.json` for hardware and versions.
- Raw trace directories are never touched.

## 8. Known limits (to state in any writeup)

- Single machine, Ed25519 via OpenSSL, no network. Absolute numbers do not transfer to other deployments; ratios and scaling shapes are the finding.
- `is_target_revoked` re-verifies each matching statement's full lineage, and `authorize` calls it per node. That cost is part of the frozen design and is measured as-is, not optimized.
- Depth 4 and 8, fanout 4 and 8 are beyond anything observed in real traces.
- Credential audience, authority sets and expiry use fixed synthetic values.

## 9. Open choices for the owner

1. Accept grid d in {0,1,2,4,8} x f in {1,2,4,8}, or shrink to save time?
2. Accept the three revocation scenarios (root-child, mid, leaf)?
3. Accept R = L in {5, 30, 300, 3600} s and K in {0, 1, 10, 100, 1000}?
4. Include the high-water-mark disk write in the headline latency, or report both?
5. OK to put harness code under `experiments/controlled/` and results under `artifacts/controlled/`?
