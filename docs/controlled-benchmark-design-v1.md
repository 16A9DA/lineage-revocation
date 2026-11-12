# Controlled Benchmark Design v1

**Status: PROPOSED. Nothing in this document is APPROVED.** No benchmark code has been written and no controlled benchmark has been run. This document contains no experimental results. Every recommendation below is labelled PROPOSED and needs supervisor approval before any benchmark code is written.

Evidence type: controlled synthetic. It is kept strictly separate from real-agent traces. It says nothing about how real agents delegate.

Constraints observed: `src/lineage_revocation/` is frozen and is only called through its public functions. The harness adds no code under `src/`.

Companion document: `docs/controlled-benchmark-design-review.md` (verified facts, risks, missing evidence, next steps). This v1 supersedes the earlier scratch draft `docs/controlled-benchmark-design.md`, which contains a few statements that this version corrects (see review section 4).

## 0. What the frozen protocol actually offers (verified by reading the source)

Present and usable:

| API | what it does | measurable cost |
|---|---|---|
| `create_root_node`, `create_child_node`, `sign_node` | build and sign nodes | 1 Ed25519 sign + canonical CBOR encode |
| `compute_node_id(body)` | node id is a pure function of the unsigned body | 1 CBOR encode + hash |
| `Node.to_cose_sign1_bytes` / `from_cose_sign1_bytes` | wire encoding | parse cost, byte size |
| `verify_lineage(lineage, anchor)` | verifies one chain, list of `Node` | per node: 1 node-id recompute + 1 Ed25519 verify |
| `create_revocation_statement`, `verify_revocation_statement`, `is_target_revoked` | statement issue and check | see below |
| `StatusArtifact` (dataclass), `accept_status_artifact(artifact, store_path, now, max_staleness)` | freshness window plus high-water-mark rollback check, with a JSON file on disk | file read and write per accepted artifact |
| `authorize(lineage, anchor, audience, now, status_artifact, status_store_path, max_staleness, ...)` | the frozen verifier | everything above |

Not present (so not assumed):

- No fetch, cache, refresh or push function. The spec pseudocode (section 13) has a `cache`; the code does not. `authorize()` is handed an artifact by the caller.
- No propagation operation of any kind. Revocation is enforced only when a verifier is given an artifact containing a statement.
- No `StatusArtifact` serializer and no artifact-level signature field in the dataclass. Only statements are signed. Whether the spec requires an artifact-level signature beyond the pseudocode's `verify_status_artifact` line was not checked.
- No operation counters, no clock (`now` is always passed in), no topology generator, no TTL scheme.
- `authorize()` checks `expires_at` of the **leaf only**. It does not require a child's validity to nest inside its ancestors' validity.
- Re-presenting an artifact whose version is not above the stored high-water mark raises `StaleStatusArtifact`. Repeated `authorize()` calls therefore need a new artifact version each time (section 2).

## Decision 1: deterministic topology generation (PROPOSED)

**Depth.** Depth `d` is the number of delegation hops from the root node. A lineage has `d + 1` nodes. `d = 0` is the root credential alone. This is a mapping from the measurement layer (manager to specialist = 1 hop, manager to mid to leaf = 2 hops) onto lineage length. It is an analogy, not a measurement of the protocol: the real traces record task delegation, not credential transfer (`instrumentation-validity-evidence.md` section 3).

**Fanout.** Fanout `f` is the number of children of every non-leaf node, uniformly. Tree size is the sum of `f^i` for `i = 0..d`. At the largest candidate cell (`d=5`, `f=8`) that is 37,449 nodes. This is small enough to build eagerly.

**Node identifiers.** Never invented. They are `compute_node_id(body)`, the protocol's own function.

**Keys and determinism.** Each node's private key is derived from `sha256(experiment_id | seed | path)` where `path` is the tuple of child indices, loaded with `load_private_key_from_raw`. Ed25519 signing is deterministic, and `issued_at`/`expires_at` come from a fixed simulated epoch, so the same seed produces byte-identical nodes. Authority sets use opaque strings, with child authority a subset of parent authority and `can_delegate=False` on leaves, so attenuation checks pass legitimately.

**Candidate grid.** Depth {0,1,2,3,4,5} x fanout {1,2,4,8}. Not all combinations are meaningful:

- `d = 0`: one node, no children, so fanout is undefined. Run one cell with `f = n/a`. It is a fixed-cost control. Only root revocation exists; sibling isolation cannot be tested.
- `f = 1`: a pure chain. No siblings exist, so sibling isolation is untestable. Keep it, since it isolates depth cost, but mark sibling checks "not applicable".
- `d = 1`: no intermediate node exists, only root and leaves.
- Meaningful cells: 1 (`d=0`) + 5 x 4 = **21 cells**.
- Anchor labelling: cells with `d <= 2` and `f <= 2` are within what real traces showed (depth 2 only when elicited, fanout 2 only sequentially). Everything else is `projected`. The label travels with every result row.

**Revocation targets (three scenarios per cell, where defined):**

| scenario | target | issuer | defined for | expected effect |
|---|---|---|---|---|
| S-root | the root node | root key | all `d` | every chain denied |
| S-mid | an intermediate node at depth `max(1, floor(d/2))` that has descendants | its parent | `d >= 2` | target and all descendants denied; ancestors, siblings and cousins allowed |
| S-leaf | one leaf | its parent | `d >= 1` | only that leaf denied |

**Sibling isolation test.** For each scenario the expected outcome of every chain comes from an oracle computed from the tree structure alone (a leaf chain is denied iff the target is on it), independent of the verifier. Then `authorize()` is run on every leaf chain and compared. Exhaustive when there are at most 4,096 leaves; otherwise all chains through the target path plus a seeded sample of 512 other leaves. Also check ancestors of the target directly. Any disagreement is a correctness failure (Part 3).

**Topology validation (before any timing):** node count equals the closed form; every chain passes `verify_lineage`; parent links consistent; node ids unique; attenuation holds along every edge; regenerating from the same seed gives an identical hash over all node bytes; a different seed gives different node ids.

**Seeds.** One topology seed per cell, derived from `sha256(experiment_id | d | f)`, recorded in every row. Timing repetitions do not change the topology (signing is deterministic, so variation between repetitions is system noise). The exposure simulation (Decision 4) uses a separate recorded seed for request timing.

## Decision 2: latency methodology (PROPOSED)

**Primary operation timed.** One call to `authorize()` on an already-parsed `list[Node]`, no disk or network, in steady state, with a status artifact supplied. This is the frozen verifier.

**Inclusion of parsing.** Reported separately, not folded in:

- `T_auth`: `authorize()` on parsed nodes (primary).
- `T_parse`: `Node.from_cose_sign1_bytes` over the chain.
- `T_wire = T_parse + T_auth`: the cost a verifier pays when it receives wire bytes.

**Artifact handling constraint.** Because `accept_status_artifact` rejects a repeated version, every timed call gets a fresh artifact object with a version one higher than the last (built outside the timed region). This models a verifier ingesting a fresh artifact on each authorization, the worst case, because the API has no cache-hit path. A cached-statements path (one prior `accept_status_artifact`, then `verify_lineage` plus per-node `is_target_revoked` on the stored statements) can be timed only as a **harness composition of public functions**. It is not the frozen `authorize()`, and must be labelled so.

**Components, timed separately by calling public functions:** `verify_lineage`; `accept_status_artifact` (includes the high-water-mark disk read and write; `load_high_water_mark` and `save_high_water_mark` are public and can be timed on their own); `is_target_revoked` per node; end-to-end `authorize()`. The remainder (root binding, attenuation, audience, expiry) is reported as a **residual**, since those helpers are private.

**Cold start versus steady state.**

- Steady state: warmup calls discarded, then repetitions. The counts are fixed at PROPOSED values: warmup 200 calls; 30 repetitions; inner loop sized so each repetition lasts at least about 50 ms.
- Cold start: a fresh subprocess per sample, timing the first `authorize()` call, 30 samples per cell. Reported separately and never mixed with steady state.

**Clock and noise control.** `time.perf_counter_ns()`; `gc.disable()` inside the timed region and `gc.collect()` between repetitions; single process, single thread; the interpreter and the `.venv` files are warmed before the run (first reads of the venv were observed to take about 1.2 s per file on this machine, which would corrupt timings). Report p50, p95, p99 and a 95% bootstrap interval over repetitions. Concurrency is out of scope for v1.

No timing numbers appear in this document because none exist.

## Decision 3: revocation propagation cost (PROPOSED)

**What can genuinely be measured.** The protocol has no propagation operation. A revocation becomes effective at a verifier when that verifier ingests a status artifact containing the statement and `now >= effective_at`. So there is no "propagation latency" to time. The measurable quantities are enforcement cost and artifact distribution size.

Candidate metrics, with what the code supports:

| metric | measurable how | genuine? |
|---|---|---|
| Ed25519 verifications per authorization | wrapper counters around `lineage.verify_node_signature` and `revocation.verify_payload` applied in the harness only (no `src/` edit), in a separate counting run, checked against a closed-form count from the code | yes |
| statements scanned | `authorize()` loops over all K statements for each authenticated node, so comparisons = (d+1) x K | yes, from code |
| statements fully verified | those whose `target_node_id` matches a node on the chain; each costs `len(target_lineage)` node verifications plus 1 statement-signature verification | yes |
| artifact bytes | harness-side CBOR sizing: each statement's `canonical_bytes()` (it embeds the target node and the whole target lineage) plus signature. Spec section 19 requires growth with revocation count x depth to be reported | yes; no serializer exists, so this is a harness definition |
| descendants affected | counted from the generated tree (oracle), never by the verifier | a topology fact, not a protocol operation. Report it as "blast radius" |
| revocation issuance cost | time and bytes of `create_revocation_statement` (1 sign plus canonical encode) | yes |

**PROPOSED primary metric: Ed25519 verifications per authorization decision (`verify_ops`).** Why: it is deterministic and hardware independent, derived directly from public APIs, it dominates the CPU cost of the verifier, and the TTL baseline has the same quantity (chain length), so the two are directly comparable. **Co-primary: artifact bytes**, because the spec makes it mandatory. Latency (Decision 2) is the secondary, hardware-dependent view of the same cost.

Terminology: avoid "propagation cost" in results. Use **revocation enforcement cost** (`verify_ops`, statements scanned, artifact bytes). Distribution cost per verifier is `artifact_bytes / R` for refresh interval `R`; it is computed, not measured over a network.

## Decision 4: TTL-only baseline (PROPOSED)

**Definition.** Same node format, same chain, same `verify_lineage`, but no status artifact and no revocation statements. Revocation means the issuer refuses to renew. Credentials carry `expires_at = issued_at + L`.

**A validity problem the baseline must handle.** The frozen `authorize()` checks only the **leaf's** `expires_at`. A compromised intermediary can mint a descendant with any expiry, so leaf-only TTL gives no exposure bound against the very adversary the protocol targets. Two variants:

- **B1 (primary, PROPOSED): chain-minimum TTL.** The verifier requires `now < min(expires_at)` over the whole chain, applied by the harness on top of `verify_lineage`. This is the conventional meaning of short-lived chained credentials and is the fair baseline. It is a harness-side check, not the frozen `authorize()`, and must be labelled so.
- **B2 (reported as an observation): frozen leaf-only check.** Shown to document that the frozen verifier does not bound exposure by TTL alone. Not used for the crossover comparison. Whether the spec intends expiry nesting is a question for the supervisor.

**Issuance per hop and renewal.** Each hop's credential is issued independently by its parent. A node's id is a hash of its body, and each child body contains `parent_node_id`. So renewing any node changes its id and invalidates the parent links of every descendant. Two renewal models, both reported:

- **T-active (primary): only chains in active use are renewed.** Cost per `L` is the number of distinct nodes on active chains (one signature each).
- **T-full (upper bound): the whole subtree under the renewed node is reissued.**

**Grid.** PROPOSED: keep {30 s, 1 min, 5 min, 15 min, 1 h}. Justification: measured task durations are about 1 s to a few hundred seconds in the non-outlier real traces, so 30 s and 1 min fall inside typical task lifetimes (renewal mid-task) and 15 min and 1 h exceed them. The same values are used as the pull design's refresh interval `R`.

**After revocation.** Decision time `t_r`. B1 chain-minimum: the compromised branch keeps working until its already-issued credentials expire, so exposure is at most `L` and equals the remaining lifetime of the earliest-expiring credential on the chain. Pull: the revoked branch keeps working until the verifier ingests an artifact containing the statement, bounded by `min(valid_until, issued_at + max_staleness)` and the refresh interval `R`, plus `effective_at` lag and any simulated fetch delay.

**Exposure calculation.** Simulated, with `now` injected, no sleeping. An attacker issues requests at rate `r` (seeded schedule). Exposure window = time of the last accepted post-decision request minus `t_r`, and the count of accepted post-decision requests. The phase between `t_r` and the next renewal or refresh is varied across a seeded sweep so both the worst case and the distribution appear. Nothing assumes a uniform phase unless stated.

**Status lookup.** The baseline needs none. The pull design needs artifact retrieval every `R`.

**What goes into the timing comparison (equal footing):** both pay the same `verify_lineage`. Per-request latency compares pull (`verify_lineage` plus status check) against TTL (`verify_lineage` plus chain-minimum expiry check). Renewal signatures (TTL) and artifact fetches/bytes (pull) are reported as **operational cost per unit time**, never folded into per-request latency.

**Equal-exposure rule.** Compare at `L = R` so the worst-case exposure bounds match, and also show the exposure-versus-cost trade-off over the whole grid. Neither side is charged for the other's mechanism.

## Decision 5: result schema and storage (PROPOSED)

One JSON object per line, one row per (experiment, cell, scenario, scheme, repetition):

```json
{
  "schema_version": 1,
  "evidence_type": "controlled_synthetic",
  "experiment_id": "...",
  "timestamp_utc": "...",
  "topology": {"depth": 2, "fanout": 2, "node_count": 7, "anchor": "real|projected"},
  "seed": {"topology": 0, "exposure_schedule": 0},
  "revocation": {"scenario": "S-mid", "target_node_id": "hex", "K": 10, "revoker": "parent|root"},
  "scheme": {"name": "pull|ttl_b1|ttl_b2", "R_s": 300, "L_s": 300, "renewal_model": "t_active|t_full|null"},
  "repetition": 0,
  "verification_latency_ns": {"T_auth": 0, "T_parse": 0, "T_wire": 0, "verify_lineage": 0, "accept_status": 0, "is_target_revoked": 0, "residual": 0, "cold_start_ns": null},
  "revocation_cost": {"verify_ops": 0, "statements_scanned": 0, "statements_verified": 0, "artifact_bytes": 0, "issuance_ns": 0, "descendants_affected": 0},
  "exposure": {"window_s": 0.0, "accepted_requests_after_decision": 0, "attacker_rate_per_s": 0.0},
  "correctness": {"passed": true, "failed_checks": []},
  "hardware": {"cpu": "...", "cores": 0, "os": "...", "python": "...", "cryptography": "...", "cbor2": "..."},
  "software": {"git_commit": "...", "git_dirty": false}
}
```

Field values above are placeholders showing shape only. A row with `correctness.passed = false` is stored but **excluded from every statistic by an explicit, logged filter**, never silently.

**Directory structure:**

```
artifacts/controlled/<experiment_id>/
    metadata.json          hardware, software, grid, seeds, approved-design reference
    raw/results.jsonl      append-only, one row per measurement (the authoritative data)
    summaries/summary.json derived: percentiles and intervals, regenerated from raw
    reports/               derived: tables and plots, regenerated from summaries
experiments/controlled/    harness code (not written yet)
```

Raw is authoritative; summaries and reports are regenerable and never edited by hand. Real traces stay in `artifacts/raw_traces/` and `artifacts/raw_traces_haiku/`. Nothing controlled is ever written there, and no controlled row is ever read by `measurement/`.

## Part 3: correctness invariants (must pass before any performance result is accepted)

PROPOSED gate: a cell's performance rows are accepted only if every item passes for that cell. Existing coverage is reused where it exists; items marked **gap** need new tests, in the harness, not in `src/`.

| invariant | existing coverage | status |
|---|---|---|
| Valid lineage accepted before revocation | `test_valid_chain_authorizes` (`test_leaf_status_redirect.py`) | covered at one fixed chain; harness re-checks per cell |
| Revoked target rejected after revocation | `test_revoked_intermediary_denies_whole_subtree` | covered |
| Descendants of a revoked ancestor rejected | same test (descendant `c` of revoked `b`) | covered |
| Not-yet-effective statement does not revoke | `test_not_yet_effective_statement_does_not_revoke` | covered at statement level |
| Unrelated sibling branches remain valid | no `authorize()`-level test found; only `test_issuer_cannot_revoke_a_sibling` at statement level | **gap** (the oracle in Decision 1 fills it) |
| Forged ancestor rejected | `test_wrong_parent_key_rejected`, `test_root_signed_by_wrong_key_rejected` | covered |
| Root binding preserved | `test_root_subject_is_never_used_as_its_own_trust_anchor`, `test_compromised_intermediary_status_redirect_denied_and_never_contacted`, `test_revocation_trust_anchor_divergence_also_denied` | covered |
| Unauthorized or invalid statement ignored | `test_invalid_statement_ignored_but_valid_one_still_revokes`, `test_tampered_statement_signature_ignored_without_crashing` | covered |
| Rollback and stale artifact | `test_status_artifact_rollback_denied`, `..._persists_across_restart`, `test_stale_status_artifact_denied` | covered |
| Duplicate id, broken parent link | `test_duplicate_node_id_rejected`, `test_parent_node_id_mismatch_rejected` | covered |
| TTL credentials expire at configured lifetime | `test_expired_leaf_denied` covers leaf only | **gap** for B1 chain-minimum, which is harness-side |
| Network outage maps to configured unavailable behavior | no test found that exercises it | **gap** (noted; may stay out of v1 scope) |
| No invalid result silently included in statistics | does not exist | **gap**: harness filter that counts and logs exclusions, with a test |

I searched `tests/` by name and by grep for `sibling` and `StatusUnavailable`. I did not read every test body, so "covered" means a test with a matching name and purpose exists, not that its assertions were audited against the spec line by line.

## Part 4: comparing lineage-based revocation with TTL-only

Four quantities must stay separate. They are not interchangeable.

1. **Verification latency.** Per-request cost of authorizing (Decision 2, `verify_ops`). Expectation, to be tested not assumed: the pull design does strictly more work per request (status ingest plus statement checks), so it may be slower.
2. **Revocation responsiveness.** Time from a revocation decision to enforcement at a verifier. Pull: governed by refresh interval and staleness policy. TTL: governed by remaining credential lifetime.
3. **Post-revocation exposure.** What a non-cooperating compromised node can still do after the decision: window length and accepted request count (Decision 4). Under TTL, a compromised intermediary does not have to cooperate with non-renewal, and its descendants already issued live to their own expiry unless chain-minimum is enforced. Under the pull design, the verifier checks ancestors' revocation status itself, so the intermediary's cooperation is not needed.
4. **Operational cost.** Per unit time: renewal signatures (TTL, with the subtree effect of Decision 4) versus artifact fetches and bytes (pull), plus statement issuance.

**Evidence that would support a crossover finding.** A region of the controlled parameter space (depth, fanout, revocation count `K`, `R = L`, request rate, revocation frequency) where, at matched worst-case exposure, one scheme has a lower operational cost than the other, or where at matched cost one has a smaller exposure window, with 95% intervals that do not overlap, all correctness gates passed, and the conclusion stable under reasonable changes to how costs are weighted. Reported as controlled and projected, with the `real` or `projected` anchor shown.

**Possible outcomes (none presupposed):**

- **Positive:** a region exists where pull gives equal or smaller exposure at lower total operational cost, for instance where TTL renewal cost grows with subtree size or short lifetimes become expensive, while the per-request verification premium is small relative to task latency.
- **Negative:** TTL (B1) matches the exposure bound at equal or lower cost across the realistic range. This hits kill criteria in Design section 24 (short-lived credentials suffice; added latency or complexity without measurable benefit). The design document already treats this as a valid result, possibly a measurement-study paper.
- **Inconclusive:** differences fall inside the intervals; or the answer depends on a cost weighting not measurable here; or the realistic region (`d <= 2`, `f <= 2`) is too small for either scheme to matter while the interesting differences appear only in `projected` cells.

## Not claimed

- No controlled benchmark has run. No latency, count, size or exposure number in any document was produced by this design.
- The grid, scenarios, repetition counts, `L = R` rule, schema and directory layout are PROPOSED only.
- Nothing here shows real agents commonly delegate to depth 2 or fan out (see the review document, section 1).
