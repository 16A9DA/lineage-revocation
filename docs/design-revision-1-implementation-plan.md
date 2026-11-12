# DR-1 Implementation Plan (companion to `docs/design-revision-1.md`)

Status: **PLAN ONLY. NO IMPLEMENTATION HAS STARTED.** Date: 2026-11-12.

DR-1 is supervisor-approved (rulings relayed 2026-11-12; the signature block in DR-1 section 13 is blank, so no signature is recorded). This plan is the order of work for a **later, separately started** implementation task. This commit authorizes no code. `src/lineage_revocation/` stays unchanged until that task begins.

"Ruling n" and "D14 to D19" refer to DR-1 section 0.2 and section 3. Filenames are confirmed by repository inspection unless marked **NEW (name TBD)**.

## Approved sequence

1. **F: spec-shape conformance** (D14 tagged COSE_Sign1, D15 audience arrays and subset attenuation, D16 `delegation_rights` map).
2. **A: signed status artifacts** (including D17 statement identifiers and wire form, D18).
3. **C: per-node expiry.**
4. **Audience attenuation** (the attenuation and membership rules of ruling 16 and D15, beyond the F body change).
5. **B: equal-version idempotency and equivocation detection** (SHA-256 digest, reject and alert).

Then conformance (re-evaluate all 21 Spec §18 rows) and, separately authorized, the controlled benchmark.

**Constraints that never change:**

- **A before B.** B alone on unsigned artifacts would let any party on the distribution path replace the current artifact by presenting a different one with the same version. Revision B never precedes Revision A. If the supervisor changes the order, record the reason in DR-1; B before A stays excluded.
- **F before A.** F changes node bodies (audience array, `delegation_rights` map), so every fixture node id and every signature over a body changes. A builds artifacts and statements over those fixtures; doing A first would force a second fixture migration. The tag in D14 changes wire bytes only; node ids and body signatures are unaffected by it.
- **Tests first.** For every step, write the approved tests (DR-1 7.2, per the approved conformance plan) and see them fail before the change. No existing test is weakened.
- **Canonical encoding is validated.** Property-based CBOR tests (ruling 23) run in step A. If canonical encoding fails them, stop and escalate to the supervisor; do not substitute another encoder or relax the byte comparison.

## Phase 1. Implementation questions to settle before the dependent step starts

Nothing implementation-related starts in this phase. These are **implementation questions, not approved decisions**; each blocks only the step named. Rulings 7, 10, 13 and 14 are recorded in full in DR-1 (5.4, 5.3, 8.2, 7) and are no longer open.

| item | blocks | question |
|---|---|---|
| `delegation_rights` key name (D16) | F | the supervisor did not supply it; it is not invented here |
| name and shape of the explicit TTL-only no-status opt-in; reason-code names | A | fixed test-first with the supervisor |
| `schema_version` value, artifact AAD bytes | A | fixed test-first |
| alert log field set, counter name (ruling 18) | A | confirm |
| artifact key rotation and compromise recovery | A (documentation) | not addressed by any text |
| digest-less legacy store entry on an equal version | B | record the digest on first sight or reject |

## Normative `status_artifact=None` behavior (ruling 7; applies from step A)

1. `None` routes through the unavailable-status policy. The silent skip is removed.
2. The default is fail-closed.
3. A TTL-only no-status mode requires an explicit, deliberately named opt-in. Omission never enables it.
4. S2, S4 and S5 use one policy function with distinct reason codes; S5 raises a mandatory alert; S3 (unreadable or corrupt store) fails closed and a missing file is a first run; S6 is where bounded staleness over the last authenticated artifact applies, as the configured alternative and a benchmark arm; fail-open exists only as an experimental baseline.
5. Test impact: `test_valid_chain_authorizes` must be migrated to the explicit opt-in or to a supplied artifact. Written first, in the implementation task.

## Phase 2. F: spec-shape conformance

| field | content |
|---|---|
| Files likely affected | `src/lineage_revocation/nodes.py` (`NodeBody`, `Node.to_cose_sign1_bytes`, `from_cose_sign1_bytes`, `create_root_node`, `create_child_node`); `src/lineage_revocation/verifier.py` (the `_attenuated` check, leaf audience check, `can_delegate` use); tests in all modules that build nodes (`tests/test_cbor_canonical.py`, `tests/test_cose_roundtrip.py`, `tests/test_leaf_status_redirect.py`, `tests/test_revocation_correctness.py`, `tests/test_root_binding.py`) |
| Tests first | tagged-only parser (untagged rejected); node ids and body signatures unchanged by the tag; audience array round trip; `delegation_rights` map with an unknown key rejected; fixtures updated together |
| Expected behavior | tagged COSE_Sign1 wrapping the envelope (not the `Sig_structure`); `audience` array; `delegation_rights` map with one recognized key carrying the boolean; unknown keys rejected; frozen root and direct-issuer revocation scope unchanged |
| Security acceptance | a node signature still verifies exactly as before; the strict parser rejects untagged and malformed input with a typed failure; no existing authority-amplification test is weakened |
| Regression risks | every fixture node id changes; wire bytes change; `can_delegate` call sites (`verifier.py`, tests); DR-0001 semantics preserved (see `docs/decisions/DR-0001.md`) |

## Phase 3. A: signed status artifacts

| field | content |
|---|---|
| Files likely affected | `src/lineage_revocation/status.py` (`StatusArtifact`, `accept_status_artifact`, `save_high_water_mark`, `_demo`); `src/lineage_revocation/revocation.py` (statement serializer, `revocation_id`, alert and counter); `src/lineage_revocation/verifier.py` (`authorize`: key from the root-bound anchor, strict verification order); `src/lineage_revocation/nodes.py` (`sign_payload` and `verify_payload`: optional external AAD, default empty); `canonical.py` for validation helpers only |
| Tests first | `schema_version` required; unsigned, wrong-signer and omission (statement removed) artifacts rejected; forged higher version and forged `10**12` version leave the store byte-identical; other-URI validly signed artifact rejected; descendant-supplied anchor never used; Option K decoded strictly; artifact-only AAD (node and statement signatures do not verify as artifact signatures); decode, canonical re-encode and byte-compare check; malformed artifacts give typed failures with no side effect; `status_store_path=None` typed failure; `revocation_id` equals SHA-256 of the unsigned statement body; structured alert and counter; **property-based CBOR tests with the escalation rule**; end-to-end omission scenario of DR-1 4.2 |
| Tests to modify | the seven `StatusArtifact(...)` call sites in `tests/test_leaf_status_redirect.py` (`test_revoked_intermediary_denies_whole_subtree`, `test_status_artifact_cannot_be_bypassed_with_wrong_uri`, `test_status_artifact_rollback_denied`, `test_status_artifact_rollback_persists_across_restart`, `test_stale_status_artifact_denied`) must build signed artifacts; fixtures that put a placeholder `revocation_trust_anchor` in a test that ingests an artifact need a real serialized COSE_Key |
| Verification order (DR-1 5.1.7) | strict parse and keep received bytes, canonical check, structural validation, optional early URI check, authenticate under the Option K anchor with artifact-only AAD over the exact body bytes, use fields only from verified bytes, URI binding check after verification (repeating any early check), then rollback, persistence before freshness, freshness, statements. No persistent state mutation before authentication succeeds |
| Expected behavior | fail-closed on any parse or authentication failure; `None` routes to the unavailable policy (see above); S5 raises a mandatory alert; mark never advanced by an unauthenticated artifact |
| Security acceptance | the DR-1 4.2 scenarios are rejected with the store byte-identical; the artifact key is distinct from delegation and statement keys in every test setup; the distribution service is never modelled as a key holder |
| Regression risks | every artifact-using test breaks until migrated; statement signed bytes change (D17); the persistence point moves before the freshness check; `StaleStatusArtifact` reused for rollback and staleness |

## Phase 4. C: per-node expiry

| field | content |
|---|---|
| Files likely affected | `src/lineage_revocation/verifier.py` (`authorize`, `CredentialExpired`); tests in `tests/test_leaf_status_redirect.py` or a **NEW (name TBD)** module |
| Tests first | expired root, expired intermediate with a valid leaf, child outliving its parent, every node position and the boundary `now == expires_at`, all-valid lineage, node id in the error through a compatible `CredentialExpired` subclass, expiry checked before status ingestion; **test 20 uses distinct `expires_at` values per node (ruling 14)** |
| Tests to modify | none. `test_expired_leaf_denied` keeps passing; its fixture shares one expiry, so it does not discriminate leaf-only from per-node behavior |
| Expected behavior | every node satisfies `now < expires_at` after lineage authentication and before status processing; any failure rejects the whole lineage; **no verification-time nesting, no `issued_at`/not-before check, no issuance-time refusal** (ruling 10); an optional non-normative warning in `create_child_node` is permitted |
| Security acceptance | the temporal amplification lineage (child outliving parent) is denied after the parent expires; no store write for an expired lineage |
| Regression risks | failure order changes (expiry before status); `CredentialExpired` compatibility with `pytest.raises` |

## Phase 5. Audience attenuation

| field | content |
|---|---|
| Files likely affected | `src/lineage_revocation/verifier.py` (`_attenuated` and the leaf audience check) |
| Tests first | child audience subset allowed; non-subset denied as authority amplification; leaf check is membership of the requested resource |
| Expected behavior | per DR-1 5.5 |
| Security acceptance | a child cannot widen the audience; the existing audience-mismatch test (`test_audience_mismatch_denied`) is migrated to the array form, not weakened |
| Regression risks | interaction with F's body change; error type for a non-subset audience |

## Phase 6. B: artifact version handling (only after Phase 3)

| field | content |
|---|---|
| Files likely affected | `src/lineage_revocation/status.py` (`accept_status_artifact`, store format, `_demo`); `src/lineage_revocation/verifier.py` (P-2 ingestion path and the `status_artifact=` compatibility path) |
| Tests first | equal version idempotent; lower version still rejected after an equal was accepted; higher version advances the mark only after authentication and persists before the freshness check; equal version with an invalid signature rejected; equal-version stale artifact rejected on use; equal version after restart; equal version with a **different digest rejected and alerted** (ruling 6); legacy `{uri: int}` entry loads; ingested artifact reused across calls with freshness and `effective_at <= now` re-evaluated at each injected `now` |
| Work | idempotency; strictly-lower rejection preserved (including across restart); `{uri: {version, digest}}` store with SHA-256 over canonical body bytes; P-2 accepted-status state with the DR-1 6.2 binding and security requirements; **migrate `status._demo()`** (ruling 22) |
| Security acceptance | `test_status_artifact_rollback_denied` and `test_status_artifact_rollback_persists_across_restart` keep passing; an equal version with a bad signature, stale window or different digest is never used |
| Regression risks | shipping B before A (excluded); store-format change must tolerate old files; freshness accidentally cached in the accepted state |

## Phase 7. Conformance

1. Run the full test suite; record exact counts and date.
2. Re-evaluate all 21 Spec §18 rows against the actual test bodies and results; update the DR-1 section 7.1 matrix from actual results.
3. Add the approved gap-closing tests (rows 4, 6, 7, 8, 10, 12, 13, 14, 21; 11b only).
4. **Row 11:** the local unreadable-store test (11b) does not close row 11. Row 11a (network outage) needs a defined, implemented and tested behavior; do not report full conformance before then.
5. Review `git diff --stat -- src/lineage_revocation/`; every changed file maps to a DR-1 section.

## Phase 8. Controlled benchmark (separate authorization required)

| field | content |
|---|---|
| Authorized by | Phases 2 to 7 complete with the protocol correctness gates passing, plus a separate supervisor authorization |
| Order | (1) topology generation, topology validation and the structural oracle first; (2) timing and cost measurements only after correctness is established |
| Files likely affected | **NEW (name TBD)**: harness under `experiments/controlled/` (proposed by CBD-v1; the directory does not exist); results under `artifacts/controlled/<experiment_id>/` |
| Scope | 23 cells (21 grid plus depth spur {10, 20} at fanout 1); `K ∈ {1,10,100,1000}` on (2,2), (5,4), (20,1); **decoy forest** under the same root, disjoint from measured chains, sized to K, depth-stratified, effective revocations, oracle covering all K, seeded 50/50 signer mix, policy recorded in metadata and per row; per-call timing vectors; paths `per_request`, `per_refresh`, `worst_case_fresh_version`, `cold_start`; fail-closed default with bounded-staleness over the last authenticated artifact as a measured arm and the explicit no-status mode for the TTL baseline; GC-disabled steady state primary, cold-start and GC-enabled as separate labelled conditions never mixed; chain-minimum TTL baseline, T-active, T-full, L = R, seeded exposure phase sweeps; schema version 2 with the exposure-phase field |
| What it measures | legitimate artifact ingestion and statement verification; not malformed-input handling |
| Regression risks | timer overhead and I/O warm-up noise; large artifacts at K=1000, depth 20 (Git LFS for raw data if large); no controlled row is ever read by `measurement/`; the HTTP API (D19) is not needed for in-process runs |

## Standing evidence tasks (independent of the protocol steps)

Each paid run needs its own go-ahead. Datasets stay separate: Groq 34 raw traces and 5 failure records; Haiku 12 raw traces; Haiku `chained_2` 5 of 6 topology-scorable. Natural, elicited and projected categories stay separate; sequential breadth is not genuine parallel fanout.

1. **Stall annotations** for Haiku `chained_2` traces 00 to 03 (extend `experiments/traces/stall_annotations.json` or add a separate Haiku file; do not overwrite the Groq entries). Analysis only; no estimates.
2. **One bounded retry window** for `manager_multi_specialist` indices 04 and 05 (Groq, same configuration). First restore the Groq endpoint and model in `experiments/runners/collect.py` (it names `claude-haiku-5-5` now), using the workload filter. On repeat failure freeze the cell at 4/6 and keep the failure records. Which Groq `model_id` counts as "the same" is open.
3. **Bounded Haiku same-step multi-tool-call smoke test** (`experiments/runners/probe_toolcalling_parallelism.py` or `experiments/runners/smoke_toolcalling.py`). Success needs two registered-agent calls in one manager step, both completing.
4. **`chained_2` trace 02** stays an unresolved instrumentation issue until per-invocation capture and a rerun confirm or refute `docs/chained2-trace02-investigation.md`.
5. After each task rerun `python scripts/count_traces.py` and quote its output.
