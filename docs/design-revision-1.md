# Design Revision 1 (DR-1)

Status: **FINAL TEXT FOR SIGNATURE (DR-1 v1).** Date: 2026-11-12 (text); implementation-status block updated 2026-11-15. Author: Rayyan Ahmed (drafted with AI assistance).
The supervisor has approved DR-1 Draft 2 and the remaining design decisions (relayed in the task statements of 2026-11-12). **The supervisor's signature itself is not recorded in this file; the signature block in section 13 is blank.** Nothing here is a verified signature.
**Implementation status, as of 2026-11-15 (this block supersedes the drafting-time statements in sections 1 to 6 that the source is frozen and that nothing is implemented).** The drafting-time text of sections 3 to 6 describes the code as it was on 2026-11-12 ("today") and the intended behavior ("after DR-1"). Those passages are kept as written because they are the historical record of the divergences; where they say "not implemented", read this block. The implementation sequence is `docs/design-revision-1-implementation-plan.md`.

| item | state | where |
|---|---|---|
| F: tagged COSE_Sign1, audience array, `delegation_rights` map | implemented and committed | `f8e60dc`, `tests/test_revision_f.py` |
| D20: RFC 8949 deterministic encoder (`docs/decisions/DR-0002.md`) | implemented and committed | `56ddc12`, `tests/test_canonical_encoder.py` |
| A: signed status artifacts, Option K anchor, artifact-only AAD, key separation, unavailable-status policy, alerts, D17 identifiers, artifact-integrity and per-statement classification, policy-independent artifact rejection and policy-governed request verdict (5.6, `docs/decisions/DR-0003.md`) | implemented and committed; supervisor rulings are still pending, listed in `docs/decisions/DR-0003.md` section 4 (known risks and limitations are in this document, section 11) | `ec750bb`, `tests/test_revision_a.py`; conformance rows in 7.4 |
| C: per-node expiry, and moving the expiry check before status processing | not implemented; expiry currently follows status (6.2.1), explicitly deferred to Revision C | |
| Audience attenuation (child audience subset of parent) | not implemented | |
| B: equal-version idempotency, digest equivocation, `status._demo()` migration | not committed. At `ec750bb` an equal version is rejected as a rollback and `status._demo()` is a stub that raises `NotImplementedError` until this revision lands | |
| Status-service ingestion layer (D19) | not implemented; deferred. Service-side obligations in 5.6 are stated, not enforced anywhere in this repository | |
| Spec §18 conformance | not complete: row 11a (network outage) has no defined or implemented behavior | 7.4 |

The signature block in section 13 is still blank; nothing here is a verified signature. The frozen Spec and Design documents are unchanged. A proposed reissue text is in `docs/proposed-spec-reissue.md` (not part of the frozen documents).

## 0. How to read this document

### 0.1 Labels and sources

| label | meaning |
|---|---|
| **VERIFIED** | read in source code or a test body, read in the authoritative specification text, or reproduced by running existing unmodified code on 2026-11-12 |
| **FROZEN** | a requirement in the frozen Spec v1.0.3 or the approved Design v1.1 |
| **AMENDMENT** | a supervisor-approved change to, or resolution of, the frozen text (relayed in the task statements of 2026-11-12) |
| **DIVERGENCE** | the prototype code differs from the frozen text |
| **DEFERRED** | approved as non-blocking future work |
| **PROPOSED** | my technical detail, not separately ruled. Needs review at implementation (test-first) time |
| **OPEN** | not resolved: the ruling text was not supplied to me, or the evidence cannot settle it |

"Supervisor ruling relayed" means the ruling reached me only through the user's task statements. I could not check it against a supervisor-authored document, and I have not widened it. Where a ruling was supplied only as a label, this document says so and does not add content.

Authoritative sources (hashes and provenance in `docs/frozen/PROVENANCE.md`):

- **Spec** = `docs/frozen/Lineage_Keyed_Revocation_Implementation_Spec_v1_0_3.docx`, sha256 `1b4cc41b345b0322f1a932e45f5bdc6024b1cdef045a5b501ae0c89cb9e4b160`. The supervisor confirmed that this is the exact document submitted for signature. That is a confirmation of document identity, not independent verification of a signature. Byte-identical to commit `168a91a`; text and 11 tables identical.
- **Design** = `docs/frozen/Lineage_Keyed_Verifier_Side_Revocation_Design_Document_v1_1.docx`, sha256 `ee8e4fb828dabbfdcf36cc7788457401728ab42689141d7217bebf1afc677d8e`. Approved per supervisor review of record, 2026-08-16 (checklist letter, not in the repository); invalid-statement amendment carried in Implementation Spec v1.0.x. The file's own status line is preserved unchanged.
- Code and tests: `src/lineage_revocation/{canonical,keys,nodes,lineage,revocation,status,verifier}.py`, `tests/*.py`.
- Benchmark and evidence: `docs/controlled-benchmark-design-v1.md` (**CBD-v1**), `docs/controlled-benchmark-design-review.md`, `docs/research-evidence-status.md`, `scripts/count_traces.py` output.
- Decision records: `docs/decisions/` (numbered; DR-0001 is retroactive). All future decisions use numbered records there.

**Earlier drafts of DR-1 (Drafts 1 and 2) cited the two repository `.docx` files `docs/Lineage_Keyed_Verifier_Side_Revocation_{Spec_v1_0_3,Design_Document}.docx`. Those are later `html-to-docx` renderings without tables and are not authoritative. Several statements in the drafts, that sections were empty or that P1 to P4 were undefined, were wrong and are corrected in this version (section 0.3).**

### 0.2 Decision register

Status column: "ruling relayed" = approved by the supervisor, text as relayed in the task statements. Rulings 7, 10, 13 and 14 were relayed in full and are recorded in full. Implementation questions that no ruling answers are listed in section 11 and are not decisions.

| # | decision | status | where |
|---|---|---|---|
| 1 | `schema_version` is a required artifact-body field; artifact is a signed canonical collection | ruling relayed | 5.1.3 |
| 2 | root-bound anchor representation: **Option K**, a serialized COSE_Key | ruling relayed | 5.1.5 |
| 3 | dedicated artifact-signing key, separate from delegation and statement keys | ruling relayed | 5.1.6 |
| 4 | domain separation: external AAD for the **artifact only**; nodes and statements keep empty AAD | ruling relayed. The AAD byte string is not supplied and is fixed test-first | 5.1.4 |
| 5 | equal version accepted idempotently after authentication and freshness; lower rejected; higher authenticated then accepted | ruling relayed | 5.2 |
| 6 | equal version with different signed content: SHA-256 digest detection, **reject and alert** | ruling relayed | 5.2.4 |
| 7 | unavailable-status policy for the six situations: `None` routes to the unavailable policy; explicit TTL-only no-status mode; one policy function with distinct reason codes; mandatory alert on S5; **fail-closed default**; bounded-staleness over the last authenticated artifact as the configured alternative and a benchmark arm; fail-open experimental only | ruling relayed in full (5.4) | 5.4 |
| 8 | high-water-mark persisted after authentication and before the freshness check | ruling relayed | 5.2.5 |
| 9 | API option **P-2 approved**; `status_artifact=` compatibility retained | ruling relayed | 6.2 |
| 10 | per-node expiry `now < expires_at` for every node; no verification-time nesting; no `issued_at`/not-before check in this revision; no issuance-time refusal; optional non-normative warning in `create_child_node`; error carries the node id through a compatible subclass | ruling relayed in full (5.3) | 5.3 |
| 11 | K-axis representative cells (2,2), (5,4), (20,1) | ruling relayed | 8.1 |
| 12 | K statements built as a decoy forest under the same root | ruling relayed | 8.1 |
| 13 | measurement: GC-disabled steady state is primary; cold-start and GC-enabled are separate labelled conditions, never mixed | ruling relayed in full (8.2) | 8.2 |
| 14 | conformance: the approved section 7.2 test list is preserved; 11a (network outage) and 11b (unreadable store) stay distinct; test 20 uses distinct `expires_at` values per node | ruling relayed in full (7) | 7 |
| 15 | four evidence-collection authorizations and their conditions | ruling relayed as stated in the earlier task statement; each paid run still needs its stated go-ahead | Appendix A |
| 16 | audience attenuation: child audience is a subset of parent audience; leaf check is membership of the requested resource | ruling relayed | 5.5 |
| 17 | staleness boundary: stale when `now >= min(valid_until, issued_at + max_staleness)` | ruling relayed | 5.2.5 |
| 18 | invalid statements: structured alert log plus a monotonic metrics counter | ruling relayed | 5.6 |
| 19 | revoked revokers' statements remain valid within their scope | ruling relayed | 5.7 |
| 20 | P1 to P4 mapping from Design §13 | ruling relayed | 4.3 |
| 21 | restore authoritative frozen documents, record hashes | done in this commit | `docs/frozen/` |
| 22 | migrate `status._demo()` with Revision B; DR-0001 citation corrected to a decision record | ruling relayed; record created | `docs/decisions/DR-0001.md` |
| 23 | property-based CBOR tests; escalate to the supervisor if canonical encoding fails | ruling relayed | 5.1.7 |
| D14 to D19 | divergence rulings | ruling relayed | section 3 |
| D20 | deterministic encoding: conform to RFC 8949 section 4.2.1 with a protocol-owned encoder | ruling relayed (escalation under ruling 23) | section 3; `docs/decisions/DR-0002.md` |
| 24 | statement defect classification (Revision A): wire-malformed statements (including signature member presence, type and length) and conflicting duplicates reject the whole artifact; semantic failures are ignored per statement; artifact rejection is policy-independent, the request verdict is policy-governed; fail-open is experimental-arm only with distinct telemetry | ruling relayed (final) | 5.6; `docs/decisions/DR-0003.md` |
| 25 | D21: Design §7.2 `scope` field absent from Spec §8; implementation follows the Spec | recorded, awaiting ruling | 3 |
| 26 | D22: `target_node.issuer == statement.revoker` (Spec §9) not implemented; authority is derived from node ids and keys | recorded, awaiting ruling | 3 |

Benchmark rulings relayed and retained unchanged: depth-as-analogy; original 21-cell grid; deterministic topology generation; structural revocation oracle; sibling isolation; chain-only depth spur (depth 10 and 20, fanout 1); `K ∈ {1,10,100,1000}`; steady-state per-request primary path; ingestion on a separate per-refresh axis; fresh-version-per-call kept as a labelled worst case; individual-call timing with per-call vectors where practical; cold-start and GC retained; chain-minimum TTL primary; T-active primary and T-full upper bound; TTL values 30 s, 1 min, 5 min, 15 min, 1 h; `L = R`; seeded exposure-phase sweeps; leaf-only expiry documented once as a historical vulnerability and not used as the baseline; node-id renewal cascade as an experimental question; JSONL schema and layout retained plus an exposure-phase field; commit metadata, raw results and summaries, Git LFS if large.

### 0.3 Source corrections and remaining source gaps

Corrections to earlier drafts (checked against the authoritative Spec and Design on 2026-11-12):

- **P1 to P7 are defined** in Design §13 (table). Draft 1 and 2 said they were undefined. Mapping in 4.3.
- **Spec §8** has a statement-format table (fields and rules); **§10** has an ingestion-check table; **§12** has a table with the default prototype policy; **§15** has a guarantees table; **§16** has an HTTP API table; **§5** has a COSE profile table; **§3** has the credential field table. **Design §3.3** (verifier classes), **§4** (requirements R1 to R10), **§6** (credential table), **§8.2** (freshness parameters) and **§14** (attack table) exist. Earlier drafts called these empty.
- There is **no Spec §8.1 and no Spec §9.1**. **Design §8.1** and **Design §9.1** exist. Revision B's textual basis is Spec §13, Spec §12 (rollback row) and Design §9.1.
- Spec §18 (21 tests) and the Spec §13 pseudocode are identical in the authoritative file and in the repository rendering, so the matrix in 7.1 stands.

Contradictions that remain in the frozen texts (Spec governs; Design is the approved architecture):

- Signature failure on the artifact: Design §9.1 `DENY("untrusted revocation state")`; Spec §13 `handle_unavailable_status(now)`. Resolved by the fail-closed amendment in 5.4: both lead to rejection.
- Invalid statement: Design §9.1 `DENY("invalid revocation statement")`; Spec §11 and §13 ignore, log and continue. The Spec governs ("invalid-statement amendment carried in Implementation Spec v1.0.x").
- Freshness: Design §9.1 `now > valid_until or age > limit`; Spec §13 leaves `expired` and `too_stale` undefined. Resolved by ruling 17.
- Spec §12 table: "Effective freshness: min(valid_until - issued_at, max_staleness)" is written as a duration; the approved boundary in ruling 17 is expressed on absolute times.
- Spec §5 lists protected headers `alg`, `kid` and a content-type identifier; the code writes `alg` only. Not ruled; see D14.
- Spec §13 `remember_highest` runs before `status.expired`; Spec §12 says "persist ... before serving authorization decisions based on that version". Consistent with ruling 8.

Provenance gaps that remain: the Design approval letter is not in the repository (recorded from the supervisor's statement), and the supervisor's signature on the Spec is not independently verified.

## 1. Executive summary

DR-1 records the supervisor's rulings on the frozen protocol and the prototype. It specifies; it does not implement.

- **Revision A.** Status artifacts are signed, canonical, carry a required `schema_version`, and are authenticated against the root-bound anchor (Option K) with a dedicated artifact key and artifact-only external AAD, before the high-water mark moves. Design §8.1, §9 step 7 and Spec §13 already require this; the code does not do it (D1, D18).
- **Revision B.** Equal-version artifacts are accepted idempotently after authentication and freshness; a strictly lower version is rejected; an equal version with a different SHA-256 digest is rejected and alerted.
- **Revision C.** Every node must satisfy `now < expires_at`.
- **Spec-shape conformance (F).** Tagged COSE_Sign1 (D14), audience arrays with subset attenuation (D15), a `delegation_rights` map (D16). Statement identifiers and wire form (D17) belong to Revision A.
- **Policy.** Fail-closed replaces the Spec §12 bounded-staleness default as the unavailable-status policy (5.4).
- **Revision D.** The 21-row Spec §18 matrix (section 7): 10 rows covered for the aspect tested, 9 partial, 2 missing. **The 61 passing tests of the 2026-11-12 run do not prove Spec §18 conformance.**
- **Revision E.** Benchmark amendments (section 8), including the decoy-forest K construction.

Motivating finding (VERIFIED by running unmodified code, 4.2): a forged unsigned version 2 with no statements authorized a revoked lineage and caused the genuine artifact to be rejected as a rollback; a forged version `10**12` blocked every genuine artifact.

Implementation sequence (`docs/design-revision-1-implementation-plan.md`): **F, then A, then C, then audience attenuation, then B**. Tests first. F precedes A because F changes node bodies and so changes every fixture node id. **B never precedes A.**

Rulings 7, 10, 13 and 14 are recorded in full (5.4, 5.3, 8.2, 7); open implementation questions are listed in section 11.

## 2. Motivation and scope

Spec §20 says: "Do not change the trust model to accommodate implementation convenience without a written design revision." This document is that revision. In scope: F, A, B, C, audience attenuation, D, E and the standing evidence items (Appendix A). Out of scope: code, tests, benchmark code, any result.

Relationship to the existing documents:

- **Design v1.1** (approved per the supervisor's review of record, 2026-08-16). DR-1 does not change the research question or threat model. It restores conformance with Design §8.1 ("signed append-only collection of revocation statements"), Design §9 step 7 ("Verify the revocation artifact's signature, issuer, version, validity period, and trust chain") and the `<` rollback rule of Design §9.1.
- **Spec v1.0.3.** Each change states which Spec clause it implements. Where DR-1 departs from the Spec text it is marked **AMENDMENT** with the ruling: the fail-closed policy (Spec §12 default) and artifact-only external AAD (Spec §5 has no external AAD clause).

## 3. Existing implementation divergences (VERIFIED unless marked)

| id | what the code does | what Spec / Design says | revision |
|---|---|---|---|
| D1 | `StatusArtifact` (`status.py`) has `version, root_revocation_state_uri, issued_at, valid_until, statements`. No signature, no serializer. `accept_status_artifact` never authenticates the artifact | Spec §13 `verify_status_artifact(status, trust)`; Design §9 step 7; Design §9.1 `verify_status_signature(status, trust_anchor)`; Design §8.1 | A |
| D2 | `accept_status_artifact` rejects `artifact.version <= highest_seen` | Spec §13 `if status.version < highest_seen(uri)`; Spec §12 rollback row "rejects lower versions"; Design §9.1 `if status.version < highest` | B |
| D3 | `authorize` checks only `lineage[-1].body.expires_at` | Spec §18 test 20 says "Expired leaf credential". Per-node expiry is an **AMENDMENT** (ruling 10) | C |
| D4 | no fetch and no `handle_unavailable_status`. With `status_artifact=None`, `authorize` silently skips revocation checking and can return success (removed by ruling 7); `test_valid_chain_authorizes` asserts that success | Spec §13 routes missing or unfetchable status to `handle_unavailable_status`; Design §11 "not implicit allow"; fail-closed default per ruling 7 | A (policy) |
| D5 | invalid statements: `_logger.warning(...)` only | Spec §11 and §13: log the failure and "emit an alert/metric". Ruling 18: structured alert log plus a monotonic counter | A |
| D6 | `NodeBody.revocation_trust_anchor` is opaque `bytes`, compared for equality with the root's value; never used as a key. Statement verification uses the caller-supplied `root_trust_anchor: COSEKey` | Spec §7: read it from the root node; a descendant copy "is treated only as a consistency value". Spec §3: "COSE key identifier/material". Ruling 2: Option K | A |
| D7 | the mark is saved after the freshness check passes | Spec §13 runs `remember_highest` before the staleness check. Ruling 8: persist after authentication and before freshness | B |
| D8 | audience is one `str`, checked by equality on the leaf only | Spec §3: `audience` is an array; Spec §13 `audience_allows(chain, request)`. Rulings 16 and D15 | F |
| D9 | `save_high_water_mark` uses `Path.write_text` (not atomic, no fsync). `status_store_path=None` with an artifact raises an untyped `AttributeError` | Spec §12: durable local storage; failure to load is "status unavailable" | A (hardening, PROPOSED) |
| D10 | n/a (document divergence) | artifact signature failure: Design §9.1 DENY versus Spec §13 `handle_unavailable_status`. Both reject under the fail-closed amendment | resolved by ruling 7 |
| D11 | implementation follows the Spec | invalid statement: Design §9.1 DENY versus Spec §11 ignore | none; Spec governs |
| D12 | stale when `now >= min(valid_until, issued_at + max_staleness)` | Design §9.1: `now > valid_until or age > limit`. Ruling 17 fixes `now >= min(valid_until, issued_at + max_staleness)` | none: **the code already matches ruling 17** |
| D13 | `status._demo()` asserts same-version replay "should be rejected as stale" | conflicts with the equal-version ruling | B (migrate with Revision B, ruling 22) |
| D14 | `Node.to_cose_sign1_bytes()` emits an **untagged** array `[protected, {}, payload, signature]`; `protected` holds `alg` only | Spec §5: "prototype uses tagged representation"; protected headers `alg`, `kid`, content-type | F |
| D15 | `audience: str`; leaf equality check; attenuation checks `authority` and `can_delegate` only | Spec §3: `audience` array. Ruling: arrays; child audience is a subset of the parent's; leaf check is membership of the requested resource | F |
| D16 | boolean `can_delegate` (commit `ea91bf2`, DR-0001) | Spec §3 and §4: `delegation_rights` is a CBOR map in the node body | F |
| D17 | `revocation_id` is a caller-supplied `bytes` field inside the signed statement body; no statement wire encoding | Spec §8: `revocation_id` "content-derived from statement body"; `signature` is "COSE_Sign1" | A |
| D18 | artifact has no signature | the signature requirement is already in the frozen design (Design §8.1, §9 step 7, §9.1; Spec §13 and the §22 checklist line "Revocation artifact: signed statements (Option A)") | A restores it |
| D19 | library only; no HTTP endpoints | Spec §16 lists `POST /delegations`, `POST /revocations`, `GET /status/{root-id}`, `POST /authorize`, `GET /metrics` | **DEFERRED, non-blocking, not a protocol divergence** |
| D20 | `encode_canonical` is `cbor2.dumps(..., canonical=True)`, which orders map keys length-first (RFC 7049 section 3.9). `{"a": 1, 1000: 2}` encodes with `"a"` first | Spec §4: RFC 8949 core deterministic encoding (section 4.2.1: keys ordered by the bytewise order of their complete encodings; `1000` (`19 03 e8`) sorts before `"a"` (`61 61`)) | **conform**; ahead of F and A. Record: `docs/decisions/DR-0002.md` |
| D21 | Spec §8 defines the statement fields without a `scope`; the implementation has none. A revocation always applies to the target node and, through lineage checking, to every credential whose authenticated lineage contains it | Design §7.2 lists a `scope` field: "At minimum: target node plus all valid descendants that depend on it." Spec §8 (which governs) has no such field, and no Spec text reintroduces it | **recorded, not ruled** (supervisor). Spec §8 governs and the implementation follows it |
| D22 | `target_node.issuer` is a text label that is serialized in the signed node body and **never read for any decision** (`nodes.py:66,84` only). A direct-issuer revocation is authorized by structure instead: `check_revocation_statement` requires `statement.revoker == parent.node_id` for the target's parent in the verified `target_lineage` and verifies the signature under that parent's `subject` key (Spec §9 key rule). `revoker` is a node id (`bytes`); `issuer` is free text, so the two cannot be compared directly | Spec §9: "The verifier or ingestion validator checks target_node.issuer == statement.revoker for direct-child revocation." Spec §8: `revoker` is the "Identity of signer issuing the revocation." The frozen text defines no mapping between a node's `issuer` string and a `revoker` identity | **recorded, not ruled.** The literal check is **not implemented**. The authority it protects (only the target's direct issuer or the root may revoke) is enforced by node-id and key derivation. What is not enforced: that a node's `issuer` label names its actual issuer; tests use arbitrary labels (a child created by the root carries `issuer="root"`, one created by `a` carries `"a"`) and the verifier would accept a label that lies. Whether the label must be checked, and against what identity format, needs a ruling |

**Dispositions (rulings relayed; the approved rulings are the supervisor's, the implementation notes are mine):**

- **D14, COSE tagging.** The implementation MUST conform to tagged COSE_Sign1. The tag wraps the envelope, not the `Sig_structure`, so node ids (a hash of the body) and signatures over the body are **unaffected**; only the wire bytes change. The parser is **strict and tagged-only**: an untagged array is rejected. DR-1 adds **no protected-header requirement** beyond what the supervisor ruled: the ruling covers the tag only. The Spec §5 table text lists protected headers `alg`, `kid` and a content-type identifier and the code writes `alg` only; that is recorded as an observation, not as a requirement of this revision. Any change to protected headers would change every signature and is not part of D14.
- **D15, audience.** `audience` becomes an array. Attenuation adds: each child's audience MUST be a subset of its parent's. The leaf check becomes: the requested resource is a member of the leaf's audience. A change to the node body, so node ids change.
- **D16, delegation rights.** Use a `delegation_rights` map. Frozen semantics are retained: the single recognized key carries the boolean. Unknown keys are rejected. The frozen root and direct-issuer revocation scope (Spec §9) is not changed. The name of the recognized key was **not supplied by the supervisor and is not invented here**; it is fixed with the supervisor before F starts. A change to the node body, so node ids change.
- **D17, statement identifiers and wire form.** `revocation_id` is SHA-256 over the canonical unsigned statement body, mirroring `node_id`. The statement serializer uses the node-shaped COSE_Sign1 envelope. Belongs to Revision A. **Implementation note (VERIFIED from `RevocationStatement._unsigned_cbor_dict`):** that dict currently contains `revocation_id`. The "canonical unsigned statement body" that `revocation_id` hashes must therefore not include `revocation_id` itself, as `NodeBody` has no `node_id` field and `node_id` hashes the unsigned body. The self-exclusion follows from the ruling's definition ("SHA-256 over the canonical unsigned statement body"); it changes the statement's signed bytes, which is the implementation task's concern.
- **D17 addendum (rulings relayed; reasoning in `docs/decisions/DR-0003.md`).** Verifiers recompute `revocation_id` as SHA-256 over the canonical unsigned statement body and never trust the wire value. The wire field stays (frozen Spec §8) as a reference whose presence and equality are checked; absence or mismatch is a wire-malformed defect (5.6). Identical bodies deduplicate and are logged; different valid signatures over one body are the same semantic revocation. The same recomputed id with a different body is an artifact-integrity defect (5.6).
- **Artifact-key separation scope (ruling relayed; DR-0003).** The artifact key must differ from the root key, every lineage subject key and every statement-signing key, compared by canonical encoded key bytes. The requirement lives at key generation; the verifier check is detection, and a match is alerted.
- **D18, artifact signature.** Revision A restores a requirement already present in the frozen design. It is **not** a newly invented protocol requirement.
- **D19, HTTP API.** Deferred prototype scaffolding. Non-blocking, not a protocol divergence. The in-process benchmark phases do not require it. Revisit only if real-socket network conditions are to be measured.
- **D20, deterministic encoding.** Implementation divergence, not a reason to amend the frozen Spec. Disposition: conform. A protocol-owned encoder in `src/lineage_revocation/canonical.py` replaces reliance on cbor2 `canonical=True`: recursive, keys sorted by the bytewise order of each complete encoded key, definite lengths only, shortest-form integers, no floats, unsupported types rejected, no tags except COSE_Sign1 tag 18. **Domain restriction is input validation; canonical correctness comes from the encoder.** Over the current protocol objects (text-keyed bodies, small-label COSE maps) the two orderings coincide, so existing bytes, node ids and signatures do not change (a differential test records this; it is not the conformance oracle). Ruling 23 property tests are retargeted at the new encoder.
- **D21, statement `scope`.** Design §7.2 lists `scope`; Spec §8 does not, and the Spec governs. Not ruled by the supervisor; recorded here. Revocation reach is determined by authenticated lineage membership, so the minimum scope the Design names ("target node plus all valid descendants") is the behavior, but it is not a statement field and cannot be narrowed or widened per statement.
- **D22, `target_node.issuer == statement.revoker`.** Recorded accurately: the check is **not implemented**; `issuer` is never read. Direct-issuer authority is established by `revoker == parent.node_id` plus verification under the parent's subject key, which is the Spec §9 key rule ("MUST verify under the COSE public key in the subject field of the target node's parent"). The gap is that a node's `issuer` label is unchecked content. It does not let a non-issuer revoke (the key derivation prevents that); it means the label cannot be relied on as evidence of who issued a node. Disposition requires a supervisor ruling.

No test in `tests/` asserts equal-version rejection; only `status._demo()` does. The rollback tests use strictly lower versions (`test_status_artifact_rollback_denied`: 2 then 1; `test_status_artifact_rollback_persists_across_restart`: 5 then 3).

## 4. Security analysis

### 4.1 Why statement-level signatures do not prevent omission

`verify_revocation_statement` (VERIFIED, `revocation.py`) authenticates each statement as issued by an authorized revoker. It says nothing about the set. A verifier holding an artifact cannot tell which genuine statements are missing. Omission needs no forgery: the attacker presents a collection with the revocation left out. `version`, `issued_at` and `valid_until` are also unsigned, so the attacker also chooses freshness and the version counter. Spec §2 says: "The status distribution service is not trusted to decide authorization; it is trusted only for availability and, at most, syntactic ingestion checks." Completeness is a decision about authorization, so the verifier cannot delegate it to the service. Only an artifact-level signature by a root-designated key binds version, validity window, URI and statement set together.

### 4.2 Attack scenarios (reproduced against unmodified code)

Attacker model (Spec §2): controls the status distribution path; holds no private key. Setup: root issues `A`, `A` issues `B`; the root revokes `A` in genuine artifact version 1; the verifier authorizes `[root, A, B]`. A read-only script (kept outside the repository, importing frozen code, modifying nothing) was run on 2026-11-12:

| step | action | observed |
|---|---|---|
| 1 | genuine version 1 (revocation of `A`) | DENY, `NodeRevoked` |
| 2 | attacker builds an unsigned version 2 with `statements=[]` | **ALLOW**: all three node ids returned |
| 3 | genuine version 1 again | rejected: `artifact version 1 <= highest seen 2` |
| 4 | fresh store; attacker's unsigned version `10**12` | **ALLOW** |
| 5 | genuine versions 2 and 3 afterwards | rejected: `<= highest seen 1000000000000` |
| 6 | the same genuine version 1 presented twice | second presentation rejected (the behavior Revision B changes) |

Consequences: (1) omission or suppression, with freshness fields chosen by the attacker; (2) the genuine artifact is refused as a rollback, turning the rollback defense into the attacker's tool; (3) high-water-mark poisoning: because the mark is durable (Spec §12) it survives restart, and the revocation feed is permanently denied until an operator edits the store; under a fail-open unavailable-status policy this becomes a revocation bypass; (4) nothing ties the artifact's signer to `revocation_trust_anchor` (URI binding is enforced, `test_status_artifact_cannot_be_bypassed_with_wrong_uri`; signer binding is not).

### 4.3 Properties affected

Design §13 defines the properties (VERIFIED in the authoritative Design file): **P1** subtree revocation, **P2** sibling preservation, **P3** adversary-on-path resistance, **P4** bounded exposure, P5 no guarantee against a compromised verifier, P6 no retroactive rollback, P7 revocation authority confinement.

Mapping (ruling 20: P1 and P4):

- **P1, subtree revocation** ("If a revoked node appears in an authenticated lineage and the verifier has sufficiently fresh revocation state, the request is denied", conditions: cooperative verifier, authenticated lineage, fresh state). An unsigned artifact lets the distribution path remove the revocation, so the verifier no longer has the revocation state the claim assumes. **Broken by omission (4.2 steps 1 to 2).**
- **P4, bounded exposure** ("bounded by publication latency + distribution/retrieval latency + permitted freshness/cache staleness + verifier processing delay", condition: known maximum staleness). The freshness fields `issued_at` and `valid_until` are unsigned, so the attacker chooses them and the bound no longer holds. High-water-mark poisoning (4.2 steps 4 to 5) also removes the revocation feed for an unbounded period. **Broken.**
- My observation, not part of the ruling: **P3** carries the condition "Verifier can independently obtain status state"; a verifier that cannot authenticate state it obtains does not satisfy it. **P2** and **P7** are not affected by the attacks in 4.2.

Other frozen statements: Spec §15 "Rollback: Older status versions are rejected once a higher version has been accepted"; Design §14 "Attacker modifies revocation list: Signature verification fails; verifier denies or follows failure policy". The code gives neither for the artifact.

### 4.4 Temporal amplification (reasoned from code, not run)

An intermediary `B` holds a credential valid until `t1` and may mint a child `C` (VERIFIED: `create_child_node` accepts any `expires_at`; `_attenuated` checks only `authority` and `can_delegate`). `B` sets `C.expires_at = t2 > t1` and presents `[root, A, B, C]` after `t1`. `verify_lineage` does not read expiry; `authorize` checks only `C`; the lineage is accepted. Authority outlives the grant that justified it. `test_expired_leaf_denied` cannot detect this: all four fixture nodes share `expires_at=1_700_100_000` and `now` is past all of them.

## 5. Normative protocol changes

Normative words follow RFC 2119. Everything below is a specification of intended behavior after sign-off. **None of it is implemented or tested.**

### 5.1 Revision A: signed, canonical, root-bound status artifacts

**5.1.1 Requirement (ruling relayed; restores a frozen requirement, D18).** The artifact MUST be a signed collection. The verifier MUST authenticate it against the root-bound revocation trust anchor. Authentication MUST complete before the high-water mark advances. Forged or incorrectly anchored artifacts MUST be rejected. Malformed artifacts MUST be handled without crashing. The requirement is already in the frozen design (Design §8.1 "signed append-only collection", Design §9 step 7, Spec §13 `verify_status_artifact`); DR-1 does not introduce it.

**5.1.2 Serialization conventions in use (VERIFIED).**

- `encode_canonical(value) = cbor2.dumps(value, canonical=True)` (`canonical.py`); cbor2 6.1.4. Equivalence with RFC 8949 section 4.2.1 for all inputs is **OPEN** (I checked a few mixed-key maps only; Spec §4 requires RFC 8949 core deterministic encoding).
- `NodeBody.to_cbor_dict()` is a map with text keys; `node_id = SHA-256(canonical_bytes)`.
- `Node.to_cose_sign1_bytes()` is `encode_canonical([protected, {}, payload, signature])` with `protected = encode_canonical({1: -8})`; an **untagged** array.
- Signed bytes: `encode_canonical(["Signature1", protected, b"", payload])`. External AAD is always empty. `sign_payload`/`verify_payload` serve both nodes and revocation statements.
- Statements: `_unsigned_cbor_dict()`, `canonical_bytes()`, signature by `sign_payload`. **No wire serializer for a statement or an artifact exists.**
- `COSEKey` is OKP/Ed25519 only, one field `x` (raw public key bytes).

**5.1.3 Artifact serialization (ruling 1 for `schema_version` and the signed collection; the remaining shape is PROPOSED and is fixed test-first).** Reuse the existing envelope and add no new primitive.

- `ArtifactBody`: a map with text keys `schema_version` (**required**, ruling 1), `version`, `root_revocation_state_uri`, `issued_at`, `valid_until`, `statements`. An artifact without `schema_version`, or with an unsupported value, is malformed (5.1.8). The value that denotes this format is not supplied and is fixed test-first.
- Each element of `statements` is the statement's signed encoding in the node-shaped COSE_Sign1 envelope (D17). The statement serializer is part of Revision A.
- Envelope: **tagged** COSE_Sign1 (D14) around `[protected, {}, ArtifactBody canonical bytes, artifact_signature]`, with `protected` carrying `alg` (header content beyond `alg` follows the D14 open question). The signature covers version, URI, window and the statement set; this is what defeats omission.
- The artifact signature uses artifact-only external AAD (5.1.4).

**5.1.4 Domain separation (ruling relayed: external AAD for the artifact only).** The artifact signature MUST be computed and verified with an external AAD that is specific to artifacts. Node signatures and statement signatures keep the empty external AAD, so **existing node and statement signatures are unchanged by this ruling**. Effect: a signature over a node or statement body cannot verify as an artifact signature, and conversely, even if a key were shared. The exact AAD byte string is **not supplied** and is fixed test-first. Mechanism (**PROPOSED**): `sign_payload` and `verify_payload` (`nodes.py`) gain an optional external-AAD argument defaulting to empty, so the default path is bit-identical. The ruling also requires the artifact key to be distinct from delegation and statement keys (5.1.6).

**5.1.5 Root-bound trust anchor representation (ruling relayed: Option K).** `revocation_trust_anchor` holds a **serialized COSE_Key**: the canonical CBOR encoding of the key map `COSEKey.to_cbor_dict()` (OKP, Ed25519, `x`). This is consistent with Spec §3 ("COSE key identifier/material") and Design §6 ("public key/trust-anchor identifier"), and with the encoding of `NodeBody.subject`.

Rationale for deriving trust from the authenticated root (FROZEN, Spec §7 and §9): "The verifier MUST obtain revocation-state discovery information from the authenticated root node. Any copy of root_revocation_state_uri or revocation_trust_anchor appearing in a descendant is treated only as a consistency value", "Never trust a revocation-signing key introduced by a descendant", and a statement key must not be "supplied independently by the statement, a network URL, or an untrusted status service". The artifact verification key is therefore never taken from the artifact, a leaf, a URL or the distribution service.

Verification of the field (**PROPOSED strictness**): decode strictly; require `kty` OKP and `crv` Ed25519; reject extra or missing keys; a malformed or unsupported value is an artifact authentication failure (S4/S5), never an untyped exception. Existing fixtures use the placeholder `b"\x01" * 32`, which is not a COSE_Key encoding; tests that ingest an artifact need a real value. Key rotation and compromise recovery for the artifact key are **not addressed** by any available text (**OPEN**).

**5.1.6 Artifact signing key (ruling relayed: dedicated key).** The artifact is signed by a **dedicated artifact-signing key, separate from every delegation key and every statement (revoker) key**. Spec §2 (FROZEN) says the status distribution service "is not trusted to decide authorization; it is trusted only for availability and, at most, syntactic ingestion checks". If the distribution service held the key, Revision A would not defend against a compromised service, so the key MUST NOT be held by the distribution service (derived from Spec §2; my wording). Who holds it beyond "dedicated, and not the distribution service" was **not supplied**. Statement signing keys are unchanged (Spec §9).

**5.1.7 Verification order and failure behavior (PROPOSED order; specification of intent, not implemented).** Property-based tests and escalation: see the end of this subsection.

1. Authenticate the lineage, check root binding, attenuation (including audience subset, 5.5) and per-node expiry (5.3) (existing and amended).
2. **Strictly parse** the artifact from the bytes as received: tagged-only COSE_Sign1, well-formed CBOR, no indefinite-length items, no trailing bytes. Keep the exact received body bytes. Parsing mutates no persistent state.
3. **Canonical-form check (ruling 2):** decode the body, re-encode it canonically, and **compare the result byte for byte with the received body bytes**. Any difference is rejection.
4. **Validate structure and required fields** (including `schema_version`, field types, `valid_until >= issued_at`).
5. *Optional cheap early rejection:* compare `root_revocation_state_uri` with the authenticated root's value. It is permitted only as an early rejection and **MUST be repeated after authentication** (step 8); it never substitutes for step 8, because the value is not yet trusted.
6. **Authenticate:** derive the verification key from the authenticated root's `revocation_trust_anchor` (Option K, 5.1.5) and verify the artifact signature, with artifact-only external AAD, over **the exact canonical body bytes** received.
7. **Use fields only from the verified bytes.** Every field used from here on (version, URI, window, statements) is read from those verified bytes; there is no second parse of different bytes and no use of an unsigned field.
8. **URI binding check after verification:** `artifact.root_revocation_state_uri == root.root_revocation_state_uri` (existing; `RevocationBindingMismatch`).
9. Rollback, equal-version and digest processing (5.2.2, 5.2.4).
10. **Persist the high-water mark** (and digest) after authentication and before the freshness check (5.2.5).
11. **Freshness** at the injected `now`: stale when `now >= min(valid_until, issued_at + max_staleness)`.
12. Process the authenticated statements; invalid statements are ignored, logged and counted (5.6); a statement is effective when `effective_at <= now`.

**No persistent state mutation occurs before step 6 succeeds.** A parsing, canonical, structural or authentication failure leaves the store file unchanged and the artifact unused. No high-water-mark advancement happens before authentication. The verifier processes exactly the body whose signature was verified.

**Canonical encoding is validated, not assumed (rulings 2 and 23).** `encode_canonical` is `cbor2.dumps(value, canonical=True)` (VERIFIED, `canonical.py`, cbor2 6.1.4). Equivalence with RFC 8949 section 4.2.1 is established only by **property-based CBOR tests** (ruling 23). **If canonical encoding fails those tests, the implementation MUST escalate to the supervisor; it MUST NOT silently substitute another encoder or relax the byte comparison.**

A failure at steps 2 to 8 follows the unavailable-status policy (5.4): under the approved fail-closed default the request is rejected.

**5.1.8 Malformed artifacts (PROPOSED).** Truncated or non-canonical CBOR, wrong types, missing fields, negative or non-integer version, `valid_until < issued_at`, wrong key length for the chosen representation, wrong signature length, unsupported algorithm in the protected header: treated as a failure at steps 2 to 6 (5.1.7), with no untyped exception and no store write. `schema_version` missing or unsupported, a `revocation_trust_anchor` that is not a valid Option K COSE_Key, an untagged envelope, and a body that is not in canonical form (5.1.7 step 3) are all in this class. `status_store_path=None` with an artifact MUST yield the documented unavailable failure instead of `AttributeError` (D9).

### 5.2 Revision B: artifact version handling

**5.2.1 Requirement (ruling relayed).** A strictly lower version is rejected as a rollback. An equal version is accepted idempotently, subject to the normal signature, authenticity and freshness checks. A higher version is authenticated and accepted, advancing the high-water mark. Equal-version acceptance MUST NOT weaken rollback protection.

**5.2.2 Normative acceptance rules (my wording of the ruling; the last row is not covered by it).**

"Stored" means the durable high-water mark for the artifact's `root_revocation_state_uri`. "Valid signature" means verification under the root-bound anchor (5.1). "Fresh" means the freshness check at the injected `now` passes.

| # | condition | required behavior |
|---|---|---|
| 1 | lower version than stored | **Reject as rollback.** No store change |
| 2 | equal version, valid signature, fresh | **Accept idempotently.** No new proof of newness; no store advance. Use the artifact for this authorization |
| 3 | equal version, invalid signature | **Reject.** No store change; rejected under the fail-closed default (5.4). This is an authentication failure, not an equivocation (5.2.4 case 3) |
| 4 | higher version, valid signature, fresh | **Accept; advance the high-water mark** (after authentication, before the freshness check; 5.2.5) |
| 5 | higher version, invalid signature | **Reject without advancing the high-water mark** |
| 6 | equal version, valid signature, **different signed content** (digest differs) | **Reject and alert** (ruling 6; 5.2.4). No store change |
| 7 | equal or higher version, valid signature, **not fresh** | Do not use the artifact. A higher authenticated version still advances the mark, because persistence precedes the freshness check (5.2.5); the request is then rejected under the fail-closed default |
| 8 | equal or higher version, artifact for another URI or signed by a non-anchor key | Reject (incorrectly anchored). No store change |
| 9 | malformed artifact, any version | Reject; typed failure; no store change |

**5.2.3 Equal-version acceptance never bypasses authentication or freshness.** Rows 2 and 3 differ only in the signature result, and rows 2 and 7 differ only in freshness. An equal version is not "already trusted": the verifier trusts a *version number it stored*, not the bytes presented now. Therefore every presentation of an equal-version artifact MUST be authenticated and MUST pass freshness at the current injected `now`. Under API option P-2 (6.2) authentication may be performed once at ingestion and remembered for the same authenticated artifact, but freshness MUST still be evaluated on every authorization. Authentication of a *different* artifact (different bytes) is never inherited.

**5.2.4 Equal-version equivocation (ruling 6: SHA-256 digest detection, reject and alert).**

*Problem.* The version is a counter chosen by the signer. A signer fault, a publishing race or a stolen artifact key can produce two validly signed bodies with one version number. A rule that compares only versions cannot tell them apart; verifiers would then hold different revocation states under the same version.

*Rule (ruling relayed).* Store, beside the version, the **SHA-256 digest of the artifact's canonical body bytes** (the bytes whose signature was verified). On an equal version: an equal digest is the same artifact (idempotent acceptance); a **different digest is rejected and alerted**.

Three distinct situations:

1. **Equal presentation of the same authenticated artifact.** Same bytes, same digest. Idempotent acceptance (row 2), after authentication and freshness.
2. **A different artifact signed by the same authorized signer with the same version.** Authenticates, digest differs. **Reject and alert** (row 6). The alert indicates signer fault or compromise.
3. **An artifact with an invalid signature claiming the same version.** Fails authentication at step 6 (5.1.7) and is rejected before any digest comparison. It is not equivocation and is never compared against the stored digest. (Logging of authentication failures is not ruled.)

*Storage format.* The store is today JSON `{uri: int}` (VERIFIED). The approved rule needs `{uri: {version, digest}}` or an equivalent. Consequences: legacy integer entries must still load as version-only; the digest is over the canonical body bytes (SHA-256, consistent with the node id construction); the write stays durable and ideally atomic (D9); code that reads only integers must tolerate or reject the new format. **OPEN sub-question (not ruled):** the treatment of an equal-version artifact that meets a legacy digest-less entry. Recording the digest on first sight is a store write on an equal version; to be decided before Revision B's tests are written.

**5.2.5 Persistence ordering (ruling 8) and staleness boundary (ruling 17).** The high-water mark is persisted **after authentication and before the freshness check**. This matches Spec §13 (`remember_highest` precedes `status.expired`) and Spec §12 ("persist ... before serving authorization decisions based on that version"). The code today writes after the freshness check (D7). Staleness: an artifact is stale when `now >= min(valid_until, issued_at + max_staleness)`; the code already uses this boundary (D12).

**5.2.6 Concepts (the current code merges them).**

| # | concept | meaning | current code |
|---|---|---|---|
| 1 | ingestion | first acceptance: parse, authenticate, rollback check, persist, extract statements | `accept_status_artifact`, called on every `authorize` |
| 2 | repeated presentation | the same ingested artifact used for many authorizations | not representable; the second call is rejected by `<=` |
| 3 | freshness validation | depends on `now`; MUST be re-evaluated on every authorization; never cached | inside `accept_status_artifact` |
| 4 | durable mark persistence | highest accepted version per URI on disk, loaded before serving (Spec §12) | JSON `{uri: int}` via `write_text` |

**5.2.7 Ordering constraint (security-critical; adopted in the implementation sequence).** On today's unsigned artifacts, Revision B alone would let any party on the distribution path present a different unsigned artifact carrying the *current* version number and have it accepted. **Revision B MUST NOT be implemented or released before Revision A.** If the supervisor chooses another order, the reason must be recorded, and B before A is still excluded.

### 5.3 Revision C: per-node credential expiry

**5.3.1 Requirement (ruling relayed).** For every node `N_i` in the lineage, `now < N_i.expires_at`. If any node fails, the whole lineage is rejected. A child MUST NOT remain usable after any ancestor expires.

**5.3.2 Details (ruling relayed in full).** Evaluate after lineage authentication (an expiry on an unauthenticated node must not be trusted) and before status processing. Boundary: `now >= expires_at` is expired (the existing leaf rule).
- **No verification-time nesting:** the verifier does not additionally require a child's `expires_at` to be `<=` its parent's. The per-node check already denies a child once any ancestor has expired.
- **No `issued_at` / not-before check in this revision.**
- **No issuance-time refusal:** `create_child_node` does not refuse a child that outlives its parent. An **optional, non-normative warning** in `create_child_node` is permitted.
- **Error identity:** the failure carries the offending node id through a **compatible subclass** of `CredentialExpired`, so existing `pytest.raises(CredentialExpired)` sites keep working.
Spec §18 test 20 remains true and is subsumed. After Revision C, chain-minimum expiry is the frozen verifier's own behavior (8.4).

### 5.4 Unavailable-status behavior (ruling 7: fail-closed)

The code lets `authorize(status_artifact=None)` skip revocation checking and return success (D4). The six situations below are not equivalent and are kept distinct.

| situation | current behavior (VERIFIED) | frozen text | what it tells the verifier |
|---|---|---|---|
| S1. no status artifact supplied (`status_artifact=None`) | revocation silently skipped; success possible (`test_valid_chain_authorizes`) | Spec §13: a missing cache entry leads to a fetch; a failed fetch to `handle_unavailable_status`. The library has no fetch | no evidence about revocation state |
| S2. status service or network unavailable | not representable (no network code) | Spec §13 `handle_unavailable_status(now)`; Design §11: "Network retrieval failure is treated as status unavailable, not implicit allow" | no evidence; possibly an attacker causing it |
| S3. high-water-mark store unreadable | `load_high_water_mark` raises `StatusUnavailable` on `OSError` or invalid JSON; a missing file returns `None`. Untested | Spec §12: "Failure to load it is treated as status unavailable." | rollback protection cannot be enforced; a missing file looks like a first run |
| S4. artifact malformed | not handled (no parser) | not specified in the Spec | untrusted input; no evidence |
| S5. artifact signature invalid | not applicable (no signature) | Spec §13 `handle_unavailable_status(now)`; Design §9.1 `DENY("untrusted revocation state")` | evidence of tampering or misconfiguration |
| S6. artifact stale | raises `StaleStatusArtifact` | Spec §13 `handle_stale_status(now)`; Design §9 step 9 "configured fail-closed or bounded-staleness policy" | **authenticated** evidence of an older state |

**AMENDMENT (ruling 7).** **Fail-closed supersedes the original bounded-staleness default.** The Spec §12 table says "Default prototype policy: Bounded-staleness; fail-closed is a separate experimental condition" (FROZEN). The supervisor ruled that fail-closed is now the default. This is a recorded, supervisor-approved supersession of that Spec default.

*Why.* Bounded staleness needs previously authenticated evidence: a retained authenticated artifact and its age. Where none exists (S1, S4, S5) "stale but within bound" has no meaning. Fail-closed is defined in all six situations; bounded-staleness is not.

**Approved behavior per situation (ruling 7, relayed in full):**

| situation | approved behavior |
|---|---|
| **S1** no artifact (`status_artifact=None`) | **The silent skip is removed.** `None` routes to the unavailable-status policy. Under the fail-closed default the request is rejected. The TTL-only baseline is reachable only through the **explicit no-status mode** below, never by omitting the argument |
| **S2** status service or network unavailable | handled by the **one policy function** shared with S4 and S5, with a **distinct reason code** |
| **S3** high-water-mark store unreadable or corrupt | **fails closed**. A **missing** file is a first run, not a failure |
| **S4** artifact malformed | one policy function, distinct reason code |
| **S5** artifact signature invalid | one policy function, distinct reason code, and a **mandatory alert** |
| **S6** stale authenticated evidence | this is where **bounded staleness applies**: it is the configured alternative, evaluated over the **last authenticated artifact** |

*Policies.*
- **Default: fail-closed.**
- **Bounded-staleness** over the last authenticated artifact is the **configured alternative** and a **measured benchmark arm** (Design §11 requires at least two verifier policies to be implemented and measured).
- **Fail-open** exists only as an **experimental baseline** (Design §11: "experimental only").

**`status_artifact=None` (normative).**
1. `None` MUST route through the unavailable-status policy. It never skips revocation checking.
2. The default behavior is **fail-closed**.
3. A TTL-only **no-status mode** requires an **explicit, deliberately named opt-in**. **Omission never enables no-status mode.**
4. The exact name and shape of the opt-in are not supplied and are fixed test-first. Consequence: `test_valid_chain_authorizes`, which today expects success with no artifact, must be migrated to the explicit opt-in or to a supplied artifact (a test change for the implementation task, not made here).
5. For the benchmark, the chain-minimum TTL baseline (8.4) uses the explicit no-status mode.

### 5.5 Audience attenuation (ruling 16, D15)

`audience` is an array (Spec §3). Attenuation adds: for every child, the child's audience MUST be a subset of its parent's audience. A violation is an authority amplification (denied, as for `authority`). The leaf check becomes: the requested resource is a **member** of the leaf's audience array. Spec §13 has `audience_allows(chain, request)` and `attenuated(chain)`; the Spec does not define per-node audience semantics, so this is an AMENDMENT. Changes the node body (node ids change).

### 5.6 Invalid statements: classification, alert and metric (ruling 18 and the final Revision A ruling)

**Normative dividing principle (to be carried into the next Spec reissue; see `docs/proposed-spec-reissue.md`):**

> The verifier escalates to artifact-level rejection exactly those defects that the ingestion contract obliges the service to reject and that the verifier can detect without any authorization semantics.

Two categories, never conflated:

| category | defects | verifier behavior | reason code | alert kind |
|---|---|---|---|---|
| **artifact integrity** (wire-malformed) | malformed CBOR or invalid wire structure; missing required fields (`reason_code` is optional, as in frozen Spec §8); incorrect field types; **a received statement payload that is not the exact canonical encoding of its own content, including a non-canonical node envelope embedded in it**; **missing, wrongly typed, or not-64-byte (Ed25519) signature member**; missing `revocation_id`; `revocation_id` different from the recomputed SHA-256; conflicting duplicates (same recomputed id, different unsigned body) | **reject the entire signed artifact**; no persistent mutation; route through the unavailable-status policy (fail-closed by default; bounded-staleness fallback to the last authenticated artifact if configured) | `StatusReason.ARTIFACT_INTEGRITY` | `artifact_integrity`, with a `defect` field (`malformed_wire`, `signature_malformed`, `revocation_id_missing`, `revocation_id_mismatch`, `conflicting_duplicate`) |
| **per-statement semantic** | a correctly formed (64-byte) signature that fails verification under the key derived through Spec §9; revoker unauthorized or outside its scope; target id or lineage mismatch; invalid target lineage | **ignore that statement**, log, alert, continue with the others (frozen Spec §11); the artifact stays usable | `StatementReason` (`SIGNATURE_INVALID`, `REVOKER_UNAUTHORIZED`, `TARGET_ID_MISMATCH`, `TARGET_LINEAGE_MISMATCH`, `LINEAGE_INVALID`) | `invalid_revocation_statement`, with a `reason_code` field |

*Dividing rule for signatures (final ruling).* A defect that is **detectable without consulting a key is wire-malformed; a defect that requires the key is semantic.** A missing signature member, a signature member of the wrong type, and an Ed25519 signature whose length is not 64 bytes are detectable from the bytes alone (the pinned algorithm fixes the length), so they are artifact-integrity defects. A 64-byte signature that fails verification under the authorized key is a semantic failure, as is an unauthorized revoker. (A tagged envelope that is not a four-element array, including one with no signature member at all, is refused earlier by the strict decoder and is reported with defect `malformed_wire`.) *Exact reconstruction.* A statement's signature is verified over its canonical reconstruction, and the strict decoder sees embedded node envelopes only as opaque byte strings, so the parser also requires the received payload to equal that reconstruction; any difference is `malformed_wire`. *Unusable keys.* Key material that cannot verify anything (for example a lineage node whose subject key is not 32 bytes) is a failed verification: a per-statement semantic failure (`LINEAGE_INVALID`) inside a statement, and a typed lineage failure in a presented lineage. It never raises an untyped exception.

*Artifact rejection is invariant across policies; the request verdict is policy-governed.* These are two separate stages.

1. **Artifact disposition (policy-independent).** Under every policy, including the experimental fail-open arm, an artifact with an integrity defect is rejected: its statements are not processed, its contents are not used for authorization, the high-water mark does not advance, it cannot replace the accepted artifact, and nothing is persisted. Rejection happens before the verdict stage and before any persistence, so no policy can reach the failed artifact.
2. **Request verdict (policy-governed).** `FAIL_CLOSED` denies the request. `BOUNDED_STALENESS` uses the last authenticated artifact only while it remains fresh; its revocations keep applying; the rejected artifact is never used. `FAIL_OPEN_EXPERIMENTAL` may allow the request when no usable authenticated state exists (and uses a fresh last authenticated state when one exists, rather than discarding known revocations). `TTL_ONLY_NO_STATUS` excuses only an absent artifact.

*Standing rule for `FAIL_OPEN_EXPERIMENTAL`.* It exists only inside an explicitly labelled experimental benchmark arm and is never a production policy or configuration option. The implementation refuses it unless an `experimental_arm` label is supplied (`ValueError` otherwise); the label is written to its telemetry. **The label is a benchmark label and a guard against accidental use, not a cryptographic or production-enforcement boundary**; fail-open stays unavailable as a production policy by rule, not because the label enforces it. It never overrides an unreadable store (S3), artifact-key reuse, or a rollback.

*Fail-open telemetry.* Two findings are distinct from every status reason so a benchmark can separate the outcomes: `fail_open_after_status_unavailable` (any non-integrity status failure, with the underlying `reason_code`) and `fail_open_after_artifact_integrity`. Each is an alert kind with its own counter and carries `finding`, `reason_code`, `experimental_arm` and `authenticated_state_used`. A fallback to a last authenticated artifact is reported as `status_fallback_last_authenticated`, once per request and only after the state is confirmed bound to the root; its `policy` field distinguishes a bounded-staleness fallback from fail-open using authenticated state.

*Scope of the signature-length ruling.* It concerns revocation statements only. A wrong-length signature on the artifact's outer envelope is unchanged: it is reported as an artifact signature failure (S5, mandatory alert). The statement rule is not extended to the outer envelope without a ruling.

*Why the first category rejects the whole artifact.* Spec §11 ignores invalid statements because statements could be injected by unauthorized parties, so rejecting an artifact over them would be a denial-of-service vector. A wire-malformed statement is different in kind. After Revision A only the revocation authority can produce a signed artifact, so a malformed or conflicting statement inside one is evidence of an authority fault or compromise, the same category as equivocation, and gets the same policy: reject plus alert through the unavailable-status path. Detecting these defects needs no authorization semantics: the ingestion contract (Spec §10: well-formedness, COSE structure, required fields and types, duplicate `revocation_id`) already obliges the status service to reject them, and the verifier re-checks because the service is trusted only for availability.

*Why the second category is ignored per statement.* Deciding that a signature is invalid or a revoker unauthorized needs the §9 key derivation and scope rules, which are authorization semantics. Statement authors are delegators, not the artifact authority; one delegator's garbage must not take down the revocation feed.

*Scope of enforcement.* **No status-service ingestion layer exists in this repository** (D19, deferred). Only the verifier-side check is implemented and tested. The service-side obligation is stated in the proposed Spec text and is not enforced anywhere here.

Telemetry (ruling 18): each alert is a structured log record (logger `lineage_revocation.alerts`; attributes `alert_kind` and `alert_fields`) plus a monotonic counter per kind. Integrity and semantic alerts use different kinds and reason namespaces. The field set and names are implementation choices, not fixed by the Spec. An invalid statement never causes denial by itself (Spec §9, §11).

### 5.7 Revoked revokers (ruling 19)

A revoked node's revocation statements remain valid **within the revoker's scope**: a revoked B that legitimately revokes its own child C causes C to be denied, and B remains revoked (Spec §18 test 12; Design §14, "Revoked B signs revocation of its own child C: Valid if B retained authority to revoke C"). B still cannot revoke a sibling or any node outside its scope (test 13; Spec §9). `verify_revocation_statement` does not consult the revoker's own revocation status (VERIFIED), so the behavior already holds; tests are needed (7.2).

## 6. Updated API behavior

Names that do not exist in the repository are **PROPOSED labels**.

### 6.1 `StatusArtifact` and `accept_status_artifact` (`status.py`)

| item | today (VERIFIED) | after DR-1 (not implemented) |
|---|---|---|
| `StatusArtifact` | `version, root_revocation_state_uri, issued_at, valid_until, statements` | add the signature, required, with no default that permits an unsigned artifact |
| `accept_status_artifact(artifact, store_path, *, now, max_staleness)` | returns `list[RevocationStatement]`; raises `StatusUnavailable`, `StaleStatusArtifact` | also needs the key derived from the Option K anchor (5.1.5); authenticates before the mark moves; implements table 5.2.2; no write on equal version except as 5.2.4 requires |
| exceptions | `StaleStatusArtifact` for both "lower version" and "stale" | OPEN whether to split; a subclass keeps existing `pytest.raises` working |
| store format | `{uri: int}` | `{uri: {version, digest}}` or equivalent (ruling 6); legacy integer entries still load |

Security invariant: the mark changes only after the artifact is authenticated. Failure behavior: no store write, typed exception.

### 6.2 `authorize()` (`verifier.py`): P-2 approved (ruling 9)

Today `authorize(...)` re-ingests the artifact on every call.

**Decision (ruling relayed): P-2 is approved, and the `status_artifact=` compatibility is retained.** Artifact ingestion is a distinct operation that authenticates the artifact, verifies the statements once (statement verification depends on the statement, its lineage and the anchor, not on `now`) and produces an authenticated accepted-status state, with a verified-statement index keyed by `target_node_id`. Repeated authorization calls reuse that state. The existing `status_artifact=` parameter keeps working: it ingests inline and then proceeds (the behavior P-1 described). P-1 therefore survives as the compatibility path, not as a competing design.

Reasons recorded: P-2 separates refresh cost from per-request authorization cost, and it matches the supervisor's benchmark methodology (repeated `authorize()` calls over one ingested artifact are the primary path; ingestion is timed separately per refresh). Costs accepted: new public surface in a frozen module, more trusted state, and a verified-statement index that must be replaced on each new version. The benchmark report states which path was measured.

**Security requirements on the accepted-status state.** The state produced by ingestion and reused across authorization calls MUST satisfy all of the following. No class name, field name or signature is fixed by DR-1; they are chosen test-first.

*Binding.* The state MUST be bound to all four of:

1. the **exact authenticated canonical artifact bytes**, or an **authenticated digest** of those bytes (SHA-256 over the canonical body bytes, as in 5.2.4);
2. the artifact's **`root_revocation_state_uri`**;
3. the **root-bound revocation trust context** used to authenticate it (the Option K anchor read from the authenticated root node);
4. the **authenticated artifact version**.

*Consequences the binding must have.*

- **No substitution.** The state cannot be substituted by a different artifact. Anything not covered by the binding is not the same state, even if it parses.
- **No cross-URI reuse.** The state cannot be reused under a different root status URI. Each `authorize` call MUST compare the state's URI with the authenticated root node's `root_revocation_state_uri` before use.
- **No cross-anchor reuse.** The state cannot be reused for a lineage whose authenticated root carries a different anchor or is a different authenticated root.
- **Replacement only by an authenticated, persisted higher version.** A higher version replaces the accepted state only after successful artifact authentication **and** the approved persistence ordering (5.2.5). A failed or unauthenticated candidate leaves the existing state and the store file unchanged.
- **Equal version.** An equal version with a different digest is rejected and alerted (5.2.4); an equal version with the same digest keeps the existing state.
- **Freshness on every authorization.** Freshness is evaluated against the current injected `now` on **every** authorization (`now >= min(valid_until, issued_at + max_staleness)` is stale). An authenticated state is not permanently fresh.
- **Effective time on every authorization.** `effective_at <= now` is evaluated against the current injected `now` on **every** authorization, for every matching statement.
- **No stale reuse.** An expired accepted-status state cannot remain usable merely because it was previously authenticated; once the freshness check fails the state is unusable until replaced, and the request is rejected under the fail-closed default (5.4).
- **Authentication is not inherited.** Only the exact artifact the state is bound to is covered by its authentication; a different artifact must be authenticated again (5.2.3).

*What the state does not decide.* It does not fix the serialization, the anchor representation, the key ownership, the domain separation or the unavailable-status policy; each stays with its own ruling. The state may carry a non-canonical or partially processed view (for example a statement index) only for lookup, never as a substitute for the bytes it is bound to. Invalid statements are ignored, logged and counted at ingestion (5.6).

### 6.2.1 Order of checks in `authorize` (Revision A, verified against the code)

| step | check | failure | Spec §13 |
|---|---|---|---|
| 0 | `FAIL_OPEN_EXPERIMENTAL` requires an `experimental_arm` label | `ValueError` | (not in the Spec; benchmark guard) |
| 1 | lineage authentication (`verify_lineage`) | typed `LineageVerificationError` | `invalid lineage` |
| 2 | root binding (URI and anchor equal the root's in every node) | `RevocationBindingMismatch` | `revocation binding mismatch` |
| 3 | audience: requested resource is a member of the leaf's audience | `AudienceMismatch` | `audience mismatch` |
| 4 | attenuation (DR-0001) | `AuthorityAmplification` | `authority amplification` |
| 5 | status: key separation, ingestion or accepted state, freshness, policy verdict (5.1.7, 5.4, 5.6) | `StatusFailure` subclasses; `RevocationBindingMismatch` for a URI or anchor mismatch; `NodeRevoked` follows from step 6 | status, rollback, stale handling |
| 6 | revocation of any node in the authenticated lineage (`effective_at <= now`) | `NodeRevoked` | `revoked lineage` |
| 7 | leaf expiry (`now >= expires_at`) | `CredentialExpired` | (not in the Spec) |
| 8 | session reauthorization interval | `ReauthRequired` | (Spec §14) |

**Error precedence.** The first failing step wins, so a request with several defects reports the earliest: an audience mismatch is reported before attenuation and before every status failure, and it touches no revocation-state machinery (no ingestion, no high-water-mark write, no alert, no policy verdict). Steps 1 to 4 reproduce the Spec §13 order. Before Revision A the audience check ran after status; `docs/decisions/DR-0003.md` section 5 records the change and `tests/test_revision_a.py` (`test_audience_mismatch_*`) pins it.

**Expiry placement is a deferred discrepancy, not a defect of Revision A.** Leaf expiry (step 7) currently runs **after** status. DR-1 5.3.2 requires every node's expiry to be evaluated after lineage authentication and **before** status processing; that move, with per-node expiry, is **Revision C** (`docs/design-revision-1-implementation-plan.md`, Phase 4). Until C lands, a request with an expired leaf can still ingest an artifact and advance the high-water mark before it is denied. Revision A does not change this.

### 6.3 Other

Revision C changes `authorize` only. `revocation.py` needs a statement serializer (5.1.3). `nodes.py`, `canonical.py`, `keys.py` are unchanged unless 5.1.4 option (i) is chosen.

## 7. Spec §18 conformance (Revision D)

### 7.1 Matrix of the 21 mandatory tests

Spec requirement text is quoted from the numbered list in Spec §18. Test names are functions whose **bodies I read**; all exist in the repository (checked by script on 2026-11-12). Every listed test is a protocol test. Coverage terms: **EXISTING** (a test asserts the requirement for the aspect named), **PARTIAL** (part of the requirement is asserted), **MISSING** (no test asserts it). "Proposed after sign-off" tests are not written and carry proposed names in 7.2 only.

| # | Requirement (Spec §18) | Existing test function | Existing coverage assessment | DR-1 action (after sign-off only) |
|---|---|---|---|---|
| 1 | Leaf attempts to replace `root_revocation_state_uri` → DENY | `test_compromised_intermediary_status_redirect_denied_and_never_contacted` | **EXISTING** for the leaf: leaf `c` carries `ATTACKER_URI`; `RevocationBindingMismatch` with `node_id == c.node_id` | none; optional intermediate-position variant |
| 2 | Leaf attempts to replace `revocation_trust_anchor` → DENY | `test_revocation_trust_anchor_divergence_also_denied` | **EXISTING** (leaf `c` carries `b"\xff"*32`) | fixtures that ingest an artifact need a real Option K value (5.1.5) |
| 3 | Compromised B points verifier to attacker status service → verifier never dereferences it | `test_compromised_intermediary_status_redirect_denied_and_never_contacted`; `test_status_artifact_cannot_be_bypassed_with_wrong_uri` | **PARTIAL.** The first patches `socket.create_connection` and asserts no call, but the code contains no network code, so the assertion holds trivially. The second covers an artifact claiming the wrong URI | if a fetch path is added, add a test that a leaf-selected URI is never contacted |
| 4 | Valid A→B revocation → B denied after effective freshness point | `test_revoked_intermediary_denies_whole_subtree`; `test_direct_issuer_may_revoke_its_child` | **PARTIAL.** The `authorize` test uses a **root-signed** statement (`revoker_node_id=root.node_id`). A as direct issuer is tested only at `is_target_revoked` level | proposed: direct-issuer revocation through `authorize` |
| 5 | B→C descendant after B revocation → C denied | `test_revoked_intermediary_denies_whole_subtree` | **EXISTING.** `[root,a,b,c]`, `b` revoked, `NodeRevoked.node_id == b.node_id` | none |
| 6 | B revoked while sibling C is absent from B branch → sibling branch remains eligible | none (`test_issuer_cannot_revoke_a_sibling` concerns authority scope, not eligibility) | **MISSING.** No `authorize()` test uses two branches | proposed: revoked branch does not affect sibling branch; the benchmark oracle also exercises it |
| 7 | Unauthorized revocation statement targeting B → ignored/logged, not denial | `test_issuer_cannot_revoke_its_own_parent`; `test_issuer_cannot_revoke_a_sibling`; `test_tampered_statement_signature_ignored_without_crashing` | **PARTIAL.** They assert `not is_target_revoked(...)`; none checks a log record; none runs through `authorize` with an artifact; no alert or metric exists (D5) | tests: structured alert log and counter (ruling 18, 5.6); log assertion for ignored statements |
| 8 | Valid revocation + invalid statement in same artifact → valid revocation still denies | `test_invalid_statement_ignored_but_valid_one_still_revokes` | **PARTIAL.** Passes `[invalid, valid]` directly to `is_target_revoked`, not through `StatusArtifact` and `authorize` | proposed: artifact-level variant, signed artifacts |
| 9 | Old artifact served after higher version was accepted → DENY rollback | `test_status_artifact_rollback_denied`; `test_status_artifact_rollback_persists_across_restart` | **EXISTING** for a strictly lower version, including across restart through the store file. Raises `StaleStatusArtifact` | stays valid under Revision B; fixtures rebuilt with signed artifacts |
| 10 | Expired artifact → configured stale-status behavior | `test_stale_status_artifact_denied` | **PARTIAL.** `issued_at = NOW-10_000`, `max_staleness=100`, `valid_until = NOW+1000` exercises the staleness limit only; the `valid_until` expiry branch is not exercised. "Configured behavior" is a single hard-coded raise | tests: `valid_until` expiry and the boundary `now == min(valid_until, issued_at + max_staleness)`; policy is fail-closed (ruling 7) |
| 11 | Network outage → configured unavailable-status behavior | **none** | **MISSING.** See 7.1.1 | **policy approved: fail-closed (ruling 7). Per-situation text and the network-outage test are not yet defined. Do not mark covered** |
| 12 | Revoked B legitimately revokes C → C denied; B remains revoked | `test_grandchild_issuer_may_revoke_its_own_child` | **PARTIAL.** Covers a non-root issuer B revoking its child C. B is not made revoked, the two statements are not combined, and the code never considers whether the revoker is itself revoked | tests: revoked B revokes C, B stays revoked (ruling 19, 5.7) |
| 13 | Revoked B attempts to revoke sibling → statement invalid/unauthorized and ignored | `test_issuer_cannot_revoke_a_sibling` | **PARTIAL.** Scope rule covered (b cannot revoke sibling d); the revoked state of B is not exercised | tests: B revoked and then revoking a sibling is ignored (ruling 19) |
| 14 | Long-lived session crosses reauthorization interval after revocation → next authorization denied | `test_stale_session_requires_reauth`; `test_fresh_session_does_not_require_reauth` | **PARTIAL.** Covers `ReauthRequired`; no revocation in either test | proposed: reauthorization after a published revocation |
| 15 | Duplicate node IDs in lineage → DENY | `test_duplicate_node_id_rejected` | **EXISTING** at `verify_lineage` (`DuplicateNodeId`); `authorize` calls it first | none |
| 16 | Broken `parent_node_id` linkage → DENY | `test_parent_node_id_mismatch_rejected` | **EXISTING** (`ParentLinkMismatch`) | none |
| 17 | Forged ancestor signature → DENY | `test_wrong_parent_key_rejected`; `test_root_signed_by_wrong_key_rejected`; `test_root_subject_is_never_used_as_its_own_trust_anchor` | **EXISTING** (`ChildSignatureInvalid`, `RootSignatureInvalid`) | none |
| 18 | Authority amplification in child → DENY | `test_malicious_intermediary_authority_amplification_denied`; `test_can_delegate_false_blocks_any_child` | **EXISTING.** The test comment cites "DR-0001"; the record now exists as `docs/decisions/DR-0001.md` (retroactive, landing commit `ea91bf2`). The comment itself was not edited | none; the DR-0001 citation now has a record: `docs/decisions/DR-0001.md` |
| 19 | Audience mismatch → DENY | `test_audience_mismatch_denied` | **EXISTING for the leaf only, string equality** (D8, D15) | F: audience array, subset attenuation, leaf membership check (ruling 16, 5.5) |
| 20 | Expired leaf credential → DENY | `test_expired_leaf_denied` | **EXISTING for the leaf, non-discriminating**: all fixture nodes share one `expires_at` and `now` is past all of them, so a chain-minimum check would also pass | per-node expiry tests (7.2); **test 20 fixture correction (ruling 14): distinct `expires_at` per node, so the test discriminates leaf-only from per-node behavior** |
| 21 | Future-dated revocation statement → ALLOW before `effective_at`; DENY at/after | `test_not_yet_effective_statement_does_not_revoke`; `test_revoked_intermediary_denies_whole_subtree` | **PARTIAL.** "Before" tested (`effective_at = NOW+1`); "after" only with `effective_at = NOW-1`; the boundary `effective_at == now` is not tested | proposed: boundary test |

Tally of existing coverage: **EXISTING 10** (1, 2, 5, 9, 15, 16, 17, 18, 19, 20), **PARTIAL 9** (3, 4, 7, 8, 10, 12, 13, 14, 21), **MISSING 2** (6, 11). Rows 19 and 20 are existing for the leaf only. I read the bodies of the 41 protocol tests in `test_cbor_canonical.py`, `test_cose_roundtrip.py`, `test_leaf_status_redirect.py`, `test_revocation_correctness.py` and `test_root_binding.py`. I did not run mutation testing, so "EXISTING" means the asserted behavior matches the requirement for the aspect named, not that the test would catch every defect.

**The 61 passing tests of the 2026-11-12 run (41 protocol tests plus 20 harness and evidence tests) do not prove full Spec §18 conformance.** Two rows are missing, nine are partial, and rows 19 and 20 cover the leaf only.

#### 7.1.1 Row 11 must not be collapsed

Row 11 has two different parts, and a test for one is not a test for the other.

| part | what it is | state |
|---|---|---|
| 11a. network outage → configured unavailable-status behavior | what the verifier does when the status source cannot be reached (situation S2) | **MISSING.** The default policy is fail-closed (ruling 7) but no fetch exists in the code; no `handle_unavailable_status`; the behavior is not defined. This is the requirement of Spec §18 test 11 |
| 11b. local high-water-mark store unreadable | `load_high_water_mark` raises `StatusUnavailable` (situation S3, Spec §12) | behavior exists in code (VERIFIED); **no test references `StatusUnavailable`** (grep of `tests/`). A local unreadable-store test would cover 11b only |

Adding the 11b test later would **not** make row 11 covered. The fail-closed default is approved (ruling 7) but the network-outage behavior and its test are not yet defined. This document makes no claim that the unavailable-status behavior is implemented or tested.

### 7.2 Additional tests proposed after sign-off (names PROPOSED; none exist; none written)

These are not existing coverage and not part of the 61 passing tests. None collides with an existing function name.

**Revision A:** `test_unsigned_artifact_rejected`; `test_artifact_signed_by_wrong_key_rejected`; `test_artifact_with_statement_removed_rejected`; `test_forged_higher_version_does_not_advance_mark` (store bytes identical before and after; genuine version still accepted); `test_hwm_poisoning_with_huge_version_rejected`; `test_artifact_for_other_uri_rejected_even_if_validly_signed`; `test_descendant_supplied_anchor_never_used_for_artifact`; `test_malformed_artifact_typed_failure_no_side_effect`; `test_omission_attack_with_forged_next_version_denied` (4.2 end to end); `test_status_store_path_none_with_artifact_is_typed_failure`.

**Revision B:** `test_equal_version_authenticated_artifact_accepted_idempotently`; `test_strictly_lower_version_still_rejected_after_equal_accepted`; `test_higher_version_advances_mark_only_after_authentication`; `test_equal_version_invalid_signature_rejected`; `test_equal_version_stale_artifact_rejected_on_use`; `test_equal_version_after_restart_accepted`; `test_equal_version_does_not_rewrite_store`. **Now approved:** `test_equal_version_different_body_rejected` (ruling 6: reject and alert) and `test_ingested_artifact_reused_across_calls` (P-2, ruling 9).

**Revision C:** `test_expired_root_denied_when_leaf_valid`; `test_expired_intermediate_denied_when_leaf_valid` (fixture with distinct `expires_at` per node); `test_child_outliving_parent_denied_after_parent_expiry`; `test_each_node_position_expiry_denied` (boundary `now == expires_at` denied, `now == expires_at - 1` allowed); `test_all_nodes_valid_allowed`; `test_expired_node_reported_with_node_id`; `test_expiry_checked_before_status_ingestion`.

**Spec-shape (F), tests first:** tagged-only COSE parser (untagged rejected); node ids and body signatures unchanged by the tag; audience array round trip; child audience subset allowed, non-subset denied; leaf membership; `delegation_rights` map with unknown key rejected; fixture node ids change with the body changes.

**Canonical encoding (ruling 23):** property-based CBOR tests (canonical re-encoding of decoded bodies equals the received bytes; non-canonical encodings of the same value are rejected); escalation path if they fail.

**Artifact (A), additions:** `schema_version` required; strict canonical check by decode, re-encode and byte comparison; Option K anchor decoded strictly; artifact-only AAD (a node or statement signature does not verify as an artifact signature); statement `revocation_id` equals SHA-256 of the unsigned statement body (D17); structured alert and counter.

**Version handling (B), additions:** equal version with a different digest rejected and alerted (replaces the conditional test of Draft 2); legacy integer store entry loads; `status._demo()` migrated.

**Gap closers for matrix rows:** `test_direct_issuer_revocation_through_authorize` (4); `test_revoked_branch_does_not_affect_sibling_branch` (6); `test_invalid_statement_logged_not_denial` (7); `test_valid_and_invalid_statements_in_artifact` (8); `test_artifact_valid_until_expiry_denied` (10); `test_reauth_after_revocation_denied` (14); `test_revocation_effective_at_boundary` (21); `test_unreadable_high_water_store_is_unavailable` (**11b only**; it does not close row 11). Row 11a has no proposed test until the network-outage behavior is defined.

### 7.3 Protocol tests versus harness-only tests

Protocol tests (import `lineage_revocation`): the five files above. Harness and evidence tests (do not exercise the protocol): `tests/test_measurement.py`, `tests/test_smolagents_adapter.py`, `tests/test_smolagents_toolcalling_adapter.py`, `tests/test_search_safety.py`, `tests/test_count_traces.py`. The Spec §18 matrix uses protocol tests only.

### 7.4 Revision A conformance status (after implementation, 2026-11-15)

Only the rows that Revision A changes are re-evaluated; the other rows of 7.1 stand as written. Evidence is the named test in `tests/` (read, and mutation-checked where noted in the implementation report). "EXISTING" keeps the meaning of 7.1: the asserted behavior matches the requirement for the aspect named.

| # | 7.1 status | now | evidence |
|---|---|---|---|
| 2 | EXISTING | EXISTING; fixtures use a real Option K anchor | `test_revocation_trust_anchor_divergence_also_denied`; `test_option_k_*` |
| 7 | PARTIAL | **EXISTING** | `test_semantically_invalid_statement_is_ignored_and_the_artifact_stays_usable[REVOKER_UNAUTHORIZED]`; `test_malformed_subject_key_in_a_statement_lineage_is_a_semantic_failure_not_a_crash`; `test_correct_length_invalid_signature_stays_a_per_statement_semantic_failure`; `test_invalid_statement_alone_never_denies`; structured alert and counter asserted (`test_invalid_statement_alert_is_structured_counted_monotonic_and_not_a_denial`) |
| 8 | PARTIAL | **EXISTING** | `test_valid_and_invalid_statements_in_artifact` (artifact level, signed, through `authorize`); the invalid fixture is asserted well-formed on the wire, so it is a semantic failure only; five semantic reasons parametrized; wrong-length, missing and wrongly typed signatures are artifact-integrity, not row-8 invalid statements (`test_wrong_length_signature_rejects_the_entire_artifact`) |
| 9 | EXISTING | EXISTING with signed artifacts | `test_status_artifact_rollback_denied`; `test_status_artifact_rollback_persists_across_restart`; `test_forged_artifacts_leave_store_byte_identical_and_genuine_still_accepted` |
| 10 | PARTIAL | **EXISTING** | `test_stale_status_artifact_denied`; `test_artifact_valid_until_boundary`; `test_max_staleness_boundary`; fail-closed default and bounded-staleness alternative (`test_none_fails_closed_by_default`; `test_bounded_staleness_applies_to_s6_and_s2_over_last_authenticated_artifact`); artifact-integrity verdict under each policy (`test_fail_closed_denies_on_integrity_failure`; `test_bounded_staleness_uses_only_a_fresh_last_authenticated_artifact_and_its_revocations_apply`; `test_fail_open_may_allow_when_no_usable_authenticated_state_exists`) |
| 11 | MISSING | **MISSING (not covered)** | 11b exists: `test_s3_missing_file_is_first_run_and_unreadable_store_fails_closed_for_every_policy`. 11a (network outage) has no fetch path; S2 is exercised only through the policy function (`test_s2_network_unavailable_has_its_own_reason_via_policy_function`). Closing 11b does not close row 11 |
| 21 | PARTIAL | **EXISTING** | `test_accepted_state_reused_across_calls_reevaluates_freshness_and_effective_time` (`effective_at` one before, and equal to, `now`) |

The artifact-integrity invariants (no high-water-mark advance, no replacement of the accepted artifact, no statements supplied, nothing persisted, under every policy including fail-open) are not rows of the 21-row Spec §18 list; they are covered by `test_integrity_rejected_artifact_*` and `test_no_persistent_state_is_written_on_any_integrity_failure_under_any_policy`.

Row 19 (audience mismatch) is unchanged in status (EXISTING for the leaf only); its ordering relative to status now follows Spec §13 (`test_audience_mismatch_does_not_advance_or_create_the_high_water_mark`, `test_audience_mismatch_is_reported_before_any_status_failure_and_touches_no_telemetry`, `test_audience_mismatch_precedes_attenuation_as_in_spec_section_13`). Rows 3, 4, 6, 12, 13, 14 remain as in 7.1. Rows 19 and 20 depend on F, C and audience attenuation, not on A.

## 8. Controlled benchmark methodology amendments (Revision E)

Nothing here has run. No controlled benchmark code exists. Anything that depends on Revisions A, B or C is a design for after implementation, not a measurement, and every cell label below is a label, not a result. Spec §19 says artifact growth with revocation count times chain depth "This cost MUST be measured and reported, not silently optimized away."; this section keeps that requirement.

### 8.1 Topology, depth spur and K axis

Retained as relayed (ruling relayed): depth is hops and is an analogy to the measurement layer (a lineage of `d+1` nodes); the original 21-cell grid (depth {0..5} × fanout {1,2,4,8}, `d=0` once); deterministic topology generation; structural revocation oracle; sibling isolation. **Chain-only depth spur** (ruling relayed): depth ∈ {10, 20}, fanout 1, two more cells, 23 in total, labelled `projected`. Evidence labels used in results: `real-anchored (elicited)` for cells inside what elicited real traces showed, `projected` for the rest; none is "natural".

**K axis (definition ruling relayed):** `K ∈ {1, 10, 100, 1000}` is the number of revocation statements in the artifact, crossed with three representative depth/fanout cells.

**Representative cells (ruling relayed, approved): (depth=2, fanout=2), (depth=5, fanout=4), (depth=20, fanout=1).** Reasons (mine): (2,2) is the largest cell inside what elicited real traces showed (depth 2 only when elicited, breadth 2 only sequentially), label `real-anchored (elicited)`; (5,4) is mid-grid with 1,365 nodes, label `projected`; (20,1) is the deepest spur cell, label `projected`, where each statement embeds its `target_lineage` (VERIFIED in `RevocationStatement`) so artifact size and statement-verification cost scale with `K` times lineage length. That artifact cost depends on the target's depth and on `K`, not on fanout, is a hypothesis, not a result.

**K-statement construction: the decoy forest (ruling relayed).** The K values {1, 10, 100, 1000} are unchanged.

*Why a forest.* The measured tree of the (2,2) cell has 7 nodes, so it cannot supply 1000 distinct valid revocation targets off the measured chains. The statements therefore target a **dedicated decoy forest**, which makes K=1000 feasible for every cell, including (2,2), without changing the measured topology.

*Construction (all relayed):*

- **Dedicated decoy subtrees under the same root** as the measured tree, so every decoy target lineage authenticates to the same root anchor and the artifact's `root_revocation_state_uri` is the same.
- **Disjoint from every measured chain:** no decoy target is, or is an ancestor or descendant of, a node on a measured chain.
- **Sized to K:** the forest holds at least the `K-1` distinct decoy targets (plus whatever internal nodes their lineages need). The exact subtree shape is not supplied and is fixed test-first.
- **Depth-stratified targets:** decoy targets are spread over the depths available in the forest, by a fixed rule, not clustered at one depth.
- **Effective revocations:** every decoy statement has `effective_at <= now`, so each is a real, effective revocation of its (off-chain) target and subtree.
- **The structural oracle incorporates all K statements:** the expected outcome of every chain is computed from the tree structure and the full statement set. Because the forest is disjoint, the measured chains' expected outcomes are unchanged by the decoys; the oracle must still account for them for any chain that passes through the forest.
- **Signer mix:** the signers of the K statements are a **root-signed and direct-issuer-signed mix, seeded at 50/50**. Note (VERIFIED, `verify_revocation_statement`): for a depth-1 target the direct issuer is the root, so the two signer classes coincide there; the 50/50 split is therefore only meaningful over targets at depth 2 or more, and how depth-1 targets are counted is a detail fixed test-first.
- **The same seeded procedure across repetitions**, so repetitions differ only by system noise.
- **The policy is recorded in the metadata and in each benchmark row** (`revocation.decoy_policy`, 9).

**Three requirements that are separate and must all hold for every statement** (the scenario-defining statement and every decoy). None implies another.

| requirement | what it means (VERIFIED against `verify_revocation_statement`, `revocation.py`) |
|---|---|
| **structurally valid target lineage** | `target_node` hashes to `target_node_id`; `target_lineage` is non-empty and ends at the target; the whole lineage authenticates with `verify_lineage` from the root anchor |
| **cryptographically valid statement signature** | the signature verifies over the statement's canonical bytes under the key the Spec §9 rule selects: the root trust anchor for a root revocation, or the subject key of the target's parent for a direct-issuer revocation |
| **authorized revocation scope** | the statement's `revoker` is either the root node id, or the node id of the target's direct parent in the target lineage. Only the root and the direct issuer may revoke (Spec §9) |

Every statement uses the same validation path as the scenario-defining statement, with no relaxed path for decoys. Selecting a node off the measured chain does not by itself make a statement valid. All K statements are valid, authorized and effective; none is malformed, forged or unauthorized, so the benchmark measures **legitimate artifact ingestion and statement verification**, not malformed-input handling or any attack path (those belong to the correctness tests of 7.2).

Note on where the cost lands (VERIFIED, `is_target_revoked` in `revocation.py`): the current per-request loop skips a statement whose `target_node_id` differs from the node being checked before verifying it, so off-chain decoys are scanned but not verified per request; under P-2 every statement is verified once at ingestion. Spec §19 says artifact size growth with revocation count times chain depth "MUST be measured and reported, not silently optimized away"; the forest keeps that measurable.

### 8.2 Latency

- **Primary path (ruling relayed):** steady-state repeated `authorize()` calls over one ingested artifact. The report MUST state whether API option P-1 or P-2 was measured: under P-1 the per-request path includes artifact authentication and a store read each call.
- **Per-refresh axis (ruling relayed):** artifact ingestion, artifact-signature verification and the statement checks performed during ingestion are timed separately.
- **Worst case (ruling relayed):** the earlier condition, a fresh artifact version for every call, is kept and labelled `worst_case_fresh_version`. It is not the primary result.
- **Timing (ruling relayed):** time individual `authorize()` calls (`time.perf_counter_ns`) and preserve per-call sample vectors where practical; do not hide tail behavior in batches when individual timing is feasible. If timer resolution forces batching for a cell, record the batch size and say that tail statistics for that cell are over batches. **PROPOSED:** measure timer overhead and report it.
- **Measurement conditions (ruling 13, relayed in full).** **GC-disabled steady state is the primary condition** (warmed, repeated calls over one ingested artifact, GC disabled inside the timed region). **Cold start** (a fresh subprocess, first call) and **GC-enabled** runs are **separate, labelled conditions and are never mixed** with the primary condition or with each other. Warmup, `perf_counter_ns()` and bootstrap confidence intervals are retained.
- Components timed through public functions; p50, p95, p99 and a bootstrap interval; warmup 200 calls and 30 repetitions as in CBD-v1 (PROPOSED there, not ruled).

### 8.3 Cost metrics

Retained from CBD-v1 (PROPOSED there): Ed25519 verifications per authorization as primary and artifact bytes as co-primary; "enforcement cost", never "propagation cost". Added: ingestion cost per refresh (one artifact signature, K statement verifications, and the node verifications inside each statement's lineage) on the refresh axis.

### 8.4 TTL baseline (ruling relayed, with consequences PROPOSED)

Chain-minimum TTL is the primary baseline; T-active is the primary renewal model; T-full the upper-bound model; TTL values 30 s, 1 min, 5 min, 15 min, 1 h; `L = R` for matched worst-case exposure; seeded exposure-phase sweeps. The earlier leaf-only expiry behavior is documented once as a historical vulnerability (4.4) and is not used as the baseline.

**Structural re-issuance cost (experimental question, not an established result).** The node id is `SHA-256` of the canonical body, and the body contains `expires_at` and `parent_node_id` (VERIFIED, `nodes.py`). Renewing a node changes its body and so its id. Each child body contains `parent_node_id`, so each child's id changes in turn, down the subtree: **renewal cascades through the subtree**. Its magnitude (re-signatures as a function of depth, fanout and the renewed share) is to be measured; T-active and T-full are two bounds on it.

**OPEN (not ruled):** revocation statements target a `node_id`; a re-issued node has a new id, so a statement naming the old id does not match it. How the pull design treats renewal is not defined in the text I can read.

**Consequence of Revision C (PROPOSED):** once implemented, the frozen verifier itself enforces chain-minimum expiry. The TTL-only baseline uses the **explicit no-status mode** of 5.4 (never reached by omitting the artifact).

### 8.5 Interaction of A, B, C with the benchmark API (PROPOSED)

A: the harness must build signed artifacts (artifact key in the harness; statement serializer), and `artifact_bytes` is then measured from the real encoding instead of a harness definition. B: enables the steady-state path; without A and B only the worst case is possible. C: adds an `O(depth)` comparison per authorization, reported in the residual. The CBD-v1 correctness gates stay, and the 7.2 tests for A, B, C must pass before any timing is accepted.

## 9. Result schema changes

ruling relayed: retain the CBD-v1 JSONL schema and the layout `artifacts/controlled/<experiment_id>/{metadata.json, raw/results.jsonl, summaries/summary.json, reports/}`. Add an exposure-phase value to every relevant result row (the requirement is relayed; field names are PROPOSED):

- `exposure.phase_s` (or `phase_fraction`), plus the existing `seed.exposure_schedule`;
- `measurement_path`: `per_request`, `per_refresh`, `worst_case_fresh_version`, `cold_start`;
- `api_option`: `P-1` or `P-2`; `gc`: `enabled` or `disabled`;
- `topology.cell_kind`: `grid` or `depth_spur`; `revocation.K`; `revocation.decoy_policy` (the recorded target-selection policy, 8.1);
- per-call latency vectors stored in raw rows or an adjacent raw file; the summary records any batched cell;
- `schema_version` 2.

ruling relayed: commit metadata, raw results and summaries; use Git LFS if raw artifacts become large. This document is committed with the final DR-1 commit (the `docs` ignore rule is removed).

## 10. Migration and compatibility

- **`StatusArtifact` constructor.** Tests build it with keywords: seven call sites in `tests/test_leaf_status_redirect.py` (`test_revoked_intermediary_denies_whole_subtree`, `test_status_artifact_cannot_be_bypassed_with_wrong_uri`, `test_status_artifact_rollback_denied` (two), `test_status_artifact_rollback_persists_across_restart` (two), `test_stale_status_artifact_denied`) and `status._demo`. A required signature breaks them; they must be migrated, not shimmed, since an unsigned default would defeat Revision A.
- **Node-body changes (F).** Audience array (D15) and the `delegation_rights` map (D16) change node bodies, so every fixture node id and every signature over a body changes. Tagging (D14) changes wire bytes only; node ids and body signatures are unaffected. This is why F precedes A.
- **`revocation_trust_anchor` placeholders.** `b"\x01" * 32` and `b"\xff" * 32` appear in five test modules (`test_cbor_canonical.py`, `test_cose_roundtrip.py`, `test_leaf_status_redirect.py`, `test_revocation_correctness.py`, `test_root_binding.py`). Placeholders are acceptable where no artifact is ingested; where one is, the field must hold a serialized COSE_Key (Option K, 5.1.5).
- **High-water store.** Existing files are `{uri: int}`. Any new reader must still load them (PROPOSED). Handling of a digest-less entry that meets an equal version is an open sub-question (5.2.4).
- **Exceptions.** Keep the existing raised types so `pytest.raises` sites keep working; new failures SHOULD subclass the closest existing type.
- **`authorize` signature.** Proposed changes are additive (P-2) or internal (P-1); positional order is unchanged.
- **Intentional visible behavior changes:** equal-version artifacts accepted; unsigned artifacts rejected; any expired node rejected; failure order changes (expiry before status), so an input failing with `StaleStatusArtifact` and also having an expired leaf will raise `CredentialExpired`. Revision A also restores the Spec §13 order for audience: `authorize` checks the audience after root binding and before attenuation and status (`docs/decisions/DR-0003.md` section 5), so an audience mismatch is reported before any status failure and leaves the high-water mark untouched.
- **`status._demo()`** asserts the old behavior and is migrated together with Revision B (ruling 22).
- **Wire compatibility.** No wire format for statements or artifacts exists, so nothing deployed needs compatibility. Node wire bytes are unchanged unless 5.1.4 option (i) is chosen.
- **Evidence.** No measurement trace depends on the protocol code; `artifacts/` and `experiments/` need no migration.

## 11. Risks and unresolved questions

Still open (implementation questions, **not** approved decisions; rulings 7, 10, 13 and 14 are now recorded in full):

1. The name of the recognized `delegation_rights` key (D16): not supplied by the supervisor and not invented.
2. The exact name and shape of the explicit TTL-only no-status opt-in (5.4); the reason-code names; the alert log field set and counter name (5.6).
3. The `schema_version` value and the artifact AAD byte string (5.1.3, 5.1.4).
4. Artifact key rotation and compromise recovery (5.1.5); who holds the dedicated key beyond "not the distribution service" (5.1.6).
5. Handling of a digest-less legacy store entry on an equal version (5.2.4).
6. The decoy forest shape, and the handling of depth-1 targets in the 50/50 signer mix (8.1).
7. Renewal and revocation (8.4): a re-issued node has a new id, so a statement naming the old id does not match.
8. Provenance: the Design approval letter is not in the repository; the Spec signature is not independently verified; the author of DR-0001's decision is unknown.

**Known limitations of the Revision A implementation (recorded, not hidden; 2026-11-15).**

- **`AcceptedStatus` is verifier-internal.** It is a plain frozen dataclass with no unforgeable proof of authentication. `authorize` trusts any instance it is handed, so one must only come from `ingest_status_artifact` inside the verifier process. The threat model assumes the attacker is on the distribution path, not inside the verifier (Spec §2, P5).
- **The high-water-mark store is non-atomic and unlocked.** It is a JSON file written with `write_text` (no temporary file and rename, no fsync), and load, compare and save are not locked. Concurrent verifier processes sharing one store can race; a torn write leaves a corrupt file that fails closed (S3). Atomic, durable writes remain PROPOSED hardening under D9.
- **The last authenticated artifact is caller-supplied.** Bounded staleness and fail-open fallback use `last_accepted_status`, which the library does not persist; after a restart bounded staleness degrades to fail-closed.
- **No size or count limits** on the statements in an artifact.

Risks: B before A would weaken the protocol (5.2.7), so the sequence forbids it; F changes every fixture node id and must be done first; P-2 and statement serialization add trusted code in a frozen module; at `K=1000` and depth 20 artifact size and ingestion cost are large (no number exists); a missing-file high-water store is indistinguishable from a first run (S3); fail-closed `None` handling (S1) means `test_valid_chain_authorizes` must be migrated in the implementation task; single machine, no real network, so absolute numbers will not transfer.

## 12. Implementation acceptance criteria (for a later, authorized implementation)

DR-1 is satisfied only when:

1. The supervisor has signed section 13 (the signature block is blank in this file), and every OPEN item in section 11 that a phase depends on is answered or deferred in writing before that phase starts.
2. Tests are written first, per the approved conformance plan (7.2), and pass for the approved parts of F, A, C, audience attenuation and B; all 61 existing tests still pass after the planned fixture migration; no test is weakened.
3. No path advances the high-water mark with an unauthenticated artifact; the store file is byte-identical after any rejected artifact.
4. Lower version rejected; equal accepted idempotently after authentication and freshness; equal with a different digest rejected and alerted; higher authenticated then persisted before the freshness check; freshness evaluated on every authorization.
5. Any expired node in the lineage denies the whole lineage; the test 20 fixture uses distinct `expires_at` per node.
6. The 21-row matrix is re-evaluated after implementation. Row 6 is no longer missing. Row 11 is not claimed as covered unless 11a (network outage) has a defined, implemented and tested behavior; closing 11b alone does not count.
7. **Revision A lands before Revision B; F lands before A.** The implementation order is F, A, C, audience attenuation, B.
8. A diff of `src/lineage_revocation/` maps each change to a section of this document.
9. A Spec reissue lists the changed clauses, including the fail-closed supersession of the Spec §12 default.
10. Canonical encoding is validated by property-based tests; if it fails, the work stops and is escalated to the supervisor.
11. Benchmark work starts only after items 1 to 9 and a separate go-ahead; its first deliverable is topology generation, validation and the correctness oracle, then timing and cost.

## 13. Approval record and sign-off

This table records what the supervisor approved, as relayed in the task statements of 2026-11-12. It matches the register in 0.2 one for one. The supervisor's response column carries the relay, **not a signature**. Rulings 7, 10, 13 and 14 were relayed in full and are recorded as such.

| # | decision | recorded ruling | supervisor response (relayed) | notes |
|---|---|---|---|---|
| 1 | `schema_version` required; signed canonical artifact (5.1.3) | accept | Approved (ruling relayed) | value denoting the format fixed test-first |
| 2 | Root-bound anchor representation (5.1.5) | Option K, serialized COSE_Key | Approved: Option K (ruling relayed) | fixtures need a real value |
| 3 | Artifact signing key (5.1.6) | dedicated key, separate from delegation and statement keys | Approved (ruling relayed) | holder beyond "not the distribution service" not supplied |
| 4 | Domain separation (5.1.4) | artifact-only external AAD | Approved (ruling relayed) | AAD bytes fixed test-first |
| 5 | Equal-version idempotency (5.2) | accept after authentication and freshness | Approved (ruling relayed) |  |
| 6 | Equal-version equivocation (5.2.4) | SHA-256 digest, reject and alert | Approved (ruling relayed) | legacy-entry handling open |
| 7 | Unavailable-status policy (5.4) | fail-closed default; `None` routes to the policy; explicit no-status opt-in, never by omission; one policy function with distinct reason codes (S2, S4, S5), mandatory alert on S5; S3 fails closed, missing file is first run; bounded-staleness over the last authenticated artifact (S6) as the alternative and a benchmark arm; fail-open experimental only | Approved (ruling relayed in full) | supersedes the Spec §12 default; opt-in name fixed test-first |
| 8 | Persistence ordering (5.2.5) | after authentication, before freshness | Approved (ruling relayed) |  |
| 9 | API design (6.2) | P-2 with `status_artifact=` compatibility | Approved (ruling relayed) |  |
| 10 | Per-node expiry (5.3) | `now < expires_at` for every node; no verification-time nesting; no `issued_at` check this revision; no issuance-time refusal; optional non-normative warning in `create_child_node`; node id in the error via a compatible subclass | Approved (ruling relayed in full) | |
| 11 | K-axis cells (8.1) | (2,2), (5,4), (20,1) | Approved (ruling relayed) |  |
| 12 | K-axis construction (8.1) | decoy forest under the same root | Approved (ruling relayed) | shape and depth-1 signer handling fixed test-first |
| 13 | Measurement conditions (8.2) | GC-disabled steady state primary; cold-start and GC-enabled separate labelled conditions, never mixed | Approved (ruling relayed in full) | |
| 14 | Conformance plan and test 20 fixture (7) | approved 7.2 test list preserved; 11a and 11b distinct; test 20 uses distinct `expires_at` per node | Approved (ruling relayed in full) | |
| 15 | Evidence tasks (Appendix A) | four tasks with their conditions | Approved as relayed | each paid run needs its go-ahead |
| 16 | Audience attenuation (5.5) | child subset of parent; leaf membership | Approved (ruling relayed) |  |
| 17 | Staleness boundary (5.2.5) | `now >= min(valid_until, issued_at + max_staleness)` | Approved (ruling relayed) | code already matches |
| 18 | Invalid-statement alert (5.6) | structured log plus monotonic counter | Approved (ruling relayed) | field set and counter name open |
| 19 | Revoked revokers (5.7) | statements stay valid within scope | Approved (ruling relayed) | code already behaves so |
| 20 | P1 to P4 mapping (4.3) | from Design §13 | Approved (ruling relayed) |  |
| 21 | Frozen documents restored (`docs/frozen/`) | byte-for-byte, hashes recorded | Done | Spec identity confirmed by the supervisor; no signature verified |
| 22 | `status._demo()` and DR-0001 | migrate with B; decision record | Approved (ruling relayed); record created | `docs/decisions/DR-0001.md` |
| 23 | Canonical CBOR tests (5.1.7) | property-based; escalate on failure | Approved (ruling relayed) |  |
| D14 | COSE tagging | tagged, tag wraps the envelope, strict tagged-only parser | Approved (ruling relayed) | no protected-header requirement added |
| D15 | Audience arrays | arrays, subset, membership | Approved (ruling relayed) |  |
| D16 | Delegation rights | `delegation_rights` map; single recognized key carries the boolean; reject unknown keys | Approved (ruling relayed) | key name not supplied, not invented |
| D17 | Statement id and wire form | `revocation_id` = SHA-256 of the canonical unsigned statement body; node-shaped envelope; Revision A | Approved (ruling relayed) | self-exclusion follows from the definition |
| D18 | Artifact signature provenance | restores a frozen requirement | Approved (ruling relayed) |  |
| D19 | HTTP API | deferred, non-blocking | Approved (ruling relayed) |  |

Signed off by: ______________________  Date: ______________  (blank: no signature is recorded in this file)

Until implementation is authorized under `docs/design-revision-1-implementation-plan.md`, `src/lineage_revocation/` MUST NOT be modified. Implementation starts with F (spec-shape conformance), tests first.

## Appendix A. Standing evidence items (separate from the protocol revision)

Counts come from `scripts/count_traces.py` (run 2026-11-12); datasets are never pooled; labels are not reinterpreted.

- **Groq:** 34 raw traces and 5 failure records, kept separate; the per-trace model is not recorded in the files (model provenance is unverified for most traces).
- **Haiku:** 12 raw traces (6 `chained_2`, 6 `forced_multi_lookup`), 0 failure records.
- **Haiku `chained_2`:** 5 of 6 traces are topology-scorable; trace 02 is not.
- **Evidence categories stay separate:** Groq workload traces (prompt-dependent delegation; Groq `manager_*` prompts never audited for natural versus elicited delegation); Haiku `chained_2` (**elicited** by topology: the manager's only agent is `mid_agent`); Haiku `forced_multi_lookup` (**elicited** by prompt wording); controlled benchmark cells (**projected**, or real-anchored (elicited)). Nothing is labelled natural.
- **Sequential breadth is not genuine parallel fanout.** `CodeAgent` executes sequentially; no real trace shows same-step parallel delegation on any provider; F-par is gated and unexecuted.

| item | status |
|---|---|
| `chained_2` trace 02 | **instrumentation issue, unresolved.** `docs/chained2-trace02-investigation.md` gives a best-supported but unconfirmed explanation (a timeout-driven re-invocation of `mid_agent`; smolagents resets memory on each run and the collector serializes once, so the first invocation is not recorded). Confirmation needs per-invocation capture and a rerun |
| Haiku `chained_2` traces 00 to 03 | **require stall annotations** so their durations are excluded from duration statistics. Not yet written (`experiments/traces/stall_annotations.json` holds only two Groq traces). Observed in `scripts/chained2_timeline.py`: trace 02 about 1,672 s and trace 03 about 10,134 s |
| `manager_multi_specialist` indices 04 and 05 (Groq) | **one bounded retry window** using the same Groq configuration. If attempts fail again, **freeze the cell at 4/6** and preserve the failure evidence. Note: `experiments/runners/collect.py` now names `claude-haiku-5-5` (commit `375b5fc`), so the Groq endpoint and model must be restored first, and which Groq `model_id` counts as "the same" is **OPEN** because traces do not record it. Paid run; needs an explicit go-ahead |
| Haiku same-step multi-tool-call smoke test | **bounded smoke test**: a ToolCallingAgent manager with two managed agents; success only if one manager step contains two registered-agent calls and both complete. The probe and smoke runners already name Haiku. Not run. Paid run; needs an explicit go-ahead |
