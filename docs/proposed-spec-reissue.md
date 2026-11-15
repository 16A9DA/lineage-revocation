# Proposed Spec reissue text (Revision A and D20)

**Status: PROPOSED wording for the next Implementation Spec reissue. It is not part of the frozen signed Spec v1.0.3 and is not signed. The frozen Spec and Design Document are unchanged. Every item needs the supervisor's approval before it enters a reissue.** Section numbers refer to Spec v1.0.3. Provenance of each item: `docs/design-revision-1.md` and `docs/decisions/DR-0002.md`, `DR-0003.md`.

## §4 Encoding (D20)

All signed or hashed protocol objects MUST use RFC 8949 section 4.2.1 core deterministic encoding: definite lengths only; shortest-form integer arguments; map keys sorted by the bytewise lexicographic order of their complete encodings. Floating-point values, indefinite-length items and CBOR tags other than tag 18 (COSE_Sign1) MUST NOT appear. Containers MUST NOT nest deeper than 32 levels [PROPOSED limit; protocol objects nest about five levels]; a verifier MUST treat deeper input as a malformed object, never as an unhandled error. A verifier MUST reject any received protocol object whose bytes differ from the deterministic encoding of its decoded value (decode, re-encode, compare byte for byte).

## §5 COSE profile

Node, statement and artifact envelopes are tagged COSE_Sign1 (tag 18). Node and statement signatures use an empty external AAD. The artifact signature MUST use the external AAD `lineage-revocation:status-artifact:v1`, so that a node or statement signature cannot verify as an artifact signature.

## §3 and §7 Trust anchor and artifact key

`revocation_trust_anchor` is the canonical CBOR encoding of a COSE_Key (OKP, Ed25519, with exactly the members `kty`, `crv` and `x`). A verifier MUST derive the artifact verification key only from the authenticated root node. The artifact-signing key MUST be dedicated: distinct from the root delegation key, every statement-signing key and every delegation (subject) key, and never held by the status distribution service or by any agent. Key rotation and compromise recovery are out of scope. A verifier SHOULD compare the artifact key, by canonical encoded key bytes, with the keys of the presented lineage and statements, and MUST reject and alert on a match; this is detection, because the requirement is enforced at key generation.

## §8 Revocation statement

`revocation_id` is SHA-256 over the canonical encoding of the unsigned statement body, excluding the `revocation_id` field. The statement is a tagged COSE_Sign1 whose signature covers that body. The `revocation_id` field of §8 is carried as a required reference value in the unprotected header of the statement's COSE_Sign1 envelope, under the text label `revocation_id`, with a byte-string value (placement approved by the supervisor). The wire revocation_id is a reference value and never load-bearing; were it load-bearing, unprotected placement would violate the frozen §5 rule.

`statement_version` MUST be 1, as §8 already states; a verifier MUST treat any other value, a missing value or a non-integer value as a malformed statement (clarification of §8; no change of meaning).

`reason_code` remains optional, as in §8: when absent it is omitted from the body (never encoded as null) and when present it is a text string. A statement that omits it is well-formed. [Pending supervisor confirmation.] A verifier MUST also require the received statement payload, including every embedded node envelope, to be byte-for-byte the deterministic encoding of its content.

A verifier MUST recompute the identifier as SHA-256 over the canonical unsigned statement body, MUST require the wire value to be present, MUST require it to equal the recomputed value, and MUST NOT use the wire value as an authorization or identity input. Absence or mismatch is an artifact-integrity defect (§11).

## §10 Ingestion contract (additions)

| Ingestion check | Action |
|---|---|
| `revocation_id` presence and equality | Reject a statement without a `revocation_id`, or whose `revocation_id` differs from the recomputed SHA-256 identifier. |
| Duplicate `revocation_id` | Deduplicate identical statements deterministically. Reject conflicting duplicates (same recomputed identifier, different unsigned bodies); a conflicting duplicate in a signed artifact is an artifact-integrity failure. |

**Dividing principle.** The verifier escalates to artifact-level rejection exactly those defects that the ingestion contract obliges the service to reject and that the verifier can detect without any authorization semantics.

## §11 Verifier handling of invalid statements (replacement text)

Statement defects fall into two categories.

1. **Artifact-integrity defects** (wire-malformed statements): malformed CBOR or invalid wire structure, a payload (including any embedded node envelope) that is not the exact deterministic encoding of its content, missing required fields (`reason_code` is optional), incorrect field types, a missing or wrongly typed signature member, an Ed25519 signature whose length is not 64 octets, a missing or mismatched `revocation_id`, and conflicting duplicates. The verifier MUST reject the entire signed artifact, MUST NOT persist any state from it, MUST emit an artifact-integrity alert with a reason code distinct from every other, and MUST then determine the verdict for the request through the unavailable-status policy of §12. These defects need no authorization semantics to detect. Because only the revocation authority can produce a signed artifact, such a defect is evidence of an authority fault or compromise.
2. **Semantic defects** (a well-formed statement, including a correctly formed 64-octet signature, that fails authorization or signature verification under §9): the verifier MUST treat the statement as absent, log the failure, emit a statement-semantic alert with a reason code distinct from artifact-integrity reasons, and continue with the other statements. It MUST NOT deny the request solely because such a statement targets a node in the chain.

Key material that cannot verify anything (for example a subject key that is not 32 octets) is a failed verification, not an error: a semantic defect inside a statement, a lineage failure in a presented lineage.

Dividing rule for signatures of revocation statements: a defect detectable without consulting a key is wire-malformed; a defect that requires the key is semantic. **Scope:** the supervisor's signature-length ruling concerns revocation statements only. The signature of the artifact's outer envelope is not reclassified by it: a wrong-length outer signature continues to be handled as an artifact signature failure (§12, alert mandatory). The reissue does not extend the statement rule to the outer envelope unless the supervisor rules so.

Identical statements (same unsigned body, including different valid signatures over it) are one revocation and are deduplicated and logged.

## §12 Artifact, freshness and unavailable status (replacement text, summarised)

- The artifact is a signed canonical collection with a required `schema_version`. The verifier authenticates the exact received body bytes under the root-bound anchor before using any field, checks the root status URI after authentication, and persists the high-water mark after authentication and before the freshness check. No persistent mutation occurs before authentication.
- An artifact is stale when `now >= min(valid_until, issued_at + max_staleness)`. Freshness and statement effective times are re-evaluated on every authorization.
- Accepted status is bound to the exact artifact body digest, the root status URI, the root-bound trust context and the authenticated version.
- **Default policy: fail-closed.** This supersedes the "bounded staleness" default of the v1.0.3 table. A missing artifact routes through the unavailable-status policy and never silently skips revocation checking. A TTL-only mode requires an explicit, deliberately named opt-in. Bounded staleness over the last authenticated artifact is the configured alternative for network failure, stale authenticated evidence and artifact-integrity failure. Fail-open is an experimental baseline only.
- **Artifact rejection is invariant across policies; the request verdict is policy-governed.** Under every policy, including fail-open, a rejected artifact MUST NOT have its statements processed or its contents used for authorization, MUST NOT advance the high-water mark or replace the accepted artifact, and MUST NOT cause anything to be persisted. The policy governs only the request: fail-closed denies; bounded staleness uses the last authenticated artifact only while it remains fresh, its revocations continue to apply, and the rejected artifact is never used; fail-open MAY allow the request when no usable authenticated state exists.
- **Fail-open exists only inside an explicitly labelled experimental benchmark arm and MUST NOT be exposed as a production configuration option.** The arm label is a benchmark label and guard against accidental use; it is not a cryptographic or production-enforcement boundary, and a deployment MUST NOT rely on it to keep fail-open out of production (a production build omits the policy). An implementation SHOULD record the arm label and SHOULD report fail-open outcomes with findings that distinguish an allow after ordinary status unavailability from an allow after an artifact-integrity failure.
- An unreadable or corrupt high-water-mark store fails closed under every policy; a missing store file is a first run. An artifact signature failure is handled as unavailable status with a mandatory alert.
