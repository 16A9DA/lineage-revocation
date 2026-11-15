from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cbor2 import CBORTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .alerts import emit_alert
from .canonical import COSE_SIGN1_TAG, CanonicalEncodingError, decode_strict, encode_canonical
from .keys import COSEKey
from .nodes import Node, _protected_header_bytes, sign_payload, verify_payload
from .revocation import (
    RevocationStatement,
    StatementFormatError,
    StatementReason,
    _find_parent,
    alert_invalid_statement,
    check_revocation_statement,
)

_log = logging.getLogger(__name__)

# Artifact-only external AAD (DR-1 5.1.4). Node and statement signatures keep the empty AAD.
ARTIFACT_AAD = b"lineage-revocation:status-artifact:v1"
SCHEMA_VERSION = 1

# Threat-model limit (DR-1 A2): the artifact-signing key is held by the root authority operator,
# never by the status distribution service. Compromise of that key collapses revocation integrity.
# Key rotation and compromise recovery are out of scope for this revision.

_ARTIFACT_FIELDS = {"schema_version", "version", "root_revocation_state_uri", "issued_at", "valid_until", "statements"}


class StatusReason(Enum):
    STATUS_MISSING = "S1"
    STATUS_NETWORK_UNAVAILABLE = "S2"
    STORE_UNREADABLE = "S3"
    ARTIFACT_MALFORMED = "S4"
    ARTIFACT_SIGNATURE_INVALID = "S5"
    ARTIFACT_STALE = "S6"
    ARTIFACT_INTEGRITY = "integrity"  # wire-malformed statement or conflicting duplicate inside an authenticated artifact
    ARTIFACT_KEY_REUSE = "key-reuse"  # artifact key equals a delegation or statement-signing key
    VERSION_ROLLBACK = "rollback"


class StatusPolicy(Enum):
    FAIL_CLOSED = "fail_closed"  # default
    BOUNDED_STALENESS = "bounded_staleness"  # configured alternative for S2 and S6
    TTL_ONLY_NO_STATUS = "ttl_only_no_status"  # explicit opt-in; only for a deliberately absent artifact (S1)
    FAIL_OPEN_EXPERIMENTAL = "fail_open_experimental"  # experimental baseline only


class FailOpenFinding(Enum):
    """Benchmark telemetry for the experimental fail-open arm. Distinct from every StatusReason, so an
    analysis can tell an allow that followed ordinary status unavailability from one that followed an
    artifact-integrity rejection. The value is also the alert kind (and so the counter name)."""

    AFTER_STATUS_UNAVAILABLE = "fail_open_after_status_unavailable"
    AFTER_ARTIFACT_INTEGRITY = "fail_open_after_artifact_integrity"


class StatusFailure(Exception):
    def __init__(self, reason: StatusReason, message: str = ""):
        super().__init__(f"{reason.name}: {message}" if message else reason.name)
        self.reason = reason


class StatusUnavailable(StatusFailure):
    pass


class StaleStatusArtifact(StatusFailure):
    pass


class StatusRollback(StaleStatusArtifact):
    """Lower or equal version than the durable high-water mark (equal-version handling is Revision B)."""


class ArtifactKeyReuse(StatusFailure):
    """The artifact-signing key is not distinct from a delegation or statement-signing key (A2)."""


class UriBindingMismatch(Exception):
    """The artifact or accepted state is not bound to the authenticated root (URI, anchor or root node)."""


@dataclass(frozen=True)
class AcceptedStatus:
    """Authenticated accepted-status state (P-2). Bound to the exact body digest, root URI,
    root-bound trust context (root node and Option K anchor) and version. Freshness is never
    cached here: it is evaluated at every authorization.

    VERIFIER-INTERNAL. Only `ingest_status_artifact` should construct one. The dataclass carries no
    unforgeable proof of authentication: code inside the verifier process that builds one by hand is
    trusted, and `authorize` will use it. The threat model puts the attacker on the status distribution
    path, not inside the verifier (Spec section 2, P5), so an `AcceptedStatus` must never be deserialized
    from, or handed over by, anything outside the verifier process. Known limitation of Revision A."""

    version: int
    root_revocation_state_uri: str
    issued_at: int
    valid_until: int
    statements: tuple[RevocationStatement, ...]  # semantically verified statements only
    body_digest: bytes
    root_node_id: bytes
    trust_anchor: bytes


def build_status_artifact(
    artifact_signing_key: Ed25519PrivateKey,
    *,
    version: int,
    root_revocation_state_uri: str,
    issued_at: int,
    valid_until: int,
    statements: list[RevocationStatement | bytes],
    schema_version: int = SCHEMA_VERSION,
) -> bytes:
    """Wire form: tagged COSE_Sign1 over the canonical artifact body, signed with artifact-only AAD."""
    wires = [s.to_cose_sign1_bytes() if isinstance(s, RevocationStatement) else s for s in statements]
    body = encode_canonical({
        "schema_version": schema_version,
        "version": version,
        "root_revocation_state_uri": root_revocation_state_uri,
        "issued_at": issued_at,
        "valid_until": valid_until,
        "statements": wires,
    })
    signature = sign_payload(body, artifact_signing_key, ARTIFACT_AAD)
    return encode_canonical(CBORTag(COSE_SIGN1_TAG, [_protected_header_bytes(), {}, body, signature]))


def _is_uint(v) -> bool:
    return type(v) is int and v >= 0


def _parse_artifact(wire: bytes) -> tuple[bytes, bytes, dict]:
    """Steps 2 to 4 of DR-1 5.1.7: strict parse, canonical check, structure. No state is touched."""
    try:
        envelope = decode_strict(wire)
        if not isinstance(envelope, CBORTag) or envelope.tag != COSE_SIGN1_TAG:
            raise ValueError("artifact envelope must carry CBOR tag 18")
        protected, unprotected, body_bytes, signature = envelope.value
        if protected != _protected_header_bytes() or unprotected != {}:
            raise ValueError("unsupported protected or unprotected header")
        if type(body_bytes) is not bytes or type(signature) is not bytes:
            raise ValueError("body and signature must be byte strings")
        body = decode_strict(body_bytes)
        if not isinstance(body, dict) or set(body) != _ARTIFACT_FIELDS:
            raise ValueError("artifact body fields are not exactly the specified set")
        if body["schema_version"] != SCHEMA_VERSION or type(body["schema_version"]) is not int:
            raise ValueError("unsupported schema_version")
        if not (_is_uint(body["version"]) and _is_uint(body["issued_at"]) and _is_uint(body["valid_until"])):
            raise ValueError("version, issued_at and valid_until must be non-negative integers")
        if body["valid_until"] < body["issued_at"]:
            raise ValueError("valid_until precedes issued_at")
        if type(body["root_revocation_state_uri"]) is not str:
            raise ValueError("root_revocation_state_uri must be text")
        if not isinstance(body["statements"], list) or any(type(x) is not bytes for x in body["statements"]):
            raise ValueError("statements must be an array of byte strings")
    except (CanonicalEncodingError, ValueError, TypeError) as exc:
        raise StatusUnavailable(StatusReason.ARTIFACT_MALFORMED, str(exc)) from exc
    return body_bytes, signature, body


def check_key_separation(anchor_key: COSEKey, forbidden: dict[str, COSEKey], uri: str) -> None:
    """A2: the artifact-signing key must differ from the root delegation key and every
    statement-signing key, and from every lineage subject key (any agent may be compromised).

    The normative requirement lives at key generation (a dedicated key, never held by the distribution
    service or any agent). This check can only see the keys of the presented chain and statements, so it is
    detection: a match between honestly generated random keys cannot happen, hence an observed match is
    evidence of misconfiguration or attack and is alerted. Raises ArtifactKeyReuse; never policy-excusable."""
    anchor_bytes = anchor_key.to_anchor_bytes()
    for role, key in forbidden.items():
        if key.to_anchor_bytes() == anchor_bytes:  # canonical encoded key bytes, not object identity
            emit_alert("artifact_key_reuse", reason_code=StatusReason.ARTIFACT_KEY_REUSE.name,
                       root_revocation_state_uri=uri, reused_as=role)
            raise ArtifactKeyReuse(StatusReason.ARTIFACT_KEY_REUSE, f"artifact key is also the {role}")


def statement_signing_key(statement: RevocationStatement, root_trust_anchor: COSEKey) -> COSEKey | None:
    """The key a statement claims to be signed by: the root key, or its target's direct issuer's subject key."""
    lineage = statement.target_lineage
    if lineage and statement.revoker == lineage[0].node_id:
        return root_trust_anchor
    parent = _find_parent(statement.target_node, lineage)
    return parent.body.subject if parent is not None else None


def _integrity_failure(uri: str, defect: str, detail: str, **fields) -> StatusUnavailable:
    """Artifact-integrity failure: the whole authenticated artifact is rejected, nothing is persisted,
    and the failure is routed through the unavailable-status policy."""
    emit_alert("artifact_integrity", reason_code=StatusReason.ARTIFACT_INTEGRITY.name,
               root_revocation_state_uri=uri, defect=defect, detail=detail, **fields)
    return StatusUnavailable(StatusReason.ARTIFACT_INTEGRITY, detail)


def _signature_failure(message: str, uri: str) -> StatusUnavailable:
    # D10: a single verifier cannot tell tampering from corruption; the alert carries the signal.
    emit_alert("artifact_signature_invalid", reason_code=StatusReason.ARTIFACT_SIGNATURE_INVALID.name,
               root_revocation_state_uri=uri, detail=message)
    return StatusUnavailable(StatusReason.ARTIFACT_SIGNATURE_INVALID, message)


def load_high_water_mark(store_path: Path, uri: str) -> int | None:
    if not store_path.exists():
        return None  # first run
    try:
        data = json.loads(store_path.read_text())
        if not isinstance(data, dict):
            raise ValueError("store is not a JSON object")
    except (OSError, ValueError) as exc:  # JSONDecodeError is a ValueError
        raise StatusUnavailable(StatusReason.STORE_UNREADABLE, f"cannot load high-water mark store at {store_path}") from exc
    mark = data.get(uri)
    if mark is not None and type(mark) is not int:
        raise StatusUnavailable(StatusReason.STORE_UNREADABLE, f"corrupt high-water mark for {uri!r}")
    return mark


def save_high_water_mark(store_path: Path, uri: str, version: int) -> None:
    # KNOWN LIMITATION (Revision A; DR-1 D9 hardening is PROPOSED, not done): the store is a JSON file written
    # with write_text. The write is not atomic (no temp file and rename, no fsync) and the load-compare-save
    # sequence in ingest_status_artifact is not locked, so concurrent verifier processes sharing one store can
    # race. A torn write leaves a corrupt file, which then fails closed (S3) on the next read.
    try:
        data = json.loads(store_path.read_text()) if store_path.exists() else {}
    except (OSError, json.JSONDecodeError):
        data = {}
    data[uri] = version
    store_path.write_text(json.dumps(data))


def ingest_status_artifact(
    wire: bytes, *, root: Node, root_trust_anchor: COSEKey, store_path: Path | None
) -> AcceptedStatus:
    """DR-1 5.1.7 steps 2 to 10 (+ statement processing). Nothing is persisted before authentication."""
    body_bytes, signature, _unauthenticated = _parse_artifact(wire)
    uri = root.body.root_revocation_state_uri

    try:  # Option K anchor from the authenticated root, never from the artifact or a descendant
        anchor_key = COSEKey.from_anchor_bytes(root.body.revocation_trust_anchor)
        authentic = verify_payload(body_bytes, signature, anchor_key, ARTIFACT_AAD)
    except ValueError as exc:
        raise _signature_failure(f"unusable revocation_trust_anchor or signature: {exc}", uri) from exc
    if not authentic:
        raise _signature_failure("artifact signature does not verify under the root-bound anchor", uri)

    body = decode_strict(body_bytes)  # the exact verified bytes; fields below come only from here
    if body["root_revocation_state_uri"] != uri:  # URI binding, after authentication
        raise UriBindingMismatch(f"artifact URI {body['root_revocation_state_uri']!r} != root URI {uri!r}")

    # Statement set. Dividing principle: the verifier escalates to artifact-level rejection exactly those
    # defects that the ingestion contract obliges the service to reject and that the verifier can detect
    # without any authorization semantics. Wire-malformed statements (including a missing or wrong wire
    # revocation_id) and conflicting duplicates are artifact-integrity failures. Semantic failures are
    # per-statement and handled below. Ids are RECOMPUTED; the wire value is only checked, never trusted.
    groups: dict[bytes, dict[bytes, RevocationStatement]] = {}  # recomputed id -> {wire: statement}
    received: dict[bytes, int] = {}
    for index, stmt_wire in enumerate(body["statements"]):
        try:
            statement = RevocationStatement.from_cose_sign1_bytes(stmt_wire)
        except StatementFormatError as exc:
            raise _integrity_failure(uri, exc.defect, f"statement {index}: {exc}") from exc
        groups.setdefault(statement.revocation_id, {})[stmt_wire] = statement
        received[statement.revocation_id] = received.get(statement.revocation_id, 0) + 1
    for rid, members in groups.items():
        if len({m.canonical_bytes() for m in members.values()}) > 1:
            # Same recomputed id, different unsigned body: a SHA-256 collision or a signing-pipeline fault.
            raise _integrity_failure(uri, "conflicting_duplicate",
                                     f"statements with revocation_id {rid.hex()} have different bodies", revocation_id=rid)
    ordered = {rid: [members[w] for w in sorted(members)] for rid, members in groups.items()}  # deterministic

    forbidden = {"root trust anchor key": root_trust_anchor, "root delegation key": root.body.subject}
    for members in ordered.values():
        signer = statement_signing_key(members[0], root_trust_anchor)
        if signer is not None:
            forbidden[f"statement-signing key of {members[0].revoker.hex()[:16]}"] = signer
    check_key_separation(anchor_key, forbidden, uri)  # before any persistent mutation

    # Semantic verification of every statement is pure, so it runs BEFORE anything is persisted: if it fails to
    # complete for any reason, the high-water mark has not moved. Its alerts are held back and emitted only after
    # the artifact is accepted, so a rejected artifact (for example a rollback) raises no statement alerts.
    verified = []
    deferred: list[tuple[bytes, list[RevocationStatement], list[tuple[RevocationStatement, StatementReason]]]] = []
    for rid, members in ordered.items():
        good = None
        failures = []
        for statement in members:  # different valid signatures over one body are one semantic revocation
            reason = check_revocation_statement(statement, root_trust_anchor)
            if reason is None:
                good = good or statement
            else:
                failures.append((statement, reason))
        deferred.append((rid, members, failures))
        if good is not None:
            verified.append(good)

    if store_path is None:
        raise StatusUnavailable(StatusReason.STORE_UNREADABLE, "no high-water mark store configured")
    highest = load_high_water_mark(store_path, uri)
    if highest is not None and body["version"] <= highest:
        raise StatusRollback(StatusReason.VERSION_ROLLBACK, f"artifact version {body['version']} <= highest seen {highest}")
    save_high_water_mark(store_path, uri, body["version"])  # after authentication, before freshness

    for rid, members, failures in deferred:  # the artifact is accepted: now report
        if received[rid] > 1:  # identical unsigned body: deduplicate deterministically and log
            _log.info("deduplicated %d revocation statements with id %s", received[rid], rid.hex(),
                      extra={"dedup_revocation_id": rid, "dedup_count": received[rid]})
        for statement, reason in failures:  # per-statement semantic failure (Spec section 11): ignore, log, alert
            alert_invalid_statement(statement, reason)
    return AcceptedStatus(
        version=body["version"], root_revocation_state_uri=uri, issued_at=body["issued_at"],
        valid_until=body["valid_until"], statements=tuple(verified),
        body_digest=hashlib.sha256(body_bytes).digest(), root_node_id=root.node_id,
        trust_anchor=root.body.revocation_trust_anchor,
    )


def check_bound(state: AcceptedStatus, root: Node) -> None:
    """P-2: the state is only usable for the root, URI and anchor it was authenticated under."""
    if (
        state.root_node_id != root.node_id
        or state.root_revocation_state_uri != root.body.root_revocation_state_uri
        or state.trust_anchor != root.body.revocation_trust_anchor
    ):
        raise UriBindingMismatch("accepted status is not bound to this authenticated root")


def is_fresh(state: AcceptedStatus, now: int, max_staleness: int) -> bool:
    return now < min(state.valid_until, state.issued_at + max_staleness)  # ruling 17


def check_fresh(state: AcceptedStatus, now: int, max_staleness: int) -> None:
    if not is_fresh(state, now, max_staleness):
        raise StaleStatusArtifact(
            StatusReason.ARTIFACT_STALE,
            f"now {now} >= freshness deadline {min(state.valid_until, state.issued_at + max_staleness)}",
        )


def handle_unavailable_status(
    failure: StatusFailure,
    *,
    policy: StatusPolicy,
    now: int,
    max_staleness: int,
    last_accepted: AcceptedStatus | None = None,
    experimental_arm: str | None = None,
    root_revocation_state_uri: str | None = None,
) -> AcceptedStatus | None:
    """REQUEST VERDICT for a status failure (S1, S2, S4, S5, S6, artifact integrity), by policy.

    This is the only place a policy acts. It never touches the failed artifact: an artifact rejection
    (nothing persisted, high-water mark unmoved, statements unprocessed, contents unused) has already
    happened, identically under every policy, before this function is called. The policy decides only what
    verdict the REQUEST gets, from the last authenticated state:

    - FAIL_CLOSED: deny (raise `failure`).
    - BOUNDED_STALENESS: use the last authenticated artifact only while it is fresh; its revocations keep
      applying; otherwise deny.
    - FAIL_OPEN_EXPERIMENTAL: experimental benchmark arm only, never a production setting. Uses a fresh
      last authenticated state if there is one; if no usable authenticated state exists it allows the
      request without revocation checking (returns None) and records which kind of failure it followed.
    - TTL_ONLY_NO_STATUS: allows only an absent artifact (S1), by explicit opt-in.

    Returns the state to apply, None for "no status checking", or raises `failure`. S3 (unreadable store)
    and key reuse always fail closed. The caller must check_bound() a returned state."""
    reason = failure.reason
    if reason in (StatusReason.STORE_UNREADABLE, StatusReason.ARTIFACT_KEY_REUSE):
        raise failure  # S3 and key reuse always fail closed, whatever the policy
    usable = last_accepted if last_accepted is not None and is_fresh(last_accepted, now, max_staleness) else None
    if policy is StatusPolicy.TTL_ONLY_NO_STATUS and reason is StatusReason.STATUS_MISSING:
        return None
    if policy is StatusPolicy.BOUNDED_STALENESS and usable is not None and reason in (
        StatusReason.STATUS_NETWORK_UNAVAILABLE, StatusReason.ARTIFACT_STALE,
        StatusReason.ARTIFACT_INTEGRITY,  # authority-side defect: same policy as equivocation
    ):
        return usable  # the caller reports the fallback (emit_fallback) once the state is bound to the root
    if policy is StatusPolicy.FAIL_OPEN_EXPERIMENTAL:
        require_experimental_arm(policy, experimental_arm)
        if usable is not None:  # a usable authenticated state exists: known revocations are not discarded
            return usable
        finding = (FailOpenFinding.AFTER_ARTIFACT_INTEGRITY if reason is StatusReason.ARTIFACT_INTEGRITY
                   else FailOpenFinding.AFTER_STATUS_UNAVAILABLE)
        emit_alert(finding.value, finding=finding.value, reason_code=reason.name,
                   experimental_arm=experimental_arm, root_revocation_state_uri=root_revocation_state_uri,
                   authenticated_state_used=False)
        return None
    raise failure


def emit_fallback(policy: StatusPolicy, reason: StatusReason, state: AcceptedStatus, uri: str | None,
                  arm: str | None) -> None:
    """One alert per request that is decided from the last authenticated artifact instead of the one that
    failed. `policy` tells bounded-staleness fallback from fail-open using authenticated state. Emitted only
    after the state is confirmed bound to the root, so it always means "this state was actually used"."""
    emit_alert("status_fallback_last_authenticated", policy=policy.name, reason_code=reason.name,
               experimental_arm=arm, root_revocation_state_uri=uri, authenticated_state_used=True,
               fallback_version=state.version)


def require_experimental_arm(policy: StatusPolicy, experimental_arm: str | None) -> None:
    """FAIL_OPEN_EXPERIMENTAL is an experimental baseline only. It must be selected inside an explicitly
    labelled experimental benchmark arm and must never be a production configuration option.

    The label is a benchmark label and a guard against accidental selection. It is NOT a cryptographic or
    production-enforcement boundary: any caller can pass any string. Keeping fail-open out of production is
    a rule about what a production configuration offers, not something this check enforces."""
    if policy is StatusPolicy.FAIL_OPEN_EXPERIMENTAL and not (isinstance(experimental_arm, str) and experimental_arm.strip()):
        raise ValueError("FAIL_OPEN_EXPERIMENTAL requires an explicit experimental_arm label (experimental benchmark arm only)")


def _demo() -> None:
    # PENDING MIGRATION (Revision B, DR-1 ruling 22). The original self-check used the unsigned
    # StatusArtifact and accept_status_artifact, which Revision A removed. It is not retained here.
    # Original text: `git show 4402f3e:src/lineage_revocation/status.py` (lines 63-81).
    raise NotImplementedError(
        "status._demo() awaits migration to signed artifacts and equal-version handling in Revision B"
    )


if __name__ == "__main__":
    _demo()
