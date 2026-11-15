from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum

from cbor2 import CBORTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .alerts import emit_alert
from .canonical import COSE_SIGN1_TAG, CanonicalEncodingError, decode_strict, encode_canonical
from .keys import COSEKey
from .lineage import LineageVerificationError, verify_lineage
from .nodes import Node, NodeFormatError, _protected_header_bytes, compute_node_id, sign_payload, verify_payload


class StatementFormatError(ValueError):
    """A revocation statement is malformed on the wire (an artifact-integrity defect).

    `defect` names the class: malformed_wire, signature_malformed, revocation_id_missing or
    revocation_id_mismatch."""

    def __init__(self, message: str, defect: str = "malformed_wire"):
        super().__init__(message)
        self.defect = defect


STATEMENT_VERSION = 1  # frozen Spec section 8: statement_version rule is "1"
ED25519_SIGNATURE_LEN = 64  # the pinned algorithm fixes the length, so a length defect needs no key to detect


class StatementReason(Enum):
    """Per-statement SEMANTIC failures (Spec section 11): the statement is well-formed on the wire but
    fails authorization or signature verification. Disjoint from artifact-integrity reasons."""

    TARGET_ID_MISMATCH = "target_id_mismatch"
    TARGET_LINEAGE_MISMATCH = "target_lineage_mismatch"
    LINEAGE_INVALID = "lineage_invalid"
    REVOKER_UNAUTHORIZED = "revoker_unauthorized"
    SIGNATURE_INVALID = "signature_invalid"


_REQUIRED_BODY_FIELDS = {
    "statement_version", "target_node_id", "target_node", "target_lineage", "revoker",
    "revoker_scope_proof", "effective_at", "issued_at",
}
_BODY_FIELDS = _REQUIRED_BODY_FIELDS | {"reason_code"}  # reason_code is optional (frozen Spec section 8)


@dataclass(frozen=True)
class RevocationStatement:
    statement_version: int
    target_node_id: bytes
    target_node: Node
    target_lineage: list[Node]
    revoker: bytes  # claimed revoker's node_id; only trusted once matched against target_lineage below
    revoker_scope_proof: bytes
    effective_at: int
    issued_at: int
    reason_code: str | None  # optional operational reason; never an authorization input (Spec section 8)
    signature: bytes

    def _unsigned_cbor_dict(self) -> dict:
        # The unsigned statement body. It excludes revocation_id (D17): the id is derived from it.
        body = {
            "statement_version": self.statement_version,
            "target_node_id": self.target_node_id,
            "target_node": self.target_node.to_cose_sign1_bytes(),
            "target_lineage": [n.to_cose_sign1_bytes() for n in self.target_lineage],
            "revoker": self.revoker,
            "revoker_scope_proof": self.revoker_scope_proof,
            "effective_at": self.effective_at,
            "issued_at": self.issued_at,
        }
        if self.reason_code is not None:  # absent, never null, when omitted
            body["reason_code"] = self.reason_code
        return body

    def canonical_bytes(self) -> bytes:
        return encode_canonical(self._unsigned_cbor_dict())

    @property
    def revocation_id(self) -> bytes:
        """D17: SHA-256 over the canonical unsigned statement body, excluding the id itself."""
        return hashlib.sha256(self.canonical_bytes()).digest()

    def to_cose_sign1_bytes(self) -> bytes:
        """Node-shaped tagged COSE_Sign1 envelope; the signature covers canonical_bytes().

        The unprotected header carries `revocation_id` (frozen Spec section 8) as an unsigned reference
        only. Verifiers recompute the id from the body and never trust this value (DR-0003)."""
        return encode_canonical(CBORTag(
            COSE_SIGN1_TAG,
            [_protected_header_bytes(), {"revocation_id": self.revocation_id}, self.canonical_bytes(), self.signature],
        ))

    @classmethod
    def from_cose_sign1_bytes(cls, data: bytes) -> "RevocationStatement":
        try:
            envelope = decode_strict(data)
            if not isinstance(envelope, CBORTag) or envelope.tag != COSE_SIGN1_TAG:
                raise StatementFormatError("statement envelope must carry CBOR tag 18")
            items = envelope.value
            # decode_strict already refuses a tag-18 envelope that is not a four-element array, so a statement
            # whose signature member is absent altogether (three elements) is rejected there as malformed_wire.
            if not isinstance(items, (list, tuple)) or len(items) != 4:
                raise StatementFormatError("tagged COSE_Sign1 must wrap a four-element array")
            protected, unprotected, payload, signature = items
            # Dividing rule: detectable without consulting a key -> wire-malformed. The signature member's
            # presence, type and (pinned-algorithm) length need no key; whether it VERIFIES does (semantic).
            if type(signature) is not bytes or len(signature) != ED25519_SIGNATURE_LEN:
                raise StatementFormatError(
                    f"statement signature must be a {ED25519_SIGNATURE_LEN}-byte string", "signature_malformed")
            if protected != _protected_header_bytes():
                raise StatementFormatError("unsupported statement protected header")
            if isinstance(unprotected, Mapping) and not unprotected:
                raise StatementFormatError("statement has no revocation_id", "revocation_id_missing")
            if not isinstance(unprotected, Mapping) or set(unprotected) != {"revocation_id"} \
                    or type(unprotected["revocation_id"]) is not bytes:
                raise StatementFormatError("statement unprotected header must be exactly {revocation_id: bytes}")
            if type(payload) is not bytes:
                raise StatementFormatError("statement payload must be a byte string")
            body = decode_strict(payload)
            if not isinstance(body, Mapping) or not (_REQUIRED_BODY_FIELDS <= set(body) <= _BODY_FIELDS):
                raise StatementFormatError("statement body fields are not the specified set")
            ints = ("statement_version", "effective_at", "issued_at")
            if any(type(body[k]) is not int for k in ints):
                raise StatementFormatError("statement integer fields must be integers")
            if body["statement_version"] != STATEMENT_VERSION:  # unsupported version: wire-malformed, never effective
                raise StatementFormatError(f"unsupported statement_version {body['statement_version']!r}")
            if "reason_code" in body and type(body["reason_code"]) is not str:
                raise StatementFormatError("reason_code, when present, must be text")
            if any(type(body[k]) is not bytes for k in ("target_node_id", "target_node", "revoker", "revoker_scope_proof")):
                raise StatementFormatError("statement byte fields must be byte strings")
            lineage = body["target_lineage"]
            if not isinstance(lineage, list) or any(type(x) is not bytes for x in lineage):
                raise StatementFormatError("target_lineage must be an array of byte strings")
            statement = cls(
                statement_version=body["statement_version"],
                target_node_id=body["target_node_id"],
                target_node=Node.from_cose_sign1_bytes(body["target_node"]),
                target_lineage=[Node.from_cose_sign1_bytes(x) for x in lineage],
                revoker=body["revoker"],
                revoker_scope_proof=body["revoker_scope_proof"],
                effective_at=body["effective_at"],
                issued_at=body["issued_at"],
                reason_code=body.get("reason_code"),
                signature=signature,
            )
            # Exact reconstruction: the received payload must equal the canonical encoding of the parsed
            # statement. This also covers the node envelopes embedded in the statement, which the strict
            # decoder sees only as opaque byte strings. Anything else is wire-malformed.
            if statement.canonical_bytes() != payload:
                raise StatementFormatError("statement payload is not the exact canonical encoding of its content")
            if unprotected["revocation_id"] != statement.revocation_id:
                raise StatementFormatError(
                    "stated revocation_id does not equal SHA-256 of the unsigned body", "revocation_id_mismatch")
            return statement
        except (CanonicalEncodingError, NodeFormatError, ValueError, TypeError) as exc:
            if isinstance(exc, StatementFormatError):
                raise
            raise StatementFormatError(f"malformed revocation statement: {exc}") from exc


def create_revocation_statement(
    revoker_signing_key: Ed25519PrivateKey,
    *,
    target_node: Node,
    target_lineage: list[Node],
    revoker_node_id: bytes,
    revoker_scope_proof: bytes,
    effective_at: int,
    issued_at: int,
    reason_code: str | None = None,
    statement_version: int = 1,
) -> RevocationStatement:
    unsigned = RevocationStatement(
        statement_version=statement_version,
        target_node_id=target_node.node_id,
        target_node=target_node,
        target_lineage=target_lineage,
        revoker=revoker_node_id,
        revoker_scope_proof=revoker_scope_proof,
        effective_at=effective_at,
        issued_at=issued_at,
        reason_code=reason_code,
        signature=b"",
    )
    signature = sign_payload(unsigned.canonical_bytes(), revoker_signing_key)
    return replace(unsigned, signature=signature)


def _find_parent(target_node: Node, target_lineage: list[Node]) -> Node | None:
    for node in target_lineage:
        if node.node_id == target_node.body.parent_node_id:
            return node
    return None


def check_revocation_statement(statement: RevocationStatement, root_trust_anchor: COSEKey) -> StatementReason | None:
    """Semantic verification (Spec sections 9 and 11). Returns None when valid, else the failure reason.
    Never raises, so a malformed or malicious statement can only be treated as absent by a caller, never
    accidentally propagate into a deny. (Unusable key material in a lineage, such as a subject key that is
    not 32 bytes, is a failed verification: `verify_payload` returns False.)"""
    if compute_node_id(statement.target_node.body) != statement.target_node_id:
        return StatementReason.TARGET_ID_MISMATCH
    if not statement.target_lineage or statement.target_lineage[-1].node_id != statement.target_node_id:
        return StatementReason.TARGET_LINEAGE_MISMATCH

    try:
        verify_lineage(statement.target_lineage, root_trust_anchor)
    except LineageVerificationError:
        return StatementReason.LINEAGE_INVALID

    root = statement.target_lineage[0]
    if statement.revoker == root.node_id:
        verifier_key = root_trust_anchor
    else:
        parent = _find_parent(statement.target_node, statement.target_lineage)
        if parent is None or statement.revoker != parent.node_id:
            return StatementReason.REVOKER_UNAUTHORIZED
        verifier_key = parent.body.subject

    if not verify_payload(statement.canonical_bytes(), statement.signature, verifier_key):
        return StatementReason.SIGNATURE_INVALID
    return None


def verify_revocation_statement(statement: RevocationStatement, root_trust_anchor: COSEKey) -> bool:
    return check_revocation_statement(statement, root_trust_anchor) is None


def alert_invalid_statement(statement: RevocationStatement, reason: StatementReason) -> None:
    """Semantic per-statement failure alert (frozen Spec section 11): the statement is ignored."""
    emit_alert(
        "invalid_revocation_statement", reason_code=reason.name,
        revocation_id=statement.revocation_id, target_node_id=statement.target_node_id,
    )


def is_target_revoked(
    target_node_id: bytes,
    statements: list[RevocationStatement],
    root_trust_anchor: COSEKey,
    *,
    now: int,
) -> bool:
    revoked = False
    for statement in statements:
        if statement.target_node_id != target_node_id:
            continue
        reason = check_revocation_statement(statement, root_trust_anchor)
        if reason is not None:
            alert_invalid_statement(statement, reason)
            continue
        if statement.effective_at <= now:
            revoked = True
    return revoked
