from __future__ import annotations

import logging
from dataclasses import dataclass, replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import encode_canonical
from .keys import COSEKey
from .lineage import LineageVerificationError, verify_lineage
from .nodes import Node, compute_node_id, sign_payload, verify_payload

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RevocationStatement:
    statement_version: int
    revocation_id: bytes
    target_node_id: bytes
    target_node: Node
    target_lineage: list[Node]
    revoker: bytes  # claimed revoker's node_id; only trusted once matched against target_lineage below
    revoker_scope_proof: bytes
    effective_at: int
    issued_at: int
    reason_code: str
    signature: bytes

    def _unsigned_cbor_dict(self) -> dict:
        return {
            "statement_version": self.statement_version,
            "revocation_id": self.revocation_id,
            "target_node_id": self.target_node_id,
            "target_node": self.target_node.to_cose_sign1_bytes(),
            "target_lineage": [n.to_cose_sign1_bytes() for n in self.target_lineage],
            "revoker": self.revoker,
            "revoker_scope_proof": self.revoker_scope_proof,
            "effective_at": self.effective_at,
            "issued_at": self.issued_at,
            "reason_code": self.reason_code,
        }

    def canonical_bytes(self) -> bytes:
        return encode_canonical(self._unsigned_cbor_dict())


def create_revocation_statement(
    revoker_signing_key: Ed25519PrivateKey,
    *,
    revocation_id: bytes,
    target_node: Node,
    target_lineage: list[Node],
    revoker_node_id: bytes,
    revoker_scope_proof: bytes,
    effective_at: int,
    issued_at: int,
    reason_code: str,
    statement_version: int = 1,
) -> RevocationStatement:
    unsigned = RevocationStatement(
        statement_version=statement_version,
        revocation_id=revocation_id,
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


def verify_revocation_statement(statement: RevocationStatement, root_trust_anchor: COSEKey) -> bool:
    """Pure boolean check: never raises, so a malformed/malicious statement can only
    ever be treated as absent by a caller, never accidentally propagate into a deny."""
    if compute_node_id(statement.target_node.body) != statement.target_node_id:
        return False
    if not statement.target_lineage or statement.target_lineage[-1].node_id != statement.target_node_id:
        return False

    try:
        verify_lineage(statement.target_lineage, root_trust_anchor)
    except LineageVerificationError:
        return False

    root = statement.target_lineage[0]
    if statement.revoker == root.node_id:
        verifier_key = root_trust_anchor
    else:
        parent = _find_parent(statement.target_node, statement.target_lineage)
        if parent is None or statement.revoker != parent.node_id:
            return False
        verifier_key = parent.body.subject

    return verify_payload(statement.canonical_bytes(), statement.signature, verifier_key)


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
        if not verify_revocation_statement(statement, root_trust_anchor):
            _logger.warning(
                "invalid revocation statement %r for target %r ignored",
                statement.revocation_id, target_node_id,
            )
            continue
        if statement.effective_at <= now:
            revoked = True
    return revoked
