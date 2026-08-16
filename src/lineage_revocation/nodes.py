from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import decode_canonical, encode_canonical
from .keys import COSEKey

COSE_ALG_EDDSA = -8  # RFC 8152 sec8.2 / IANA COSE Algorithms registry
COSE_HEADER_ALG = 1


@dataclass(frozen=True)
class NodeBody:
    version: int
    issuer: str
    subject: COSEKey  # delegatee's COSE public key
    parent_node_id: bytes | None  # None only for the root node
    audience: str
    authority: str
    delegation_rights: list[str]
    root_revocation_state_uri: str
    revocation_trust_anchor: bytes
    issued_at: int
    expires_at: int

    def to_cbor_dict(self) -> dict:
        return {
            "version": self.version,
            "issuer": self.issuer,
            "subject": self.subject.to_cbor_dict(),
            "parent_node_id": self.parent_node_id,
            "audience": self.audience,
            "authority": self.authority,
            "delegation_rights": self.delegation_rights,
            "root_revocation_state_uri": self.root_revocation_state_uri,
            "revocation_trust_anchor": self.revocation_trust_anchor,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_cbor_dict(cls, d: dict) -> "NodeBody":
        return cls(
            version=d["version"],
            issuer=d["issuer"],
            subject=COSEKey.from_cbor_dict(d["subject"]),
            parent_node_id=d["parent_node_id"],
            audience=d["audience"],
            authority=d["authority"],
            delegation_rights=list(d["delegation_rights"]),
            root_revocation_state_uri=d["root_revocation_state_uri"],
            revocation_trust_anchor=d["revocation_trust_anchor"],
            issued_at=d["issued_at"],
            expires_at=d["expires_at"],
        )

    def canonical_bytes(self) -> bytes:
        return encode_canonical(self.to_cbor_dict())


def compute_node_id(body: NodeBody) -> bytes:
    return hashlib.sha256(body.canonical_bytes()).digest()


def _sig_structure(protected_bytes: bytes, payload_bytes: bytes) -> bytes:
    # COSE_Sign1 Sig_structure, RFC 8152 sec4.4. external_aad always empty here.
    return encode_canonical(["Signature1", protected_bytes, b"", payload_bytes])


def _protected_header_bytes() -> bytes:
    return encode_canonical({COSE_HEADER_ALG: COSE_ALG_EDDSA})


@dataclass(frozen=True)
class Node:
    body: NodeBody
    node_id: bytes
    signature: bytes  # raw 64-byte Ed25519 signature over the Sig_structure

    def to_cose_sign1_bytes(self) -> bytes:
        protected = _protected_header_bytes()
        payload = self.body.canonical_bytes()
        return encode_canonical([protected, {}, payload, self.signature])

    @classmethod
    def from_cose_sign1_bytes(cls, data: bytes) -> "Node":
        _protected, _unprotected, payload, signature = decode_canonical(data)
        body = NodeBody.from_cbor_dict(decode_canonical(payload))
        return cls(body=body, node_id=compute_node_id(body), signature=signature)


def sign_node(body: NodeBody, signer_private_key: Ed25519PrivateKey) -> Node:
    payload = body.canonical_bytes()
    to_sign = _sig_structure(_protected_header_bytes(), payload)
    signature = signer_private_key.sign(to_sign)
    return Node(body=body, node_id=compute_node_id(body), signature=signature)


def verify_node_signature(node: Node, verifier_public_key: COSEKey) -> bool:
    to_verify = _sig_structure(_protected_header_bytes(), node.body.canonical_bytes())
    try:
        verifier_public_key.to_cryptography_key().verify(node.signature, to_verify)
        return True
    except InvalidSignature:
        return False


def create_root_node(
    root_signing_key: Ed25519PrivateKey,
    root_public_key: COSEKey,
    *,
    issuer: str,
    audience: str,
    authority: str,
    delegation_rights: list[str],
    root_revocation_state_uri: str,
    revocation_trust_anchor: bytes,
    issued_at: int,
    expires_at: int,
    version: int = 1,
) -> Node:
    body = NodeBody(
        version=version,
        issuer=issuer,
        subject=root_public_key,
        parent_node_id=None,
        audience=audience,
        authority=authority,
        delegation_rights=delegation_rights,
        root_revocation_state_uri=root_revocation_state_uri,
        revocation_trust_anchor=revocation_trust_anchor,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return sign_node(body, root_signing_key)


def create_child_node(
    parent_signing_key: Ed25519PrivateKey,
    child_public_key: COSEKey,
    parent_node_id: bytes,
    *,
    issuer: str,
    audience: str,
    authority: str,
    delegation_rights: list[str],
    root_revocation_state_uri: str,
    revocation_trust_anchor: bytes,
    issued_at: int,
    expires_at: int,
    version: int = 1,
) -> Node:
    body = NodeBody(
        version=version,
        issuer=issuer,
        subject=child_public_key,
        parent_node_id=parent_node_id,
        audience=audience,
        authority=authority,
        delegation_rights=delegation_rights,
        root_revocation_state_uri=root_revocation_state_uri,
        revocation_trust_anchor=revocation_trust_anchor,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return sign_node(body, parent_signing_key)
