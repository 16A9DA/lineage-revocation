from __future__ import annotations

import hashlib
import io
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

import cbor2
from cbor2 import CBORTag

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import encode_canonical
from .keys import COSEKey

COSE_ALG_EDDSA = -8  # RFC 8152 sec8.2 / IANA COSE Algorithms registry
COSE_HEADER_ALG = 1
COSE_SIGN1_TAG = 18  # RFC 9052 sec4.2; Spec section 5: the prototype uses the tagged representation
DELEGATION_RIGHTS_KEY = "can_delegate"  # the single recognized delegation_rights key (DR-1 D16)


class NodeFormatError(ValueError):
    """A node body or COSE_Sign1 envelope is malformed or not in the required shape."""


@dataclass(frozen=True)
class NodeBody:
    version: int
    issuer: str
    subject: COSEKey  # delegatee's COSE public key
    parent_node_id: bytes | None  # None only for the root node
    audience: Sequence[str]  # array of text values (Spec section 3); stored as a tuple
    authority: frozenset[str]  # opaque capability strings, equality-only (DR-0001)
    delegation_rights: Mapping[str, bool]  # exactly {"can_delegate": <bool>} (DR-1 D16)
    root_revocation_state_uri: str
    revocation_trust_anchor: bytes
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        audience = self.audience
        if not isinstance(audience, (list, tuple)) or not all(type(a) is str for a in audience):
            raise NodeFormatError("audience must be an array of text values")
        object.__setattr__(self, "audience", tuple(audience))

        rights = self.delegation_rights
        if not isinstance(rights, Mapping):
            raise NodeFormatError("delegation_rights must be a map")
        if set(rights) != {DELEGATION_RIGHTS_KEY}:
            raise NodeFormatError(
                f"delegation_rights must contain exactly the key {DELEGATION_RIGHTS_KEY!r}, got {sorted(map(repr, rights))}"
            )
        if type(rights[DELEGATION_RIGHTS_KEY]) is not bool:
            raise NodeFormatError(f"delegation_rights[{DELEGATION_RIGHTS_KEY!r}] must be a boolean")
        object.__setattr__(self, "delegation_rights", MappingProxyType({DELEGATION_RIGHTS_KEY: rights[DELEGATION_RIGHTS_KEY]}))

    @property
    def can_delegate(self) -> bool:
        return self.delegation_rights[DELEGATION_RIGHTS_KEY]

    def to_cbor_dict(self) -> dict:
        return {
            "version": self.version,
            "issuer": self.issuer,
            "subject": self.subject.to_cbor_dict(),
            "parent_node_id": self.parent_node_id,
            "audience": list(self.audience),
            "authority": sorted(self.authority),  # sorted for deterministic canonical CBOR
            "delegation_rights": dict(self.delegation_rights),
            "root_revocation_state_uri": self.root_revocation_state_uri,
            "revocation_trust_anchor": self.revocation_trust_anchor,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_cbor_dict(cls, d: dict) -> "NodeBody":
        if "delegation_rights" not in d:
            raise NodeFormatError("node body has no delegation_rights field")
        return cls(
            version=d["version"],
            issuer=d["issuer"],
            subject=COSEKey.from_cbor_dict(d["subject"]),
            parent_node_id=d["parent_node_id"],
            audience=d["audience"],
            authority=frozenset(d["authority"]),
            delegation_rights=d["delegation_rights"],
            root_revocation_state_uri=d["root_revocation_state_uri"],
            revocation_trust_anchor=d["revocation_trust_anchor"],
            issued_at=d["issued_at"],
            expires_at=d["expires_at"],
        )

    def canonical_bytes(self) -> bytes:
        return encode_canonical(self.to_cbor_dict())


def compute_node_id(body: NodeBody) -> bytes:
    return hashlib.sha256(body.canonical_bytes()).digest()


def _decode_single_item(data: bytes, what: str):
    if not isinstance(data, (bytes, bytearray)):
        raise NodeFormatError(f"{what} must be bytes")
    stream = io.BytesIO(data)
    try:
        value = cbor2.CBORDecoder(stream).decode()
    except Exception as exc:  # cbor2 raises several decode error types
        raise NodeFormatError(f"{what} is not well-formed CBOR: {exc}") from exc
    if stream.tell() != len(data):
        raise NodeFormatError(f"{what} has trailing data after the CBOR item")
    return value


def _sig_structure(protected_bytes: bytes, payload_bytes: bytes, external_aad: bytes = b"") -> bytes:
    # COSE_Sign1 Sig_structure, RFC 8152 sec4.4. Nodes and statements use the empty external_aad.
    return encode_canonical(["Signature1", protected_bytes, external_aad, payload_bytes])


def _protected_header_bytes() -> bytes:
    return encode_canonical({COSE_HEADER_ALG: COSE_ALG_EDDSA})


@dataclass(frozen=True)
class Node:
    body: NodeBody
    node_id: bytes
    signature: bytes  # raw 64-byte Ed25519 signature over the Sig_structure

    def to_cose_sign1_bytes(self) -> bytes:
        # The tag wraps the envelope only; the Sig_structure, node_id and body signature are unaffected.
        protected = _protected_header_bytes()
        payload = self.body.canonical_bytes()
        return encode_canonical(CBORTag(COSE_SIGN1_TAG, [protected, {}, payload, self.signature]))

    @classmethod
    def from_cose_sign1_bytes(cls, data: bytes) -> "Node":
        envelope = _decode_single_item(data, "COSE_Sign1 envelope")
        if not isinstance(envelope, CBORTag) or envelope.tag != COSE_SIGN1_TAG:
            raise NodeFormatError(f"COSE_Sign1 envelope must carry CBOR tag {COSE_SIGN1_TAG}")
        items = envelope.value
        if not isinstance(items, (list, tuple)) or len(items) != 4:
            raise NodeFormatError("tagged COSE_Sign1 must wrap a four-element array")
        _protected, unprotected, payload, signature = items
        if not isinstance(_protected, bytes) or not isinstance(payload, bytes) or not isinstance(signature, bytes):
            raise NodeFormatError("COSE_Sign1 protected header, payload and signature must be byte strings")
        if not isinstance(unprotected, Mapping):
            raise NodeFormatError("COSE_Sign1 unprotected header must be a map")
        body_map = _decode_single_item(payload, "node body")
        if not isinstance(body_map, Mapping):
            raise NodeFormatError("node body must be a map")
        try:
            body = NodeBody.from_cbor_dict(body_map)
        except (KeyError, TypeError) as exc:
            raise NodeFormatError(f"malformed node body: {exc!r}") from exc
        return cls(body=body, node_id=compute_node_id(body), signature=signature)


def sign_payload(payload: bytes, signer_private_key: Ed25519PrivateKey, external_aad: bytes = b"") -> bytes:
    return signer_private_key.sign(_sig_structure(_protected_header_bytes(), payload, external_aad))


def verify_payload(payload: bytes, signature: bytes, verifier_public_key: COSEKey, external_aad: bytes = b"") -> bool:
    try:
        verifier_public_key.to_cryptography_key().verify(
            signature, _sig_structure(_protected_header_bytes(), payload, external_aad)
        )
        return True
    except (InvalidSignature, ValueError):  # ValueError: unusable key material, e.g. not 32 bytes
        return False


def sign_node(body: NodeBody, signer_private_key: Ed25519PrivateKey) -> Node:
    signature = sign_payload(body.canonical_bytes(), signer_private_key)
    return Node(body=body, node_id=compute_node_id(body), signature=signature)


def verify_node_signature(node: Node, verifier_public_key: COSEKey) -> bool:
    return verify_payload(node.body.canonical_bytes(), node.signature, verifier_public_key)


def create_root_node(
    root_signing_key: Ed25519PrivateKey,
    root_public_key: COSEKey,
    *,
    issuer: str,
    audience: Sequence[str],
    authority: frozenset[str],
    delegation_rights: Mapping[str, bool],
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
    audience: Sequence[str],
    authority: frozenset[str],
    delegation_rights: Mapping[str, bool],
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
