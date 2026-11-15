from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .canonical import CanonicalEncodingError, decode_strict, encode_canonical

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

COSE_KTY_OKP = 1
COSE_CRV_ED25519 = 6
COSE_KEY_KTY = 1
COSE_KEY_CRV = -1
COSE_KEY_X = -2


@dataclass(frozen=True)
class COSEKey:
    """OKP/Ed25519 COSE_Key, reduced to its one variable field (the raw public key bytes)."""

    x: bytes

    def to_cbor_dict(self) -> dict:
        return {COSE_KEY_KTY: COSE_KTY_OKP, COSE_KEY_CRV: COSE_CRV_ED25519, COSE_KEY_X: self.x}

    @classmethod
    def from_cbor_dict(cls, d: dict) -> "COSEKey":
        if not isinstance(d, Mapping):
            raise ValueError(f"COSE_Key must be a map, not {type(d).__name__}")
        if d.get(COSE_KEY_KTY) != COSE_KTY_OKP or d.get(COSE_KEY_CRV) != COSE_CRV_ED25519:
            raise ValueError(f"unsupported COSE key type/curve: {d}")
        x = d[COSE_KEY_X]
        if type(x) is not bytes:  # structure, detectable without a key: key material must be a byte string
            raise ValueError(f"COSE_Key x must be a byte string, not {type(x).__name__}")
        return cls(x=x)

    def to_anchor_bytes(self) -> bytes:
        """Option K (DR-1 5.1.5): canonical CBOR of the COSE_Key map."""
        return encode_canonical(self.to_cbor_dict())

    @classmethod
    def from_anchor_bytes(cls, data: bytes) -> "COSEKey":
        """Strict inverse of to_anchor_bytes: exact key set, OKP/Ed25519, 32-byte x, canonical form."""
        try:
            d = decode_strict(data)
        except CanonicalEncodingError as exc:
            raise ValueError(f"trust anchor is not a canonical COSE_Key: {exc}") from exc
        if (
            not isinstance(d, dict)
            or set(d) != {COSE_KEY_KTY, COSE_KEY_CRV, COSE_KEY_X}
            or d[COSE_KEY_KTY] != COSE_KTY_OKP
            or d[COSE_KEY_CRV] != COSE_CRV_ED25519
            or type(d[COSE_KEY_X]) is not bytes
            or len(d[COSE_KEY_X]) != 32
        ):
            raise ValueError("trust anchor is not an OKP/Ed25519 COSE_Key with exactly kty, crv and x")
        return cls(x=d[COSE_KEY_X])

    def to_cryptography_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(self.x)

    @classmethod
    def from_cryptography_key(cls, pubkey: Ed25519PublicKey) -> "COSEKey":
        return cls(x=pubkey.public_bytes_raw())


def generate_keypair() -> tuple[Ed25519PrivateKey, COSEKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, COSEKey.from_cryptography_key(private_key.public_key())


def load_private_key_from_raw(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def private_key_to_raw(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes_raw()
