from __future__ import annotations

from dataclasses import dataclass

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
        if d.get(COSE_KEY_KTY) != COSE_KTY_OKP or d.get(COSE_KEY_CRV) != COSE_CRV_ED25519:
            raise ValueError(f"unsupported COSE key type/curve: {d}")
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
