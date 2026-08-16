from lineage_revocation.canonical import decode_canonical, encode_canonical
from lineage_revocation.keys import COSEKey, generate_keypair
from lineage_revocation.nodes import NodeBody


def _sample_body() -> NodeBody:
    _priv, pub = generate_keypair()
    return NodeBody(
        version=1,
        issuer="root",
        subject=pub,
        parent_node_id=None,
        audience="agent-x",
        authority="full",
        delegation_rights=["a", "b"],
        root_revocation_state_uri="https://status.example/v1",
        revocation_trust_anchor=b"\x01" * 32,
        issued_at=1_700_000_000,
        expires_at=1_700_003_600,
    )


def test_identical_bodies_encode_identically():
    body = _sample_body()
    b1 = encode_canonical(body.to_cbor_dict())
    b2 = encode_canonical(dict(reversed(list(body.to_cbor_dict().items()))))
    assert b1 == b2


def test_encode_decode_roundtrip_idempotent():
    body = _sample_body()
    encoded = body.canonical_bytes()
    assert encode_canonical(decode_canonical(encoded)) == encoded


def test_integer_boundary_values_roundtrip():
    for n in (0, 23, 24, 255, 256, 65535, 65536):
        assert decode_canonical(encode_canonical(n)) == n


def test_body_canonical_bytes_is_presign_source_of_truth():
    body = _sample_body()
    assert body.canonical_bytes() == encode_canonical(body.to_cbor_dict())


def test_nested_cose_key_roundtrips():
    key = COSEKey(x=b"\x02" * 32)
    d = key.to_cbor_dict()
    encoded = encode_canonical(d)
    decoded = decode_canonical(encoded)
    assert COSEKey.from_cbor_dict(decoded) == key
