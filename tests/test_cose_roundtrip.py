from dataclasses import replace

import pytest

from lineage_revocation.keys import generate_keypair
from lineage_revocation.nodes import Node, NodeBody, compute_node_id, sign_node, verify_node_signature


def _body(pub, **overrides) -> NodeBody:
    defaults = dict(
        version=1,
        issuer="root",
        subject=pub,
        parent_node_id=None,
        audience="agent-x",
        authority="full",
        delegation_rights=["a"],
        root_revocation_state_uri="https://status.example/v1",
        revocation_trust_anchor=b"\x01" * 32,
        issued_at=1_700_000_000,
        expires_at=1_700_003_600,
    )
    defaults.update(overrides)
    return NodeBody(**defaults)


def test_sign_and_verify_roundtrip():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub), priv)
    assert verify_node_signature(node, pub)


def test_tampered_body_fails_verification():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub), priv)
    tampered = replace(node, body=replace(node.body, audience="agent-y"))
    assert not verify_node_signature(tampered, pub)


def test_tampered_signature_fails_verification():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub), priv)
    bad_sig = bytes((node.signature[0] ^ 0xFF,)) + node.signature[1:]
    tampered = replace(node, signature=bad_sig)
    assert not verify_node_signature(tampered, pub)


def test_resigning_same_body_keeps_node_id_and_signature():
    priv, pub = generate_keypair()
    body = _body(pub)
    node1 = sign_node(body, priv)
    node2 = sign_node(body, priv)
    assert node1.node_id == node2.node_id
    assert node1.signature == node2.signature  # Ed25519/EdDSA is deterministic, RFC 8032


def test_changing_field_changes_node_id():
    priv, pub = generate_keypair()
    node1 = sign_node(_body(pub), priv)
    node2 = sign_node(_body(pub, audience="agent-y"), priv)
    assert node1.node_id != node2.node_id


def test_cose_sign1_wire_roundtrip():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub), priv)
    wire = node.to_cose_sign1_bytes()
    parsed = Node.from_cose_sign1_bytes(wire)
    assert parsed.node_id == node.node_id
    assert parsed.body == node.body
    assert verify_node_signature(parsed, pub)


def test_node_id_is_pure_function_of_unsigned_body():
    priv, pub = generate_keypair()
    body = _body(pub)
    assert compute_node_id(body) == sign_node(body, priv).node_id
