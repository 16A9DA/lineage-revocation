"""Revision F (DR-1 D14, D15, D16): tagged COSE_Sign1, audience array, delegation_rights map."""
import hashlib
from dataclasses import replace

import cbor2
import pytest
from cbor2 import CBORTag

from lineage_revocation.canonical import encode_canonical
from lineage_revocation.keys import generate_keypair
from lineage_revocation.nodes import (
    Node,
    NodeBody,
    NodeFormatError,
    compute_node_id,
    create_child_node,
    create_root_node,
    sign_node,
    sign_payload,
    verify_node_signature,
)
from lineage_revocation.revocation import create_revocation_statement, is_target_revoked
from lineage_revocation.verifier import AudienceMismatch, authorize

URI = "https://status.example/v1"
ANCHOR = b"\x01" * 32
NOW = 1_700_050_000
COMMON = dict(
    root_revocation_state_uri=URI, revocation_trust_anchor=ANCHOR,
    issued_at=1_700_000_000, expires_at=1_700_100_000,
)


def _body(pub, **overrides) -> NodeBody:
    fields = dict(
        version=1, issuer="root", subject=pub, parent_node_id=None, audience=["agent"],
        authority=frozenset({"full"}), delegation_rights={"can_delegate": True}, **COMMON,
    )
    fields.update(overrides)
    return NodeBody(**fields)


def _wire_parts(node: Node):
    tagged = cbor2.loads(node.to_cose_sign1_bytes())
    return list(tagged.value)


def _wire_for(parts, tag=18):
    value = list(parts)
    return encode_canonical(CBORTag(tag, value) if tag is not None else value)


def _body_dict(pub, **overrides) -> dict:
    d = _body(pub).to_cbor_dict()
    d.update(overrides)
    return d


def _signed_wire_for_body_dict(priv, body_dict) -> bytes:
    payload = encode_canonical(body_dict)
    sig = sign_payload(payload, priv)
    protected = encode_canonical({1: -8})
    return encode_canonical(CBORTag(18, [protected, {}, payload, sig]))


def _chain(root_audience=("agent",), leaf_audience=("agent",)):
    root_priv, root_pub = generate_keypair()
    leaf_priv, leaf_pub = generate_keypair()
    root = create_root_node(
        root_priv, root_pub, issuer="root", audience=list(root_audience), authority=frozenset({"full"}),
        delegation_rights={"can_delegate": True}, **COMMON,
    )
    leaf = create_child_node(
        root_priv, leaf_pub, root.node_id, issuer="root", audience=list(leaf_audience),
        authority=frozenset({"full"}), delegation_rights={"can_delegate": True}, **COMMON,
    )
    return root_priv, root_pub, root, leaf


# ---------------------------------------------------------------- D14: tagged COSE_Sign1

def test_wire_form_is_tag_18_over_four_element_array():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub), priv)
    decoded = cbor2.loads(node.to_cose_sign1_bytes())
    assert isinstance(decoded, CBORTag) and decoded.tag == 18
    assert len(decoded.value) == 4


def test_tagged_roundtrip_preserves_node_and_signature():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub), priv)
    parsed = Node.from_cose_sign1_bytes(node.to_cose_sign1_bytes())
    assert parsed == node
    assert verify_node_signature(parsed, pub)


def test_untagged_envelope_rejected():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub), priv)
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(_wire_for(_wire_parts(node), tag=None))


@pytest.mark.parametrize("tag", [16, 17, 19, 98, 1000])
def test_wrong_tag_rejected(tag):
    priv, pub = generate_keypair()
    node = sign_node(_body(pub), priv)
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(_wire_for(_wire_parts(node), tag=tag))


def test_nested_tag_rejected():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub), priv)
    nested = encode_canonical(CBORTag(18, CBORTag(18, _wire_parts(node))))
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(nested)


def test_tag_inside_array_element_rejected():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub), priv)
    protected, unprotected, payload, signature = _wire_parts(node)
    wire = encode_canonical(CBORTag(18, [protected, unprotected, CBORTag(24, payload), signature]))
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(wire)


@pytest.mark.parametrize("mutate", [
    lambda p: p[:3],                              # three elements
    lambda p: p + [b"extra"],                     # five elements
    lambda p: [p[0], p[1], "not-bytes", p[3]],    # payload not bytes
    lambda p: [p[0], p[1], p[2], "not-bytes"],    # signature not bytes
    lambda p: ["not-bytes", p[1], p[2], p[3]],    # protected not bytes
    lambda p: [p[0], b"not-a-map", p[2], p[3]],   # unprotected not a map
])
def test_malformed_envelope_shape_rejected(mutate):
    priv, pub = generate_keypair()
    node = sign_node(_body(pub), priv)
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(_wire_for(mutate(_wire_parts(node))))


@pytest.mark.parametrize("value", [1, "text", b"bytes", {"a": 1}, None])
def test_tag_over_non_array_rejected(value):
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(encode_canonical(CBORTag(18, value)))


@pytest.mark.parametrize("data", [b"", b"\xff", b"\xd2", b"\xd2\x84"])
def test_garbage_and_truncated_input_rejected(data):
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(data)


def test_trailing_data_rejected():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub), priv)
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(node.to_cose_sign1_bytes() + b"\x00")


def test_tag_alone_does_not_change_node_id_or_body_signature():
    priv, pub = generate_keypair()
    body = _body(pub)
    node = sign_node(body, priv)
    expected_id = hashlib.sha256(body.canonical_bytes()).digest()
    assert node.node_id == expected_id == compute_node_id(body)
    assert node.signature == sign_payload(body.canonical_bytes(), priv)
    untagged = cbor2.loads(_wire_for(_wire_parts(node), tag=None))
    assert untagged[2] == body.canonical_bytes()
    assert untagged[3] == node.signature


# ---------------------------------------------------------------- D15: audience array

def test_audience_is_array_in_body_and_preserves_order():
    _priv, pub = generate_keypair()
    body = _body(pub, audience=["b", "a", "c"])
    assert body.audience == ("b", "a", "c")
    assert body.to_cbor_dict()["audience"] == ["b", "a", "c"]


def test_audience_array_survives_wire_roundtrip():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub, audience=["x", "y"]), priv)
    assert Node.from_cose_sign1_bytes(node.to_cose_sign1_bytes()).body.audience == ("x", "y")


def test_empty_audience_is_valid_node():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub, audience=[]), priv)
    parsed = Node.from_cose_sign1_bytes(node.to_cose_sign1_bytes())
    assert parsed.body.audience == ()


@pytest.mark.parametrize("bad", ["agent", b"agent", None, 7, {"agent"}, [1], ["a", None], [b"a"]])
def test_non_array_or_non_text_audience_rejected_at_construction(bad):
    _priv, pub = generate_keypair()
    with pytest.raises(NodeFormatError):
        _body(pub, audience=bad)


def test_string_audience_on_the_wire_rejected():
    priv, pub = generate_keypair()
    wire = _signed_wire_for_body_dict(priv, _body_dict(pub, audience="agent"))
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(wire)


def test_leaf_authorizes_when_resource_is_member():
    _priv, root_pub, root, leaf = _chain(leaf_audience=("other", "agent"))
    assert authorize([root, leaf], root_pub, audience="agent", now=NOW)[-1] == leaf.node_id


def test_leaf_denied_when_resource_is_not_member():
    _priv, root_pub, root, leaf = _chain(leaf_audience=("other", "more"))
    with pytest.raises(AudienceMismatch):
        authorize([root, leaf], root_pub, audience="agent", now=NOW)


def test_empty_leaf_audience_denies_every_resource():
    _priv, root_pub, root, leaf = _chain(leaf_audience=())
    with pytest.raises(AudienceMismatch):
        authorize([root, leaf], root_pub, audience="agent", now=NOW)


def test_membership_is_exact_not_substring():
    _priv, root_pub, root, leaf = _chain(leaf_audience=("agent-x",))
    with pytest.raises(AudienceMismatch):
        authorize([root, leaf], root_pub, audience="agent", now=NOW)


# ---------------------------------------------------------------- D16: delegation_rights map

def test_delegation_rights_map_in_body_and_roundtrip():
    priv, pub = generate_keypair()
    for flag in (True, False):
        node = sign_node(_body(pub, delegation_rights={"can_delegate": flag}), priv)
        assert node.body.to_cbor_dict()["delegation_rights"] == {"can_delegate": flag}
        assert "can_delegate" not in node.body.to_cbor_dict()
        parsed = Node.from_cose_sign1_bytes(node.to_cose_sign1_bytes())
        assert parsed.body.can_delegate is flag
        assert dict(parsed.body.delegation_rights) == {"can_delegate": flag}


@pytest.mark.parametrize("bad", [
    {},                                        # empty map
    {"other": True},                           # missing can_delegate (and unknown key)
    {"can_delegate": True, "scope": ["x"]},    # unknown extra key
    {"can_delegate": True, "can_delegate2": False},
    {"can_delegate": 1},                       # non-boolean
    {"can_delegate": 0},
    {"can_delegate": "true"},
    {"can_delegate": None},
    {"can_delegate": [True]},
    True,                                      # not a map
    [("can_delegate", True)],
    None,
])
def test_invalid_delegation_rights_rejected_at_construction(bad):
    _priv, pub = generate_keypair()
    with pytest.raises(NodeFormatError):
        _body(pub, delegation_rights=bad)


@pytest.mark.parametrize("bad", [{}, {"other": True}, {"can_delegate": True, "x": 1}, {"can_delegate": 1}])
def test_invalid_delegation_rights_rejected_on_the_wire(bad):
    priv, pub = generate_keypair()
    wire = _signed_wire_for_body_dict(priv, _body_dict(pub, delegation_rights=bad))
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(wire)


def test_delegation_rights_is_required_on_the_wire():
    priv, pub = generate_keypair()
    d = _body_dict(pub)
    del d["delegation_rights"]
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(_signed_wire_for_body_dict(priv, d))


def test_old_can_delegate_body_field_is_not_accepted_in_place_of_the_map():
    priv, pub = generate_keypair()
    d = _body_dict(pub)
    del d["delegation_rights"]
    d["can_delegate"] = True
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(_signed_wire_for_body_dict(priv, d))


def test_factories_require_delegation_rights():
    root_priv, root_pub = generate_keypair()
    with pytest.raises(TypeError):
        create_root_node(
            root_priv, root_pub, issuer="root", audience=["agent"], authority=frozenset({"full"}), **COMMON,
        )


def test_factory_rejects_invalid_delegation_rights():
    root_priv, root_pub = generate_keypair()
    with pytest.raises(NodeFormatError):
        create_root_node(
            root_priv, root_pub, issuer="root", audience=["agent"], authority=frozenset({"full"}),
            delegation_rights={}, **COMMON,
        )


# ---------------------------------------------------------------- identifiers, parents, statements

def test_node_id_matches_independently_built_canonical_body():
    priv, pub = generate_keypair()
    node = sign_node(_body(pub, audience=["a", "b"]), priv)
    expected = cbor2.dumps({
        "version": 1, "issuer": "root",
        "subject": {1: 1, -1: 6, -2: pub.x},
        "parent_node_id": None, "audience": ["a", "b"], "authority": ["full"],
        "delegation_rights": {"can_delegate": True},
        "root_revocation_state_uri": URI, "revocation_trust_anchor": ANCHOR,
        "issued_at": 1_700_000_000, "expires_at": 1_700_100_000,
    }, canonical=True)
    assert node.body.canonical_bytes() == expected
    assert node.node_id == hashlib.sha256(expected).digest()


def test_node_id_changes_with_audience_and_with_delegation_rights():
    priv, pub = generate_keypair()
    base = sign_node(_body(pub), priv).node_id
    assert sign_node(_body(pub, audience=["agent", "more"]), priv).node_id != base
    assert sign_node(_body(pub, delegation_rights={"can_delegate": False}), priv).node_id != base


def test_parent_references_follow_recomputed_ids_through_the_chain():
    _priv, root_pub, root, leaf = _chain()
    assert leaf.body.parent_node_id == root.node_id == compute_node_id(root.body)
    assert authorize([root, leaf], root_pub, audience="agent", now=NOW) == [root.node_id, leaf.node_id]


def test_statement_embeds_tagged_node_envelopes_and_still_verifies():
    root_priv, root_pub, root, leaf = _chain()
    statement = create_revocation_statement(
        root_priv, revocation_id=b"\x01" * 4, target_node=leaf, target_lineage=[root, leaf],
        revoker_node_id=root.node_id, revoker_scope_proof=b"", effective_at=NOW - 1,
        issued_at=1_700_000_000, reason_code="compromise",
    )
    body = cbor2.loads(statement.canonical_bytes())
    for wire in [body["target_node"], *body["target_lineage"]]:
        decoded = cbor2.loads(wire)
        assert isinstance(decoded, CBORTag) and decoded.tag == 18
        Node.from_cose_sign1_bytes(wire)
    assert body["target_node"] == leaf.to_cose_sign1_bytes()
    assert is_target_revoked(leaf.node_id, [statement], root_pub, now=NOW)


def test_statement_signature_depends_on_the_tagged_node_bytes():
    root_priv, root_pub, root, leaf = _chain()
    statement = create_revocation_statement(
        root_priv, revocation_id=b"\x01" * 4, target_node=leaf, target_lineage=[root, leaf],
        revoker_node_id=root.node_id, revoker_scope_proof=b"", effective_at=NOW - 1,
        issued_at=1_700_000_000, reason_code="compromise",
    )
    other_priv, other_pub = generate_keypair()
    other_leaf = create_child_node(
        root_priv, other_pub, root.node_id, issuer="root", audience=["agent", "other"],
        authority=frozenset({"full"}), delegation_rights={"can_delegate": True}, **COMMON,
    )
    swapped = replace(statement, target_node=other_leaf, target_node_id=other_leaf.node_id,
                      target_lineage=[root, other_leaf])
    assert not is_target_revoked(other_leaf.node_id, [swapped], root_pub, now=NOW)
