from dataclasses import replace

from lineage_revocation.keys import generate_keypair
from lineage_revocation.nodes import create_child_node, create_root_node
from lineage_revocation.revocation import create_revocation_statement, is_target_revoked

REVOCATION_URI = "https://status.example/v1"
TRUST_ANCHOR = b"\x01" * 32
NOW = 1_700_050_000


def _delegation_chain():
    root_priv, root_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    c_priv, c_pub = generate_keypair()
    d_priv, d_pub = generate_keypair()

    root = create_root_node(
        root_priv, root_pub,
        issuer="root", audience="agent", authority=frozenset({"full"}), can_delegate=True,
        root_revocation_state_uri=REVOCATION_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    a = create_child_node(
        root_priv, a_pub, root.node_id,
        issuer="root", audience="agent", authority=frozenset({"full"}), can_delegate=True,
        root_revocation_state_uri=REVOCATION_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    b = create_child_node(
        a_priv, b_pub, a.node_id,
        issuer="a", audience="agent", authority=frozenset({"full"}), can_delegate=True,
        root_revocation_state_uri=REVOCATION_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    c = create_child_node(
        b_priv, c_pub, b.node_id,
        issuer="b", audience="agent", authority=frozenset({"full"}), can_delegate=True,
        root_revocation_state_uri=REVOCATION_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    d = create_child_node(  # a's other child, sibling of b
        a_priv, d_pub, a.node_id,
        issuer="a", audience="agent", authority=frozenset({"full"}), can_delegate=True,
        root_revocation_state_uri=REVOCATION_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    return dict(
        root_priv=root_priv, root_pub=root_pub, root=root,
        a_priv=a_priv, a=a, b_priv=b_priv, b=b, c_priv=c_priv, c=c, d=d,
    )


def _statement(*, signing_key, target_node, target_lineage, revoker_node_id, effective_at=NOW - 1, revocation_id=b"\x01" * 4):
    return create_revocation_statement(
        signing_key,
        revocation_id=revocation_id,
        target_node=target_node,
        target_lineage=target_lineage,
        revoker_node_id=revoker_node_id,
        revoker_scope_proof=b"",
        effective_at=effective_at,
        issued_at=1_700_000_000,
        reason_code="compromise",
    )


def test_root_may_revoke_any_node():
    ch = _delegation_chain()
    statement = _statement(
        signing_key=ch["root_priv"], target_node=ch["a"], target_lineage=[ch["root"], ch["a"]],
        revoker_node_id=ch["root"].node_id,
    )
    assert is_target_revoked(ch["a"].node_id, [statement], ch["root_pub"], now=NOW)


def test_direct_issuer_may_revoke_its_child():
    ch = _delegation_chain()
    statement = _statement(
        signing_key=ch["a_priv"], target_node=ch["b"], target_lineage=[ch["root"], ch["a"], ch["b"]],
        revoker_node_id=ch["a"].node_id,
    )
    assert is_target_revoked(ch["b"].node_id, [statement], ch["root_pub"], now=NOW)


def test_grandchild_issuer_may_revoke_its_own_child():
    ch = _delegation_chain()
    statement = _statement(
        signing_key=ch["b_priv"], target_node=ch["c"], target_lineage=[ch["root"], ch["a"], ch["b"], ch["c"]],
        revoker_node_id=ch["b"].node_id,
    )
    assert is_target_revoked(ch["c"].node_id, [statement], ch["root_pub"], now=NOW)


def test_issuer_cannot_revoke_its_own_parent():
    ch = _delegation_chain()
    statement = _statement(
        signing_key=ch["b_priv"], target_node=ch["a"], target_lineage=[ch["root"], ch["a"]],
        revoker_node_id=ch["b"].node_id,
    )
    assert not is_target_revoked(ch["a"].node_id, [statement], ch["root_pub"], now=NOW)


def test_issuer_cannot_revoke_a_sibling():
    ch = _delegation_chain()
    statement = _statement(
        signing_key=ch["b_priv"], target_node=ch["d"], target_lineage=[ch["root"], ch["a"], ch["d"]],
        revoker_node_id=ch["b"].node_id,
    )
    assert not is_target_revoked(ch["d"].node_id, [statement], ch["root_pub"], now=NOW)


def test_invalid_statement_ignored_but_valid_one_still_revokes():
    ch = _delegation_chain()
    invalid = _statement(
        signing_key=ch["b_priv"], target_node=ch["a"], target_lineage=[ch["root"], ch["a"]],
        revoker_node_id=ch["b"].node_id,
    )
    valid = _statement(
        signing_key=ch["root_priv"], target_node=ch["a"], target_lineage=[ch["root"], ch["a"]],
        revoker_node_id=ch["root"].node_id,
    )
    assert is_target_revoked(ch["a"].node_id, [invalid, valid], ch["root_pub"], now=NOW)


def test_not_yet_effective_statement_does_not_revoke():
    ch = _delegation_chain()
    statement = _statement(
        signing_key=ch["root_priv"], target_node=ch["a"], target_lineage=[ch["root"], ch["a"]],
        revoker_node_id=ch["root"].node_id, effective_at=NOW + 1,
    )
    assert not is_target_revoked(ch["a"].node_id, [statement], ch["root_pub"], now=NOW)


def test_tampered_statement_signature_ignored_without_crashing():
    ch = _delegation_chain()
    statement = _statement(
        signing_key=ch["root_priv"], target_node=ch["a"], target_lineage=[ch["root"], ch["a"]],
        revoker_node_id=ch["root"].node_id,
    )
    tampered = replace(statement, signature=bytes((statement.signature[0] ^ 0xFF,)) + statement.signature[1:])
    assert not is_target_revoked(ch["a"].node_id, [tampered], ch["root_pub"], now=NOW)
