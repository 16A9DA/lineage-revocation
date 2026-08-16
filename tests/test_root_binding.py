from dataclasses import replace

import pytest

from lineage_revocation.keys import generate_keypair
from lineage_revocation.lineage import (
    ChildSignatureInvalid,
    DuplicateNodeId,
    ParentLinkMismatch,
    RootSignatureInvalid,
    verify_lineage,
)
from lineage_revocation.nodes import compute_node_id, create_child_node, create_root_node

REVOCATION_URI = "https://status.example/v1"
TRUST_ANCHOR = b"\x01" * 32


def _chain():
    root_priv, root_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    c_priv, c_pub = generate_keypair()

    root = create_root_node(
        root_priv, root_pub,
        issuer="root", audience="agent", authority="full", delegation_rights=["*"],
        root_revocation_state_uri=REVOCATION_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    a = create_child_node(
        root_priv, a_pub, root.node_id,
        issuer="root", audience="agent", authority="full", delegation_rights=["*"],
        root_revocation_state_uri=REVOCATION_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    b = create_child_node(
        a_priv, b_pub, a.node_id,
        issuer="a", audience="agent", authority="full", delegation_rights=["*"],
        root_revocation_state_uri=REVOCATION_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    c = create_child_node(
        b_priv, c_pub, b.node_id,
        issuer="b", audience="agent", authority="full", delegation_rights=["*"],
        root_revocation_state_uri=REVOCATION_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    return dict(
        root_priv=root_priv, root_pub=root_pub, root=root,
        a_priv=a_priv, a_pub=a_pub, a=a,
        b_priv=b_priv, b_pub=b_pub, b=b,
        c_priv=c_priv, c_pub=c_pub, c=c,
    )


def test_valid_chain_verifies():
    ch = _chain()
    result = verify_lineage([ch["root"], ch["a"], ch["b"], ch["c"]], root_trust_anchor=ch["root_pub"])
    assert result == [ch["root"].node_id, ch["a"].node_id, ch["b"].node_id, ch["c"].node_id]


def test_wrong_parent_key_rejected():
    ch = _chain()
    mallory_priv, _mallory_pub = generate_keypair()
    forged_b = create_child_node(
        mallory_priv, ch["b_pub"], ch["a"].node_id,
        issuer="a", audience="agent", authority="full", delegation_rights=["*"],
        root_revocation_state_uri=REVOCATION_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    with pytest.raises(ChildSignatureInvalid):
        verify_lineage([ch["root"], ch["a"], forged_b, ch["c"]], root_trust_anchor=ch["root_pub"])


def test_parent_node_id_mismatch_rejected():
    ch = _chain()
    misdirected_body = replace(ch["b"].body, parent_node_id=ch["root"].node_id)
    misdirected_b = replace(ch["b"], body=misdirected_body, node_id=compute_node_id(misdirected_body))
    with pytest.raises(ParentLinkMismatch):
        verify_lineage([ch["root"], ch["a"], misdirected_b, ch["c"]], root_trust_anchor=ch["root_pub"])


def test_duplicate_node_id_rejected():
    ch = _chain()
    with pytest.raises(DuplicateNodeId):
        verify_lineage([ch["root"], ch["a"], ch["a"], ch["b"]], root_trust_anchor=ch["root_pub"])


def test_root_signed_by_wrong_key_rejected():
    ch = _chain()
    unrelated_priv, unrelated_pub = generate_keypair()
    with pytest.raises(RootSignatureInvalid):
        verify_lineage([ch["root"], ch["a"], ch["b"], ch["c"]], root_trust_anchor=unrelated_pub)


def test_root_subject_is_never_used_as_its_own_trust_anchor():
    ch = _chain()
    # root.body.subject == root_pub, but a forged root claiming that same subject
    # while actually signed by a different key must still fail against the real anchor.
    mallory_priv, _mallory_pub = generate_keypair()
    forged_root = create_root_node(
        mallory_priv, ch["root_pub"],
        issuer="root", audience="agent", authority="full", delegation_rights=["*"],
        root_revocation_state_uri=REVOCATION_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    with pytest.raises(RootSignatureInvalid):
        verify_lineage([forged_root], root_trust_anchor=ch["root_pub"])
