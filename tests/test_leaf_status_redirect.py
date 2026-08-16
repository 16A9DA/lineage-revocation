import socket
from unittest.mock import patch

import pytest

from lineage_revocation.keys import generate_keypair
from lineage_revocation.nodes import create_child_node, create_root_node
from lineage_revocation.verifier import AudienceMismatch, CredentialExpired, RevocationBindingMismatch, authorize

REAL_URI = "https://status.example/v1"
ATTACKER_URI = "https://attacker.example/status"
TRUST_ANCHOR = b"\x01" * 32
NOW = 1_700_050_000


def _chain(*, c_revocation_state_uri=REAL_URI, c_revocation_trust_anchor=TRUST_ANCHOR):
    root_priv, root_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    _c_priv, c_pub = generate_keypair()

    root = create_root_node(
        root_priv, root_pub,
        issuer="root", audience="agent", authority="full", delegation_rights=["*"],
        root_revocation_state_uri=REAL_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    a = create_child_node(
        root_priv, a_pub, root.node_id,
        issuer="root", audience="agent", authority="full", delegation_rights=["*"],
        root_revocation_state_uri=REAL_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    b = create_child_node(
        a_priv, b_pub, a.node_id,
        issuer="a", audience="agent", authority="full", delegation_rights=["*"],
        root_revocation_state_uri=REAL_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    # b is compromised: it issues c with a diverging revocation binding.
    c = create_child_node(
        b_priv, c_pub, b.node_id,
        issuer="b", audience="agent", authority="full", delegation_rights=["*"],
        root_revocation_state_uri=c_revocation_state_uri, revocation_trust_anchor=c_revocation_trust_anchor,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    return dict(root_pub=root_pub, root=root, a=a, b=b, c=c)


def test_valid_chain_authorizes():
    ch = _chain()
    result = authorize([ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="agent", now=NOW)
    assert result[-1] == ch["c"].node_id


def test_compromised_intermediary_status_redirect_denied_and_never_contacted():
    ch = _chain(c_revocation_state_uri=ATTACKER_URI)
    lineage = [ch["root"], ch["a"], ch["b"], ch["c"]]

    with patch.object(socket, "create_connection") as mock_connect:
        with pytest.raises(RevocationBindingMismatch) as exc_info:
            authorize(lineage, ch["root_pub"], audience="agent", now=NOW)
        mock_connect.assert_not_called()

    assert exc_info.value.node_id == ch["c"].node_id


def test_revocation_trust_anchor_divergence_also_denied():
    ch = _chain(c_revocation_trust_anchor=b"\xff" * 32)
    with pytest.raises(RevocationBindingMismatch):
        authorize([ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="agent", now=NOW)


def test_audience_mismatch_denied():
    ch = _chain()
    with pytest.raises(AudienceMismatch):
        authorize([ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="other-agent", now=NOW)


def test_expired_leaf_denied():
    ch = _chain()
    with pytest.raises(CredentialExpired):
        authorize([ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="agent", now=1_700_999_999)
