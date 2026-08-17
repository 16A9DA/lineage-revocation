import socket
from unittest.mock import patch

import pytest

from lineage_revocation.keys import generate_keypair
from lineage_revocation.nodes import create_child_node, create_root_node
from lineage_revocation.revocation import create_revocation_statement
from lineage_revocation.status import StaleStatusArtifact, StatusArtifact
from lineage_revocation.verifier import (
    AudienceMismatch,
    AuthorityAmplification,
    CredentialExpired,
    NodeRevoked,
    ReauthRequired,
    RevocationBindingMismatch,
    authorize,
)

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
        issuer="root", audience="agent", authority=frozenset({"full"}), can_delegate=True,
        root_revocation_state_uri=REAL_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    a = create_child_node(
        root_priv, a_pub, root.node_id,
        issuer="root", audience="agent", authority=frozenset({"full"}), can_delegate=True,
        root_revocation_state_uri=REAL_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    b = create_child_node(
        a_priv, b_pub, a.node_id,
        issuer="a", audience="agent", authority=frozenset({"full"}), can_delegate=True,
        root_revocation_state_uri=REAL_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    # b is compromised: it issues c with a diverging revocation binding.
    c = create_child_node(
        b_priv, c_pub, b.node_id,
        issuer="b", audience="agent", authority=frozenset({"full"}), can_delegate=True,
        root_revocation_state_uri=c_revocation_state_uri, revocation_trust_anchor=c_revocation_trust_anchor,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    return dict(
        root_priv=root_priv, root_pub=root_pub, root=root,
        a_priv=a_priv, a=a, b_priv=b_priv, b=b, c=c,
    )


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


def test_stale_session_requires_reauth():
    ch = _chain()
    with pytest.raises(ReauthRequired):
        authorize(
            [ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="agent", now=NOW,
            last_authorized_at=NOW - 100, session_reauth_interval=50,
        )


def _revocation_statement(ch, *, effective_at=NOW - 1):
    return create_revocation_statement(
        ch["root_priv"], revocation_id=b"\x01" * 4, target_node=ch["b"],
        target_lineage=[ch["root"], ch["a"], ch["b"]], revoker_node_id=ch["root"].node_id,
        revoker_scope_proof=b"", effective_at=effective_at, issued_at=1_700_000_000, reason_code="compromise",
    )


def test_revoked_intermediary_denies_whole_subtree(tmp_path):
    ch = _chain()
    artifact = StatusArtifact(
        version=1, root_revocation_state_uri=REAL_URI, issued_at=NOW - 100, valid_until=NOW + 1000,
        statements=[_revocation_statement(ch)],
    )
    with pytest.raises(NodeRevoked) as exc_info:
        authorize(
            [ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="agent", now=NOW,
            status_artifact=artifact, status_store_path=tmp_path / "hwm.json", max_staleness=10_000,
        )
    assert exc_info.value.node_id == ch["b"].node_id


def test_status_artifact_cannot_be_bypassed_with_wrong_uri(tmp_path):
    ch = _chain()
    artifact = StatusArtifact(
        version=1, root_revocation_state_uri=ATTACKER_URI, issued_at=NOW - 100, valid_until=NOW + 1000,
        statements=[_revocation_statement(ch)],
    )
    with pytest.raises(RevocationBindingMismatch):
        authorize(
            [ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="agent", now=NOW,
            status_artifact=artifact, status_store_path=tmp_path / "hwm.json", max_staleness=10_000,
        )


def test_status_artifact_rollback_denied(tmp_path):
    ch = _chain()
    store = tmp_path / "hwm.json"
    newer = StatusArtifact(version=2, root_revocation_state_uri=REAL_URI, issued_at=NOW - 100, valid_until=NOW + 1000, statements=[])
    older = StatusArtifact(version=1, root_revocation_state_uri=REAL_URI, issued_at=NOW - 100, valid_until=NOW + 1000, statements=[])

    authorize(
        [ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="agent", now=NOW,
        status_artifact=newer, status_store_path=store, max_staleness=10_000,
    )
    with pytest.raises(StaleStatusArtifact):
        authorize(
            [ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="agent", now=NOW,
            status_artifact=older, status_store_path=store, max_staleness=10_000,
        )


def test_status_artifact_rollback_persists_across_restart(tmp_path):
    ch = _chain()
    store = tmp_path / "hwm.json"
    accepted = StatusArtifact(version=5, root_revocation_state_uri=REAL_URI, issued_at=NOW - 100, valid_until=NOW + 1000, statements=[])
    authorize(
        [ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="agent", now=NOW,
        status_artifact=accepted, status_store_path=store, max_staleness=10_000,
    )

    # simulated restart: fresh call, no shared in-process state, only the durable store file.
    replayed = StatusArtifact(version=3, root_revocation_state_uri=REAL_URI, issued_at=NOW - 100, valid_until=NOW + 1000, statements=[])
    with pytest.raises(StaleStatusArtifact):
        authorize(
            [ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="agent", now=NOW,
            status_artifact=replayed, status_store_path=store, max_staleness=10_000,
        )


def test_stale_status_artifact_denied(tmp_path):
    ch = _chain()
    artifact = StatusArtifact(
        version=1, root_revocation_state_uri=REAL_URI, issued_at=NOW - 10_000, valid_until=NOW + 1000,
        statements=[],
    )
    with pytest.raises(StaleStatusArtifact):
        authorize(
            [ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="agent", now=NOW,
            status_artifact=artifact, status_store_path=tmp_path / "hwm.json", max_staleness=100,
        )


def test_fresh_session_does_not_require_reauth():
    ch = _chain()
    result = authorize(
        [ch["root"], ch["a"], ch["b"], ch["c"]], ch["root_pub"], audience="agent", now=NOW,
        last_authorized_at=NOW - 10, session_reauth_interval=50,
    )
    assert result[-1] == ch["c"].node_id


def test_malicious_intermediary_authority_amplification_denied():
    # mandatory test #18 (DR-0001): child claims a capability its parent never held.
    ch = _chain()
    _mallory_priv, mallory_pub = generate_keypair()
    amplified = create_child_node(
        ch["b_priv"], mallory_pub, ch["b"].node_id,
        issuer="b", audience="agent", authority=frozenset({"full", "admin"}), can_delegate=True,
        root_revocation_state_uri=REAL_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    with pytest.raises(AuthorityAmplification) as exc_info:
        authorize([ch["root"], ch["a"], ch["b"], amplified], ch["root_pub"], audience="agent", now=NOW)
    assert exc_info.value.node_id == amplified.node_id


def test_valid_authority_attenuation_allowed():
    ch = _chain()
    _priv, pub = generate_keypair()
    narrowed = create_child_node(
        ch["b_priv"], pub, ch["b"].node_id,
        issuer="b", audience="agent", authority=frozenset(), can_delegate=True,  # strict subset of parent's {"full"}
        root_revocation_state_uri=REAL_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    result = authorize([ch["root"], ch["a"], ch["b"], narrowed], ch["root_pub"], audience="agent", now=NOW)
    assert result[-1] == narrowed.node_id


def test_can_delegate_false_blocks_any_child():
    ch = _chain()
    root_priv, root_pub = generate_keypair()
    _a_priv, a_pub = generate_keypair()
    _b_priv, b_pub = generate_keypair()
    non_delegable_root = create_root_node(
        root_priv, root_pub,
        issuer="root", audience="agent", authority=frozenset({"full"}), can_delegate=False,
        root_revocation_state_uri=REAL_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    child = create_child_node(
        root_priv, a_pub, non_delegable_root.node_id,
        issuer="root", audience="agent", authority=frozenset({"full"}), can_delegate=True,
        root_revocation_state_uri=REAL_URI, revocation_trust_anchor=TRUST_ANCHOR,
        issued_at=1_700_000_000, expires_at=1_700_100_000,
    )
    with pytest.raises(AuthorityAmplification):
        authorize([non_delegable_root, child], root_pub, audience="agent", now=NOW)
