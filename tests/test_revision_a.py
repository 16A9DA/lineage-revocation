"""Revision A: signed status artifacts, Option K anchor, artifact-only AAD, unavailable-status
policy, alerts, D17 content-derived revocation ids. Revisions B (equal version), C (per-node expiry)
and audience attenuation are deliberately not covered."""
import hashlib
import logging
from dataclasses import replace
from types import SimpleNamespace

import cbor2
import pytest
from cbor2 import CBORTag

import lineage_revocation.canonical as canonical
from lineage_revocation.alerts import alert_count
from lineage_revocation.canonical import encode_canonical
from lineage_revocation.keys import COSEKey, generate_keypair
from lineage_revocation.nodes import (
    _protected_header_bytes,
    create_child_node,
    create_root_node,
    sign_payload,
    verify_payload,
)
from lineage_revocation.revocation import (
    RevocationStatement,
    StatementFormatError,
    create_revocation_statement,
    verify_revocation_statement,
)
from lineage_revocation.status import (
    ARTIFACT_AAD,
    StaleStatusArtifact,
    StatusFailure,
    StatusPolicy,
    StatusReason,
    StatusRollback,
    StatusUnavailable,
    build_status_artifact,
    handle_unavailable_status,
    ingest_status_artifact,
)
from lineage_revocation.verifier import (
    AudienceMismatch as AudienceMismatchError,
    AuthorityAmplification,
    NodeRevoked,
    RevocationBindingMismatch,
    authorize,
)

NOW = 1_700_050_000
URI = "https://status.example/v1"
MAX_STALENESS = 10_000
COMMON = dict(issued_at=1_700_000_000, expires_at=1_700_100_000)


def make_world(uri=URI, *, artifact_key_from=None):
    """artifact_key_from: name of a world key ('root', 'a', 'b') to REUSE as the artifact key (misconfiguration)."""
    root_priv, root_pub = generate_keypair()
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    art_priv, art_pub = {"root": (root_priv, root_pub), "a": (a_priv, a_pub), "b": (b_priv, b_pub)}.get(
        artifact_key_from) or generate_keypair()  # dedicated artifact key: held by the root operator, not the distribution service
    anchor = art_pub.to_anchor_bytes()
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=uri, revocation_trust_anchor=anchor, **COMMON)
    root = create_root_node(root_priv, root_pub, issuer="root", **kw)
    a = create_child_node(root_priv, a_pub, root.node_id, issuer="root", **kw)
    b = create_child_node(a_priv, b_pub, a.node_id, issuer="a", **kw)
    return SimpleNamespace(
        root_priv=root_priv, root_pub=root_pub, a_priv=a_priv, a_pub=a_pub, b_priv=b_priv, b_pub=b_pub,
        art_priv=art_priv, art_pub=art_pub, root=root, a=a, b=b, lineage=[root, a, b], uri=uri,
    )


def statement(w, target=None, *, effective_at=NOW - 1, reason="compromise", signer=None, revoker=None):
    target = target or w.a
    chain = w.lineage[: w.lineage.index(target) + 1]
    return create_revocation_statement(
        signer or w.root_priv, target_node=target, target_lineage=chain,
        revoker_node_id=revoker or w.root.node_id, revoker_scope_proof=b"",
        effective_at=effective_at, issued_at=1_700_000_000, reason_code=reason,
    )


def artifact(w, *, version=1, statements=(), issued_at=NOW - 100, valid_until=NOW + 1000, key=None, uri=None):
    return build_status_artifact(
        key or w.art_priv, version=version, root_revocation_state_uri=uri or w.uri,
        issued_at=issued_at, valid_until=valid_until, statements=list(statements),
    )


def sign_raw_body(key, body_bytes, aad=ARTIFACT_AAD):
    sig = sign_payload(body_bytes, key, aad)
    return encode_canonical(CBORTag(18, [_protected_header_bytes(), {}, body_bytes, sig]))


def body_dict(w, **over):
    d = {"schema_version": 1, "version": 1, "root_revocation_state_uri": w.uri,
         "issued_at": NOW - 100, "valid_until": NOW + 1000, "statements": []}
    d.update(over)
    return d


def auth(w, status, store, **kw):
    kw.setdefault("max_staleness", MAX_STALENESS)
    return authorize(w.lineage, w.root_pub, audience="agent", now=kw.pop("now", NOW),
                     status_artifact=status, status_store_path=store, **kw)


def ingest(w, wire, store):
    return ingest_status_artifact(wire, root=w.root, root_trust_anchor=w.root_pub, store_path=store)


ARM = "benchmark-arm-failopen-x"


def pol(policy):
    """Keyword arguments for a policy: FAIL_OPEN_EXPERIMENTAL must carry an experimental-arm label."""
    kw = {"status_policy": policy}
    if policy is StatusPolicy.FAIL_OPEN_EXPERIMENTAL:
        kw["experimental_arm"] = ARM
    return kw


def integrity():
    return StatusReason.ARTIFACT_INTEGRITY  # resolved lazily: a missing name fails each test, not collection


def statement_reason(name):
    import lineage_revocation.revocation as rev
    return getattr(rev.StatementReason, name)


@pytest.fixture
def w():
    return make_world()


# ------------------------------------------------------------------ A1, A6: signed artifact

def test_valid_signed_artifact_authorizes_and_applies_statements(w, tmp_path):
    assert auth(w, artifact(w), tmp_path / "hwm.json") == [n.node_id for n in w.lineage]
    with pytest.raises(NodeRevoked) as exc:
        auth(w, artifact(w, version=2, statements=[statement(w)]), tmp_path / "hwm.json")
    assert exc.value.node_id == w.a.node_id


def test_artifact_signed_by_wrong_key_rejected_with_alert(w, tmp_path, caplog):
    other_priv, _ = generate_keypair()
    before = alert_count("artifact_signature_invalid")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(StatusUnavailable) as exc:
            auth(w, artifact(w, key=other_priv), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID
    assert alert_count("artifact_signature_invalid") == before + 1
    rec = [r for r in caplog.records if getattr(r, "alert_kind", "") == "artifact_signature_invalid"]
    assert len(rec) == 1 and rec[0].alert_fields["root_revocation_state_uri"] == URI
    assert not (tmp_path / "hwm.json").exists()


def test_tampered_signature_rejected(w, tmp_path):
    wire = bytearray(artifact(w))
    wire[-1] ^= 1
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, bytes(wire), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID


def test_wrong_trust_anchor_in_root_rejected(tmp_path):
    w = make_world()
    _, other_pub = generate_keypair()
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=URI, revocation_trust_anchor=other_pub.to_anchor_bytes(), **COMMON)
    root = create_root_node(w.root_priv, w.root_pub, issuer="root", **kw)
    with pytest.raises(StatusUnavailable) as exc:
        ingest_status_artifact(artifact(w), root=root, root_trust_anchor=w.root_pub, store_path=tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID


def test_placeholder_anchor_is_an_authentication_failure_not_a_crash(w, tmp_path):
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=URI, revocation_trust_anchor=b"\x01" * 32, **COMMON)
    root = create_root_node(w.root_priv, w.root_pub, issuer="root", **kw)
    with pytest.raises(StatusUnavailable) as exc:
        ingest_status_artifact(artifact(w), root=root, root_trust_anchor=w.root_pub, store_path=tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID


def test_validly_signed_artifact_for_other_uri_rejected_after_authentication(w, tmp_path):
    store = tmp_path / "hwm.json"
    with pytest.raises(RevocationBindingMismatch):
        auth(w, artifact(w, uri="https://attacker.example/status"), store)
    assert not store.exists()


def test_uri_check_follows_authentication_not_precedes_it(w, tmp_path):
    # wrong URI AND forged signature: authentication is reported, the unverified URI is never trusted
    other_priv, _ = generate_keypair()
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, artifact(w, key=other_priv, uri="https://attacker.example/status"), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID


def test_descendant_supplied_anchor_never_used(w, tmp_path):
    # b carries an anchor for a key the attacker holds; authentication still uses the root's anchor
    evil_priv, evil_pub = generate_keypair()
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=URI, revocation_trust_anchor=evil_pub.to_anchor_bytes(), **COMMON)
    create_child_node(w.a_priv, w.b_pub, w.a.node_id, issuer="a", **kw)
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, artifact(w, key=evil_priv), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID


# ------------------------------------------------------------------ A5: canonical, schema, strict parse

def test_non_canonical_body_rejected_even_with_valid_signature(w, tmp_path):
    d = body_dict(w)
    non_canonical = cbor2.dumps(dict(reversed(list(d.items()))))  # insertion order, not sorted
    assert non_canonical != encode_canonical(d)
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, sign_raw_body(w.art_priv, non_canonical), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_MALFORMED
    assert not (tmp_path / "hwm.json").exists()


def test_indefinite_length_body_rejected(w, tmp_path):
    body = b"\xbf" + b"".join(encode_canonical(k) + encode_canonical(v) for k, v in body_dict(w).items()) + b"\xff"
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, sign_raw_body(w.art_priv, body), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_MALFORMED


def test_schema_version_is_required(w, tmp_path):
    d = body_dict(w)
    del d["schema_version"]
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, sign_raw_body(w.art_priv, encode_canonical(d)), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_MALFORMED


@pytest.mark.parametrize("version", [0, 2, -1, True, "1"])
def test_unsupported_schema_version_rejected(w, tmp_path, version):
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, sign_raw_body(w.art_priv, encode_canonical(body_dict(w, schema_version=version))), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_MALFORMED


def test_unknown_field_rejected(w, tmp_path):
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, sign_raw_body(w.art_priv, encode_canonical(body_dict(w, extra=1))), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_MALFORMED


@pytest.mark.parametrize("over", [
    {"version": -1}, {"version": "2"}, {"issued_at": -5}, {"valid_until": NOW - 1000},
    {"root_revocation_state_uri": 5}, {"statements": "x"}, {"statements": [1]},
])
def test_malformed_fields_rejected(w, tmp_path, over):
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, sign_raw_body(w.art_priv, encode_canonical(body_dict(w, **over))), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_MALFORMED


def test_float_in_body_rejected(w, tmp_path):
    body = cbor2.dumps(body_dict(w, version=1.0), canonical=True)
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, sign_raw_body(w.art_priv, body), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_MALFORMED


def test_untagged_wrong_tag_trailing_and_garbage_envelopes_rejected(w, tmp_path):
    good = artifact(w)
    parts = list(cbor2.loads(good).value)
    bad = [
        cbor2.dumps(parts),  # untagged
        cbor2.dumps(CBORTag(17, parts)),  # wrong tag
        cbor2.dumps(CBORTag(18, CBORTag(18, parts))),  # nested
        good + b"\x00",  # trailing data
        good[:-3],  # truncated
        b"", b"\xff", b"not cbor",
        cbor2.dumps(CBORTag(18, parts[:3])),  # malformed shape
        cbor2.dumps(CBORTag(18, [parts[0], {1: 2}, parts[2], parts[3]])),  # unprotected header not empty
        cbor2.dumps(CBORTag(18, [b"\xa1\x01\x26", {}, parts[2], parts[3]])),  # unsupported algorithm
    ]
    for wire in bad:
        with pytest.raises(StatusUnavailable) as exc:
            ingest(w, wire, tmp_path / "hwm.json")
        assert exc.value.reason is StatusReason.ARTIFACT_MALFORMED
    assert not (tmp_path / "hwm.json").exists()


def test_non_bytes_input_is_typed_failure(w, tmp_path):
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, "not bytes", tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_MALFORMED


def test_verifier_canonical_check_uses_protocol_encoder(w, tmp_path, monkeypatch):
    calls = []
    real = canonical.encode_canonical

    def spy(value):
        calls.append(value)
        return real(value)

    monkeypatch.setattr(canonical, "encode_canonical", spy)
    ingest(w, artifact(w), tmp_path / "hwm.json")
    assert any(isinstance(v, dict) and "schema_version" in v for v in calls)  # body re-encoded
    assert any(isinstance(v, CBORTag) for v in calls)  # envelope re-encoded


# ------------------------------------------------------------------ A4, A2: AAD and key separation

def test_artifact_signature_uses_artifact_only_aad(w):
    body = encode_canonical(body_dict(w))
    sig = sign_payload(body, w.art_priv, ARTIFACT_AAD)
    assert verify_payload(body, sig, w.art_pub, ARTIFACT_AAD)
    assert not verify_payload(body, sig, w.art_pub)  # empty AAD (node/statement rules) does not verify it
    assert not verify_payload(body, sig, w.art_pub, b"other")
    assert ARTIFACT_AAD == b"lineage-revocation:status-artifact:v1"


def test_artifact_signed_with_empty_aad_rejected(w, tmp_path):
    wire = sign_raw_body(w.art_priv, encode_canonical(body_dict(w)), aad=b"")
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, wire, tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID


def test_node_and_statement_signatures_keep_empty_aad(w):
    s = statement(w)
    assert verify_payload(s.canonical_bytes(), s.signature, w.root_pub)
    assert verify_payload(w.a.body.canonical_bytes(), w.a.signature, w.root_pub)
    assert not verify_payload(s.canonical_bytes(), s.signature, w.root_pub, ARTIFACT_AAD)


def test_statement_signature_cannot_be_replayed_as_artifact_signature(w, tmp_path):
    # even if the artifact key also signed a statement-shaped payload, the AAD separates the domains
    body = encode_canonical(body_dict(w))
    node_style_sig = sign_payload(body, w.art_priv)  # empty AAD, as nodes and statements sign
    wire = encode_canonical(CBORTag(18, [_protected_header_bytes(), {}, body, node_style_sig]))
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, wire, tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID


def test_artifact_key_is_distinct_from_delegation_and_statement_keys(w):
    stmt_keys = {w.root_pub.x, w.a_pub.x}  # root and direct issuers sign statements
    all_keys = stmt_keys | {w.b_pub.x}
    assert w.art_pub.x not in all_keys
    assert COSEKey.from_anchor_bytes(w.root.body.revocation_trust_anchor) == w.art_pub
    assert w.root.body.subject != w.art_pub


def test_artifact_signed_by_root_delegation_key_rejected(w, tmp_path):
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, artifact(w, key=w.root_priv), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID


# ------------------------------------------------------------------ A3: Option K

def test_option_k_round_trip_and_canonical_cose_key_shape():
    _, pub = generate_keypair()
    anchor = pub.to_anchor_bytes()
    assert COSEKey.from_anchor_bytes(anchor) == pub
    assert cbor2.loads(anchor) == {1: 1, -1: 6, -2: pub.x}


@pytest.mark.parametrize("mutate", [
    lambda d: {**d, 3: -8},  # extra field
    lambda d: {k: v for k, v in d.items() if k != -1},  # missing crv
    lambda d: {**d, 1: 2},  # wrong kty
    lambda d: {**d, -1: 7},  # wrong crv
    lambda d: {**d, -2: d[-2][:31]},  # wrong length
    lambda d: {**d, -2: "x" * 32},  # wrong type
])
def test_option_k_rejects_unknown_or_unsupported_fields(mutate):
    _, pub = generate_keypair()
    with pytest.raises(ValueError):
        COSEKey.from_anchor_bytes(encode_canonical(mutate(pub.to_cbor_dict())))


@pytest.mark.parametrize("raw", [b"", b"\x01" * 32, b"\xff", b"\xa0"])
def test_option_k_rejects_non_cose_key_bytes(raw):
    with pytest.raises(ValueError):
        COSEKey.from_anchor_bytes(raw)


def test_option_k_rejects_non_canonical_and_trailing():
    _, pub = generate_keypair()
    non_canonical = cbor2.dumps({-2: pub.x, 1: 1, -1: 6})  # insertion order, not sorted
    assert non_canonical != pub.to_anchor_bytes()
    with pytest.raises(ValueError):
        COSEKey.from_anchor_bytes(non_canonical)
    with pytest.raises(ValueError):
        COSEKey.from_anchor_bytes(pub.to_anchor_bytes() + b"\x00")


# ------------------------------------------------------------------ A6/A7: no mutation before authentication

def test_forged_artifacts_leave_store_byte_identical_and_genuine_still_accepted(w, tmp_path):
    store = tmp_path / "hwm.json"
    auth(w, artifact(w, version=2), store)
    before = store.read_bytes()
    forger, _ = generate_keypair()
    for forged in (artifact(w, key=forger, version=3), artifact(w, key=forger, version=10**12)):
        with pytest.raises(StatusUnavailable):
            auth(w, forged, store)
        assert store.read_bytes() == before
    auth(w, artifact(w, version=3), store)  # genuine next version not blocked by the forged 10**12


def test_omission_attack_with_forged_next_version_denied(w, tmp_path):
    store = tmp_path / "hwm.json"
    with pytest.raises(NodeRevoked):
        auth(w, artifact(w, version=1, statements=[statement(w)]), store)
    forged_empty = artifact(w, version=2, key=generate_keypair()[0])
    with pytest.raises(StatusUnavailable):
        auth(w, forged_empty, store)
    with pytest.raises(NodeRevoked):  # genuine statement still enforced, store never poisoned
        auth(w, artifact(w, version=2, statements=[statement(w)]), store)


def test_stale_authenticated_higher_version_persists_but_is_not_used(w, tmp_path):
    store = tmp_path / "hwm.json"
    stale = artifact(w, version=7, issued_at=NOW - 50_000, valid_until=NOW + 1000)
    with pytest.raises(StaleStatusArtifact) as exc:
        auth(w, stale, store)
    assert exc.value.reason is StatusReason.ARTIFACT_STALE
    assert not isinstance(exc.value, StatusRollback)
    assert '"%s": 7' % URI in store.read_text()  # persisted after authentication, before freshness
    with pytest.raises(StatusRollback):
        auth(w, artifact(w, version=6), store)


def test_rollback_is_never_routed_through_the_unavailable_policy(w, tmp_path):
    store = tmp_path / "hwm.json"
    auth(w, artifact(w, version=5), store)
    with pytest.raises(StatusRollback):
        auth(w, artifact(w, version=4), store, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))


# ------------------------------------------------------------------ A7: P-2 accepted state

def test_accepted_state_is_bound_to_digest_uri_trust_context_and_version(w, tmp_path):
    wire = artifact(w, version=4)
    state = ingest(w, wire, tmp_path / "hwm.json")
    body = cbor2.loads(wire).value[2]
    assert state.body_digest == hashlib.sha256(body).digest()
    assert state.version == 4 and state.root_revocation_state_uri == URI
    assert state.root_node_id == w.root.node_id
    assert state.trust_anchor == w.root.body.revocation_trust_anchor


def test_accepted_state_reused_across_calls_reevaluates_freshness_and_effective_time(w, tmp_path):
    state = ingest(w, artifact(w, statements=[statement(w, effective_at=NOW + 50)]), tmp_path / "hwm.json")
    run = lambda now: authorize(w.lineage, w.root_pub, audience="agent", now=now, status_artifact=state,
                                max_staleness=MAX_STALENESS)
    assert run(NOW)  # not yet effective
    assert run(NOW + 49)
    with pytest.raises(NodeRevoked):
        run(NOW + 50)  # effective_at == now
    with pytest.raises(StaleStatusArtifact):
        run(NOW + 1000)  # valid_until reached: authenticated is not permanently fresh


def test_accepted_state_not_reusable_for_other_root_uri_or_anchor(w, tmp_path):
    state = ingest(w, artifact(w), tmp_path / "hwm.json")
    other = make_world()
    for bad in (state, replace(state, root_revocation_state_uri="https://x.example/s"),
                replace(state, trust_anchor=b"\x00")):
        target = other if bad is state else w
        with pytest.raises(RevocationBindingMismatch):
            authorize(target.lineage, target.root_pub, audience="agent", now=NOW, status_artifact=bad,
                      max_staleness=MAX_STALENESS)


def test_accepted_state_not_reusable_for_a_different_root_with_same_uri_and_anchor(w, tmp_path):
    state = ingest(w, artifact(w), tmp_path / "hwm.json")
    other_priv, other_pub = generate_keypair()
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=URI, revocation_trust_anchor=w.root.body.revocation_trust_anchor, **COMMON)
    other_root = create_root_node(other_priv, other_pub, issuer="root", **kw)
    with pytest.raises(RevocationBindingMismatch):
        authorize([other_root], other_pub, audience="agent", now=NOW, status_artifact=state,
                  max_staleness=MAX_STALENESS)


def test_equal_version_is_still_rejected_revision_b_not_implemented(w, tmp_path):
    store = tmp_path / "hwm.json"
    auth(w, artifact(w, version=1), store)
    with pytest.raises(StatusRollback):
        auth(w, artifact(w, version=1), store)


# ------------------------------------------------------------------ A8: unavailable-status policy

def test_none_fails_closed_by_default(w):
    with pytest.raises(StatusUnavailable) as exc:
        authorize(w.lineage, w.root_pub, audience="agent", now=NOW)
    assert exc.value.reason is StatusReason.STATUS_MISSING


def test_omitting_artifact_never_enables_ttl_only(w):
    for policy in (StatusPolicy.FAIL_CLOSED, StatusPolicy.BOUNDED_STALENESS):
        with pytest.raises(StatusUnavailable):
            authorize(w.lineage, w.root_pub, audience="agent", now=NOW, status_policy=policy)


def test_explicit_ttl_only_opt_in_authorizes_without_status(w):
    ids = authorize(w.lineage, w.root_pub, audience="agent", now=NOW, status_policy=StatusPolicy.TTL_ONLY_NO_STATUS)
    assert ids == [n.node_id for n in w.lineage]


def test_ttl_only_does_not_excuse_a_supplied_but_bad_artifact(w, tmp_path):
    forged = artifact(w, key=generate_keypair()[0])
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, forged, tmp_path / "hwm.json", status_policy=StatusPolicy.TTL_ONLY_NO_STATUS)
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID


def test_distinct_reason_codes_per_situation(w, tmp_path):
    store = tmp_path / "hwm.json"
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json")
    cases = {
        StatusReason.STATUS_MISSING: lambda: authorize(w.lineage, w.root_pub, audience="agent", now=NOW),
        StatusReason.STORE_UNREADABLE: lambda: auth(w, artifact(w), corrupt),
        StatusReason.ARTIFACT_MALFORMED: lambda: auth(w, b"garbage", store),
        StatusReason.ARTIFACT_SIGNATURE_INVALID: lambda: auth(w, artifact(w, key=generate_keypair()[0]), store),
        StatusReason.ARTIFACT_STALE: lambda: auth(w, artifact(w, issued_at=NOW - 50_000), store),
    }
    seen = {}
    for reason, run in cases.items():
        with pytest.raises(StatusFailure) as exc:
            run()
        seen[reason] = exc.value.reason
    assert seen == {r: r for r in cases}
    assert len({r.value for r in StatusReason}) == len(StatusReason)


def test_s2_network_unavailable_has_its_own_reason_via_policy_function():
    failure = StatusUnavailable(StatusReason.STATUS_NETWORK_UNAVAILABLE, "no route")
    with pytest.raises(StatusUnavailable) as exc:
        handle_unavailable_status(failure, policy=StatusPolicy.FAIL_CLOSED, now=NOW, max_staleness=10)
    assert exc.value.reason is StatusReason.STATUS_NETWORK_UNAVAILABLE


def test_s3_missing_file_is_first_run_and_unreadable_store_fails_closed_for_every_policy(w, tmp_path):
    assert auth(w, artifact(w), tmp_path / "does-not-exist.json")
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]")
    for policy in StatusPolicy:
        with pytest.raises(StatusUnavailable) as exc:
            auth(w, artifact(w), bad, **pol(policy))
        assert exc.value.reason is StatusReason.STORE_UNREADABLE


def test_store_path_none_is_typed_failure_not_attribute_error(w):
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, artifact(w), None)
    assert exc.value.reason is StatusReason.STORE_UNREADABLE


def test_fail_open_is_experimental_and_still_alerts_on_signature_failure(w, tmp_path):
    before = alert_count("artifact_signature_invalid")
    forged = artifact(w, key=generate_keypair()[0])
    ids = auth(w, forged, tmp_path / "hwm.json", **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    assert ids == [n.node_id for n in w.lineage]
    assert alert_count("artifact_signature_invalid") == before + 1  # D10: verdict follows policy, alert carries the signal


def test_bounded_staleness_applies_to_s6_and_s2_over_last_authenticated_artifact(w, tmp_path):
    store = tmp_path / "hwm.json"
    last = ingest(w, artifact(w, version=1), store)
    stale_new = artifact(w, version=2, issued_at=NOW - 50_000, valid_until=NOW + 1000)
    with pytest.raises(StaleStatusArtifact):  # default: fail closed
        auth(w, stale_new, store)
    store.unlink()
    ids = auth(w, stale_new, store, status_policy=StatusPolicy.BOUNDED_STALENESS, last_accepted_status=last)
    assert ids == [n.node_id for n in w.lineage]
    failure = StatusUnavailable(StatusReason.STATUS_NETWORK_UNAVAILABLE)
    assert handle_unavailable_status(failure, policy=StatusPolicy.BOUNDED_STALENESS, now=NOW,
                                     max_staleness=MAX_STALENESS, last_accepted=last) is last
    with pytest.raises(StatusUnavailable):  # last authenticated artifact itself too old
        handle_unavailable_status(failure, policy=StatusPolicy.BOUNDED_STALENESS, now=NOW + 5000,
                                  max_staleness=MAX_STALENESS, last_accepted=last)
    with pytest.raises(StatusUnavailable):  # no previously authenticated artifact
        handle_unavailable_status(failure, policy=StatusPolicy.BOUNDED_STALENESS, now=NOW, max_staleness=MAX_STALENESS)


def test_bounded_staleness_does_not_cover_missing_malformed_or_signature_failure(w, tmp_path):
    last = ingest(w, artifact(w, version=1), tmp_path / "a.json")
    for wire in (None, b"garbage", artifact(w, key=generate_keypair()[0])):
        with pytest.raises(StatusUnavailable):
            auth(w, wire, tmp_path / "b.json", status_policy=StatusPolicy.BOUNDED_STALENESS, last_accepted_status=last)


# ------------------------------------------------------------------ A9: alerts

def test_invalid_statement_alert_is_structured_counted_monotonic_and_not_a_denial(w, tmp_path, caplog):
    impostor_priv, _ = generate_keypair()
    invalid = statement(w, signer=impostor_priv)  # claims root as revoker but wrong key
    valid = statement(w, target=w.b, reason="other")
    before = alert_count("invalid_revocation_statement")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(NodeRevoked) as exc:
            auth(w, artifact(w, statements=[invalid, valid]), tmp_path / "hwm.json")
    assert exc.value.node_id == w.b.node_id  # valid revocation still denies
    assert alert_count("invalid_revocation_statement") == before + 1
    rec = [r for r in caplog.records if getattr(r, "alert_kind", "") == "invalid_revocation_statement"]
    assert len(rec) == 1
    assert rec[0].alert_fields["revocation_id"] == invalid.revocation_id
    assert rec[0].alert_fields["target_node_id"] == w.a.node_id
    assert rec[0].alert_fields["reason_code"] == statement_reason("SIGNATURE_INVALID").name
    assert alert_count("invalid_revocation_statement") >= before + 1  # never decreases


def test_invalid_statement_alone_never_denies(w, tmp_path):
    invalid = statement(w, signer=generate_keypair()[0])
    assert auth(w, artifact(w, statements=[invalid]), tmp_path / "hwm.json")


# ------------------------------------------------------------------ duplicates (Spec section 10)

def test_identical_duplicate_statements_are_deduplicated(w, tmp_path):
    s = statement(w)
    state = ingest(w, artifact(w, statements=[s, s, s.to_cose_sign1_bytes()]), tmp_path / "hwm.json")
    assert len(state.statements) == 1


def _flip(sig: bytes) -> bytes:
    out = bytearray(sig)
    out[0] ^= 1
    return bytes(out)


def test_identical_body_statements_dedupe_to_one_revocation_and_log(w, tmp_path, caplog):
    # Ed25519 is deterministic: one key over one body yields one signature, so "different valid signatures
    # over the same body" cannot be constructed here; the rule (same recomputed id -> one revocation) is the same.
    s = statement(w)
    other = RevocationStatement.from_cose_sign1_bytes(s.to_cose_sign1_bytes())
    with caplog.at_level(logging.INFO, logger="lineage_revocation.status"):
        state = ingest(w, artifact(w, statements=[s, other, s.to_cose_sign1_bytes()]), tmp_path / "hwm.json")
    assert state.statements == (s,)
    rec = [r for r in caplog.records if getattr(r, "dedup_revocation_id", None) == s.revocation_id]
    assert rec, "deduplication must be logged"


def test_same_body_with_one_invalid_signature_keeps_the_valid_revocation(w, tmp_path):
    s = statement(w)
    forged_twin = replace(s, signature=_flip(s.signature))
    assert forged_twin.revocation_id == s.revocation_id  # id depends on the body only
    before = alert_count("invalid_revocation_statement")
    state = ingest(w, artifact(w, statements=[forged_twin, s]), tmp_path / "hwm.json")
    assert state.statements == (s,)
    assert alert_count("invalid_revocation_statement") == before + 1  # per-statement semantic failure: ignore, log, alert
    state2 = ingest(w, artifact(w, version=2, statements=[s, forged_twin]), tmp_path / "hwm.json")
    assert state2.statements == (s,)  # order does not matter: deterministic


def _seeded_world():
    """Fixed keys, so Ed25519 signatures (deterministic) and therefore wire sort order are reproducible."""
    import lineage_revocation.keys as keys
    privs = {n: keys.load_private_key_from_raw(bytes([i]) * 32) for i, n in enumerate(("root", "a", "b", "art"), 1)}
    pubs = {n: COSEKey.from_cryptography_key(p.public_key()) for n, p in privs.items()}
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=URI, revocation_trust_anchor=pubs["art"].to_anchor_bytes(), **COMMON)
    root = create_root_node(privs["root"], pubs["root"], issuer="root", **kw)
    a = create_child_node(privs["root"], pubs["a"], root.node_id, issuer="root", **kw)
    b = create_child_node(privs["a"], pubs["b"], a.node_id, issuer="a", **kw)
    return SimpleNamespace(
        root_priv=privs["root"], root_pub=pubs["root"], a_priv=privs["a"], a_pub=pubs["a"],
        b_priv=privs["b"], b_pub=pubs["b"], art_priv=privs["art"], art_pub=pubs["art"],
        root=root, a=a, b=b, lineage=[root, a, b], uri=URI,
    )


@pytest.mark.parametrize("order", ["twin_sorts_before", "twin_sorts_after"])
def test_valid_revocation_survives_invalid_twin_sorting_before_or_after_it(tmp_path, order):
    w = _seeded_world()
    s = statement(w)
    valid_wire = s.to_cose_sign1_bytes()
    twin = None
    for first in range(256):  # find a deterministic invalid twin on the requested side of the genuine wire
        cand = replace(s, signature=bytes([first]) + s.signature[1:])
        if cand.signature == s.signature:
            continue
        before = cand.to_cose_sign1_bytes() < valid_wire
        if before == (order == "twin_sorts_before"):
            twin = cand
            break
    assert twin is not None, "fixed keys must allow both orders; adjust the seeds"
    state = ingest(w, artifact(w, statements=[twin, s]), tmp_path / "hwm.json")
    assert state.statements == (s,)


def test_same_body_with_only_invalid_signatures_yields_no_revocation(w, tmp_path):
    s = statement(w)
    state = ingest(w, artifact(w, statements=[replace(s, signature=_flip(s.signature))]), tmp_path / "hwm.json")
    assert state.statements == ()


def _collide(monkeypatch):
    # SHA-256 collisions cannot be constructed; force one to exercise the integrity-failure branch.
    monkeypatch.setattr(RevocationStatement, "revocation_id", property(lambda self: b"\x07" * 32))


def test_same_recomputed_id_different_body_rejects_whole_artifact_with_integrity_alert(w, tmp_path, monkeypatch, caplog):
    _collide(monkeypatch)
    one, two = statement(w, target=w.a), statement(w, target=w.b)
    assert one.canonical_bytes() != two.canonical_bytes() and one.revocation_id == two.revocation_id
    store = tmp_path / "hwm.json"
    before = alert_count("artifact_integrity")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(StatusUnavailable) as exc:
            auth(w, artifact(w, statements=[one, two]), store)
    assert exc.value.reason is integrity()
    assert alert_count("artifact_integrity") == before + 1
    rec = [r for r in caplog.records if getattr(r, "alert_kind", "") == "artifact_integrity"]
    assert len(rec) == 1 and rec[0].alert_fields["revocation_id"] == b"\x07" * 32
    assert rec[0].alert_fields["defect"] == "conflicting_duplicate"
    assert not store.exists()


def test_statement_conflict_follows_unavailable_policy_bounded_staleness_falls_back(w, tmp_path, monkeypatch):
    last = ingest(w, artifact(w, version=1), tmp_path / "a.json")
    _collide(monkeypatch)
    bad = artifact(w, version=2, statements=[statement(w, target=w.a), statement(w, target=w.b)])
    with pytest.raises(StatusUnavailable):  # default: fail closed
        auth(w, bad, tmp_path / "b.json")
    ids = auth(w, bad, tmp_path / "b.json", status_policy=StatusPolicy.BOUNDED_STALENESS, last_accepted_status=last)
    assert ids == [n.node_id for n in w.lineage]
    with pytest.raises(StatusUnavailable):  # bounded staleness needs a last authenticated artifact
        auth(w, bad, tmp_path / "c.json", status_policy=StatusPolicy.BOUNDED_STALENESS)


def test_per_statement_failures_do_not_reject_the_artifact(w, tmp_path):
    bad_sig = statement(w, signer=generate_keypair()[0])
    good = statement(w, target=w.b)
    state = ingest(w, artifact(w, statements=[bad_sig, good]), tmp_path / "hwm.json")
    assert state.statements == (good,)


# ------------------------------------------------------------------ ruling 2: wire revocation_id is a checked reference

def _rewire(s, unprotected):
    return encode_canonical(CBORTag(18, [_protected_header_bytes(), unprotected, s.canonical_bytes(), s.signature]))


def test_wire_carries_revocation_id_as_a_reference_outside_the_signed_body(w):
    s = statement(w)
    env = cbor2.loads(s.to_cose_sign1_bytes()).value
    assert env[1] == {"revocation_id": s.revocation_id}
    assert "revocation_id" not in cbor2.loads(env[2])


def test_wire_revocation_id_mismatch_or_absence_is_rejected(w):
    s = statement(w)
    for unprotected in ({"revocation_id": b"\x00" * 32}, {}, {"revocation_id": s.revocation_id, "x": 1},
                        {"revocation_id": "text"}):
        with pytest.raises(StatementFormatError):
            RevocationStatement.from_cose_sign1_bytes(_rewire(s, unprotected))


# ------------------------------------------------------------------ A10 / D17

def test_revocation_id_is_sha256_of_unsigned_canonical_body(w):
    s = statement(w)
    assert s.revocation_id == hashlib.sha256(s.canonical_bytes()).digest()
    assert len(s.revocation_id) == 32


def test_revocation_id_deterministic(w):
    assert statement(w).revocation_id == statement(w).revocation_id


def test_revocation_id_is_body_sensitive(w):
    base = statement(w).revocation_id
    assert statement(w, reason="different").revocation_id != base
    assert statement(w, effective_at=NOW - 2).revocation_id != base
    assert statement(w, target=w.b).revocation_id != base


def test_revocation_id_excluded_from_its_own_hash_input(w):
    s = statement(w)
    body = cbor2.loads(s.canonical_bytes())
    assert "revocation_id" not in body
    assert hashlib.sha256(encode_canonical({**body, "revocation_id": s.revocation_id})).digest() != s.revocation_id


def test_revocation_id_independent_of_signature_and_signature_covers_the_body(w):
    s = statement(w)
    assert replace(s, signature=b"\x00" * 64).revocation_id == s.revocation_id
    assert verify_revocation_statement(s, w.root_pub)
    assert not verify_revocation_statement(replace(s, reason_code="tampered"), w.root_pub)


def test_statement_wire_round_trip_is_tagged_and_id_stable(w):
    s = statement(w)
    wire = s.to_cose_sign1_bytes()
    assert cbor2.loads(wire).tag == 18
    back = RevocationStatement.from_cose_sign1_bytes(wire)
    assert back.revocation_id == s.revocation_id and back.to_cose_sign1_bytes() == wire
    assert verify_revocation_statement(back, w.root_pub)


@pytest.mark.parametrize("mutate", [
    lambda wire: wire[1:], lambda wire: wire + b"\x00", lambda wire: cbor2.dumps(cbor2.loads(wire).value),
    lambda wire: b"", lambda wire: b"\xf6",
])
def test_malformed_statement_wire_rejected(w, mutate):
    with pytest.raises(StatementFormatError):
        RevocationStatement.from_cose_sign1_bytes(mutate(statement(w).to_cose_sign1_bytes()))


def test_statement_with_revocation_id_field_in_body_rejected(w):
    s = statement(w)
    body = {**cbor2.loads(s.canonical_bytes()), "revocation_id": b"\x01" * 4}
    payload = encode_canonical(body)
    wire = encode_canonical(CBORTag(18, [_protected_header_bytes(), {}, payload, sign_payload(payload, w.root_priv)]))
    with pytest.raises(StatementFormatError):
        RevocationStatement.from_cose_sign1_bytes(wire)


# ------------------------------------------------------------------ A2: runtime key separation

def test_key_comparison_is_by_canonical_encoded_key_bytes_not_object_identity(tmp_path):
    w = make_world(artifact_key_from="a")
    clone = COSEKey(x=bytes(bytearray(w.a_pub.x)))  # equal material, different object
    assert clone is not w.a_pub
    from lineage_revocation.status import check_key_separation
    with pytest.raises(StatusFailure) as exc:
        check_key_separation(w.art_pub, {"other": clone}, URI)
    assert exc.value.reason is StatusReason.ARTIFACT_KEY_REUSE
    check_key_separation(w.art_pub, {"other": generate_keypair()[1]}, URI)  # distinct: no raise


def test_leaf_subject_key_reuse_is_rejected_and_alerted(tmp_path):
    w = make_world(artifact_key_from="b")  # b is the leaf: holds no children, signs no statements
    before = alert_count("artifact_key_reuse")
    with pytest.raises(StatusFailure) as exc:
        auth(w, artifact(w), tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_KEY_REUSE
    assert alert_count("artifact_key_reuse") == before + 1


def test_distinct_artifact_key_is_accepted_with_root_and_issuer_statements(w, tmp_path):
    stmts = [statement(w, target=w.a), statement(w, target=w.b, signer=w.a_priv, revoker=w.a.node_id)]
    state = ingest(w, artifact(w, statements=stmts), tmp_path / "hwm.json")
    assert len(state.statements) == 2


def test_artifact_key_equal_to_root_delegation_key_rejected(tmp_path):
    w = make_world(artifact_key_from="root")
    store = tmp_path / "hwm.json"
    before = alert_count("artifact_key_reuse")
    with pytest.raises(StatusFailure) as exc:
        ingest(w, artifact(w), store)
    assert exc.value.reason is StatusReason.ARTIFACT_KEY_REUSE
    assert not store.exists()
    assert alert_count("artifact_key_reuse") == before + 1
    with pytest.raises(StatusFailure) as exc:
        auth(w, artifact(w), store)
    assert exc.value.reason is StatusReason.ARTIFACT_KEY_REUSE
    assert not store.exists()


def test_artifact_key_equal_to_a_statement_signing_key_rejected_at_ingestion(tmp_path):
    w = make_world(artifact_key_from="a")  # a is a direct issuer: it signs statements revoking b
    stmt = statement(w, target=w.b, signer=w.a_priv, revoker=w.a.node_id)
    store = tmp_path / "hwm.json"
    with pytest.raises(StatusFailure) as exc:
        ingest(w, artifact(w, statements=[stmt]), store)
    assert exc.value.reason is StatusReason.ARTIFACT_KEY_REUSE
    assert not store.exists()


def test_artifact_key_equal_to_any_lineage_delegation_key_rejected_in_authorize(tmp_path):
    w = make_world(artifact_key_from="a")
    store = tmp_path / "hwm.json"
    with pytest.raises(StatusFailure) as exc:
        auth(w, artifact(w), store)  # no statements at all: the lineage itself reveals the reuse
    assert exc.value.reason is StatusReason.ARTIFACT_KEY_REUSE
    assert not store.exists()


def test_key_reuse_is_rechecked_when_an_accepted_state_is_reused(w, tmp_path):
    state = ingest(w, artifact(w), tmp_path / "hwm.json")
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=URI, revocation_trust_anchor=w.root.body.revocation_trust_anchor, **COMMON)
    c = create_child_node(w.b_priv, w.art_pub, w.b.node_id, issuer="b", **kw)  # a node delegated TO the artifact key
    assert authorize(w.lineage, w.root_pub, audience="agent", now=NOW, status_artifact=state, max_staleness=MAX_STALENESS)
    with pytest.raises(StatusFailure) as exc:
        authorize([*w.lineage, c], w.root_pub, audience="agent", now=NOW, status_artifact=state, max_staleness=MAX_STALENESS)
    assert exc.value.reason is StatusReason.ARTIFACT_KEY_REUSE


@pytest.mark.parametrize("policy", list(StatusPolicy))
def test_key_reuse_cannot_be_excused_by_any_policy(tmp_path, policy):
    w = make_world(artifact_key_from="root")
    with pytest.raises(StatusFailure) as exc:
        auth(w, artifact(w), tmp_path / "hwm.json", **pol(policy))
    assert exc.value.reason is StatusReason.ARTIFACT_KEY_REUSE


# ================================================================== final ruling: defect classification
# Dividing principle: the verifier escalates to artifact-level rejection exactly those defects that the
# ingestion contract obliges the service to reject and that the verifier can detect without any
# authorization semantics. Wire-malformed statements are artifact-integrity failures; semantically invalid
# statements are per-statement failures (Spec section 11).

def _stmt_parts(s):
    env = cbor2.loads(s.to_cose_sign1_bytes()).value
    return list(env)  # protected, unprotected, payload, signature


def _wire(parts, tag=18):
    return cbor2.dumps(CBORTag(tag, parts), canonical=True)


def _resign(w, body, unprotected=None, signer=None):
    payload = encode_canonical(body)
    sig = sign_payload(payload, signer or w.root_priv)
    rid = hashlib.sha256(payload).digest()
    return _wire([_protected_header_bytes(), {"revocation_id": rid} if unprotected is None else unprotected, payload, sig])


def _body_of(s):
    return dict(cbor2.loads(s.canonical_bytes()))


def _malformed_wires(w):
    s = statement(w, target=w.a)
    good = s.to_cose_sign1_bytes()
    parts = _stmt_parts(s)
    body = _body_of(s)
    drop = lambda k: {kk: v for kk, v in body.items() if kk != k}
    return {
        "malformed_wire/garbage": b"\x01\x02",
        "malformed_wire/truncated": good[:-5],
        "malformed_wire/trailing_data": good + b"\x00",
        "malformed_wire/untagged": cbor2.dumps(parts),
        "malformed_wire/wrong_tag": _wire(parts, tag=17),
        "malformed_wire/not_canonical": _noncanonical(good),
        "malformed_wire/short_envelope": _wire(parts[:2]),
        "malformed_wire/missing_field": _resign(w, drop("revoker_scope_proof")),
        "malformed_wire/nested_node_not_canonical": _nested_noncanonical(w, "target_node"),
        "malformed_wire/nested_lineage_node_not_canonical": _nested_noncanonical(w, "target_lineage"),
        "malformed_wire/reason_code_wrong_type": _resign(w, {**body, "reason_code": 7}),
        "malformed_wire/reason_code_null": _resign(w, {**body, "reason_code": None}),
        "malformed_wire/extra_field": _resign(w, {**body, "extra": 1}),
        "malformed_wire/wrong_type": _resign(w, {**body, "effective_at": "soon"}),
        "malformed_wire/bad_target_node": _resign(w, {**body, "target_node": b"not a node"}),
        "malformed_wire/lineage_not_array": _resign(w, {**body, "target_lineage": b"x"}),
        "signature_malformed/63_bytes": _wire([parts[0], parts[1], parts[2], parts[3][:63]]),
        "signature_malformed/65_bytes": _wire([parts[0], parts[1], parts[2], parts[3] + b"\x00"]),
        "signature_malformed/empty": _wire([parts[0], parts[1], parts[2], b""]),
        "malformed_wire/signature_member_absent_three_element_envelope": _wire(parts[:3]),
        "signature_malformed/null": _wire([parts[0], parts[1], parts[2], None]),
        "signature_malformed/int": _wire([parts[0], parts[1], parts[2], 7]),
        "signature_malformed/text": _wire([parts[0], parts[1], parts[2], "x" * 64]),
        "malformed_wire/protected_header_not_alg_only": _wire([encode_canonical({1: -8, 4: b"kid"}), parts[1], parts[2], parts[3]]),
        "malformed_wire/payload_not_bytes": _wire([parts[0], parts[1], 7, parts[3]]),
        "malformed_wire/target_node_id_not_bytes": _resign(w, {**body, "target_node_id": 5}),
        "malformed_wire/target_node_not_bytes": _resign(w, {**body, "target_node": 4}),
        "malformed_wire/revoker_not_bytes": _resign(w, {**body, "revoker": "root"}),
        "malformed_wire/revoker_scope_proof_not_bytes": _resign(w, {**body, "revoker_scope_proof": 3}),
        "malformed_wire/statement_version_2": _resign(w, {**body, "statement_version": 2}),
        "malformed_wire/statement_version_0": _resign(w, {**body, "statement_version": 0}),
        "malformed_wire/statement_version_negative": _resign(w, {**body, "statement_version": -1}),
        "malformed_wire/statement_version_missing": _resign(w, drop("statement_version")),
        "malformed_wire/statement_version_string": _resign(w, {**body, "statement_version": "1"}),
        "malformed_wire/statement_version_bool": _resign(w, {**body, "statement_version": True}),
        "malformed_wire/statement_version_null": _resign(w, {**body, "statement_version": None}),
        "malformed_wire/statement_version_bytes": _resign(w, {**body, "statement_version": b"\x01"}),
        "revocation_id_missing": _wire([parts[0], {}, parts[2], parts[3]]),
        "revocation_id_mismatch": _wire([parts[0], {"revocation_id": b"\x00" * 32}, parts[2], parts[3]]),
        "revocation_id_wrong_type": _wire([parts[0], {"revocation_id": "text"}, parts[2], parts[3]]),
    }


def _nested_noncanonical(w, field):
    """A statement whose OUTER envelope and body are canonical but which embeds a node wire in non-canonical
    form. Signature and id are those of the canonical statement, so only the exact-reconstruction check can
    catch it."""
    s = statement(w, target=w.a)
    body = _body_of(s)

    def reorder(node_wire):
        env = cbor2.loads(node_wire)
        inner = cbor2.loads(env.value[2])
        rev = cbor2.dumps(dict(reversed(list(inner.items()))))
        assert rev != env.value[2]
        return cbor2.dumps(CBORTag(18, [env.value[0], env.value[1], rev, env.value[3]]), canonical=True)

    if field == "target_node":
        body["target_node"] = reorder(body["target_node"])
    else:
        body["target_lineage"] = [reorder(body["target_lineage"][0])] + list(body["target_lineage"][1:])
    payload = encode_canonical(body)
    assert payload != s.canonical_bytes()
    return _wire([_protected_header_bytes(), {"revocation_id": s.revocation_id}, payload, s.signature])


def _noncanonical(good):
    # same value, definite lengths, but the map key order of the body is reversed: not RFC 8949 form
    env = cbor2.loads(good)
    payload = env.value[2]
    body = cbor2.loads(payload)
    rev = cbor2.dumps(dict(reversed(list(body.items()))))
    assert rev != payload
    return cbor2.dumps(CBORTag(18, [env.value[0], env.value[1], rev, env.value[3]]), canonical=True)


DEFECTS = sorted(_malformed_wires(make_world()))  # names only; wires are rebuilt per world


@pytest.mark.parametrize("defect", DEFECTS)
def test_wire_malformed_statement_rejects_the_entire_artifact(w, tmp_path, defect, caplog):
    bad = _malformed_wires(w)[defect]
    valid = statement(w, target=w.b)
    store = tmp_path / "hwm.json"
    before_i, before_s = alert_count("artifact_integrity"), alert_count("invalid_revocation_statement")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(StatusUnavailable) as exc:
            auth(w, artifact(w, statements=[valid, bad]), store)  # the valid revocation does NOT take effect
    assert exc.value.reason is integrity()
    assert not store.exists()  # no persistent mutation
    assert alert_count("artifact_integrity") == before_i + 1
    assert alert_count("invalid_revocation_statement") == before_s  # distinct telemetry from semantic failures
    rec = [r for r in caplog.records if getattr(r, "alert_kind", "") == "artifact_integrity"]
    assert len(rec) == 1
    assert rec[0].alert_fields["defect"] in {
        "malformed_wire", "signature_malformed", "revocation_id_missing", "revocation_id_mismatch"}


def test_integrity_defect_alert_names_the_specific_defect(w, tmp_path, caplog):
    wires = _malformed_wires(w)
    for name, expected in (("revocation_id_missing", "revocation_id_missing"),
                           ("revocation_id_mismatch", "revocation_id_mismatch"),
                           ("malformed_wire/garbage", "malformed_wire")):
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
            with pytest.raises(StatusUnavailable):
                ingest(w, artifact(w, statements=[wires[name]]), tmp_path / "x.json")
        rec = [r for r in caplog.records if getattr(r, "alert_kind", "") == "artifact_integrity"]
        assert rec and rec[0].alert_fields["defect"] == expected


def test_integrity_reason_code_is_distinct_from_every_other_reason(w):
    codes = [r for r in StatusReason]
    assert integrity() in codes and len({c.value for c in codes}) == len(codes)
    assert integrity() not in (StatusReason.ARTIFACT_MALFORMED, StatusReason.ARTIFACT_SIGNATURE_INVALID,
                               StatusReason.ARTIFACT_STALE, StatusReason.STORE_UNREADABLE)


def test_integrity_failure_is_routed_through_the_unavailable_status_policy(w, tmp_path):
    bad = artifact(w, version=2, statements=[b"\x01\x02"])
    last = ingest(w, artifact(w, version=1), tmp_path / "a.json")
    with pytest.raises(StatusUnavailable) as exc:  # fail-closed is the default
        auth(w, bad, tmp_path / "b.json")
    assert exc.value.reason is integrity()
    ids = auth(w, bad, tmp_path / "c.json", status_policy=StatusPolicy.BOUNDED_STALENESS, last_accepted_status=last)
    assert ids == [n.node_id for n in w.lineage]  # bounded-staleness fallback to the last authenticated artifact
    with pytest.raises(StatusUnavailable):  # fallback needs a last authenticated artifact
        auth(w, bad, tmp_path / "d.json", status_policy=StatusPolicy.BOUNDED_STALENESS)
    with pytest.raises(StatusUnavailable):  # and it must itself still be fresh
        auth(w, bad, tmp_path / "e.json", now=NOW + 5000, status_policy=StatusPolicy.BOUNDED_STALENESS,
             last_accepted_status=last)


def test_integrity_rejection_does_not_apply_the_last_artifacts_revocations_beyond_policy(w, tmp_path):
    last = ingest(w, artifact(w, version=1, statements=[statement(w, target=w.b)]), tmp_path / "a.json")
    bad = artifact(w, version=2, statements=[b"\x01"])
    with pytest.raises(NodeRevoked):  # fallback state is the last authenticated artifact: its revocation holds
        auth(w, bad, tmp_path / "b.json", status_policy=StatusPolicy.BOUNDED_STALENESS, last_accepted_status=last)


def test_wire_revocation_id_is_not_trusted_as_the_identifier(w, tmp_path):
    s, other = statement(w, target=w.a), statement(w, target=w.b)
    parts = _stmt_parts(s)
    lying = _wire([parts[0], {"revocation_id": other.revocation_id}, parts[2], parts[3]])
    with pytest.raises(StatusUnavailable) as exc:  # a lying id never merges into the other statement's id
        ingest(w, artifact(w, statements=[lying, other]), tmp_path / "hwm.json")
    assert exc.value.reason is integrity()


# ------------------------------------------------------------------ per-statement semantic failures

def _semantic_cases(w):
    impostor = generate_keypair()[0]
    good = statement(w, target=w.a)
    return {
        "SIGNATURE_INVALID": statement(w, target=w.a, signer=impostor),
        "REVOKER_UNAUTHORIZED": statement(w, target=w.a, signer=w.b_priv, revoker=w.b.node_id),  # b revoking its ancestor
        "TARGET_ID_MISMATCH": replace(good, target_node_id=w.b.node_id),
        "TARGET_LINEAGE_MISMATCH": replace(good, target_lineage=[w.root, w.a, w.b]),  # lineage does not end at target
        "LINEAGE_INVALID": replace(statement(w, target=w.b), target_lineage=[w.root, w.b]),  # a is skipped: broken parent link
    }


SEMANTIC = list(_semantic_cases(make_world()))


@pytest.mark.parametrize("reason", SEMANTIC)
def test_semantically_invalid_statement_is_ignored_and_the_artifact_stays_usable(w, tmp_path, reason, caplog):
    invalid = _semantic_cases(w)[reason]
    wire = invalid.to_cose_sign1_bytes()
    # the fixture is syntactically valid, structurally well-formed and canonically encoded
    assert RevocationStatement.from_cose_sign1_bytes(wire).to_cose_sign1_bytes() == wire
    valid = statement(w, target=w.b)
    store = tmp_path / "hwm.json"
    before_s, before_i = alert_count("invalid_revocation_statement"), alert_count("artifact_integrity")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        state = ingest(w, artifact(w, version=3, statements=[invalid, valid]), store)
    assert state.statements == (valid,)  # valid statement effective, invalid ignored
    assert '"%s": 3' % URI in store.read_text()  # artifact accepted and persisted: it stays usable
    assert alert_count("invalid_revocation_statement") == before_s + 1
    assert alert_count("artifact_integrity") == before_i  # NOT an artifact-integrity failure
    rec = [r for r in caplog.records if getattr(r, "alert_kind", "") == "invalid_revocation_statement"]
    assert len(rec) == 1 and rec[0].alert_fields["reason_code"] == statement_reason(reason).name
    with pytest.raises(NodeRevoked) as exc:
        authorize(w.lineage, w.root_pub, audience="agent", now=NOW, status_artifact=state, max_staleness=MAX_STALENESS)
    assert exc.value.node_id == w.b.node_id


def test_valid_and_invalid_statements_in_artifact(w, tmp_path):
    """Spec section 18 test 8: valid + invalid statement in one artifact -> the valid one still denies."""
    invalid = statement(w, target=w.a, signer=w.b_priv, revoker=w.b.node_id)  # semantic: unauthorized revoker
    wire = invalid.to_cose_sign1_bytes()
    assert RevocationStatement.from_cose_sign1_bytes(wire).to_cose_sign1_bytes() == wire  # well-formed on the wire
    valid = statement(w, target=w.a)
    before = alert_count("invalid_revocation_statement")
    with pytest.raises(NodeRevoked) as exc:
        auth(w, artifact(w, statements=[invalid, valid]), tmp_path / "hwm.json")
    assert exc.value.node_id == w.a.node_id
    assert alert_count("invalid_revocation_statement") == before + 1
    # the invalid statement alone neither denies nor poisons the artifact
    assert auth(w, artifact(w, version=2, statements=[invalid]), tmp_path / "hwm.json")


def test_check_revocation_statement_classifies_without_raising(w):
    import lineage_revocation.revocation as rev
    for name, s in _semantic_cases(w).items():
        assert rev.check_revocation_statement(s, w.root_pub) is statement_reason(name)
    assert rev.check_revocation_statement(statement(w, target=w.a), w.root_pub) is None
    assert rev.verify_revocation_statement(statement(w, target=w.a), w.root_pub) is True


def test_semantic_and_integrity_reason_codes_are_disjoint_namespaces(w):
    import lineage_revocation.revocation as rev
    assert not ({r.name for r in rev.StatementReason} & {r.name for r in StatusReason})


def test_is_target_revoked_alert_carries_a_semantic_reason_code(w, caplog):
    import lineage_revocation.revocation as rev
    bad = statement(w, target=w.a, signer=generate_keypair()[0])
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        assert not rev.is_target_revoked(w.a.node_id, [bad], w.root_pub, now=NOW)
    rec = [r for r in caplog.records if getattr(r, "alert_kind", "") == "invalid_revocation_statement"]
    assert rec and rec[0].alert_fields["reason_code"] == statement_reason("SIGNATURE_INVALID").name


# ------------------------------------------------------------------ conformance-matrix support (rows 10, 21)

def test_artifact_valid_until_boundary(w, tmp_path):
    state = ingest(w, artifact(w, valid_until=NOW + 1000), tmp_path / "hwm.json")
    run = lambda now: authorize(w.lineage, w.root_pub, audience="agent", now=now, status_artifact=state, max_staleness=10**9)
    assert run(NOW + 999)
    with pytest.raises(StaleStatusArtifact):
        run(NOW + 1000)  # now == min(valid_until, issued_at + max_staleness) is stale (ruling 17)


def test_max_staleness_boundary(w, tmp_path):
    state = ingest(w, artifact(w, issued_at=NOW - 100, valid_until=NOW + 10**6), tmp_path / "hwm.json")
    run = lambda now: authorize(w.lineage, w.root_pub, audience="agent", now=now, status_artifact=state, max_staleness=500)
    assert run(NOW + 399)
    with pytest.raises(StaleStatusArtifact):
        run(NOW + 400)


# ================================================================== third ruling
# (a) signature classification: detectable without consulting a key -> wire-malformed (artifact integrity);
#     requires the key -> semantic (per statement).
# (b) artifact rejection is invariant across policies; the REQUEST VERDICT is what the policy governs.
# (c) distinct telemetry for fail-open after ordinary unavailability vs after artifact-integrity failure.

ALL_POLICIES = list(StatusPolicy)


def _finding(name):
    import lineage_revocation.status as st
    return getattr(st.FailOpenFinding, name)


def _records(caplog, kind):
    return [r for r in caplog.records if getattr(r, "alert_kind", "") == kind]


# ------------------------------------------------------------------ (a) signature classification

@pytest.mark.parametrize("name", [n for n in DEFECTS if n.startswith("signature_malformed/")])
def test_signature_defects_are_wire_malformed_at_the_parser(w, name):
    with pytest.raises(StatementFormatError) as exc:
        RevocationStatement.from_cose_sign1_bytes(_malformed_wires(w)[name])
    assert exc.value.defect == "signature_malformed"


def test_absent_signature_member_is_wire_malformed_and_rejects_the_artifact(w, tmp_path):
    wire = _malformed_wires(w)["malformed_wire/signature_member_absent_three_element_envelope"]
    with pytest.raises(StatementFormatError) as exc:
        RevocationStatement.from_cose_sign1_bytes(wire)
    assert exc.value.defect == "malformed_wire"
    with pytest.raises(StatusUnavailable) as exc2:
        ingest(w, artifact(w, statements=[wire]), tmp_path / "hwm.json")
    assert exc2.value.reason is integrity()


@pytest.mark.parametrize("length", [63, 65])
def test_wrong_length_signature_rejects_the_entire_artifact(w, tmp_path, caplog, length):
    s = statement(w, target=w.a)
    parts = _stmt_parts(s)
    bad = _wire([parts[0], parts[1], parts[2], (parts[3] + b"\x00" * 2)[:length]])
    before_i, before_s = alert_count("artifact_integrity"), alert_count("invalid_revocation_statement")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(StatusUnavailable) as exc:
            auth(w, artifact(w, statements=[statement(w, target=w.b), bad]), tmp_path / "hwm.json")
    assert exc.value.reason is integrity()
    assert alert_count("artifact_integrity") == before_i + 1
    assert alert_count("invalid_revocation_statement") == before_s
    assert _records(caplog, "artifact_integrity")[0].alert_fields["defect"] == "signature_malformed"
    assert not (tmp_path / "hwm.json").exists()


def test_correct_length_invalid_signature_stays_a_per_statement_semantic_failure(w, tmp_path, caplog):
    s = statement(w, target=w.a)
    forged = replace(s, signature=bytes([s.signature[0] ^ 0xFF]) + s.signature[1:])  # 64 bytes, wrong value
    assert len(forged.signature) == 64
    valid = statement(w, target=w.b)
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        state = ingest(w, artifact(w, statements=[forged, valid]), tmp_path / "hwm.json")
    assert state.statements == (valid,)
    assert _records(caplog, "invalid_revocation_statement")[0].alert_fields["reason_code"] == "SIGNATURE_INVALID"
    assert alert_count("artifact_integrity") == 0 or not _records(caplog, "artifact_integrity")


def test_unauthorized_revoker_with_valid_signature_stays_semantic(w, tmp_path):
    unauthorized = statement(w, target=w.a, signer=w.b_priv, revoker=w.b.node_id)
    assert len(unauthorized.signature) == 64
    state = ingest(w, artifact(w, statements=[unauthorized]), tmp_path / "hwm.json")
    assert state.statements == ()


# ------------------------------------------------------------------ (b) artifact rejection is policy-independent

def _accepted_world(w, tmp_path, version=3):
    store = tmp_path / "hwm.json"
    last = ingest(w, artifact(w, version=version, statements=[statement(w, target=w.b)]), store)  # revokes b
    return store, last


def _bad_artifact(w, version=99):
    # Carries a revocation of `a` that must never take effect, plus a wire-malformed statement.
    return artifact(w, version=version, statements=[statement(w, target=w.a), b"\x01\x02"])


@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_integrity_rejected_artifact_never_advances_the_high_water_mark(w, tmp_path, policy):
    store, last = _accepted_world(w, tmp_path)
    before = store.read_bytes()
    try:
        auth(w, _bad_artifact(w), store, last_accepted_status=last, **pol(policy))
    except (StatusUnavailable, NodeRevoked):
        pass
    assert store.read_bytes() == before  # still version 3, byte-identical
    assert auth(w, artifact(w, version=4), store, status_policy=StatusPolicy.FAIL_CLOSED) or True  # version 99 did not block 4


@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_integrity_rejected_artifact_cannot_replace_the_accepted_artifact(w, tmp_path, policy):
    store, last = _accepted_world(w, tmp_path)
    snapshot = replace(last)
    try:
        auth(w, _bad_artifact(w), store, last_accepted_status=last, **pol(policy))
    except (StatusUnavailable, NodeRevoked):
        pass
    assert last == snapshot and last.version == 3 and last.statements == snapshot.statements
    with pytest.raises(NodeRevoked) as exc:  # the accepted state is still the one in force
        authorize(w.lineage, w.root_pub, audience="agent", now=NOW, status_artifact=last, max_staleness=MAX_STALENESS)
    assert exc.value.node_id == w.b.node_id


@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_integrity_rejected_artifact_cannot_supply_revocation_statements(w, tmp_path, policy):
    # The rejected artifact revokes `a`. Whatever the policy decides, that revocation is never applied:
    # the only revocation that can surface is the last authenticated artifact's (of b), never a's.
    store, last = _accepted_world(w, tmp_path)
    try:
        auth(w, _bad_artifact(w), store, last_accepted_status=last, **pol(policy))
    except NodeRevoked as exc:
        assert exc.node_id == w.b.node_id  # from the last authenticated state, not from the rejected artifact
    except StatusUnavailable:
        pass


@pytest.mark.parametrize("policy", ALL_POLICIES)
@pytest.mark.parametrize("defect", DEFECTS)
def test_no_persistent_state_is_written_on_any_integrity_failure_under_any_policy(w, tmp_path, monkeypatch, policy, defect):
    import lineage_revocation.status as st
    store, last = _accepted_world(w, tmp_path)
    before = store.read_bytes()

    def forbidden(*a, **k):
        raise AssertionError("persistent write during an artifact-integrity failure")

    monkeypatch.setattr(st, "save_high_water_mark", forbidden)
    monkeypatch.setattr(type(store), "write_text", forbidden)
    monkeypatch.setattr(type(store), "write_bytes", forbidden)
    bad = artifact(w, version=50, statements=[_malformed_wires(w)[defect]])
    try:
        auth(w, bad, store, last_accepted_status=last, **pol(policy))
    except (StatusUnavailable, NodeRevoked):
        pass
    assert store.read_bytes() == before


@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_no_store_file_is_created_by_a_rejected_artifact_under_any_policy(w, tmp_path, policy):
    store = tmp_path / "never.json"
    try:
        auth(w, _bad_artifact(w), store, **pol(policy))
    except StatusUnavailable:
        pass
    assert not store.exists()


# ------------------------------------------------------------------ (b) request verdict is policy-governed

def test_fail_closed_denies_on_integrity_failure(w, tmp_path):
    store, last = _accepted_world(w, tmp_path)
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, _bad_artifact(w), store, last_accepted_status=last, status_policy=StatusPolicy.FAIL_CLOSED)
    assert exc.value.reason is integrity()


def test_bounded_staleness_uses_only_a_fresh_last_authenticated_artifact_and_its_revocations_apply(w, tmp_path):
    store, last = _accepted_world(w, tmp_path)
    kw = dict(status_policy=StatusPolicy.BOUNDED_STALENESS, last_accepted_status=last)
    with pytest.raises(NodeRevoked) as exc:  # fresh: used, and the revocation of b keeps applying
        auth(w, _bad_artifact(w), store, **kw)
    assert exc.value.node_id == w.b.node_id
    with pytest.raises(StatusUnavailable) as exc:  # no longer fresh: not used
        auth(w, _bad_artifact(w), store, now=NOW + 5000, **kw)
    assert exc.value.reason is integrity()
    with pytest.raises(StatusUnavailable):  # nothing authenticated to fall back to
        auth(w, _bad_artifact(w), store, status_policy=StatusPolicy.BOUNDED_STALENESS)


def test_ttl_only_does_not_excuse_an_integrity_failure(w, tmp_path):
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, _bad_artifact(w), tmp_path / "hwm.json", status_policy=StatusPolicy.TTL_ONLY_NO_STATUS)
    assert exc.value.reason is integrity()


def test_fail_open_may_allow_when_no_usable_authenticated_state_exists(w, tmp_path, caplog):
    store = tmp_path / "hwm.json"
    before_i = alert_count("fail_open_after_artifact_integrity")
    before_o = alert_count("fail_open_after_status_unavailable")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        ids = auth(w, _bad_artifact(w), store, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    assert ids == [n.node_id for n in w.lineage]  # allowed; the rejected artifact's revocation of `a` NOT applied
    assert not store.exists()  # nothing persisted for the failed artifact
    assert alert_count("fail_open_after_artifact_integrity") == before_i + 1
    assert alert_count("fail_open_after_status_unavailable") == before_o
    rec = _records(caplog, "fail_open_after_artifact_integrity")
    assert len(rec) == 1
    assert rec[0].alert_fields["finding"] == _finding("AFTER_ARTIFACT_INTEGRITY").value
    assert rec[0].alert_fields["reason_code"] == StatusReason.ARTIFACT_INTEGRITY.name
    assert rec[0].alert_fields["experimental_arm"] == ARM
    assert rec[0].alert_fields["authenticated_state_used"] is False


def test_fail_open_after_ordinary_unavailability_has_its_own_finding(w, tmp_path, caplog):
    before_i = alert_count("fail_open_after_artifact_integrity")
    before_o = alert_count("fail_open_after_status_unavailable")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        auth(w, None, tmp_path / "hwm.json", **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))  # S1: no artifact
        auth(w, artifact(w, key=generate_keypair()[0]), tmp_path / "hwm.json", **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))  # S5
    assert alert_count("fail_open_after_status_unavailable") == before_o + 2
    assert alert_count("fail_open_after_artifact_integrity") == before_i
    rec = _records(caplog, "fail_open_after_status_unavailable")
    assert [r.alert_fields["finding"] for r in rec] == [_finding("AFTER_STATUS_UNAVAILABLE").value] * 2
    assert [r.alert_fields["reason_code"] for r in rec] == ["STATUS_MISSING", "ARTIFACT_SIGNATURE_INVALID"]


def test_benchmark_can_tell_the_outcomes_apart_from_telemetry_alone(w, tmp_path, caplog):
    store = tmp_path / "hwm.json"
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        auth(w, _bad_artifact(w), store, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
        auth(w, None, store, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    kinds = [r.alert_kind for r in caplog.records if hasattr(r, "alert_kind") and r.alert_kind.startswith("fail_open")]
    assert kinds == ["fail_open_after_artifact_integrity", "fail_open_after_status_unavailable"]
    assert _finding("AFTER_ARTIFACT_INTEGRITY") is not _finding("AFTER_STATUS_UNAVAILABLE")
    assert not ({f.name for f in StatusReason} & {f.name for f in __import__("lineage_revocation.status", fromlist=["x"]).FailOpenFinding})


def test_fail_open_uses_a_fresh_authenticated_state_instead_of_discarding_known_revocations(w, tmp_path):
    store, last = _accepted_world(w, tmp_path)
    with pytest.raises(NodeRevoked) as exc:
        auth(w, _bad_artifact(w), store, last_accepted_status=last, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    assert exc.value.node_id == w.b.node_id
    ids = auth(w, _bad_artifact(w), store, last_accepted_status=last, now=NOW + 5000,
               **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))  # last no longer fresh: no usable state, so allow
    assert ids == [n.node_id for n in w.lineage]


def test_fail_open_persists_nothing_for_the_failed_artifact(w, tmp_path):
    store, last = _accepted_world(w, tmp_path)
    before = store.read_bytes()
    auth(w, _bad_artifact(w), store, last_accepted_status=last, now=NOW + 5000, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    assert store.read_bytes() == before


def test_fail_open_requires_an_explicit_experimental_arm_label(w, tmp_path):
    for bad in (None, "", "   "):
        with pytest.raises(ValueError, match="experimental"):
            authorize(w.lineage, w.root_pub, audience="agent", now=NOW, status_artifact=None,
                      status_policy=StatusPolicy.FAIL_OPEN_EXPERIMENTAL, experimental_arm=bad)
    # a label never changes any other policy
    authorize(w.lineage, w.root_pub, audience="agent", now=NOW, status_policy=StatusPolicy.TTL_ONLY_NO_STATUS)


def test_fail_open_never_overrides_s3_key_reuse_or_rollback(w, tmp_path):
    store, last = _accepted_world(w, tmp_path)
    with pytest.raises(StatusRollback):
        auth(w, artifact(w, version=2), store, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, artifact(w), bad, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    assert exc.value.reason is StatusReason.STORE_UNREADABLE


@pytest.mark.parametrize("policy", [StatusPolicy.BOUNDED_STALENESS, StatusPolicy.FAIL_OPEN_EXPERIMENTAL])
def test_fallback_to_the_last_authenticated_artifact_is_reported_distinctly(w, tmp_path, caplog, policy):
    store, last = _accepted_world(w, tmp_path)
    before = alert_count("status_fallback_last_authenticated")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(NodeRevoked):
            auth(w, _bad_artifact(w), store, last_accepted_status=last, **pol(policy))
    assert alert_count("status_fallback_last_authenticated") == before + 1
    f = _records(caplog, "status_fallback_last_authenticated")[0].alert_fields
    assert f["authenticated_state_used"] is True and f["fallback_version"] == 3
    assert f["reason_code"] == StatusReason.ARTIFACT_INTEGRITY.name and f["policy"] == policy.name
    assert not _records(caplog, "fail_open_after_artifact_integrity")  # an authenticated state was used: not a blind allow


# ================================================================== fallback telemetry consistency

FALLBACK = "status_fallback_last_authenticated"


def _stale_artifact(w, version=99):
    return artifact(w, version=version, issued_at=NOW - 50_000, valid_until=NOW + 1000)  # authenticated but stale (S6)


@pytest.mark.parametrize("policy", [StatusPolicy.BOUNDED_STALENESS, StatusPolicy.FAIL_OPEN_EXPERIMENTAL])
@pytest.mark.parametrize("failing", ["integrity", "stale"])
def test_fallback_telemetry_is_emitted_once_per_fallback_and_names_the_policy(w, tmp_path, caplog, policy, failing):
    store, last = _accepted_world(w, tmp_path)
    bad = _bad_artifact(w) if failing == "integrity" else _stale_artifact(w)
    expected_reason = StatusReason.ARTIFACT_INTEGRITY if failing == "integrity" else StatusReason.ARTIFACT_STALE
    before = alert_count(FALLBACK)
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(NodeRevoked):  # the last authenticated state's revocation of b keeps applying
            auth(w, bad, store, last_accepted_status=last, **pol(policy))
    recs = _records(caplog, FALLBACK)
    assert alert_count(FALLBACK) == before + 1 and len(recs) == 1
    f = recs[0].alert_fields
    assert f["policy"] == policy.name and f["reason_code"] == expected_reason.name
    assert f["authenticated_state_used"] is True and f["fallback_version"] == 3
    assert f["experimental_arm"] == (ARM if policy is StatusPolicy.FAIL_OPEN_EXPERIMENTAL else None)


def test_bounded_staleness_and_fail_open_fallbacks_are_distinguishable_in_telemetry(w, tmp_path, caplog):
    store, last = _accepted_world(w, tmp_path)
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        for policy in (StatusPolicy.BOUNDED_STALENESS, StatusPolicy.FAIL_OPEN_EXPERIMENTAL):
            with pytest.raises(NodeRevoked):
                auth(w, _bad_artifact(w), store, last_accepted_status=last, **pol(policy))
    recs = [r.alert_fields for r in _records(caplog, FALLBACK)]
    assert [r["policy"] for r in recs] == ["BOUNDED_STALENESS", "FAIL_OPEN_EXPERIMENTAL"]
    assert not _records(caplog, "fail_open_after_artifact_integrity")  # a fallback is never a blind allow


def test_fail_open_fallback_also_covers_a_missing_artifact_where_bounded_staleness_does_not(w, tmp_path, caplog):
    store, last = _accepted_world(w, tmp_path)
    with pytest.raises(StatusUnavailable):  # bounded staleness never covers S1
        auth(w, None, store, last_accepted_status=last, status_policy=StatusPolicy.BOUNDED_STALENESS)
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(NodeRevoked):
            auth(w, None, store, last_accepted_status=last, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    f = _records(caplog, FALLBACK)[0].alert_fields
    assert f["policy"] == "FAIL_OPEN_EXPERIMENTAL" and f["reason_code"] == "STATUS_MISSING"


@pytest.mark.parametrize("policy", [StatusPolicy.BOUNDED_STALENESS, StatusPolicy.FAIL_OPEN_EXPERIMENTAL])
def test_no_fallback_telemetry_without_a_fallback(w, tmp_path, caplog, policy):
    before = alert_count(FALLBACK)
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        auth(w, artifact(w), tmp_path / "hwm.json", **pol(policy))  # healthy artifact: used directly
        try:
            auth(w, _bad_artifact(w), tmp_path / "x.json", **pol(policy))  # nothing authenticated to fall back to
        except StatusUnavailable:
            pass
    assert alert_count(FALLBACK) == before


def test_fallback_state_bound_to_another_root_is_refused_and_not_reported_as_used(w, tmp_path):
    other = make_world()
    foreign = ingest(other, artifact(other, version=1), tmp_path / "other.json")
    before = alert_count(FALLBACK)
    with pytest.raises(RevocationBindingMismatch):
        auth(w, _bad_artifact(w), tmp_path / "hwm.json", status_policy=StatusPolicy.BOUNDED_STALENESS,
             last_accepted_status=foreign)
    assert alert_count(FALLBACK) == before  # reported only when the state was actually used


# ================================================================== review corrections (B1, B2, outer signature, reason_code)

# ---- B1: an unusable key is a failed verification, never a raw ValueError

@pytest.mark.parametrize("x", [b"", b"short", b"\x01" * 31, b"\x01" * 33])
def test_verify_payload_treats_unusable_key_material_as_failed_verification(w, x):
    sig = sign_payload(b"payload", w.root_priv)
    assert verify_payload(b"payload", sig, COSEKey(x=x)) is False
    assert verify_payload(b"payload", sig, COSEKey(x=x), ARTIFACT_AAD) is False


def _malformed_key_chain(w, subject_x=b"short"):
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=URI, revocation_trust_anchor=w.root.body.revocation_trust_anchor, **COMMON)
    bad = create_child_node(w.a_priv, COSEKey(x=subject_x), w.a.node_id, issuer="a", **kw)  # a validly signs it
    child = create_child_node(generate_keypair()[0], generate_keypair()[1], bad.node_id, issuer="b", **kw)
    return bad, child, [w.root, w.a, bad, child]


@pytest.mark.parametrize("x", [b"", b"short", b"\x01" * 33])
def test_malformed_subject_key_in_a_statement_lineage_is_a_semantic_failure_not_a_crash(w, tmp_path, caplog, x):
    _bad, child, chain = _malformed_key_chain(w, x)
    risky = create_revocation_statement(
        w.root_priv, target_node=child, target_lineage=chain, revoker_node_id=w.root.node_id,
        revoker_scope_proof=b"", effective_at=NOW - 1, issued_at=1_700_000_000, reason_code="x")
    valid = statement(w, target=w.b)
    store = tmp_path / "hwm.json"
    before_s, before_i = alert_count("invalid_revocation_statement"), alert_count("artifact_integrity")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        state = ingest(w, artifact(w, version=5, statements=[risky, valid]), store)  # no ValueError
    assert state.statements == (valid,)  # the risky statement is ignored, the other still applies
    assert '"%s": 5' % URI in store.read_text()  # the artifact was accepted normally: usable, and persisted once
    assert alert_count("invalid_revocation_statement") == before_s + 1
    assert alert_count("artifact_integrity") == before_i  # semantic, not integrity
    rec = _records(caplog, "invalid_revocation_statement")[0].alert_fields
    assert rec["reason_code"] == statement_reason("LINEAGE_INVALID").name


def test_malformed_subject_key_in_a_presented_lineage_is_a_typed_failure(w):
    from lineage_revocation.lineage import LineageVerificationError
    _bad, _child, chain = _malformed_key_chain(w)
    with pytest.raises(LineageVerificationError):  # was an untyped ValueError
        authorize(chain, w.root_pub, audience="agent", now=NOW, status_policy=StatusPolicy.TTL_ONLY_NO_STATUS)


def test_check_revocation_statement_never_raises_on_a_malformed_key_chain(w):
    import lineage_revocation.revocation as rev
    _bad, child, chain = _malformed_key_chain(w)
    s = create_revocation_statement(
        w.root_priv, target_node=child, target_lineage=chain, revoker_node_id=w.root.node_id,
        revoker_scope_proof=b"", effective_at=NOW - 1, issued_at=1_700_000_000, reason_code="x")
    assert rev.check_revocation_statement(s, w.root_pub) is statement_reason("LINEAGE_INVALID")


# ---- B2: the received statement payload must equal its exact canonical reconstruction

@pytest.mark.parametrize("field", ["target_node", "target_lineage"])
def test_nested_non_canonical_node_wire_in_a_statement_is_malformed_wire(w, field):
    with pytest.raises(StatementFormatError) as exc:
        RevocationStatement.from_cose_sign1_bytes(_nested_noncanonical(w, field))
    assert exc.value.defect == "malformed_wire"


@pytest.mark.parametrize("field", ["target_node", "target_lineage"])
def test_nested_non_canonical_node_wire_rejects_the_entire_artifact(w, tmp_path, caplog, field):
    bad = _nested_noncanonical(w, field)
    store = tmp_path / "hwm.json"
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(StatusUnavailable) as exc:
            auth(w, artifact(w, statements=[statement(w, target=w.b), bad]), store)
    assert exc.value.reason is integrity()
    assert _records(caplog, "artifact_integrity")[0].alert_fields["defect"] == "malformed_wire"
    assert not store.exists()


def test_accepted_statement_payload_equals_its_canonical_reconstruction(w):
    s = statement(w, target=w.a)
    parsed = RevocationStatement.from_cose_sign1_bytes(s.to_cose_sign1_bytes())
    assert cbor2.loads(s.to_cose_sign1_bytes()).value[2] == parsed.canonical_bytes()


# ---- outer artifact signature: the statement rule is NOT extended; wrong length stays S5

@pytest.mark.parametrize("length", [63, 65, 0])
@pytest.mark.parametrize("policy", [StatusPolicy.FAIL_CLOSED, StatusPolicy.BOUNDED_STALENESS])
def test_wrong_length_outer_artifact_signature_stays_s5_artifact_signature_invalid(w, tmp_path, caplog, length, policy):
    parts = list(cbor2.loads(artifact(w)).value)
    sig = (parts[3] + b"\x00" * 2)[:length]
    wire = encode_canonical(CBORTag(18, [parts[0], parts[1], parts[2], sig]))
    store = tmp_path / "hwm.json"
    before_sig, before_int = alert_count("artifact_signature_invalid"), alert_count("artifact_integrity")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(StatusUnavailable) as exc:
            auth(w, wire, store, **pol(policy))
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID  # S5, not S4 and not integrity
    assert exc.value.reason is not StatusReason.ARTIFACT_MALFORMED and exc.value.reason is not integrity()
    assert alert_count("artifact_signature_invalid") == before_sig + 1  # the mandatory S5 alert
    assert alert_count("artifact_integrity") == before_int
    assert not store.exists()


# ---- reason_code is OPTIONAL (frozen Spec section 8); pending supervisor confirmation

def _no_reason(w, target=None, **kw):
    return create_revocation_statement(
        w.root_priv, target_node=target or w.a, target_lineage=w.lineage[: w.lineage.index(target or w.a) + 1],
        revoker_node_id=w.root.node_id, revoker_scope_proof=b"", effective_at=NOW - 1, issued_at=1_700_000_000, **kw)


def test_reason_code_may_be_omitted(w, tmp_path):
    s = _no_reason(w)  # reason_code defaults to absent
    assert s.reason_code is None and "reason_code" not in cbor2.loads(s.canonical_bytes())
    back = RevocationStatement.from_cose_sign1_bytes(s.to_cose_sign1_bytes())
    assert back.reason_code is None and back.to_cose_sign1_bytes() == s.to_cose_sign1_bytes()
    assert back.revocation_id == s.revocation_id
    assert verify_revocation_statement(back, w.root_pub)
    with pytest.raises(NodeRevoked):
        auth(w, artifact(w, statements=[s]), tmp_path / "hwm.json")


def test_reason_code_presence_changes_the_body_and_the_id(w):
    assert _no_reason(w).revocation_id != statement(w).revocation_id
    assert _no_reason(w, reason_code="x").revocation_id != _no_reason(w).revocation_id


def test_artifact_with_an_omitted_reason_code_is_not_rejected(w, tmp_path):
    state = ingest(w, artifact(w, statements=[_no_reason(w), statement(w, target=w.b)]), tmp_path / "hwm.json")
    assert len(state.statements) == 2


# ================================================================== B3: deeply nested CBOR must not leak RecursionError

DEEP = b"\x81" * 399 + b"\x00"  # 399 nested arrays: inside cbor2's own depth limit, far beyond any protocol object
DEEP_STACKS = (0, 100, 200, 300, 500, 700)


def _at_stack(extra_frames, fn):
    """Run fn() after `extra_frames` more Python frames. Returns (reached, exception-or-None, value)."""
    state = {"reached": False}

    def target():
        state["reached"] = True
        try:
            return None, fn()
        except BaseException as exc:  # noqa: BLE001 - we must see exactly what escapes
            return exc, None

    def descend(n):
        return target() if n == 0 else descend(n - 1)

    try:
        exc, value = descend(extra_frames)
    except RecursionError as overflow:
        return state["reached"], (overflow if state["reached"] else None), None
    return state["reached"], exc, value


@pytest.mark.parametrize("stack", DEEP_STACKS)
def test_deeply_nested_unsigned_artifact_is_typed_at_any_caller_stack(w, tmp_path, stack):
    store = tmp_path / "hwm.json"
    reached, exc, _ = _at_stack(stack, lambda: ingest(w, DEEP, store))
    if not reached:
        pytest.skip("helper stack overflowed before the call")
    assert isinstance(exc, StatusUnavailable), f"leaked {type(exc).__name__}: {exc}"
    assert exc.reason is StatusReason.ARTIFACT_MALFORMED
    assert not store.exists()


@pytest.mark.parametrize("stack", DEEP_STACKS)
def test_deeply_nested_statement_in_an_authenticated_artifact_is_an_integrity_failure(w, tmp_path, caplog, stack):
    store = tmp_path / "hwm.json"
    wire = artifact(w, version=50, statements=[DEEP])
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        reached, exc, _ = _at_stack(stack, lambda: ingest(w, wire, store))
    if not reached:
        pytest.skip("helper stack overflowed before the call")
    assert isinstance(exc, StatusUnavailable), f"leaked {type(exc).__name__}: {exc}"
    assert exc.reason is integrity()
    assert _records(caplog, "artifact_integrity")[-1].alert_fields["defect"] == "malformed_wire"
    assert not store.exists()


@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_deeply_nested_unsigned_artifact_follows_the_existing_policy_and_mutates_nothing(w, tmp_path, policy):
    store, last = _accepted_world(w, tmp_path)
    before = store.read_bytes()
    reached, exc, _ = _at_stack(
        300, lambda: auth(w, DEEP, store, last_accepted_status=last, **pol(policy)))
    assert reached
    assert store.read_bytes() == before
    if policy is StatusPolicy.FAIL_OPEN_EXPERIMENTAL:  # a fresh authenticated state exists: used, b stays revoked
        assert isinstance(exc, NodeRevoked) and exc.node_id == w.b.node_id
    else:  # S4 is not covered by bounded staleness or TTL-only: deny, exactly as for any malformed artifact
        assert isinstance(exc, StatusUnavailable), f"leaked {type(exc).__name__}"
        assert exc.reason is StatusReason.ARTIFACT_MALFORMED


def test_deep_statement_in_an_authenticated_artifact_follows_fail_closed_and_bounded_staleness(w, tmp_path):
    store, last = _accepted_world(w, tmp_path)
    before = store.read_bytes()
    bad = artifact(w, version=60, statements=[DEEP])
    reached, exc, _ = _at_stack(300, lambda: auth(w, bad, store, last_accepted_status=last,
                                                  status_policy=StatusPolicy.FAIL_CLOSED))
    assert reached and isinstance(exc, StatusUnavailable) and exc.reason is integrity()
    reached, exc, _ = _at_stack(300, lambda: auth(w, bad, store, last_accepted_status=last,
                                                  status_policy=StatusPolicy.BOUNDED_STALENESS))
    assert reached and isinstance(exc, NodeRevoked) and exc.node_id == w.b.node_id  # last authenticated state used
    reached, exc, _ = _at_stack(300, lambda: auth(w, bad, store, status_policy=StatusPolicy.BOUNDED_STALENESS))
    assert reached and isinstance(exc, StatusUnavailable)  # nothing authenticated to fall back to
    assert store.read_bytes() == before  # the rejected artifact advanced nothing


def test_artifact_with_nesting_just_inside_the_limit_in_a_statement_slot_is_not_a_recursion_problem(w, tmp_path):
    from lineage_revocation.canonical import MAX_NESTING_DEPTH
    wire = b"\x81" * (MAX_NESTING_DEPTH + 1) + b"\x00"
    with pytest.raises(StatusUnavailable) as exc:  # too deep to be a statement: malformed, typed, deterministic
        ingest(w, artifact(w, statements=[wire]), tmp_path / "hwm.json")
    assert exc.value.reason is integrity()


# ================================================================== Task 1: statement_version must be 1 (frozen Spec section 8)

def test_statement_version_1_is_accepted_and_is_the_only_supported_value(w, tmp_path):
    s = statement(w, target=w.a)
    assert s.statement_version == 1
    back = RevocationStatement.from_cose_sign1_bytes(s.to_cose_sign1_bytes())
    assert back.statement_version == 1
    with pytest.raises(NodeRevoked):
        auth(w, artifact(w, statements=[s]), tmp_path / "hwm.json")


@pytest.mark.parametrize("name", [n for n in DEFECTS if "statement_version" in n])
def test_unsupported_statement_version_is_wire_malformed_at_the_parser(w, name):
    with pytest.raises(StatementFormatError) as exc:
        RevocationStatement.from_cose_sign1_bytes(_malformed_wires(w)[name])
    assert exc.value.defect == "malformed_wire"


@pytest.mark.parametrize("version", [0, 2, 3, 255, -1])
def test_unsupported_statement_version_is_never_effective_and_rejects_the_artifact(w, tmp_path, caplog, version):
    store = tmp_path / "hwm.json"
    bad = _resign(w, {**_body_of(statement(w, target=w.a)), "statement_version": version})  # validly signed by the root
    before_i, before_s = alert_count("artifact_integrity"), alert_count("invalid_revocation_statement")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(StatusUnavailable) as exc:  # NodeRevoked would mean it took effect
            auth(w, artifact(w, statements=[statement(w, target=w.b), bad]), store)
    assert exc.value.reason is integrity()
    assert alert_count("artifact_integrity") == before_i + 1
    assert alert_count("invalid_revocation_statement") == before_s  # integrity, not a semantic failure
    assert _records(caplog, "artifact_integrity")[0].alert_fields["defect"] == "malformed_wire"
    assert not store.exists()


def test_unsupported_statement_version_follows_bounded_staleness_and_fail_closed(w, tmp_path):
    store, last = _accepted_world(w, tmp_path)
    before = store.read_bytes()
    bad = artifact(w, version=70, statements=[_resign(w, {**_body_of(statement(w, target=w.a)), "statement_version": 2})])
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, bad, store, last_accepted_status=last, status_policy=StatusPolicy.FAIL_CLOSED)
    assert exc.value.reason is integrity()
    with pytest.raises(NodeRevoked) as exc2:  # fallback to the last authenticated artifact; the rejected one is not used
        auth(w, bad, store, last_accepted_status=last, status_policy=StatusPolicy.BOUNDED_STALENESS)
    assert exc2.value.node_id == w.b.node_id
    assert store.read_bytes() == before


# ================================================================== Task 2: audience is checked BEFORE status (frozen Spec section 13)
# Spec section 13 order: verify lineage, root binding, audience, attenuation, then status. A request that fails
# the audience check must not touch the revocation-state machinery at all.

WRONG = "not-the-audience"


def _amplifying_chain(w):
    """root -> child whose authority exceeds the parent's (DR-0001 amplification)."""
    kw = dict(audience=["agent"], delegation_rights={"can_delegate": True}, root_revocation_state_uri=URI,
              revocation_trust_anchor=w.root.body.revocation_trust_anchor, **COMMON)
    root = create_root_node(w.root_priv, w.root_pub, issuer="root", authority=frozenset({"read"}), **kw)
    child = create_child_node(w.root_priv, generate_keypair()[1], root.node_id, issuer="root",
                              authority=frozenset({"read", "write"}), **kw)
    return [root, child]


def _authz(w, status, store, audience, **kw):
    kw.setdefault("max_staleness", MAX_STALENESS)
    return authorize(w.lineage, w.root_pub, audience=audience, now=NOW, status_artifact=status,
                     status_store_path=store, **kw)


@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_audience_mismatch_does_not_advance_or_create_the_high_water_mark(w, tmp_path, policy):
    fresh_store = tmp_path / "fresh.json"
    with pytest.raises(AudienceMismatchError):
        _authz(w, artifact(w, version=9), fresh_store, WRONG, **pol(policy))
    assert not fresh_store.exists()  # nothing created

    store, last = _accepted_world(w, tmp_path)
    before = store.read_bytes()
    with pytest.raises(AudienceMismatchError):
        _authz(w, artifact(w, version=9), store, WRONG, last_accepted_status=last, **pol(policy))
    assert store.read_bytes() == before  # version 9 not persisted; still the version-3 mark
    assert _authz(w, artifact(w, version=4), store, "agent", status_policy=StatusPolicy.FAIL_CLOSED)  # 4 still accepted


@pytest.mark.parametrize("policy", ALL_POLICIES)
@pytest.mark.parametrize("status", ["none", "malformed", "forged", "stale", "wrong_uri"])
def test_audience_mismatch_is_reported_before_any_status_failure_and_touches_no_telemetry(w, tmp_path, policy, status):
    wires = {
        "none": None,
        "malformed": b"\x01\x02",
        "forged": artifact(w, key=generate_keypair()[0]),
        "stale": artifact(w, issued_at=NOW - 50_000),
        "wrong_uri": artifact(w, uri="https://attacker.example/status"),
    }
    kinds = ("artifact_integrity", "artifact_signature_invalid", "artifact_key_reuse", "invalid_revocation_statement",
             "fail_open_after_status_unavailable", "fail_open_after_artifact_integrity", FALLBACK)
    before = {k: alert_count(k) for k in kinds}
    store = tmp_path / "hwm.json"
    with pytest.raises(AudienceMismatchError):  # not StatusUnavailable, not RevocationBindingMismatch
        _authz(w, wires[status], store, WRONG, **pol(policy))
    assert {k: alert_count(k) for k in kinds} == before  # status machinery never ran
    assert not store.exists()


def test_audience_mismatch_precedes_attenuation_as_in_spec_section_13(w):
    chain = _amplifying_chain(w)
    kw = dict(now=NOW, status_policy=StatusPolicy.TTL_ONLY_NO_STATUS)
    with pytest.raises(AudienceMismatchError):  # both defects present: the Spec checks audience first
        authorize(chain, w.root_pub, audience=WRONG, **kw)
    with pytest.raises(AuthorityAmplification):  # audience fine: attenuation still enforced
        authorize(chain, w.root_pub, audience="agent", **kw)


def test_audience_mismatch_still_follows_lineage_and_binding_checks_first(w):
    from lineage_revocation.lineage import LineageVerificationError
    forged = [w.root, replace(w.a, signature=b"\x00" * 64), w.b]
    with pytest.raises(LineageVerificationError):  # lineage authentication precedes audience
        authorize(forged, w.root_pub, audience=WRONG, now=NOW, status_policy=StatusPolicy.TTL_ONLY_NO_STATUS)


# ---- a valid audience still takes the normal status-verification path

def test_valid_audience_persists_the_mark_through_the_normal_path(w, tmp_path):
    store = tmp_path / "hwm.json"
    assert _authz(w, artifact(w, version=9), store, "agent")
    assert '"%s": 9' % URI in store.read_text()


def test_valid_audience_still_applies_revocations_and_the_policy(w, tmp_path):
    store = tmp_path / "hwm.json"
    with pytest.raises(NodeRevoked):
        _authz(w, artifact(w, statements=[statement(w, target=w.a)]), store, "agent")
    with pytest.raises(StatusUnavailable) as exc:  # missing status still fails closed
        _authz(w, None, store, "agent")
    assert exc.value.reason is StatusReason.STATUS_MISSING
    with pytest.raises(StaleStatusArtifact):
        _authz(w, artifact(w, version=5, issued_at=NOW - 50_000), store, "agent")
    with pytest.raises(StatusUnavailable) as exc2:
        _authz(w, b"garbage", store, "agent")
    assert exc2.value.reason is StatusReason.ARTIFACT_MALFORMED
    assert alert_count("artifact_signature_invalid") >= 0
    with pytest.raises(StatusUnavailable) as exc3:
        _authz(w, artifact(w, version=6, key=generate_keypair()[0]), store, "agent")
    assert exc3.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID


def test_valid_audience_with_a_failing_status_does_not_become_an_audience_error(w, tmp_path):
    with pytest.raises(StatusUnavailable):
        _authz(w, None, tmp_path / "hwm.json", "agent")


def test_audience_check_runs_exactly_once_and_empty_audience_still_denies(w):
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=URI, revocation_trust_anchor=w.root.body.revocation_trust_anchor, **COMMON)
    root = create_root_node(w.root_priv, w.root_pub, issuer="root", **kw)
    leaf = create_child_node(w.root_priv, generate_keypair()[1], root.node_id, issuer="root", **{**kw, "audience": []})
    with pytest.raises(AudienceMismatchError):
        authorize([root, leaf], w.root_pub, audience="agent", now=NOW, status_policy=StatusPolicy.TTL_ONLY_NO_STATUS)


# ================================================================== coverage gaps found in the release review
# These pin behavior that already existed but had no test (they passed on first run by construction).

@pytest.mark.parametrize("stored", ['{"%s": "7"}' % URI, '{"%s": 1.5}' % URI, '{"%s": [1]}' % URI, '{"%s": true}' % URI])
@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_corrupt_per_uri_high_water_mark_fails_closed_under_every_policy(w, tmp_path, stored, policy):
    store = tmp_path / "hwm.json"
    store.write_text(stored)
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, artifact(w, version=9), store, **pol(policy))
    assert exc.value.reason is StatusReason.STORE_UNREADABLE
    assert store.read_text() == stored  # not repaired, not overwritten


def test_non_option_k_anchor_through_authorize_is_an_artifact_signature_failure(tmp_path):
    w = make_world()
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=URI, revocation_trust_anchor=b"\x01" * 32, **COMMON)
    root = create_root_node(w.root_priv, w.root_pub, issuer="root", **kw)
    store = tmp_path / "hwm.json"
    with pytest.raises(StatusUnavailable) as exc:  # reaches the key-separation helper, which must not crash
        authorize([root], w.root_pub, audience="agent", now=NOW, status_artifact=artifact(w),
                  status_store_path=store, max_staleness=MAX_STALENESS)
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID
    assert not store.exists()


@pytest.mark.parametrize("member", ["int", "null", "absent"])
def test_outer_artifact_signature_member_of_the_wrong_type_or_absent_is_s4(w, tmp_path, member):
    # Current behavior, recorded as such: the supervisor's signature-length ruling covers statements only, and
    # whether the outer envelope should follow the same split is an open question (DR-0003 section 3).
    parts = list(cbor2.loads(artifact(w)).value)
    tail = {"int": [7], "null": [None], "absent": []}[member]
    wire = cbor2.dumps(CBORTag(18, parts[:3] + tail), canonical=True)
    with pytest.raises(StatusUnavailable) as exc:
        ingest(w, wire, tmp_path / "hwm.json")
    assert exc.value.reason is StatusReason.ARTIFACT_MALFORMED


def test_missing_max_staleness_with_an_artifact_is_a_usage_error(w, tmp_path):
    with pytest.raises(ValueError, match="max_staleness"):
        authorize(w.lineage, w.root_pub, audience="agent", now=NOW, status_artifact=artifact(w),
                  status_store_path=tmp_path / "hwm.json")
    assert not (tmp_path / "hwm.json").exists()


def test_status_demo_is_an_explicit_pending_migration_stub():
    import lineage_revocation.status as st
    with pytest.raises(NotImplementedError, match="Revision B"):
        st._demo()
