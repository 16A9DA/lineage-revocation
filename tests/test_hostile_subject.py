"""G1 and G1b: a node a DELEGATOR can mint and sign validly, whose subject key structure is hostile.

Classification (existing design, DR-0003 dividing rule): a defect detectable from the bytes alone, without
consulting a key, is wire-malformed and rejects the whole artifact before anything is persisted. A well-formed
32-byte key that is wrong or short is key semantics (approved B1 ruling) and stays a per-statement semantic failure.
No input may escape as an untyped exception, and the high-water mark may advance only for an artifact that was
accepted."""
import hashlib
import json
import logging

import cbor2
import pytest
from cbor2 import CBORTag

import lineage_revocation.revocation as rev
import lineage_revocation.status as st
from lineage_revocation.alerts import alert_count
from lineage_revocation.canonical import encode_canonical
from lineage_revocation.keys import COSEKey, generate_keypair
from lineage_revocation.lineage import LineageVerificationError
from lineage_revocation.nodes import (
    Node,
    NodeFormatError,
    _protected_header_bytes,
    create_child_node,
    sign_payload,
    verify_payload,
)
from lineage_revocation.revocation import StatementFormatError, RevocationStatement, create_revocation_statement
from lineage_revocation.status import StatusPolicy, StatusReason, StatusUnavailable
from lineage_revocation.verifier import NodeRevoked, authorize
from test_revision_a import COMMON, NOW, URI, _records, artifact, auth, ingest, make_world, pol, statement


# Helpers local to this file, so it depends only on Revision A and runs unchanged before and after Revision B.
def stored_version(store):
    raw = json.loads(store.read_text())[URI]
    return raw if isinstance(raw, int) else raw["version"]  # legacy integer or {version, digest}


def accepted_with_revocation_of_b(w, tmp_path):
    store = tmp_path / "hwm.json"
    wire = artifact(w, version=3, statements=[statement(w, target=w.b)])
    return store, wire, ingest(w, wire, store)


def no_writes(monkeypatch, store):
    def forbidden(*a, **k):
        raise AssertionError("persistent write")
    monkeypatch.setattr(st, "save_high_water_mark", forbidden)
    monkeypatch.setattr(type(store), "write_text", forbidden)
    monkeypatch.setattr(type(store), "write_bytes", forbidden)

ALL_POLICIES = list(StatusPolicy)
KEY_PREFIX = {1: 1, -1: 6}  # kty OKP, crv Ed25519

# subject values that are not a COSE_Key map at all (G1b)
NON_MAP_SUBJECTS = {"int": 5, "negative_int": -3, "list": [1, 2], "text": "subject", "null": None, "bytes": b"\x01" * 32,
                    "true": True, "float": 1.5, "empty_list": [], "nested_list": [[1]]}
# a COSE_Key map whose key material is not a byte string (G1)
BAD_X = {"int": 5, "text": "k" * 32, "null": None, "list": [1], "map": {1: 2}, "true": True, "negative": -1, "float": 2.5}
# a map that is structurally a key but violates the strict shape
BAD_MAPS = {"missing_x": {1: 1, -1: 6}, "wrong_kty": {1: 2, -1: 6, -2: b"k" * 32}, "wrong_crv": {1: 1, -1: 7, -2: b"k" * 32},
            "extra_key": {1: 1, -1: 6, -2: b"k" * 32, 99: 1}, "empty": {}, "text_labels": {"kty": 1}}


def node_wire(w, subject):
    """A validly signed (by `a`, the delegator) node wire whose subject is `subject`, any CBOR value."""
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=URI, revocation_trust_anchor=w.root.body.revocation_trust_anchor, **COMMON)
    base = create_child_node(w.a_priv, w.b_pub, w.a.node_id, issuer="a", **kw)
    body = dict(base.body.to_cbor_dict())
    body["subject"] = subject
    payload = cbor2.dumps(body, canonical=True)  # cbor2 so that floats and odd values can be encoded for the attack
    return cbor2.dumps(CBORTag(18, [_protected_header_bytes(), {}, payload, sign_payload(payload, w.a_priv)]), canonical=True)


def statement_wire_with(w, field, subject, index=None):
    """A well-formed statement validly signed by the root, with the hostile node embedded in `field`
    ('target_node', or 'target_lineage' at `index`). The statement's own signature and id are valid."""
    good = statement(w, target=w.b)
    body = dict(cbor2.loads(good.canonical_bytes()))
    hostile = node_wire(w, subject)
    if field == "target_node":
        body["target_node"] = hostile
    else:
        lineage = list(body["target_lineage"])
        lineage[index] = hostile
        body["target_lineage"] = lineage
    payload = encode_canonical(body)
    rid = hashlib.sha256(payload).digest()
    return encode_canonical(CBORTag(18, [_protected_header_bytes(), {"revocation_id": rid}, payload,
                                         sign_payload(payload, w.root_priv)]))


def all_hostile():
    out = {}
    for name, v in NON_MAP_SUBJECTS.items():
        out[f"non_map/{name}"] = v
    for name, x in BAD_X.items():
        out[f"bad_x/{name}"] = {**KEY_PREFIX, -2: x}
    for name, m in BAD_MAPS.items():
        out[f"bad_map/{name}"] = m
    return out


HOSTILE = all_hostile()


@pytest.fixture
def w():
    return make_world()


# ================================================================== the node parser: typed, never AttributeError/TypeError

# An extra key in an otherwise valid COSE_Key is NOT rejected by the node parser (it never was: the key re-encodes
# without it). It is still caught one level up, where a statement's payload must equal its exact canonical
# reconstruction (malformed_wire); the artifact-level tests below include it. Not a G1 or G1b case.
NODE_PARSER_REJECTS = sorted(n for n in HOSTILE if n != "bad_map/extra_key")


@pytest.mark.parametrize("name", NODE_PARSER_REJECTS)
def test_node_parser_rejects_a_hostile_subject_with_node_format_error(w, name):
    with pytest.raises(NodeFormatError):
        Node.from_cose_sign1_bytes(node_wire(w, HOSTILE[name]))


def test_node_parser_still_accepts_a_well_formed_subject_including_a_short_or_long_key(w):
    for x in (b"k" * 32, b"k" * 31, b"k" * 33, b""):  # byte strings of any length are key semantics, not structure
        node = Node.from_cose_sign1_bytes(node_wire(w, {**KEY_PREFIX, -2: x}))
        assert node.body.subject == COSEKey(x=x)
    good = Node.from_cose_sign1_bytes(node_wire(w, w.b_pub.to_cbor_dict()))
    assert good.body.subject == w.b_pub


def test_cose_key_from_cbor_dict_is_strict_about_shape_and_types():
    with pytest.raises(ValueError):
        COSEKey.from_cbor_dict(5)
    with pytest.raises(ValueError):
        COSEKey.from_cbor_dict({**KEY_PREFIX, -2: 5})
    assert COSEKey.from_cbor_dict({**KEY_PREFIX, -2: b"k" * 32}) == COSEKey(x=b"k" * 32)


# ================================================================== the artifact path: wire-malformed, nothing persisted

SITES = [("target_node", None), ("target_lineage", 0), ("target_lineage", 1), ("target_lineage", 2)]
SITE_IDS = [f"{f}{'' if i is None else f'[{i}]'}" for f, i in SITES]


@pytest.mark.parametrize("site", SITES, ids=SITE_IDS)
@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_subject_in_any_embedded_node_rejects_the_whole_artifact_before_persistence(w, tmp_path, caplog, name, site):
    field, index = site
    bad = statement_wire_with(w, field, HOSTILE[name], index)
    good = statement(w, target=w.b)
    store = tmp_path / "hwm.json"
    before_i, before_s = alert_count("artifact_integrity"), alert_count("invalid_revocation_statement")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(StatusUnavailable) as exc:  # typed: never AttributeError or TypeError
            ingest(w, artifact(w, version=5, statements=[good, bad]), store)
    assert exc.value.reason is StatusReason.ARTIFACT_INTEGRITY
    assert not store.exists()  # the high-water mark did not advance
    assert alert_count("artifact_integrity") == before_i + 1
    assert alert_count("invalid_revocation_statement") == before_s  # integrity, not a semantic failure
    assert _records(caplog, "artifact_integrity")[0].alert_fields["defect"] == "malformed_wire"


@pytest.mark.parametrize("name", ["non_map/int", "bad_x/int", "bad_x/text", "bad_x/null", "bad_map/extra_key"])
def test_the_statement_parser_reports_a_hostile_subject_as_malformed_wire(w, name):
    with pytest.raises(StatementFormatError) as exc:
        RevocationStatement.from_cose_sign1_bytes(statement_wire_with(w, "target_lineage", HOSTILE[name], 1))
    assert exc.value.defect == "malformed_wire"


@pytest.mark.parametrize("policy", ALL_POLICIES)
@pytest.mark.parametrize("name", ["non_map/int", "non_map/list", "bad_x/int", "bad_x/text", "bad_x/null", "bad_x/list"])
def test_a_hostile_subject_never_advances_or_rewrites_the_store_under_any_policy(w, tmp_path, monkeypatch, policy, name):
    store, wire, last = accepted_with_revocation_of_b(w, tmp_path)
    before_bytes = store.read_bytes()
    hostile = artifact(w, version=9, statements=[statement_wire_with(w, "target_lineage", HOSTILE[name], 1)])
    no_writes(monkeypatch, store)
    try:
        auth(w, hostile, store, last_accepted_status=last, **pol(policy))
    except (StatusUnavailable, NodeRevoked):  # typed verdicts only; any other exception fails the test
        pass
    assert store.read_bytes() == before_bytes


def test_a_hostile_artifact_cannot_take_the_feed_down_for_every_later_request(w, tmp_path):
    store, wire, last = accepted_with_revocation_of_b(w, tmp_path)
    hostile = artifact(w, version=9, statements=[statement_wire_with(w, "target_node", {**KEY_PREFIX, -2: 5})])
    for policy in (StatusPolicy.FAIL_CLOSED, StatusPolicy.BOUNDED_STALENESS):
        for _ in range(3):
            with pytest.raises((StatusUnavailable, NodeRevoked)):
                auth(w, hostile, store, last_accepted_status=last, status_policy=policy)
    with pytest.raises(NodeRevoked) as exc:  # a genuine next artifact still works (independent of equal-version rules)
        auth(w, artifact(w, version=4, statements=[statement(w, target=w.b)]), store)
    assert exc.value.node_id == w.b.node_id
    assert ingest(w, artifact(w, version=10), store).version == 10  # and the next version is not blocked


# ================================================================== persistence is conditional on verification completing

def test_nothing_is_persisted_if_statement_verification_raises_unexpectedly(w, tmp_path, monkeypatch):
    # Structural guarantee: statement verification is pure and runs BEFORE the mark is written, so even a defect
    # in it (simulated here) can not leave the mark advanced for an artifact the verifier then failed to process.
    def boom(statement, anchor):
        raise RuntimeError("simulated defect")

    monkeypatch.setattr(st, "check_revocation_statement", boom)
    store = tmp_path / "hwm.json"
    with pytest.raises(RuntimeError):
        ingest(w, artifact(w, version=5, statements=[statement(w, target=w.b)]), store)
    assert not store.exists()


def test_semantically_invalid_statements_still_let_the_artifact_be_accepted_and_the_mark_advance(w, tmp_path, caplog):
    invalid = statement(w, target=w.a, signer=generate_keypair()[0])  # well-formed, wrong signature: semantic
    valid = statement(w, target=w.b)
    store = tmp_path / "hwm.json"
    before = alert_count("invalid_revocation_statement")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        state = ingest(w, artifact(w, version=5, statements=[invalid, valid]), store)
    assert state.statements == (valid,)
    assert stored_version(store) == 5  # accepted: the mark advanced exactly once
    assert alert_count("invalid_revocation_statement") == before + 1  # alert still emitted, once


def test_a_semantic_alert_is_not_emitted_for_an_artifact_that_is_then_rejected(w, tmp_path):
    store, _wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    invalid = statement(w, target=w.a, signer=generate_keypair()[0])
    before = alert_count("invalid_revocation_statement")
    with pytest.raises(st.StatusRollback):  # lower version: rejected, so its statements were never processed
        ingest(w, artifact(w, version=1, statements=[invalid]), store)
    assert alert_count("invalid_revocation_statement") == before


# ================================================================== in-memory objects: key verification is total

@pytest.mark.parametrize("x", [5, "k" * 32, None, [1], {1: 2}, b"short", b"", b"k" * 33])
def test_verify_payload_treats_any_unusable_key_material_as_failed_verification(w, x):
    sig = sign_payload(b"payload", w.root_priv)
    assert verify_payload(b"payload", sig, COSEKey(x=x)) is False


def _lineage_through_a_node_with_a_bad_in_memory_key(w, x):
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=URI, revocation_trust_anchor=w.root.body.revocation_trust_anchor, **COMMON)
    bad = create_child_node(w.a_priv, COSEKey(x=x), w.a.node_id, issuer="a", **kw)  # bypasses the parser
    child = create_child_node(generate_keypair()[0], generate_keypair()[1], bad.node_id, issuer="b", **kw)
    return bad, child, [w.root, w.a, bad, child]


@pytest.mark.parametrize("x", [5, "k" * 32, None, [1], b"short"])
def test_a_statement_over_an_in_memory_node_with_a_bad_key_is_a_semantic_failure_not_a_crash(w, x):
    _bad, child, chain = _lineage_through_a_node_with_a_bad_in_memory_key(w, x)
    s = create_revocation_statement(w.root_priv, target_node=child, target_lineage=chain, revoker_node_id=w.root.node_id,
                                    revoker_scope_proof=b"", effective_at=NOW - 1, issued_at=1_700_000_000, reason_code="x")
    assert rev.check_revocation_statement(s, w.root_pub) is rev.StatementReason.LINEAGE_INVALID


@pytest.mark.parametrize("x", [5, "k" * 32, None, [1]])
def test_a_presented_lineage_with_a_bad_key_is_a_typed_lineage_failure(w, x):
    _bad, _child, chain = _lineage_through_a_node_with_a_bad_in_memory_key(w, x)
    with pytest.raises(LineageVerificationError):
        authorize(chain, w.root_pub, audience="agent", now=NOW, status_policy=StatusPolicy.TTL_ONLY_NO_STATUS)


# ================================================================== valid input is unaffected

def test_valid_statements_and_nodes_still_work_after_the_strictness(w, tmp_path):
    for field, index in SITES:
        wire = statement_wire_with(w, field, w.b_pub.to_cbor_dict() if False else {**KEY_PREFIX, -2: b"k" * 32}, index)
        # a well-formed (if semantically meaningless) key is accepted by the parser: classification is about structure
        RevocationStatement.from_cose_sign1_bytes(wire)
    store = tmp_path / "hwm.json"
    state = ingest(w, artifact(w, version=5, statements=[statement(w, target=w.a), statement(w, target=w.b)]), store)
    assert len(state.statements) == 2 and stored_version(store) == 5
    with pytest.raises(NodeRevoked):
        auth(w, artifact(w, version=6, statements=[statement(w, target=w.b)]), store)


def test_a_short_key_inside_a_statement_remains_a_semantic_failure(w, tmp_path, caplog):
    wire = statement_wire_with(w, "target_lineage", {**KEY_PREFIX, -2: b"short"}, 1)
    store = tmp_path / "hwm.json"
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        state = ingest(w, artifact(w, version=5, statements=[wire, statement(w, target=w.b)]), store)
    assert len(state.statements) == 1  # the hostile-length statement is ignored, the valid one stays
    assert stored_version(store) == 5
    assert not _records(caplog, "artifact_integrity")


# ================================================================== every node-body field, hostile values, statement path
# Totality: whatever a delegator puts in ANY field of a node embedded in a statement, ingestion either accepts the
# artifact (the mark advanced, once) or rejects it with a typed integrity failure (the mark did not move). Never an
# untyped exception, never a mark advanced for a rejected artifact. A deterministic table plus a seeded property test.
import collections

from hypothesis import HealthCheck, given, settings, strategies as hst

FIELD_NAMES = ["version", "issuer", "subject", "parent_node_id", "audience", "authority", "delegation_rights",
               "root_revocation_state_uri", "revocation_trust_anchor", "issued_at", "expires_at", "zz_extra"]
TABLE_VALUES = [None, True, 0, -1, 5, 2**64 - 1, 1.5, "t", b"b", [], [1], ["a", 1], [[1]], {}, {"k": 1}, {1: 2}]


def node_with_field(w, field, value):
    kw = dict(audience=["agent"], authority=frozenset({"full"}), delegation_rights={"can_delegate": True},
              root_revocation_state_uri=URI, revocation_trust_anchor=w.root.body.revocation_trust_anchor, **COMMON)
    body = dict(create_child_node(w.a_priv, w.b_pub, w.a.node_id, issuer="a", **kw).body.to_cbor_dict())
    body[field] = value
    payload = cbor2.dumps(body, canonical=True)
    return cbor2.dumps(CBORTag(18, [_protected_header_bytes(), {}, payload, sign_payload(payload, w.a_priv)]), canonical=True)


def statement_embedding(w, node_wire_bytes, site):
    body = dict(cbor2.loads(statement(w, target=w.b).canonical_bytes()))
    if site == "target_node":
        body["target_node"] = node_wire_bytes
    else:
        lineage = list(body["target_lineage"])
        lineage[site] = node_wire_bytes
        body["target_lineage"] = lineage
    payload = encode_canonical(body)
    return encode_canonical(CBORTag(18, [_protected_header_bytes(), {"revocation_id": hashlib.sha256(payload).digest()},
                                         payload, sign_payload(payload, w.root_priv)]))


def check_invariant(w, tmp_path, tag, wire, version=5):
    store = tmp_path / f"{tag}.json"
    try:
        ingest(w, artifact(w, version=version, statements=[wire]), store)
    except StatusUnavailable as exc:  # typed rejection: the mark must not have moved
        assert exc.reason in (StatusReason.ARTIFACT_INTEGRITY,), exc.reason
        assert not store.exists(), f"mark advanced for a rejected artifact ({tag})"
        return "rejected"
    assert stored_version(store) == version  # accepted: advanced exactly to the artifact's version
    return "accepted"


@pytest.mark.parametrize("field", FIELD_NAMES)
def test_no_hostile_field_value_in_an_embedded_node_escapes_as_an_untyped_exception(w, tmp_path, field):
    outcomes = collections.Counter()
    for i, value in enumerate(TABLE_VALUES):
        for site in ("target_node", 1):
            wire = statement_embedding(w, node_with_field(w, field, value), site)
            outcomes[check_invariant(w, tmp_path, f"{field}_{i}_{site}", wire)] += 1
    assert sum(outcomes.values()) == 2 * len(TABLE_VALUES)


_scalar = hst.none() | hst.booleans() | hst.integers(-2**64, 2**64 - 1) | hst.floats(allow_nan=False) | hst.binary(max_size=40) | hst.text(max_size=20)
_value = hst.recursive(_scalar, lambda c: hst.lists(c, max_size=3) | hst.dictionaries(hst.integers(-3, 3) | hst.text(max_size=3), c, max_size=3), max_leaves=6)


@settings(max_examples=400, deadline=None, derandomize=True, suppress_health_check=list(HealthCheck))
@given(hst.sampled_from(FIELD_NAMES), _value, hst.sampled_from(["target_node", 0, 1, 2]))
def test_property_random_hostile_embedded_nodes_never_crash_or_advance_the_mark_when_rejected(field, value, site):
    import pathlib
    import tempfile
    w = make_world()
    tmp = pathlib.Path(tempfile.mkdtemp())
    check_invariant(w, tmp, "p", statement_embedding(w, node_with_field(w, field, value), site))
