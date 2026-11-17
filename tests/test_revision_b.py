"""Revision B: artifact version handling (DR-1 5.2). Lower versions are rollbacks; an equal version is accepted
idempotently only when authenticated and fresh; a higher version is accepted and advances the high-water mark;
an equal version with a different SHA-256 of the canonical body is equivocation (reject and alert). The store
keeps {version, digest} per URI and still reads legacy integer-only entries."""
import hashlib
import json
import logging

import cbor2
import pytest

import lineage_revocation.status as st
from lineage_revocation.alerts import alert_count
from lineage_revocation.status import (
    StaleStatusArtifact,
    StatusFailure,
    StatusPolicy,
    StatusReason,
    StatusRollback,
    StatusUnavailable,
)
from lineage_revocation.keys import generate_keypair
from lineage_revocation.verifier import NodeRevoked, authorize
from test_revision_a import (  # noqa: E402 - shared fixtures and builders
    ARM, MAX_STALENESS, NOW, URI, artifact, auth, ingest, make_world, pol, statement, _accepted_world, _records,
)

ALL_POLICIES = list(StatusPolicy)


@pytest.fixture
def w():
    return make_world()


def body_digest(wire: bytes) -> bytes:
    return hashlib.sha256(cbor2.loads(wire).value[2]).digest()


def entry(store, uri=URI):
    """(version, digest-hex-or-None) of the stored entry, whichever format it is in."""
    raw = json.loads(store.read_text())[uri]
    return (raw, None) if isinstance(raw, int) else (raw["version"], raw["digest"])


def legacy_store(tmp_path, version, other=None):
    store = tmp_path / "hwm.json"
    data = {URI: version}
    data.update(other or {})
    store.write_text(json.dumps(data))
    return store


# ================================================================== step 1: store format and legacy entries

def test_new_entry_records_version_and_sha256_of_the_canonical_body(w, tmp_path):
    store = tmp_path / "hwm.json"
    wire = artifact(w, version=3)
    state = ingest(w, wire, store)
    assert entry(store) == (3, body_digest(wire).hex())
    assert state.body_digest == body_digest(wire)  # same digest the accepted state is bound to


def test_digest_covers_the_signed_body_so_different_content_gives_a_different_digest(w):
    assert body_digest(artifact(w, version=3)) != body_digest(artifact(w, version=3, valid_until=NOW + 2000))
    assert body_digest(artifact(w, version=3)) == body_digest(artifact(w, version=3))  # deterministic


def test_legacy_integer_entry_still_enforces_rollback(w, tmp_path):
    store = legacy_store(tmp_path, 5)
    with pytest.raises(StatusRollback):
        ingest(w, artifact(w, version=4), store)
    assert json.loads(store.read_text()) == {URI: 5}  # untouched, still legacy


def test_legacy_integer_entry_upgrades_to_the_new_format_on_a_higher_version(w, tmp_path):
    store = legacy_store(tmp_path, 5)
    wire = artifact(w, version=6)
    ingest(w, wire, store)
    assert entry(store) == (6, body_digest(wire).hex())


def test_writing_one_uri_leaves_every_other_entry_untouched(w, tmp_path):
    store = legacy_store(tmp_path, 2, other={"https://other.example/s": 4,
                                            "https://new.example/s": {"version": 7, "digest": "ab" * 32}})
    ingest(w, artifact(w, version=3), store)
    data = json.loads(store.read_text())
    assert data["https://other.example/s"] == 4
    assert data["https://new.example/s"] == {"version": 7, "digest": "ab" * 32}


@pytest.mark.parametrize("raw", [
    "1.5", "true", "null", "[1]", '"x"', "-1",
    {"version": 3}, {"digest": "ab" * 32}, {"version": 3, "digest": "ab" * 32, "extra": 1},
    {"version": "3", "digest": "ab" * 32}, {"version": True, "digest": "ab" * 32}, {"version": -1, "digest": "ab" * 32},
    {"version": 3, "digest": "AB" * 32}, {"version": 3, "digest": "ab" * 31}, {"version": 3, "digest": "zz" * 32},
    {"version": 3, "digest": None}, {"version": 3, "digest": 12},
])
@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_corrupt_store_entry_fails_closed_under_every_policy_and_is_never_repaired(w, tmp_path, raw, policy):
    store = tmp_path / "hwm.json"
    text = json.dumps({URI: json.loads(raw) if isinstance(raw, str) else raw})
    store.write_text(text)
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, artifact(w, version=9), store, **pol(policy))
    assert exc.value.reason is StatusReason.STORE_UNREADABLE
    assert store.read_text() == text


def test_valid_new_format_entry_is_read_and_enforced(w, tmp_path):
    store = tmp_path / "hwm.json"
    store.write_text(json.dumps({URI: {"version": 5, "digest": "ab" * 32}}))
    with pytest.raises(StatusRollback):
        ingest(w, artifact(w, version=4), store)
    assert st.load_high_water_mark(store, URI) == 5


def test_load_high_water_mark_still_returns_the_version_for_both_formats(w, tmp_path):
    assert st.load_high_water_mark(legacy_store(tmp_path, 5), URI) == 5
    store = tmp_path / "new.json"
    ingest(w, artifact(w, version=8), store)
    assert st.load_high_water_mark(store, URI) == 8
    assert st.load_high_water_mark(tmp_path / "absent.json", URI) is None


# ================================================================== step 2: lower, equal and higher versions; backfill

def ingest_at(w, wire, store, now=NOW, max_staleness=MAX_STALENESS):
    """Direct ingestion with the freshness context `authorize` supplies."""
    return st.ingest_status_artifact(wire, root=w.root, root_trust_anchor=w.root_pub, store_path=store,
                                     now=now, max_staleness=max_staleness)


def no_writes(monkeypatch, store):
    def forbidden(*a, **k):
        raise AssertionError("persistent write")
    monkeypatch.setattr(st, "save_high_water_mark", forbidden)
    monkeypatch.setattr(type(store), "write_text", forbidden)
    monkeypatch.setattr(type(store), "write_bytes", forbidden)


def test_equal_version_same_artifact_is_accepted_idempotently_and_does_not_touch_the_store(w, tmp_path, monkeypatch):
    store = tmp_path / "hwm.json"
    wire = artifact(w, version=3, statements=[statement(w, target=w.b)])
    first = ingest_at(w, wire, store)
    before = store.read_bytes()
    no_writes(monkeypatch, store)  # the second presentation must not write anything
    second = ingest_at(w, wire, store)
    assert store.read_bytes() == before
    assert second == first  # same statements, digest, version


def test_equal_version_is_accepted_repeatedly_through_authorize_and_revocations_apply(w, tmp_path):
    store = tmp_path / "hwm.json"
    wire = artifact(w, version=3, statements=[statement(w, target=w.b)])
    for _ in range(3):
        with pytest.raises(NodeRevoked) as exc:  # not StatusRollback: the same artifact may be presented again
            auth(w, wire, store)
        assert exc.value.node_id == w.b.node_id
    assert entry(store) == (3, body_digest(wire).hex())


def test_equal_version_is_accepted_after_a_restart_from_the_store_file_alone(w, tmp_path):
    store = tmp_path / "hwm.json"
    wire = artifact(w, version=4)
    ingest_at(w, wire, store)
    reopened = type(store)(str(store))  # nothing but the durable file survives a restart
    assert ingest_at(make_world_like(w), wire, reopened).version == 4


def make_world_like(w):
    return w  # the root is configuration, not in-process state: the same lineage after restart


def test_strictly_lower_version_is_still_a_rollback_after_an_equal_version_was_accepted(w, tmp_path):
    store = tmp_path / "hwm.json"
    ingest_at(w, artifact(w, version=3), store)
    ingest_at(w, artifact(w, version=3), store)  # equal accepted
    with pytest.raises(StatusRollback) as exc:
        ingest_at(w, artifact(w, version=2), store)
    assert exc.value.reason is StatusReason.VERSION_ROLLBACK
    assert entry(store)[0] == 3


def test_lower_version_with_different_content_is_a_rollback_not_equivocation(w, tmp_path):
    store = tmp_path / "hwm.json"
    ingest_at(w, artifact(w, version=3), store)
    with pytest.raises(StatusRollback):
        ingest_at(w, artifact(w, version=2, valid_until=NOW + 5), store)


def test_higher_version_advances_the_mark_and_replaces_the_digest(w, tmp_path):
    store = tmp_path / "hwm.json"
    ingest_at(w, artifact(w, version=3), store)
    wire = artifact(w, version=4, valid_until=NOW + 2000)
    ingest_at(w, wire, store)
    assert entry(store) == (4, body_digest(wire).hex())


def test_higher_stale_authenticated_version_still_advances_the_mark_before_freshness(w, tmp_path):
    store = tmp_path / "hwm.json"
    ingest_at(w, artifact(w, version=3), store)
    stale = artifact(w, version=7, issued_at=NOW - 50_000)
    with pytest.raises(StaleStatusArtifact):
        auth(w, stale, store)
    assert entry(store) == (7, body_digest(stale).hex())  # persisted before freshness (ruling 8)


def test_equal_version_stale_artifact_is_rejected_on_use_and_changes_nothing(w, tmp_path):
    store = tmp_path / "hwm.json"
    wire = artifact(w, version=3)
    ingest_at(w, wire, store)
    before = store.read_bytes()
    with pytest.raises(StaleStatusArtifact) as exc:  # same artifact, but `now` is past its freshness deadline
        auth(w, wire, store, now=NOW + 5000)
    assert exc.value.reason is StatusReason.ARTIFACT_STALE and not isinstance(exc.value, StatusRollback)
    assert store.read_bytes() == before


def test_equal_version_with_an_invalid_signature_is_rejected_and_is_not_equivocation(w, tmp_path):
    store = tmp_path / "hwm.json"
    ingest_at(w, artifact(w, version=3), store)
    before = store.read_bytes()
    forged = artifact(w, version=3, valid_until=NOW + 4000, key=generate_keypair()[0])
    eq_before, sig_before = alert_count("artifact_equivocation"), alert_count("artifact_signature_invalid")
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, forged, store)
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID  # authentication precedes any digest comparison
    assert alert_count("artifact_equivocation") == eq_before
    assert alert_count("artifact_signature_invalid") == sig_before + 1
    assert store.read_bytes() == before


def test_equal_version_for_another_uri_is_rejected_and_changes_nothing(w, tmp_path):
    store = tmp_path / "hwm.json"
    ingest_at(w, artifact(w, version=3), store)
    before = store.read_bytes()
    with pytest.raises(Exception) as exc:
        auth(w, artifact(w, version=3, uri="https://attacker.example/status"), store)
    assert type(exc.value).__name__ == "RevocationBindingMismatch"
    assert store.read_bytes() == before


def test_equal_version_does_not_skip_freshness_when_an_accepted_state_is_reused(w, tmp_path):
    store = tmp_path / "hwm.json"
    state = ingest_at(w, artifact(w, version=3), store)
    run = lambda now: authorize(w.lineage, w.root_pub, audience="agent", now=now, status_artifact=state,
                                max_staleness=MAX_STALENESS)
    assert run(NOW)
    with pytest.raises(StaleStatusArtifact):
        run(NOW + 1000)


# ---- legacy integer entries: backfill the digest on the first PERMITTED equal-version sighting

def test_equal_version_on_a_legacy_entry_backfills_the_digest_when_authenticated_and_fresh(w, tmp_path):
    store = legacy_store(tmp_path, 5)
    wire = artifact(w, version=5)
    state = ingest_at(w, wire, store)
    assert state.version == 5
    assert entry(store) == (5, body_digest(wire).hex())  # same version, digest now recorded


def test_backfill_happens_once_and_later_presentations_do_not_rewrite(w, tmp_path, monkeypatch):
    store = legacy_store(tmp_path, 5)
    wire = artifact(w, version=5)
    ingest_at(w, wire, store)
    before = store.read_bytes()
    no_writes(monkeypatch, store)
    ingest_at(w, wire, store)
    assert store.read_bytes() == before


def test_backfill_is_not_performed_for_a_stale_equal_version_artifact(w, tmp_path):
    store = legacy_store(tmp_path, 5)
    before = store.read_bytes()
    stale = artifact(w, version=5, issued_at=NOW - 50_000)
    with pytest.raises(StaleStatusArtifact):
        auth(w, stale, store)
    assert store.read_bytes() == before and json.loads(store.read_text()) == {URI: 5}


def test_backfill_is_not_performed_for_an_unauthenticated_equal_version_artifact(w, tmp_path):
    store = legacy_store(tmp_path, 5)
    before = store.read_bytes()
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, artifact(w, version=5, key=generate_keypair()[0]), store)
    assert exc.value.reason is StatusReason.ARTIFACT_SIGNATURE_INVALID
    assert store.read_bytes() == before


def test_backfill_is_not_performed_when_the_artifact_has_an_integrity_defect(w, tmp_path):
    store = legacy_store(tmp_path, 5)
    before = store.read_bytes()
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, artifact(w, version=5, statements=[b"\x01\x02"]), store)
    assert exc.value.reason is StatusReason.ARTIFACT_INTEGRITY
    assert store.read_bytes() == before


def test_backfill_is_not_performed_on_key_reuse(tmp_path):
    w = make_world(artifact_key_from="root")
    store = legacy_store(tmp_path, 5)
    before = store.read_bytes()
    with pytest.raises(StatusFailure) as exc:
        auth(w, artifact(w, version=5), store)
    assert exc.value.reason is StatusReason.ARTIFACT_KEY_REUSE
    assert store.read_bytes() == before


def test_backfill_needs_a_freshness_context_so_direct_ingestion_without_one_never_backfills(w, tmp_path):
    store = legacy_store(tmp_path, 5)
    before = store.read_bytes()
    state = st.ingest_status_artifact(artifact(w, version=5), root=w.root, root_trust_anchor=w.root_pub, store_path=store)
    assert state.version == 5  # authenticated equal version is accepted ...
    assert store.read_bytes() == before  # ... but freshness is unknown, so the digest is not recorded


def test_legacy_lower_version_is_a_rollback_and_changes_nothing(w, tmp_path):
    store = legacy_store(tmp_path, 5)
    before = store.read_bytes()
    with pytest.raises(StatusRollback):
        ingest_at(w, artifact(w, version=4), store)
    assert store.read_bytes() == before


# ================================================================== step 3: equal version, different digest = equivocation

def equivocating(w, version=3, **kw):
    """A second, validly signed artifact at the same version but with different content."""
    kw.setdefault("valid_until", NOW + 2000)
    return artifact(w, version=version, **kw)


def accepted_with_revocation_of_b(w, tmp_path, version=3):
    store = tmp_path / "hwm.json"
    wire = artifact(w, version=version, statements=[statement(w, target=w.b)])
    return store, wire, ingest_at(w, wire, store)


def test_equal_version_with_a_different_digest_is_rejected_and_alerted(w, tmp_path, caplog):
    store, wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    other = equivocating(w)
    before = store.read_bytes()
    count = alert_count("artifact_equivocation")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(StatusUnavailable) as exc:
            ingest_at(w, other, store)
    assert exc.value.reason is StatusReason.ARTIFACT_EQUIVOCATION
    assert alert_count("artifact_equivocation") == count + 1
    f = _records(caplog, "artifact_equivocation")[0].alert_fields
    assert f["version"] == 3 and f["root_revocation_state_uri"] == URI
    assert f["stored_digest"] == body_digest(wire).hex() and f["presented_digest"] == body_digest(other).hex()
    assert f["reason_code"] == StatusReason.ARTIFACT_EQUIVOCATION.name
    assert store.read_bytes() == before  # the stored digest is never replaced


def test_equivocation_reason_is_distinct_and_is_not_a_rollback(w, tmp_path):
    assert StatusReason.ARTIFACT_EQUIVOCATION not in (StatusReason.VERSION_ROLLBACK, StatusReason.ARTIFACT_INTEGRITY,
                                                      StatusReason.ARTIFACT_SIGNATURE_INVALID)
    assert len({r.value for r in StatusReason}) == len(StatusReason)
    store, _wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    with pytest.raises(StatusUnavailable) as exc:
        ingest_at(w, equivocating(w), store)
    assert not isinstance(exc.value, StatusRollback)


def test_equivocating_artifact_is_rejected_even_when_it_is_stale_and_changes_nothing(w, tmp_path):
    store, _wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    before = store.read_bytes()
    with pytest.raises(StatusUnavailable) as exc:  # not StaleStatusArtifact: the digest conflict is decided first
        ingest_at(w, equivocating(w, issued_at=NOW - 50_000), store)
    assert exc.value.reason is StatusReason.ARTIFACT_EQUIVOCATION
    assert store.read_bytes() == before


def test_an_integrity_defect_is_reported_before_an_equivocation(w, tmp_path):
    store, _wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    with pytest.raises(StatusUnavailable) as exc:
        ingest_at(w, equivocating(w, statements=[b"\x01\x02"]), store)
    assert exc.value.reason is StatusReason.ARTIFACT_INTEGRITY


def test_equivocation_is_detected_after_a_digest_was_backfilled_onto_a_legacy_entry(w, tmp_path):
    store = legacy_store(tmp_path, 5)
    ingest_at(w, artifact(w, version=5), store)  # first permitted sighting: backfill
    with pytest.raises(StatusUnavailable) as exc:
        ingest_at(w, artifact(w, version=5, valid_until=NOW + 2000), store)
    assert exc.value.reason is StatusReason.ARTIFACT_EQUIVOCATION


def test_a_legacy_entry_cannot_detect_equivocation_before_its_first_permitted_sighting(w, tmp_path):
    # Known limit of the compatibility rule: with no recorded digest the first authenticated, fresh artifact at the
    # stored version is accepted and becomes the reference.
    store = legacy_store(tmp_path, 5)
    first = artifact(w, version=5, valid_until=NOW + 2000)
    assert ingest_at(w, first, store).version == 5
    assert entry(store) == (5, body_digest(first).hex())


@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_equivocating_artifact_is_never_persisted_or_used_under_any_policy(w, tmp_path, monkeypatch, policy):
    store, _wire, last = accepted_with_revocation_of_b(w, tmp_path)
    before = store.read_bytes()
    bad = equivocating(w, statements=[statement(w, target=w.a)])  # revokes `a`: must never take effect
    no_writes(monkeypatch, store)
    try:
        auth(w, bad, store, last_accepted_status=last, **pol(policy))
    except NodeRevoked as exc:
        assert exc.node_id == w.b.node_id  # from the last authenticated artifact, never from the rejected one
    except StatusUnavailable as exc:
        assert exc.reason is StatusReason.ARTIFACT_EQUIVOCATION
    assert store.read_bytes() == before


def test_fail_closed_denies_an_equivocating_artifact(w, tmp_path):
    store, _wire, last = accepted_with_revocation_of_b(w, tmp_path)
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, equivocating(w), store, last_accepted_status=last, status_policy=StatusPolicy.FAIL_CLOSED)
    assert exc.value.reason is StatusReason.ARTIFACT_EQUIVOCATION


def test_bounded_staleness_falls_back_to_the_last_authenticated_artifact_and_its_revocations_apply(w, tmp_path, caplog):
    store, _wire, last = accepted_with_revocation_of_b(w, tmp_path)
    count = alert_count("status_fallback_last_authenticated")
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(NodeRevoked) as exc:
            auth(w, equivocating(w), store, last_accepted_status=last, status_policy=StatusPolicy.BOUNDED_STALENESS)
    assert exc.value.node_id == w.b.node_id
    assert alert_count("status_fallback_last_authenticated") == count + 1
    f = _records(caplog, "status_fallback_last_authenticated")[0].alert_fields
    assert f["reason_code"] == StatusReason.ARTIFACT_EQUIVOCATION.name and f["policy"] == "BOUNDED_STALENESS"
    with pytest.raises(StatusUnavailable):  # nothing authenticated to fall back to
        auth(w, equivocating(w), store, status_policy=StatusPolicy.BOUNDED_STALENESS)
    with pytest.raises(StatusUnavailable):  # a fallback state that is no longer fresh is not used
        auth(w, equivocating(w), store, now=NOW + 5000, last_accepted_status=last,
             status_policy=StatusPolicy.BOUNDED_STALENESS)


def test_ttl_only_does_not_excuse_an_equivocation(w, tmp_path):
    store, _wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, equivocating(w), store, status_policy=StatusPolicy.TTL_ONLY_NO_STATUS)
    assert exc.value.reason is StatusReason.ARTIFACT_EQUIVOCATION


def test_fail_open_arm_may_allow_without_state_after_an_equivocation_and_reports_its_own_finding(w, tmp_path, caplog):
    # The approved refinement: an equivocation has its own fail-open finding (superseding the earlier mapping,
    # which recorded it as fail_open_after_artifact_integrity). Full coverage is in the section below.
    store, _wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    before = store.read_bytes()
    kind = "fail_open_after_equivocation"
    count = alert_count(kind)
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        ids = auth(w, equivocating(w, statements=[statement(w, target=w.a)]), store, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    assert ids == [n.node_id for n in w.lineage]  # allowed, the rejected artifact's revocation of `a` not applied
    assert alert_count(kind) == count + 1
    assert _records(caplog, kind)[0].alert_fields["reason_code"] == StatusReason.ARTIFACT_EQUIVOCATION.name
    assert store.read_bytes() == before


def test_the_original_artifact_is_still_accepted_after_an_equivocation_was_rejected(w, tmp_path):
    store, wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    with pytest.raises(StatusUnavailable):
        ingest_at(w, equivocating(w), store)
    assert ingest_at(w, wire, store).version == 3  # the equivocator did not displace the accepted artifact
    assert entry(store) == (3, body_digest(wire).hex())


# ================================================================== step 4: failed verification never mutates state; _demo

def _defects(w):
    from test_revision_a import _malformed_wires, DEEP
    forger = generate_keypair()[0]
    stale = dict(issued_at=NOW - 50_000)
    return {
        "forged_signature": lambda v: artifact(w, version=v, key=forger),
        "wrong_uri": lambda v: artifact(w, version=v, uri="https://attacker.example/status"),
        "malformed_statement": lambda v: artifact(w, version=v, statements=[b"\x01\x02"]),
        "statement_version_2": lambda v: artifact(w, version=v, statements=[_malformed_wires(w)["malformed_wire/statement_version_2"]]),
        "too_deeply_nested": lambda v: artifact(w, version=v, statements=[DEEP]),
        "garbage": lambda v: b"garbage",
        "stale": lambda v: artifact(w, version=v, **stale),
        "different_content": lambda v: artifact(w, version=v, valid_until=NOW + 2000),
    }


DEFECT_NAMES = sorted(_defects(make_world()))


@pytest.mark.parametrize("version_kind", ["lower", "equal"])
@pytest.mark.parametrize("store_kind", ["new", "legacy"])
@pytest.mark.parametrize("defect", DEFECT_NAMES)
def test_failed_verification_never_mutates_the_store(w, tmp_path, monkeypatch, defect, store_kind, version_kind):
    store = tmp_path / "hwm.json"
    if store_kind == "new":
        ingest_at(w, artifact(w, version=5), store)
    else:
        store.write_text(json.dumps({URI: 5}))
    before = store.read_bytes()
    no_writes(monkeypatch, store)
    wire = _defects(w)[defect](5 if version_kind == "equal" else 4)
    try:
        auth(w, wire, store)
    except (StatusFailure, StaleStatusArtifact, Exception):  # whichever typed failure: only the store matters here
        pass
    assert store.read_bytes() == before


def test_an_artifact_that_fails_at_a_higher_version_does_not_advance_the_mark(w, tmp_path):
    store = tmp_path / "hwm.json"
    ingest_at(w, artifact(w, version=5), store)
    before = store.read_bytes()
    for wire in (artifact(w, version=9, key=generate_keypair()[0]), artifact(w, version=10, statements=[b"\x01"]),
                 artifact(w, version=11, uri="https://attacker.example/status")):
        with pytest.raises(Exception):
            auth(w, wire, store)
    assert store.read_bytes() == before
    assert ingest_at(w, artifact(w, version=6), store).version == 6  # the genuine next version is not blocked


def test_status_demo_runs_and_checks_the_revision_b_rules(capsys):
    st._demo()
    assert "status.py self-check passed" in capsys.readouterr().out


def test_backfill_happens_through_authorize_when_the_equal_version_is_authenticated_and_fresh(w, tmp_path):
    store = legacy_store(tmp_path, 5)
    wire = artifact(w, version=5)
    assert auth(w, wire, store) == [n.node_id for n in w.lineage]
    assert entry(store) == (5, body_digest(wire).hex())  # `authorize` supplies the freshness context to ingestion


# ================================================================== approved equivocation policy and distinct fail-open telemetry
# Fail-closed denies; bounded staleness falls back only to a previously authenticated artifact still inside its
# freshness window; the experimental fail-open arm may allow. The equivocating artifact itself is always rejected,
# never replaces the stored digest, never advances the mark, and always raises `artifact_equivocation`.

EQ = "fail_open_after_equivocation"
OTHER_FAIL_OPEN = ("fail_open_after_artifact_integrity", "fail_open_after_status_unavailable")
TELEMETRY_KINDS = (EQ, *OTHER_FAIL_OPEN, "status_fallback_last_authenticated", "artifact_equivocation",
                   "artifact_integrity", "artifact_signature_invalid", "invalid_revocation_statement")


def counts():
    return {k: alert_count(k) for k in TELEMETRY_KINDS}


def delta(before):
    after = counts()
    return {k: after[k] - before[k] for k in TELEMETRY_KINDS if after[k] != before[k]}


def _finding(name):
    return getattr(st.FailOpenFinding, name)


def test_the_equivocation_finding_is_distinct_from_every_other_finding_and_reason():
    assert _finding("AFTER_EQUIVOCATION").value == "fail_open_after_equivocation"
    values = [f.value for f in st.FailOpenFinding]
    assert len(values) == len(set(values)) == 3
    assert not ({f.value for f in st.FailOpenFinding} & {r.value for r in StatusReason})
    assert not ({f.name for f in st.FailOpenFinding} & {r.name for r in StatusReason})
    assert StatusReason.ARTIFACT_EQUIVOCATION.value == "equivocation"  # the reason code itself is preserved


def test_fail_open_with_no_usable_state_reports_only_the_equivocation_finding(w, tmp_path, caplog):
    store, wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    before_entry, before_bytes = entry(store), store.read_bytes()
    base = counts()
    bad = equivocating(w, statements=[statement(w, target=w.a)])  # revokes `a`: must never take effect
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        ids = auth(w, bad, store, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    assert ids == [n.node_id for n in w.lineage]
    # exactly one equivocation alert and one equivocation finding; no integrity or unavailability finding
    assert delta(base) == {"artifact_equivocation": 1, EQ: 1}
    f = _records(caplog, EQ)[0].alert_fields
    assert f["finding"] == _finding("AFTER_EQUIVOCATION").value
    assert f["reason_code"] == StatusReason.ARTIFACT_EQUIVOCATION.name
    assert f["experimental_arm"] == ARM and f["authenticated_state_used"] is False
    assert f["root_revocation_state_uri"] == URI
    assert entry(store) == before_entry == (3, body_digest(wire).hex())
    assert store.read_bytes() == before_bytes


def test_fail_open_with_a_fresh_authenticated_state_uses_it_and_is_not_a_blind_allow(w, tmp_path, caplog):
    store, _wire, last = accepted_with_revocation_of_b(w, tmp_path)
    base = counts()
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        with pytest.raises(NodeRevoked) as exc:
            auth(w, equivocating(w), store, last_accepted_status=last, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    assert exc.value.node_id == w.b.node_id  # the prior authenticated artifact's revocation still applies
    assert delta(base) == {"artifact_equivocation": 1, "status_fallback_last_authenticated": 1}
    f = _records(caplog, "status_fallback_last_authenticated")[0].alert_fields
    assert f["policy"] == "FAIL_OPEN_EXPERIMENTAL" and f["reason_code"] == StatusReason.ARTIFACT_EQUIVOCATION.name


@pytest.mark.parametrize("policy, expected", [
    (StatusPolicy.FAIL_CLOSED, "deny"),
    (StatusPolicy.TTL_ONLY_NO_STATUS, "deny"),
    (StatusPolicy.BOUNDED_STALENESS, "fallback"),
    (StatusPolicy.FAIL_OPEN_EXPERIMENTAL, "fallback"),  # with a fresh prior artifact; without one see the test above
])
def test_the_three_policy_outcomes_with_a_fresh_prior_artifact(w, tmp_path, policy, expected):
    store, _wire, last = accepted_with_revocation_of_b(w, tmp_path)
    if expected == "deny":
        with pytest.raises(StatusUnavailable) as exc:
            auth(w, equivocating(w), store, last_accepted_status=last, **pol(policy))
        assert exc.value.reason is StatusReason.ARTIFACT_EQUIVOCATION
    else:
        with pytest.raises(NodeRevoked) as exc:
            auth(w, equivocating(w), store, last_accepted_status=last, **pol(policy))
        assert exc.value.node_id == w.b.node_id


def test_fail_closed_and_ttl_only_deny_even_when_a_fresh_prior_artifact_exists(w, tmp_path):
    store, _wire, last = accepted_with_revocation_of_b(w, tmp_path)
    for policy in (StatusPolicy.FAIL_CLOSED, StatusPolicy.TTL_ONLY_NO_STATUS):
        with pytest.raises(StatusUnavailable) as exc:
            auth(w, equivocating(w), store, status_policy=policy)  # and with no prior artifact at all
        assert exc.value.reason is StatusReason.ARTIFACT_EQUIVOCATION


@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_the_stored_digest_and_high_water_mark_never_change_because_of_an_equivocation(w, tmp_path, policy):
    store, wire, last = accepted_with_revocation_of_b(w, tmp_path)
    before_entry, before_bytes = entry(store), store.read_bytes()
    base = counts()
    for other in (equivocating(w), equivocating(w, valid_until=NOW + 3000), equivocating(w, statements=[statement(w, target=w.a)])):
        try:
            auth(w, other, store, last_accepted_status=last, **pol(policy))
        except (StatusUnavailable, NodeRevoked):
            pass
        assert entry(store) == before_entry == (3, body_digest(wire).hex())  # same version, same digest
        assert store.read_bytes() == before_bytes
    assert delta(base)["artifact_equivocation"] == 3  # the alert is always emitted, under every policy


def test_a_fresh_prior_artifact_still_works_after_repeated_equivocations(w, tmp_path):
    store, wire, last = accepted_with_revocation_of_b(w, tmp_path)
    for _ in range(3):
        with pytest.raises(StatusUnavailable):
            auth(w, equivocating(w), store)
    with pytest.raises(NodeRevoked):  # the genuine artifact is still the one in force
        auth(w, wire, store)
    assert ingest_at(w, artifact(w, version=4), store).version == 4  # and the next version is not blocked


# ---- bounded staleness never uses an expired or stale prior artifact

STALE_PRIORS = {
    # name: (prior artifact kwargs, `now` and `max_staleness` for the equivocation request)
    "valid_until_reached": (dict(valid_until=NOW + 100), dict(now=NOW + 100, max_staleness=MAX_STALENESS)),
    "max_staleness_reached": (dict(issued_at=NOW - 100), dict(now=NOW, max_staleness=100)),
    "both_long_past": (dict(issued_at=NOW - 20_000, valid_until=NOW + 50), dict(now=NOW + 60, max_staleness=MAX_STALENESS)),
}


def _prior(w, tmp_path, kw):
    store = tmp_path / "hwm.json"
    last = ingest_at(w, artifact(w, version=3, statements=[statement(w, target=w.b)], **kw), store,
                     now=NOW, max_staleness=10**9)  # fresh when accepted, stale later
    return store, last


@pytest.mark.parametrize("name", sorted(STALE_PRIORS))
def test_bounded_staleness_never_uses_a_stale_or_expired_prior_artifact(w, tmp_path, name):
    kw, ctx = STALE_PRIORS[name]
    store, last = _prior(w, tmp_path, kw)
    base = counts()
    with pytest.raises(StatusUnavailable) as exc:  # not NodeRevoked: the stale prior is not used
        auth(w, equivocating(w, valid_until=NOW + 9000), store, last_accepted_status=last,
             status_policy=StatusPolicy.BOUNDED_STALENESS, **ctx)
    assert exc.value.reason is StatusReason.ARTIFACT_EQUIVOCATION
    assert delta(base) == {"artifact_equivocation": 1}  # no fallback telemetry: no state was used


@pytest.mark.parametrize("name", sorted(STALE_PRIORS))
def test_fail_open_does_not_use_a_stale_prior_artifact_either(w, tmp_path, name):
    kw, ctx = STALE_PRIORS[name]
    store, last = _prior(w, tmp_path, kw)
    base = counts()
    ids = auth(w, equivocating(w, valid_until=NOW + 9000), store, last_accepted_status=last,
               **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL), **ctx)
    assert ids == [n.node_id for n in w.lineage]  # the stale prior's revocation of `b` is NOT applied
    assert delta(base) == {"artifact_equivocation": 1, EQ: 1}  # a blind allow, reported as such


def test_bounded_staleness_uses_a_prior_artifact_exactly_while_it_is_fresh(w, tmp_path):
    kw, ctx = STALE_PRIORS["valid_until_reached"]
    store, last = _prior(w, tmp_path, kw)
    with pytest.raises(NodeRevoked) as exc:  # one second before valid_until: still fresh, so it is used
        auth(w, equivocating(w, valid_until=NOW + 9000), store, last_accepted_status=last,
             status_policy=StatusPolicy.BOUNDED_STALENESS, now=NOW + 99, max_staleness=MAX_STALENESS)
    assert exc.value.node_id == w.b.node_id
    with pytest.raises(StatusUnavailable):  # at valid_until it is not (ruling 17 boundary)
        auth(w, equivocating(w, valid_until=NOW + 9000), store, last_accepted_status=last,
             status_policy=StatusPolicy.BOUNDED_STALENESS, **ctx)


def test_bounded_staleness_has_no_fallback_without_a_prior_authenticated_artifact(w, tmp_path):
    store, _wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    with pytest.raises(StatusUnavailable) as exc:
        auth(w, equivocating(w), store, status_policy=StatusPolicy.BOUNDED_STALENESS)
    assert exc.value.reason is StatusReason.ARTIFACT_EQUIVOCATION


# ---- ordinary failures keep their existing telemetry

def test_an_ordinary_integrity_failure_keeps_the_integrity_finding_under_fail_open(w, tmp_path, caplog):
    store, _wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    base = counts()
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        ids = auth(w, equivocating(w, statements=[b"\x01\x02"]), store, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    assert ids == [n.node_id for n in w.lineage]
    assert delta(base) == {"artifact_integrity": 1, "fail_open_after_artifact_integrity": 1}  # not the equivocation finding
    assert _records(caplog, "fail_open_after_artifact_integrity")[0].alert_fields["reason_code"] == StatusReason.ARTIFACT_INTEGRITY.name


def test_ordinary_unavailability_keeps_the_unavailable_finding_under_fail_open(w, tmp_path, caplog):
    base = counts()
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        auth(w, None, tmp_path / "hwm.json", **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))  # S1
        auth(w, artifact(w, key=generate_keypair()[0]), tmp_path / "hwm.json", **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))  # S5
        auth(w, artifact(w, issued_at=NOW - 50_000), tmp_path / "hwm2.json", **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))  # S6
    d = delta(base)
    assert d["fail_open_after_status_unavailable"] == 3 and EQ not in d and "fail_open_after_artifact_integrity" not in d
    assert "artifact_equivocation" not in d


def test_equivocation_and_integrity_are_told_apart_by_telemetry_alone(w, tmp_path, caplog):
    store, _wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    with caplog.at_level(logging.WARNING, logger="lineage_revocation.alerts"):
        auth(w, equivocating(w), store, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
        auth(w, equivocating(w, statements=[b"\x01"]), store, **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
        auth(w, None, tmp_path / "x.json", **pol(StatusPolicy.FAIL_OPEN_EXPERIMENTAL))
    kinds = [r.alert_kind for r in caplog.records if hasattr(r, "alert_kind") and r.alert_kind.startswith("fail_open")]
    assert kinds == [EQ, "fail_open_after_artifact_integrity", "fail_open_after_status_unavailable"]


def test_other_failures_never_raise_the_equivocation_alert(w, tmp_path):
    store, _wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    base = counts()
    for wire in (artifact(w, version=3, key=generate_keypair()[0]), artifact(w, version=2), b"garbage",
                 artifact(w, version=3, uri="https://attacker.example/status"), artifact(w, version=3, statements=[b"\x01"])):
        try:
            auth(w, wire, store)
        except Exception:
            pass
    assert delta(base).get("artifact_equivocation", 0) == 0


def test_fail_open_for_an_equivocation_still_requires_the_experimental_arm_label(w, tmp_path):
    store, _wire, _ = accepted_with_revocation_of_b(w, tmp_path)
    before = store.read_bytes()
    base = counts()
    with pytest.raises(ValueError, match="experimental"):
        authorize(w.lineage, w.root_pub, audience="agent", now=NOW, status_artifact=equivocating(w),
                  status_store_path=store, max_staleness=MAX_STALENESS, status_policy=StatusPolicy.FAIL_OPEN_EXPERIMENTAL)
    assert delta(base) == {} and store.read_bytes() == before  # refused before anything ran
