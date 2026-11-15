"""D20: protocol-owned RFC 8949 section 4.2.1 deterministic encoder.

RFC 8949 regression and property tests are the conformance oracle. The cbor2 comparison at the
bottom is a compatibility check only.
"""
import ast
import datetime
import decimal
import pathlib
import uuid

import cbor2
import pytest
from cbor2 import CBORSimpleValue, CBORTag
from hypothesis import given, settings, strategies as st

from lineage_revocation.canonical import (
    CanonicalEncodingError,
    decode_strict,
    encode_canonical,
)
from lineage_revocation.keys import COSEKey
from lineage_revocation.nodes import NodeBody

UINT64_MAX = 2**64 - 1


# ---------------------------------------------------------------- independent structural walker

def _head(data: bytes, pos: int):
    b = data[pos]
    major, ai = b >> 5, b & 31
    assert ai != 31, "indefinite length"
    if ai < 24:
        return major, ai, pos + 1
    width = {24: 1, 25: 2, 26: 4, 27: 8}.get(ai)
    assert width is not None, "reserved additional info"
    arg = int.from_bytes(data[pos + 1 : pos + 1 + width], "big")
    assert arg >= {24: 24, 25: 256, 26: 65536, 27: 2**32}[ai], "argument not shortest form"
    return major, arg, pos + 1 + width


def _walk(data: bytes, pos: int = 0) -> int:
    """Validate one item: definite lengths, shortest-form arguments, no floats, only tag 18,
    map keys strictly ascending by the bytewise order of their complete encodings."""
    major, arg, p = _head(data, pos)
    if major in (0, 1):
        return p
    if major == 2:
        assert p + arg <= len(data)
        return p + arg
    if major == 3:
        assert p + arg <= len(data)
        data[p : p + arg].decode("utf-8")
        return p + arg
    if major == 4:
        for _ in range(arg):
            p = _walk(data, p)
        return p
    if major == 5:
        prev = None
        for _ in range(arg):
            start = p
            p = _walk(data, p)
            key = data[start:p]
            assert prev is None or prev < key, "map keys not strictly ascending by encoded bytes"
            prev = key
            p = _walk(data, p)
        return p
    if major == 6:
        assert arg == 18, "unapproved tag"
        return _walk(data, p)
    assert data[pos] in (0xF4, 0xF5, 0xF6), "only false/true/null in major type 7"
    return p


def assert_conformant(data: bytes) -> None:
    assert _walk(data) == len(data)


# ---------------------------------------------------------------- A, B: fixed RFC 8949 vectors

def test_mixed_text_and_integer_keys_follow_rfc8949_not_rfc7049():
    # RFC 8949: 19 03 e8 < 61 61 bytewise. RFC 7049 (cbor2) puts the shorter "a" first.
    assert encode_canonical({"a": 1, 1000: 2}) == bytes.fromhex("a2" "1903e8" "02" "6161" "01")
    assert encode_canonical({1000: 2, "a": 1}) == bytes.fromhex("a2" "1903e8" "02" "6161" "01")


def test_mixed_sign_integer_keys_of_different_widths():
    # 1000 -> 19 03 e8, -1 -> 20, 1 -> 01. Bytewise: 01 < 19.. < 20. Length-first would give 01, 20, 19...
    assert encode_canonical({-1: 0, 1000: 0, 1: 0}) == bytes.fromhex("a3" "01" "00" "1903e8" "00" "20" "00")
    assert encode_canonical({-1: "x", 1000: "y"}) == bytes.fromhex("a2" "1903e8" "6179" "20" "6178")


def test_mixed_key_types_bytes_text_int():
    out = encode_canonical({b"\x01": 0, "a": 0, 5: 0, -1: 0})
    assert out == bytes.fromhex("a4" "05" "00" "20" "00" "4101" "00" "6161" "00")
    assert_conformant(out)


def test_nested_maps_sorted_independently():
    out = encode_canonical({"z": {"b": 1, 1000: 2, "a": 3}, "a": {}})
    assert_conformant(out)
    assert out.startswith(bytes.fromhex("a2" "6161" "a0" "617a" "a3" "1903e8"))


@pytest.mark.parametrize(
    "n, expected",
    [
        (0, "00"), (23, "17"), (24, "1818"), (255, "18ff"), (256, "190100"),
        (65535, "19ffff"), (65536, "1a00010000"), (2**32 - 1, "1affffffff"),
        (2**32, "1b0000000100000000"), (UINT64_MAX, "1bffffffffffffffff"),
        (-1, "20"), (-24, "37"), (-25, "3818"), (-256, "38ff"), (-257, "390100"),
        (-65536, "39ffff"), (-65537, "3a00010000"), (-(2**64), "3bffffffffffffffff"),
    ],
)
def test_shortest_form_integers(n, expected):
    assert encode_canonical(n).hex() == expected


def test_scalars_and_definite_containers():
    assert encode_canonical(None) == b"\xf6"
    assert encode_canonical(True) == b"\xf5"
    assert encode_canonical(False) == b"\xf4"
    assert encode_canonical(b"") == b"\x40"
    assert encode_canonical("") == b"\x60"
    assert encode_canonical([]) == b"\x80"
    assert encode_canonical(()) == b"\x80"
    assert encode_canonical({}) == b"\xa0"
    assert encode_canonical("é") == bytes.fromhex("62c3a9")
    assert encode_canonical(b"x" * 24) == bytes.fromhex("5818") + b"x" * 24


def test_approved_cose_tag_18_round_trip_bytes():
    env = CBORTag(18, [b"\xa1\x01\x27", {}, b"payload", b"\x00" * 64])
    out = encode_canonical(env)
    assert out[0] == 0xD2
    assert_conformant(out)
    assert out == cbor2.dumps(env, canonical=True)


# ---------------------------------------------------------------- C: rejections

@pytest.mark.parametrize("value", [0.0, 1.5, float("nan"), float("inf"), -float("inf")])
def test_floats_rejected_everywhere(value):
    for wrapped in (value, [value], {"k": value}, {value: 1}, CBORTag(18, [b"", {}, value, b""])):
        with pytest.raises(CanonicalEncodingError):
            encode_canonical(wrapped)


@pytest.mark.parametrize(
    "value",
    [
        set(), frozenset({1}), bytearray(b"x"), object(), 1 + 2j, decimal.Decimal(1),
        datetime.datetime(2020, 1, 1), uuid.uuid4(), cbor2.undefined, CBORSimpleValue(0),
        UINT64_MAX + 1, -(2**64) - 1, memoryview(b"x"),
    ],
)
def test_unsupported_types_rejected(value):
    with pytest.raises(CanonicalEncodingError):
        encode_canonical(value)
    with pytest.raises(CanonicalEncodingError):
        encode_canonical([value])


@pytest.mark.parametrize("key", [None, True, (1, 2), 1.0, CBORTag(18, 5)])
def test_unsupported_map_key_types_rejected(key):
    with pytest.raises(CanonicalEncodingError):
        encode_canonical({key: 1})


@pytest.mark.parametrize("tag", [0, 1, 2, 3, 16, 17, 19, 24, 55799, 258, 1000])
def test_unapproved_tags_rejected(tag):
    with pytest.raises(CanonicalEncodingError):
        encode_canonical(CBORTag(tag, [b"", {}, b"", b""]))


@pytest.mark.parametrize(
    "value",
    [5, b"x", [1, 2, 3], [1, 2, 3, 4, 5], CBORTag(18, [b"", {}, b"", b""]), {"a": 1}],
)
def test_tag_18_requires_four_element_array(value):
    with pytest.raises(CanonicalEncodingError):
        encode_canonical(CBORTag(18, value))


def test_bool_is_not_an_integer():
    assert encode_canonical([True, 1]) == bytes.fromhex("82" "f5" "01")


# ---------------------------------------------------------------- C: Hypothesis properties

_ints = st.integers(min_value=-(2**64), max_value=UINT64_MAX)
_scalars = st.none() | st.booleans() | _ints | st.binary(max_size=40) | st.text(max_size=40)
_keys = _ints | st.text(max_size=30) | st.binary(max_size=30)
_values = st.recursive(
    _scalars,
    lambda children: st.lists(children, max_size=4) | st.dictionaries(_keys, children, max_size=5),
    max_leaves=20,
)


def _shuffled(value, rnd):
    if isinstance(value, dict):
        items = [(k, _shuffled(v, rnd)) for k, v in value.items()]
        rnd.shuffle(items)
        return dict(items)
    if isinstance(value, list):
        return [_shuffled(v, rnd) for v in value]
    return value


@settings(max_examples=300, deadline=None)
@given(_values)
def test_property_output_is_conformant(value):
    assert_conformant(encode_canonical(value))


@settings(max_examples=300, deadline=None)
@given(_values, st.randoms(use_true_random=False))
def test_property_independent_of_insertion_order(value, rnd):
    assert encode_canonical(_shuffled(value, rnd)) == encode_canonical(value)


@settings(max_examples=300, deadline=None)
@given(_values)
def test_property_round_trips_through_decoder(value):
    assert cbor2.loads(encode_canonical(value)) == value


@settings(max_examples=300, deadline=None)
@given(st.dictionaries(_keys, st.integers(0, 3), min_size=2, max_size=8))
def test_property_map_keys_ordered_by_complete_encoded_key(d):
    out = encode_canonical(d)
    expected_keys = sorted(encode_canonical(k) for k in d)
    pos = _head(out, 0)[2]
    seen = []
    for _ in range(len(d)):
        end = _walk(out, pos)
        seen.append(out[pos:end])
        pos = _walk(out, end)
    assert seen == expected_keys


@settings(max_examples=200, deadline=None)
@given(_ints)
def test_property_integer_argument_is_shortest_form(n):
    out = encode_canonical(n)
    magnitude = n if n >= 0 else -1 - n
    expected_len = 1 if magnitude < 24 else 2 if magnitude < 256 else 3 if magnitude < 65536 else 5 if magnitude < 2**32 else 9
    assert len(out) == expected_len
    assert_conformant(out)


@settings(max_examples=200, deadline=None)
@given(st.floats(allow_nan=True, allow_infinity=True), _values)
def test_property_floats_rejected_at_any_depth(f, value):
    with pytest.raises(CanonicalEncodingError):
        encode_canonical([value, {"k": [f]}])


@settings(max_examples=200, deadline=None)
@given(st.integers(min_value=2**64, max_value=2**70) | st.integers(min_value=-(2**70), max_value=-(2**64) - 1))
def test_property_out_of_range_integers_rejected(n):
    with pytest.raises(CanonicalEncodingError):
        encode_canonical(n)


@settings(max_examples=200, deadline=None)
@given(st.integers(min_value=0, max_value=2**32).filter(lambda t: t != 18))
def test_property_only_tag_18_accepted(tag):
    with pytest.raises(CanonicalEncodingError):
        encode_canonical(CBORTag(tag, [b"", {}, b"", b""]))


# ---------------------------------------------------------------- E: strict decode path

def test_decode_strict_accepts_encoder_output():
    value = {"a": 1, 1000: [b"x", None, True], "z": {"k": "v"}}
    assert decode_strict(encode_canonical(value)) == value


def test_decode_strict_rejects_rfc7049_ordering_produced_by_cbor2():
    legacy = cbor2.dumps({"a": 1, 1000: 2}, canonical=True)
    assert legacy != encode_canonical({"a": 1, 1000: 2})
    with pytest.raises(CanonicalEncodingError):
        decode_strict(legacy)


@pytest.mark.parametrize(
    "raw",
    [
        bytes.fromhex("a2" "6162" "01" "6161" "02"),  # keys out of order
        bytes.fromhex("1800"),  # non-shortest integer
        bytes.fromhex("9f" "01" "ff"),  # indefinite-length array
        bytes.fromhex("bf" "6161" "01" "ff"),  # indefinite-length map
        bytes.fromhex("5f" "4101" "ff"),  # indefinite-length byte string
        bytes.fromhex("f93e00"),  # float
        bytes.fromhex("c24101"),  # bignum tag
        bytes.fromhex("01" "00"),  # trailing data
        b"",  # empty
        bytes.fromhex("82" "01"),  # truncated
        bytes.fromhex("a2" "6161" "01" "6161" "02"),  # duplicate keys
    ],
)
def test_decode_strict_rejects_non_canonical_or_unsupported(raw):
    with pytest.raises(CanonicalEncodingError):
        decode_strict(raw)


def test_decode_strict_re_encodes_with_the_protocol_encoder(monkeypatch):
    import lineage_revocation.canonical as canonical

    calls = []
    real = canonical.encode_canonical

    def spy(value):
        calls.append(value)
        return real(value)

    monkeypatch.setattr(canonical, "encode_canonical", spy)
    canonical.decode_strict(real({"a": 1}))
    assert calls == [{"a": 1}]


def test_no_cbor2_canonical_encoding_left_in_src():
    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "lineage_revocation"
    offenders = []
    for path in src.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "cbor2"
                and node.func.attr in {"dumps", "dump", "CBOREncoder"}
            ):
                offenders.append(f"{path.name}:{node.lineno}")
            if isinstance(node, ast.keyword) and node.arg == "canonical":
                offenders.append(f"{path.name}:{node.value.lineno}")
    assert offenders == []


# ---------------------------------------------------------------- D: compatibility with cbor2 (not the oracle)

def _sample_body_dict() -> dict:
    return NodeBody(
        version=1, issuer="root", subject=COSEKey(x=b"\x02" * 32), parent_node_id=b"\x03" * 32,
        audience=["agent-x", "agent-y"], authority=frozenset({"b", "a"}),
        delegation_rights={"can_delegate": True}, root_revocation_state_uri="https://status.example/v1",
        revocation_trust_anchor=b"\x01" * 32, issued_at=1_700_000_000, expires_at=1_700_100_000,
    ).to_cbor_dict()


def test_zero_byte_drift_over_existing_protocol_objects():
    body = _sample_body_dict()
    root_body = {**body, "parent_node_id": None}
    payload = encode_canonical(body)
    protected = encode_canonical({1: -8})
    objects = [
        body,
        root_body,
        COSEKey(x=b"\x07" * 32).to_cbor_dict(),
        {1: -8},
        ["Signature1", protected, b"", payload],
        CBORTag(18, [protected, {}, payload, b"\x00" * 64]),
        {
            "statement_version": 1, "revocation_id": b"\x01" * 4, "target_node_id": b"\x02" * 32,
            "target_node": b"\xaa" * 10, "target_lineage": [b"\xbb" * 10, b"\xcc" * 10],
            "revoker": b"\x03" * 32, "revoker_scope_proof": b"", "effective_at": 5, "issued_at": 4,
            "reason_code": "compromise",
        },
    ]
    for obj in objects:
        assert encode_canonical(obj) == cbor2.dumps(obj, canonical=True)


_text_keys = st.text(max_size=40)
_small_int_keys = st.integers(min_value=-24, max_value=23)
_homogeneous = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**63), 2**63) | st.binary(max_size=20) | st.text(max_size=20),
    lambda c: st.lists(c, max_size=3) | st.dictionaries(_text_keys, c, max_size=4) | st.dictionaries(_small_int_keys, c, max_size=4),
    max_leaves=15,
)


@settings(max_examples=300, deadline=None)
@given(_homogeneous)
def test_orderings_coincide_over_text_keyed_and_small_label_maps(value):
    assert encode_canonical(value) == cbor2.dumps(value, canonical=True)


# ---------------------------------------------------------------- B3: nesting limit, no RecursionError leak

import sys
import traceback

from lineage_revocation import canonical


def _nest_list(depth: int):
    value = 0
    for _ in range(depth):
        value = [value]
    return value


def _nest_wire(depth: int) -> bytes:
    return b"\x81" * depth + b"\x00"  # `depth` nested definite-length arrays around 0


def _at_stack(extra_frames: int, fn):
    """Run fn() after `extra_frames` more Python frames. Returns (reached, outcome); outcome is the exception
    fn raised, or None. `reached` is False when the helper itself overflowed before fn started."""
    state = {"reached": False}

    def target():
        state["reached"] = True
        try:
            return None, fn()
        except BaseException as exc:  # noqa: BLE001 - the point is to see exactly what escapes
            return exc, None

    def descend(n):
        return target() if n == 0 else descend(n - 1)

    try:
        exc, _ = descend(extra_frames)
    except RecursionError as helper_overflow:
        return state["reached"], (None if not state["reached"] else helper_overflow)
    return state["reached"], exc


def test_max_nesting_depth_is_a_documented_small_constant():
    assert isinstance(canonical.MAX_NESTING_DEPTH, int)
    assert 8 <= canonical.MAX_NESTING_DEPTH <= 128  # far above any protocol object, far below the stack


def test_nesting_boundary_encoder_accepts_the_limit_and_rejects_one_more():
    limit = canonical.MAX_NESTING_DEPTH
    assert encode_canonical(_nest_list(limit)) == _nest_wire(limit)
    with pytest.raises(CanonicalEncodingError):
        encode_canonical(_nest_list(limit + 1))


def test_nesting_boundary_decode_strict_accepts_the_limit_and_rejects_one_more():
    limit = canonical.MAX_NESTING_DEPTH
    assert decode_strict(_nest_wire(limit)) == _nest_list(limit)
    with pytest.raises(CanonicalEncodingError):
        decode_strict(_nest_wire(limit + 1))


def test_nesting_limit_counts_maps_and_the_cose_tag_as_levels():
    limit = canonical.MAX_NESTING_DEPTH
    maps = {}
    for _ in range(limit - 1):
        maps = {"k": maps}
    assert encode_canonical(maps)  # `limit` nested maps
    with pytest.raises(CanonicalEncodingError):
        encode_canonical({"k": maps})
    tagged = CBORTag(18, [b"", {}, b"", encode_canonical(0)])
    assert encode_canonical(tagged)  # the tag and its array are two levels, well inside the limit
    # tagged = tag (level k), its array (k+1), the empty unprotected-header map inside it (k+2).
    inside = tagged
    for _ in range(limit - 3):
        inside = [inside]
    assert encode_canonical(inside)  # k = limit-3: the innermost map sits on the last permitted level
    with pytest.raises(CanonicalEncodingError):
        encode_canonical([inside])  # k = limit-2: the map would be one level too deep, so the tag IS a level


@pytest.mark.parametrize("depth", [399, 400, 401, 5000, 100000])
@pytest.mark.parametrize("stack", [0, 100, 200, 300, 500, 700])
def test_deeply_nested_input_never_leaks_recursion_error_at_any_caller_stack(depth, stack):
    reached, exc = _at_stack(stack, lambda: decode_strict(_nest_wire(depth)))
    if not reached:
        pytest.skip("helper stack overflowed before the call; covered by the other stack offsets")
    assert isinstance(exc, CanonicalEncodingError), f"leaked {type(exc).__name__}"


def test_the_outcome_for_a_deep_input_does_not_depend_on_the_caller_stack():
    outcomes = set()
    for stack in (0, 50, 150, 300, 600):
        reached, exc = _at_stack(stack, lambda: decode_strict(_nest_wire(399)))
        if reached:
            outcomes.add((type(exc).__name__, str(exc)))
    assert len(outcomes) == 1 and next(iter(outcomes))[0] == "CanonicalEncodingError"


def test_recursion_error_near_the_stack_limit_is_converted_not_leaked():
    # Defense in depth: even a within-limit value can meet an almost exhausted stack. It must come back as a
    # typed error (fail closed), never as RecursionError.
    value = _nest_list(canonical.MAX_NESTING_DEPTH)
    limit = sys.getrecursionlimit()
    converted = 0
    for stack in range(limit - 260, limit):
        reached, exc = _at_stack(stack, lambda: encode_canonical(value))
        if not reached:
            continue
        if isinstance(exc, RecursionError):
            # A RecursionError that never entered canonical.py is the caller's own frame overflowing at the
            # call boundary (no code of ours can run there). Only one that came out of the encoder is a leak.
            frames = [t.filename for t in traceback.extract_tb(exc.__traceback__)]
            assert not any(f.endswith("canonical.py") for f in frames), f"encoder leaked RecursionError at +{stack}"
            continue
        assert exc is None or isinstance(exc, CanonicalEncodingError), f"leaked {type(exc).__name__} at +{stack}"
        converted += isinstance(exc, CanonicalEncodingError)
    assert converted > 0, "the near-limit region was never exercised"
