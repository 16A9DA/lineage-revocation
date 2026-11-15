from __future__ import annotations

import io
from collections.abc import Mapping
from typing import Any

import cbor2
from cbor2 import CBORTag

COSE_SIGN1_TAG = 18  # the only CBOR tag the protocol permits (RFC 9052 section 4.2)
_COSE_SIGN1_LEN = 4
_UINT64_MAX = 2**64 - 1

# Containers (arrays, maps, the COSE tag) may nest at most this deep. Protocol objects nest about five levels,
# so the limit is generous, and it bounds the encoder's recursion deterministically: attacker-controlled input
# can neither exhaust the Python stack nor behave differently depending on the caller's stack depth.
MAX_NESTING_DEPTH = 32


class CanonicalEncodingError(ValueError):
    """A value is unsupported by, or not in the form produced by, the protocol encoder."""


def _head(major: int, arg: int) -> bytes:
    # RFC 8949 section 4.2.1: shortest-form argument.
    if arg < 24:
        return bytes([(major << 5) | arg])
    if arg < 1 << 8:
        return bytes([(major << 5) | 24, arg])
    if arg < 1 << 16:
        return bytes([(major << 5) | 25]) + arg.to_bytes(2, "big")
    if arg < 1 << 32:
        return bytes([(major << 5) | 26]) + arg.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + arg.to_bytes(8, "big")


def _encode(value: Any, depth: int = 0, *, is_key: bool = False) -> bytes:
    # bool is checked first: it subclasses int but encodes as a simple value.
    if type(value) is bool:
        if is_key:
            raise CanonicalEncodingError("map keys must be integer, text or byte strings")
        return b"\xf5" if value else b"\xf4"
    if type(value) is int:
        if value >= 0:
            if value > _UINT64_MAX:
                raise CanonicalEncodingError("integer exceeds the unsigned 64-bit range")
            return _head(0, value)
        if value < -(2**64):
            raise CanonicalEncodingError("integer below the negative 64-bit range")
        return _head(1, -1 - value)
    if type(value) is bytes:
        return _head(2, len(value)) + value
    if type(value) is str:
        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CanonicalEncodingError("text is not valid UTF-8") from exc
        return _head(3, len(raw)) + raw
    if is_key:
        raise CanonicalEncodingError(f"map keys must be integer, text or byte strings, not {type(value).__name__}")
    if value is None:
        return b"\xf6"
    if type(value) in (list, tuple, dict) or isinstance(value, Mapping) or type(value) is CBORTag:
        if depth >= MAX_NESTING_DEPTH:
            raise CanonicalEncodingError(f"nesting exceeds the maximum depth of {MAX_NESTING_DEPTH}")
    if type(value) in (list, tuple):
        return _head(4, len(value)) + b"".join(_encode(v, depth + 1) for v in value)
    if isinstance(value, Mapping) and not isinstance(value, CBORTag):
        pairs = sorted(((_encode(k, depth + 1, is_key=True), v) for k, v in value.items()), key=lambda p: p[0])
        for (k1, _), (k2, _) in zip(pairs, pairs[1:]):
            if k1 == k2:
                raise CanonicalEncodingError("duplicate map key")
        return _head(5, len(pairs)) + b"".join(k + _encode(v, depth + 1) for k, v in pairs)
    if type(value) is CBORTag:
        if value.tag != COSE_SIGN1_TAG:
            raise CanonicalEncodingError(f"CBOR tag {value.tag} is not permitted")
        inner = value.value
        if type(inner) not in (list, tuple) or len(inner) != _COSE_SIGN1_LEN:
            raise CanonicalEncodingError("tag 18 must wrap a four-element array")
        return _head(6, COSE_SIGN1_TAG) + _encode(inner, depth + 1)
    raise CanonicalEncodingError(f"unsupported type {type(value).__name__}")


def encode_canonical(value: Any) -> bytes:
    """RFC 8949 section 4.2.1 core deterministic encoding of a protocol value.

    Map keys are ordered by the bytewise order of their complete encodings (not cbor2's
    RFC 7049 length-first order). Definite lengths and shortest-form arguments only. Floats,
    sets, indefinite items and every tag other than the COSE_Sign1 tag 18 are rejected.
    Key types int/text/bytes are accepted (COSE maps use integer labels); schema validators
    decide which key types a given protocol body permits.
    Domain restriction is input validation; canonical correctness comes from the encoder.

    Nesting is limited to MAX_NESTING_DEPTH. A RecursionError from an almost exhausted caller stack is
    converted to CanonicalEncodingError, so attacker-controlled input can never surface as an untyped
    exception (callers treat CanonicalEncodingError as a malformed object and fail closed).
    """
    try:
        return _encode(value)
    except RecursionError as exc:
        raise CanonicalEncodingError("value is nested too deeply to encode with the remaining stack") from exc


def decode_canonical(data: bytes) -> Any:
    return cbor2.loads(data)


def decode_strict(data: bytes) -> Any:
    """Decode one item and require `data` to be exactly its deterministic encoding.

    Decode, re-encode with encode_canonical, compare byte for byte (DR-1 5.1.7 step 3).
    Anything the encoder cannot produce (floats, indefinite lengths, unapproved tags,
    non-shortest integers, misordered or duplicate keys, trailing data) is rejected.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise CanonicalEncodingError("input must be bytes")
    stream = io.BytesIO(bytes(data))
    try:
        value = cbor2.CBORDecoder(stream).decode()
    except Exception as exc:  # cbor2 raises several decode error types
        raise CanonicalEncodingError(f"not well-formed CBOR: {exc}") from exc
    if stream.tell() != len(data):
        raise CanonicalEncodingError("trailing data after the CBOR item")
    if encode_canonical(value) != bytes(data):
        raise CanonicalEncodingError("input is not in deterministic (RFC 8949 section 4.2.1) form")
    return value
