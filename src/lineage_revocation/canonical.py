from __future__ import annotations

from typing import Any

import cbor2


def encode_canonical(value: Any) -> bytes:
    return cbor2.dumps(value, canonical=True)


def decode_canonical(data: bytes) -> Any:
    return cbor2.loads(data)
