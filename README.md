# lineage-revocation

## Overview

Lineage-keyed verifier-side revocation prototype. Delegation nodes are COSE_Sign1 envelopes (CBOR tag 18) over canonical CBOR bodies. Verifier walks lineage, checks leaf status, applies revocation statements.

Implemented and committed: Revision F (`f8e60dc`), the D20 deterministic encoder (`56ddc12`), and Revision A (`ec750bb`). Several supervisor rulings on Revision A are still pending; see `docs/decisions/DR-0003.md`.

Revision F node format:

- `delegation_rights` is `{"can_delegate": bool}`. Required on every node. Other shapes rejected.
- `audience` is an array. Leaf authorization needs `requested_resource` in `leaf.audience`. Empty array denies.
- COSE_Sign1 must carry tag 18. Untagged, other tags, nested tags, bad shape, trailing data rejected.
- Revocation statements embed tagged node envelopes.

D20 encoder: `canonical.py` encodes RFC 8949 section 4.2.1 deterministic CBOR itself instead of relying on cbor2 canonical mode. Nesting is limited to 32 levels (proposed).

Revision A:

- Signed status artifacts, authenticated under a root bound Option K anchor with a dedicated artifact key and artifact only AAD.
- Strict canonical decoding. Nothing is persisted before authentication.
- Unavailable status policy: fail closed by default. Explicit opt in for TTL only. Bounded staleness and an experimental fail open arm are separate policies.
- Statements carry a content derived `revocation_id`. Wire malformed statements reject the whole artifact. Semantically invalid statements are ignored one by one.
- Structured alerts with monotonic counters.

Not committed or not implemented: per node expiry (Revision C), the child audience subset check, equal version handling (Revision B, not committed yet; at this commit an equal version is rejected as a rollback), a status service or network fetch (deferred), and the `status._demo()` self check (a stub that raises until Revision B). Known limitations and open rulings are in `docs/design-revision-1.md` and `docs/decisions/`.

## Layout

```
src/lineage_revocation/
    canonical.py      canonical CBOR encoding
    keys.py           key handling
    lineage.py        lineage structures
    nodes.py          node build, parse, validate, COSE signing
    revocation.py     revocation statements
    status.py         status checks
    verifier.py       verification
tests/                pytest suite
experiments/          agent trace runners and configs
measurement/          collectors, adapters, analysis
scripts/              trace count and corroboration scripts
docs/                 design documents and decision records
```

## Install

Python 3.11 or newer.

```
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Usage

```
.venv/bin/python -m pytest -q
```

## Docs

Design and rulings live in `docs/`. See `docs/design-revision-1.md` and `docs/decisions/`. Release notes in `CHANGELOG.md`.
