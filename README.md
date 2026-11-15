# lineage-revocation

## Overview

Lineage-keyed verifier-side revocation prototype. Delegation nodes are COSE_Sign1 envelopes (CBOR tag 18) over canonical CBOR bodies. Verifier walks lineage, checks leaf status, applies revocation statements.

Implemented: Revision F node format.

- `delegation_rights` is `{"can_delegate": bool}`. Required on every node. Other shapes rejected.
- `audience` is an array. Leaf authorization needs `requested_resource` in `leaf.audience`. Empty array denies.
- COSE_Sign1 must carry tag 18. Untagged, other tags, nested tags, bad shape, trailing data rejected.
- Revocation statements embed tagged node envelopes.

Not implemented: artifact signing, status authentication, unavailable-status and rollback handling, per-node expiry, child-audience subset check.

## Layout

```
src/lineage_revocation/
    canonical.py      canonical CBOR encoding
    keys.py           key handling
    lineage.py        lineage structures
    nodes.py          node build, parse, validate
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
