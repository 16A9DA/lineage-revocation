# lineage-revocation

## Overview

Prototype for lineage revocation: canonical encoding, node/key handling, and
revocation status verification. Early scaffold stage. Modules present but
not yet implemented.

## Layout

```
src/lineage_revocation/
    canonical.py      canonical encoding
    keys.py            key handling
    lineage.py         lineage structures
    nodes.py            node definitions
    revocation.py      revocation logic
    status.py           status checks
    verifier.py         verification
tests/                  test suite (COSE, CBOR canonical, leaf status, revocation correctness, root binding)
experiments/            configs and runners
measurement/            collectors, analysis, plots, traces
docs/                    project docs
```

## Install

```
pip install -e .
```

## Usage

Prototype stage. No stable public API yet.

## Tests

```
pytest
```
