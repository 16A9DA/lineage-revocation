from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .revocation import RevocationStatement


class StatusUnavailable(Exception):
    pass


class StaleStatusArtifact(Exception):
    pass


@dataclass(frozen=True)
class StatusArtifact:
    version: int
    root_revocation_state_uri: str
    issued_at: int
    valid_until: int
    statements: list[RevocationStatement]


def load_high_water_mark(store_path: Path, uri: str) -> int | None:
    if not store_path.exists():
        return None
    try:
        data = json.loads(store_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise StatusUnavailable(f"cannot load high-water mark store at {store_path}") from exc
    return data.get(uri)


def save_high_water_mark(store_path: Path, uri: str, version: int) -> None:
    try:
        data = json.loads(store_path.read_text()) if store_path.exists() else {}
    except (OSError, json.JSONDecodeError):
        data = {}
    data[uri] = version
    store_path.write_text(json.dumps(data))


def accept_status_artifact(
    artifact: StatusArtifact, store_path: Path, *, now: int, max_staleness: int
) -> list[RevocationStatement]:
    """Raises StatusUnavailable or StaleStatusArtifact instead of returning a value;
    whether that maps to fail-open or fail-closed is a caller-side policy decision."""
    highest_seen = load_high_water_mark(store_path, artifact.root_revocation_state_uri)
    if highest_seen is not None and artifact.version <= highest_seen:
        raise StaleStatusArtifact(f"artifact version {artifact.version} <= highest seen {highest_seen}")

    freshness_deadline = min(artifact.valid_until, artifact.issued_at + max_staleness)
    if now >= freshness_deadline:
        raise StaleStatusArtifact(f"artifact stale: now {now} >= freshness deadline {freshness_deadline}")

    save_high_water_mark(store_path, artifact.root_revocation_state_uri, artifact.version)
    return artifact.statements


def _demo() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        store = Path(tmp) / "high_water_marks.json"
        uri = "https://status.example/v1"
        artifact_v1 = StatusArtifact(version=1, root_revocation_state_uri=uri, issued_at=0, valid_until=1000, statements=[])
        artifact_v2 = StatusArtifact(version=2, root_revocation_state_uri=uri, issued_at=0, valid_until=1000, statements=[])

        assert accept_status_artifact(artifact_v1, store, now=0, max_staleness=1000) == []
        try:
            accept_status_artifact(artifact_v1, store, now=0, max_staleness=1000)
        except StaleStatusArtifact:
            pass
        else:
            raise AssertionError("replayed same-version artifact should be rejected as stale")

        assert accept_status_artifact(artifact_v2, store, now=0, max_staleness=1000) == []
        print("status.py self-check passed")


if __name__ == "__main__":
    _demo()
