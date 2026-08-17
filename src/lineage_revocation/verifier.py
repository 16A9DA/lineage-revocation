from __future__ import annotations

from pathlib import Path

from .lineage import verify_lineage
from .nodes import Node
from .keys import COSEKey
from .revocation import is_target_revoked
from .status import StatusArtifact, accept_status_artifact


class AuthorizationError(Exception):
    pass


class AudienceMismatch(AuthorizationError):
    def __init__(self, actual: str, expected: str):
        super().__init__(f"leaf audience {actual!r} != expected {expected!r}")
        self.actual = actual
        self.expected = expected


class CredentialExpired(AuthorizationError):
    def __init__(self, expires_at: int, now: int):
        super().__init__(f"leaf expired at {expires_at}, now {now}")
        self.expires_at = expires_at
        self.now = now


class RevocationBindingMismatch(AuthorizationError):
    def __init__(self, node_id: bytes):
        super().__init__(f"node {node_id!r} carries a root_revocation_state_uri/revocation_trust_anchor that diverges from the authenticated root")
        self.node_id = node_id


class NodeRevoked(AuthorizationError):
    def __init__(self, node_id: bytes):
        super().__init__(f"node {node_id!r} is revoked")
        self.node_id = node_id


class AuthorityAmplification(AuthorizationError):
    def __init__(self, node_id: bytes):
        super().__init__(f"node {node_id!r} authority is not attenuated relative to its parent (DR-0001)")
        self.node_id = node_id


class ReauthRequired(AuthorizationError):
    def __init__(self, last_authorized_at: int, now: int, session_reauth_interval: int):
        super().__init__(f"session last authorized at {last_authorized_at}, now {now} exceeds reauth interval {session_reauth_interval}")
        self.last_authorized_at = last_authorized_at
        self.now = now
        self.session_reauth_interval = session_reauth_interval


def _check_revocation_binding(lineage: list[Node], root: Node) -> None:
    for node in lineage:
        if (
            node.body.root_revocation_state_uri != root.body.root_revocation_state_uri
            or node.body.revocation_trust_anchor != root.body.revocation_trust_anchor
        ):
            raise RevocationBindingMismatch(node.node_id)


def _attenuated(parent: Node, child: Node) -> bool:
    # DR-0001: parent.can_delegate AND child.authority subset-or-equal parent.authority.
    return parent.body.can_delegate and child.body.authority <= parent.body.authority


def _check_attenuation(lineage: list[Node]) -> None:
    parent = lineage[0]
    for child in lineage[1:]:
        if not _attenuated(parent, child):
            raise AuthorityAmplification(child.node_id)
        parent = child


def authorize(
    lineage: list[Node],
    root_trust_anchor: COSEKey,
    *,
    audience: str,
    now: int,
    status_artifact: StatusArtifact | None = None,
    status_store_path: Path | None = None,
    max_staleness: int | None = None,
    last_authorized_at: int | None = None,
    session_reauth_interval: int | None = None,
) -> list[bytes]:
    authenticated_ids = verify_lineage(lineage, root_trust_anchor)

    root = lineage[0]
    _check_revocation_binding(lineage, root)
    _check_attenuation(lineage)

    if status_artifact is not None:
        if status_artifact.root_revocation_state_uri != root.body.root_revocation_state_uri:
            raise RevocationBindingMismatch(root.node_id)
        revocation_statements = accept_status_artifact(
            status_artifact, status_store_path, now=now, max_staleness=max_staleness
        )
        for node_id in authenticated_ids:
            if is_target_revoked(node_id, revocation_statements, root_trust_anchor, now=now):
                raise NodeRevoked(node_id)

    leaf = lineage[-1]
    if leaf.body.audience != audience:
        raise AudienceMismatch(leaf.body.audience, audience)
    if now >= leaf.body.expires_at:
        raise CredentialExpired(leaf.body.expires_at, now)

    if last_authorized_at is not None and session_reauth_interval is not None:
        if now - last_authorized_at >= session_reauth_interval:
            raise ReauthRequired(last_authorized_at, now, session_reauth_interval)

    return authenticated_ids
