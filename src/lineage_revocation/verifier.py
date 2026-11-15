from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from .lineage import verify_lineage
from .nodes import Node
from .keys import COSEKey
from .status import (
    AcceptedStatus,
    StatusFailure,
    StatusPolicy,
    StatusReason,
    StatusRollback,
    StatusUnavailable,
    UriBindingMismatch,
    check_bound,
    check_key_separation,
    check_fresh,
    handle_unavailable_status,
    emit_fallback,
    ingest_status_artifact,
    require_experimental_arm,
)


class AuthorizationError(Exception):
    pass


class AudienceMismatch(AuthorizationError):
    def __init__(self, actual: Sequence[str], expected: str):
        super().__init__(f"requested resource {expected!r} is not in leaf audience {list(actual)!r}")
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


def _check_artifact_key_separation(lineage: list[Node], root_trust_anchor: COSEKey) -> None:
    # The anchor comes from the authenticated root; every key in the lineage is a delegation key and
    # every non-leaf subject is a potential statement-signing key. Checked on every authorization.
    try:
        anchor_key = COSEKey.from_anchor_bytes(lineage[0].body.revocation_trust_anchor)
    except ValueError:
        return  # unusable anchor: ingestion reports it as an authentication failure
    forbidden = {"root trust anchor key": root_trust_anchor}
    forbidden.update({f"subject key of node {n.node_id.hex()[:16]}": n.body.subject for n in lineage})
    check_key_separation(anchor_key, forbidden, lineage[0].body.root_revocation_state_uri)


def _resolve_status(
    lineage: list[Node],
    root: Node,
    root_trust_anchor: COSEKey,
    status_artifact: bytes | AcceptedStatus | None,
    status_store_path: Path | None,
    max_staleness: int | None,
    status_policy: StatusPolicy,
    last_accepted_status: AcceptedStatus | None,
    now: int,
    experimental_arm: str | None,
) -> AcceptedStatus | None:
    """Returns the status to apply, or None when the policy explicitly allows no status checking.

    Two separate stages. (1) ARTIFACT DISPOSITION, in `ingest_status_artifact`: policy-independent. A
    rejected artifact is never used, its statements are never processed and nothing is persisted. (2)
    REQUEST VERDICT, in `handle_unavailable_status`: policy-governed, and it never sees the rejected artifact."""
    try:
        if status_artifact is None:
            raise StatusUnavailable(StatusReason.STATUS_MISSING, "no status artifact supplied")
        if max_staleness is None:
            raise ValueError("max_staleness is required when a status artifact is supplied")
        _check_artifact_key_separation(lineage, root_trust_anchor)
        if isinstance(status_artifact, AcceptedStatus):
            state = status_artifact
            check_bound(state, root)
        else:
            state = ingest_status_artifact(
                status_artifact, root=root, root_trust_anchor=root_trust_anchor, store_path=status_store_path
            )
        check_fresh(state, now, max_staleness)  # every authorization, never cached
        return state
    except UriBindingMismatch as exc:
        raise RevocationBindingMismatch(root.node_id) from exc
    except StatusRollback:
        raise
    except StatusFailure as failure:
        failure_reason = failure.reason
        fallback = handle_unavailable_status(
            failure, policy=status_policy, now=now, max_staleness=max_staleness or 0,
            last_accepted=last_accepted_status, experimental_arm=experimental_arm,
            root_revocation_state_uri=root.body.root_revocation_state_uri,
        )
    if fallback is not None:
        try:
            check_bound(fallback, root)
        except UriBindingMismatch as exc:
            raise RevocationBindingMismatch(root.node_id) from exc
        emit_fallback(status_policy, failure_reason, fallback, root.body.root_revocation_state_uri, experimental_arm)
    return fallback


def authorize(
    lineage: list[Node],
    root_trust_anchor: COSEKey,
    *,
    audience: str,
    now: int,
    status_artifact: bytes | AcceptedStatus | None = None,
    status_store_path: Path | None = None,
    max_staleness: int | None = None,
    status_policy: StatusPolicy = StatusPolicy.FAIL_CLOSED,
    last_accepted_status: AcceptedStatus | None = None,
    experimental_arm: str | None = None,
    last_authorized_at: int | None = None,
    session_reauth_interval: int | None = None,
) -> list[bytes]:
    require_experimental_arm(status_policy, experimental_arm)
    authenticated_ids = verify_lineage(lineage, root_trust_anchor)

    root = lineage[0]
    _check_revocation_binding(lineage, root)

    # Frozen Spec section 13 order: lineage, root binding, AUDIENCE, attenuation, then status. A request that
    # fails the audience check must not reach the revocation-state machinery (no ingestion, no high-water-mark
    # write, no alert, no policy verdict).
    leaf = lineage[-1]
    if audience not in leaf.body.audience:
        raise AudienceMismatch(leaf.body.audience, audience)
    _check_attenuation(lineage)

    state = _resolve_status(
        lineage, root, root_trust_anchor, status_artifact, status_store_path, max_staleness,
        status_policy, last_accepted_status, now, experimental_arm,
    )
    if state is not None:
        for node_id in authenticated_ids:
            if any(s.target_node_id == node_id and s.effective_at <= now for s in state.statements):
                raise NodeRevoked(node_id)

    if now >= leaf.body.expires_at:
        raise CredentialExpired(leaf.body.expires_at, now)

    if last_authorized_at is not None and session_reauth_interval is not None:
        if now - last_authorized_at >= session_reauth_interval:
            raise ReauthRequired(last_authorized_at, now, session_reauth_interval)

    return authenticated_ids
