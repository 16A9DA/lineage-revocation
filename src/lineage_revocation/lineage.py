from __future__ import annotations

from .keys import COSEKey
from .nodes import Node, compute_node_id, verify_node_signature


class LineageVerificationError(Exception):
    pass


class NodeIdMismatch(LineageVerificationError):
    def __init__(self, node: Node):
        super().__init__(f"claimed node_id {node.node_id!r} does not match computed body hash")
        self.node = node


class RootSignatureInvalid(LineageVerificationError):
    def __init__(self):
        super().__init__("root signature does not verify against configured root_trust_anchor")


class ChildSignatureInvalid(LineageVerificationError):
    def __init__(self, node_id: bytes, parent_node_id: bytes):
        super().__init__(f"node {node_id!r} signature does not verify against parent {parent_node_id!r} subject key")
        self.node_id = node_id
        self.parent_node_id = parent_node_id


class ParentLinkMismatch(LineageVerificationError):
    def __init__(self, claimed_parent_node_id: bytes | None, actual_parent_node_id: bytes):
        super().__init__(f"claimed parent_node_id {claimed_parent_node_id!r} != actual {actual_parent_node_id!r}")
        self.claimed_parent_node_id = claimed_parent_node_id
        self.actual_parent_node_id = actual_parent_node_id


class DuplicateNodeId(LineageVerificationError):
    def __init__(self, node_id: bytes):
        super().__init__(f"duplicate node_id {node_id!r} in lineage")
        self.node_id = node_id


def verify_lineage(lineage: list[Node], root_trust_anchor: COSEKey) -> list[bytes]:
    if not lineage:
        raise LineageVerificationError("empty lineage")

    root = lineage[0]
    if compute_node_id(root.body) != root.node_id:
        raise NodeIdMismatch(root)
    if not verify_node_signature(root, root_trust_anchor):
        raise RootSignatureInvalid()

    seen = {root.node_id}
    authenticated_ids = [root.node_id]
    parent = root

    for child in lineage[1:]:
        if compute_node_id(child.body) != child.node_id:
            raise NodeIdMismatch(child)
        if child.node_id in seen:
            raise DuplicateNodeId(child.node_id)
        if child.body.parent_node_id != parent.node_id:
            raise ParentLinkMismatch(child.body.parent_node_id, parent.node_id)
        if not verify_node_signature(child, parent.body.subject):
            raise ChildSignatureInvalid(child.node_id, parent.node_id)

        seen.add(child.node_id)
        authenticated_ids.append(child.node_id)
        parent = child

    return authenticated_ids
