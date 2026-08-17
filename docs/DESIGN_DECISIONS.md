# Design Decision Record

Records implementation decisions for areas the frozen Implementation
Specification v1.0.3 leaves underspecified. This document does not modify
the spec. Where this record and the spec conflict, the spec's frozen wire
format and security invariants win; this record only fills semantic gaps
the spec left open.

## DR-0001: Authority / delegation_rights / attenuation semantics

Status: approved, not yet implemented.

### 1. Authority schema

```
authority: frozenset[str]
```

Finite set of opaque capability strings. No internal structure implied.

### 2. can_delegate schema

```
can_delegate: bool
```

Replaces `delegation_rights: list[str]`. Gates whether a node may mint
children at all. Not consulted for revocation authority (§9 unaffected —
revocation stays root/direct-issuer only, per frozen spec).

### 3. Attenuation formula

```
attenuated(parent, child) =
    parent.can_delegate
    AND
    child.authority ⊆ parent.authority
```

Child denied if either clause fails: `can_delegate = False` on parent, or
child's set not a subset of parent's set.

### 4. No hierarchy

Capability strings carry no namespace, path, or prefix relation. Equality
is the only relation between two capability strings. `"orders:read"` and
`"orders:*"` are two unrelated opaque strings, not parent/child.

### 5. No wildcard meaning

`"*"` is an ordinary opaque string, matched only by literal equality. It
does not mean "all capabilities." Existing fixtures using `"*"` must be
replaced with explicit capability strings before implementation, so no
wildcard semantics leak in by accident.

### 6. Rationale: supporting invariant, not thesis contribution

Thesis contribution is lineage-keyed verifier-side revocation (root-bound
discovery, self-keying lineage verification, rollback/freshness-protected
status distribution — §7-§12 of frozen spec). Attenuation is a
precondition the spec assumes holds (§2) so revocation measurements aren't
confounded by an unrelated amplification bug. It is not itself a claimed
contribution anywhere in the frozen spec. A richer authority language
(caveats, Datalog, hierarchical resources) would compete with, not
support, the revocation thesis — see prior design memo for the full
candidate comparison (Macaroons/Biscuit/UCAN).

### 7. Relation to prior art

Relation to prior art. The representation of authority as a finite set of opaque scope strings follows the basic OAuth 2.0 scope model described in RFC 6749 §3.3. The specific delegation invariant used here — that a delegated authority must be equal to or narrower than the authority previously granted — is consistent with the OAuth assertion-exchange constraint in RFC 7521, which requires requested and issued scope to be equal to or less than the originally granted scope. We deliberately adopt this minimal containment semantics rather than introducing a new authorization language.
