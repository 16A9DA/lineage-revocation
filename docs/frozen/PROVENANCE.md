# Frozen source documents: provenance

Recorded 2026-11-12. The files in this directory are byte-for-byte copies (`cmp` clean, hashes below). They are not edited. Notes and addenda live in this file only.

Distinctions kept apart: **identity** (which document this is), **authority** (whether it is the governing text), **signature** (a cryptographic or wet signature). No signature was verified by anyone in this repository. Neither document carries a signature, in the file or in its metadata (both are `python-docx` generated).

## Implementation Specification v1.0.3

| item | value |
|---|---|
| file | `Lineage_Keyed_Revocation_Implementation_Spec_v1_0_3.docx` |
| sha256 | `1b4cc41b345b0322f1a932e45f5bdc6024b1cdef045a5b501ae0c89cb9e4b160` |
| source copied from | a local `research_docs/` folder outside the repository (file mtime 2026-08-16 17:44) |
| git | byte-identical to the blob at commit `168a91a` ("Add frozen Implementation Specification v1.0.3 as project reference", 2026-08-17) |
| internal status line | "Status: implementation-ready • v1.0.2 revision • conditional signature requested" (preserved as is) |
| identity | **Supervisor confirmation (2026-11-12, relayed in the task statement):** this file, with the sha256 above, is the exact document submitted for signature. Recorded as the supervisor's confirmation of document identity, **not** as independent verification of a signature |
| comparison | the research_docs file and the `168a91a` blob are byte-identical, and their text exports (paragraphs and 11 tables) are identical. No substantive difference exists between them. Authority therefore rests on the supervisor's identity confirmation, not on the git commit |

The repository files `docs/Lineage_Keyed_Verifier_Side_Revocation_Spec_v1_0_3.docx` (`e0912838faf70360ad41ec46e190e90dba87146fadff9d06898e3f8736c88052`) and `docs/Lineage_Keyed_Verifier_Side_Revocation_Design_Document.docx` (`b3ec895399dfccc3a961a9d6461719cb7dcd6f66fc8c71551182eb2f5340a31f`) are later `html-to-docx` renderings (commits `7e80c2d`, `bec722c`). They contain no tables and are **not authoritative**. They are not part of this baseline.

## Design Document v1.1

| item | value |
|---|---|
| file | `Lineage_Keyed_Verifier_Side_Revocation_Design_Document_v1_1.docx` |
| sha256 | `ee8e4fb828dabbfdcf36cc7788457401728ab42689141d7217bebf1afc677d8e` |
| source copied from | a local `research_docs/` folder outside the repository (file mtime 2026-08-16 17:27) |
| git | not present in git history before this commit |
| internal status line (preserved, not rewritten) | "Status: proposed architecture for supervisor review. Protocol prototype remains blocked pending v1.1 approval; measurement/workload instrumentation is authorized." The final checklist box "Prototype implementation authorized" is unticked in the file |
| approval addendum (added here, not in the document) | **Approved per supervisor review of record, 2026-08-16; invalid-statement amendment carried in Implementation Spec v1.0.x.** The supervisor confirmed that Design v1.1 was approved by the checklist letter of record dated 2026-08-16. That letter is not in the repository and was not inspected; this note records the supervisor's statement |

## Reproduce

```
cd docs/frozen
shasum -a 256 Lineage_Keyed_Revocation_Implementation_Spec_v1_0_3.docx Lineage_Keyed_Verifier_Side_Revocation_Design_Document_v1_1.docx
git show 168a91a:docs/Lineage_Keyed_Revocation_Implementation_Spec_v1_0_3.docx | shasum -a 256
```

The first command must print the two hashes above; the third must print the Spec hash.

## Citation convention in DR-1

`Spec §n` = the Spec file above (its own section numbers; the text has a section 18 test list and a section 19 measurement section). `Design §n` = the Design v1.1 file above. Where the Spec's tables are cited they are cited by their section.
