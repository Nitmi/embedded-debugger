# Supplemental upstream license materials

`upstream-supplements.json` records exact UTF-8 documents and provenance for the
eight locked dependencies whose published `.crate` lacks a conventional license
filename. Text is stored in JSON strings to preserve original line endings and
the absence of a final newline. Each document has its own SHA-256; identical
documents shared by workspace packages are stored once in this catalog.

Collected on 2026-09-08 from the pinned repositories below. These are source
materials, not edited replacement licenses or approval for public distribution.

| Package | Version | Source binding | Documents |
| --- | --- | --- | --- |
| defmt-parser | 1.0.0 | [4a8cdb4](https://github.com/knurling-rs/defmt/tree/4a8cdb44891ed57b8ff5a023b6bec7137c48708f), published Cargo VCS record, `parser` | root LICENSE-MIT, LICENSE-APACHE |
| deku_derive | 0.18.1 | [8b1f5af](https://github.com/sharksforarms/deku/tree/8b1f5af4dbe082007a6c807871f955e5993a54c6), published Cargo VCS record, `deku-derive` | root LICENSE-MIT, LICENSE-APACHE |
| difflib | 0.4.0 | [f035fb8](https://github.com/DimaKudosh/difflib/tree/f035fb8e656f27119e23eca9d5b996df14f3885e), package file comparison | root LICENSE |
| docsplay-macros | 0.1.2 | [1632960](https://github.com/bugadani/docsplay/tree/16329602c0c57ed0d373897b1a62b7304bbd541c), published Cargo VCS record, `docsplay-macros` | root LICENSE-MIT, LICENSE-APACHE |
| parse_int | 0.9.0 | [2b7989b](https://gitlab.com/dns2utf8/parse_int/-/tree/2b7989bf4793c54785217162913000d2cfb6be52), published Cargo VCS record | README.md license declaration, also verified against the crate |
| probe-rs, probe-rs-espressif, probe-rs-target | 0.32.0 | [48f5e4d](https://github.com/probe-rs/probe-rs/tree/48f5e4d53c690a1d40c2454033c6f785b4f4f95c), published Cargo VCS records with each package's directory | root LICENSE-MIT, LICENSE-APACHE |

`difflib` has no `.cargo_vcs_info.json`. Its seven non-generated published files
(six Rust files and `Cargo.toml.orig`) match the corresponding Git blobs at
`f035fb8e656f27119e23eca9d5b996df14f3885e` byte-for-byte; the original manifest maps
to repository `Cargo.toml`. Commit `31ea2a244aa4ccd5954af544998426be13392341` also
matches. This identifies matching source, not an authenticated release commit.
The catalog preserves hashes for all seven comparisons. The upstream LICENSE
names Kevin B. Knapp while the package manifest lists Dima Kudosh; both are
retained without inferring or correcting copyright ownership.

The pinned `parse_int` source tree has no standalone license document. Its README
links four alternatives and includes the author's interpretation. The full README
is retained as `crate_license_declaration`; it is not counted as full license
text, and its legal interpretation is not adopted by this project. cargo-about's
selected generic text remains in the generated materials. `deku_derive` and
`docsplay-macros` publish MIT texts without a copyright line; those texts remain
unchanged. Authors from the checksum-verified published Cargo manifest are
reported separately as attribution context, not invented copyright notices.

## Offline packaging and updates

The builder reads the catalog from its clean pinned Git commit, records the
catalog hash, verifies each original text hash and immutable source URL, then
checks package name/version/repository, locked archive checksum, and either the
published VCS record or the complete package-file evidence. It also compares
in-crate declarations byte-for-byte. Collection never downloads, clones, extracts,
or executes upstream source. Source retrieval is a separate maintainer review;
an offline hash check does not authenticate upstream authors.

Reports keep conventional in-crate `documents` separate from `supplement`.
Existing fallback/no-conventional-document flags remain factual, even when
supplemental full texts are present. Declaration-only material and provenance or
attribution questions have explicit review flags. Ten unique supplemental
documents produce fourteen package-document associations: thirteen full-license
associations across seven packages and one README declaration.

On a dependency upgrade, re-check the published archive and exact source before
updating this catalog. Stale versions, changed checksums or bindings, incomplete
file evidence, altered texts and unreferenced documents fail collection. Never
substitute a moving branch URL or manufacture missing author/year information.
Review native/vendor code, toolchain runtime materials, generic fallback texts
and MPL source delivery separately; `license_compliance_verified` remains false.
