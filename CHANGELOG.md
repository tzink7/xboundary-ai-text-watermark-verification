# Changelog
 
All notable changes to this specification will be documented in this file. Entries are keyed to the draft's own revision suffix (`-00`, `-01`, ...), consistent with Internet-Draft naming conventions.
 
## [draft-zink-xboundary-ai-text-watermark-verification-**01**] — 2026-09-09

The `-00` text was a purely-asymmetric proposal. `-01` adds a bounded accommodation for the symmetric watermarking schemes actually deployed in production, and folds in the fixes from the first implementation pass (`tools/`, `tests/`, the live demo).

**New: symmetric-scheme support.**
- **§6.1 `k=` tag** — key model for `p=`. The only defined value is `k=symmetric`, which asserts the `a=` scheme has no public verification key: `p=` MUST be absent, `d=` MUST be present. `k=` absent means asymmetric and `p=` is REQUIRED (existing records unchanged). Malformed: neither present, or `k=symmetric` alongside a `p=`. Deliberately not signalled by a bare missing `p=` (indistinguishable from an error) or an empty `p=;` (which is "revoked" in DKIM — see Appendix A).
- **§6.1 `d=` broadened** — `d=` now points to one of two documents, disambiguated by the record's other tags: the §7.2 custody descriptor (for a cross-vendor `c=re-sign`) or the new §6.6 verification document (for `k=symmetric`).
- **§6.6 (new) — Verification Document Format (k=symmetric).** JSON at the `d=` URL. Required: `algorithm` (MUST match the record's `a=`), `verify` (an HTTPS URL — MAY be a machine endpoint *or* a human-operated web page), `canonicalization` (ordered transform-token array; this document defines `strip-zero-width`, `nfc`, `trim`). Optional: `access` (a URL describing how to obtain credentials for `verify`) and `ts` (publish time). A closing note ties this to §4.4: `k=symmetric` standardizes *discovery* of a provider's verification service, not its scalability — a symmetric scheme still cannot be genuinely cross-verified without an asymmetric scheme or an asymmetric outer layer.

**New: §8 — Composed Marks (Double Signatures).** A construction for two marks on one piece of text at one hop: a robust statistical *inner* mark (symmetric or asymmetric) plus a steganographic *outer* mark carrying an Ed25519-**signed manifest** that names each inner mark and its DNS record. §8.1 motivates this from the EU General-Purpose AI Code of Practice's embedded-and-robust-marking expectation. §8.3 defines the manifest fields and the signed-message construction (the concrete byte layout is deferred to the `a=` registration, §16). §8.5 gives the normative verify order — verify the outer signature first; on failure the manifest's pointers are untrusted and the verifier falls back to no-locator verification. §8.4: a single-provider composed mark needs no §7.2 custody descriptor — the signed manifest is the record. §8.6: the manifest is an optimization, never load-bearing.

**§4.1** — new paragraph: regulation is not obviously pushing providers toward asymmetric schemes (an asymmetric scheme is less mature and less edit-robust), which is why `-01` accommodates symmetric schemes in the two bounded ways above rather than assuming migration.

**Renumbering.** Sections 8–15 became 9–16 to make room for §8. All in-document `Section N` cross-references were updated. Abstract and §5 (now "four components") revised to match.

**Resolved open questions** (surfaced building `tools/`, tracked in `implementation-open-questions.md`):
- §9.2: `s=` is `active`/`revoked` only — `"(or s=deprecated)"` dropped.
- §6.1 / §16: an unrecognized `a=` — normative level unified to SHOULD-treat-as-unusable; §16 adds a carve-out for deliberately experimenting with an unregistered algorithm.
- §6.1: each `a=` registration defines its own text canonicalization, and a verifier MUST apply it before detection.
- §9.2 / §7.5 / §6.1: `nb=`/`na=` are evaluated against the current time *at verification* ("time of detection"), not a text-generation timestamp that nothing carried.
- §7.2: `d=` fetch follows HTTP redirects (no mandated cap; ~5 is a reasonable starting point), digesting the final response body.
- §6.1: `dh=` is Base64URL **without** `=` padding; a generator SHOULD omit padding, a verifier MUST accept either.
- §6.1 / §16: `a=` identifiers name complete, versioned parameter sets — a verifier that recognizes one needs no side channel to learn the scheme's constants. Registration follows Specification Required policy.

**Tooling / demo (not spec text), 2026-09-03 – 09-09:**
- `tools/fairoze.py` + `fairoze_profile.py` + `tools/colab/` — verifier for `fairoze-1`, the [Fairoze23] publicly-detectable construction with the BLS signature swapped for Ed25519. 10 real samples in `samples/fairoze-1/`, verifying against `3._watermark-text.demo.terryzink.com`.
- `tools/synthid.py` + friends — verifier and batch tooling for `synthid-1` (SynthID-Text), the symmetric comparison point. `samples/synthid-1/`, record at `4._watermark-text.demo.terryzink.com`.
- `tools/tzsataitw.py --co-sign` / `--verify` — builds and checks the §8 double-signature manifest. `tests/test_tzsataitw_manifest.py`.
- `demo/` — the sandbox at [watermark.demo.terryzink.com](https://watermark.demo.terryzink.com) now covers all four schemes, `k=symmetric` record creation, and the double signature end to end.

## [draft-zink-xboundary-ai-text-watermark-verification-**00**] — 2026-08-27
 
Initial version.
 
- First publication of the draft: problem statement, relationship to existing work (DKIM, DMARC, ARC, BIMI, C2PA), architecture overview, DNS key distribution and record syntax, multi-hop attestation (`d=` / `dh=` custody descriptors, signing vs. re-signing, key rotation), the laundering tax, worked examples (a)–(j), security considerations, known limitations, incentive analysis and use cases, and open questions for review.
- Repository scaffolding added: README, CONTRIBUTING guide, and `tools/section_ref_checker.py` for catching cross-reference drift on future revisions.
- 2026-09-02 (spec text unchanged): added `tools/watermark_dns_tool.py` (build / lint / traverse `_watermark-text` records, key-pair generation, `d=` custody descriptors, `dh=` digests) and `tools/tzsataitw.py` (a toy asymmetric text watermark, zero-width and homoglyph channels, for exercising the publish-key-in-DNS / verify-across-organizations loop end to end).
