# Changelog
 
All notable changes to this specification will be documented in this file. Entries are keyed to the draft's own revision suffix (`-00`, `-01`, ...), consistent with Internet-Draft naming conventions.
 
## [draft-zink-xboundary-ai-text-watermark-verification-**00**] — 2026-08-27
 
Initial version.
 
- First publication of the draft: problem statement, relationship to existing work (DKIM, DMARC, ARC, BIMI, C2PA), architecture overview, DNS key distribution and record syntax, multi-hop attestation (`d=` / `dh=` custody descriptors, signing vs. re-signing, key rotation), the laundering tax, worked examples (a)–(j), security considerations, known limitations, incentive analysis and use cases, and open questions for review.
- Repository scaffolding added: README, CONTRIBUTING guide, and `tools/section_ref_checker.py` for catching cross-reference drift on future revisions.
- 2026-09-02 (spec text unchanged): added `tools/watermark_dns_tool.py` (build / lint / traverse `_watermark-text` records, key-pair generation, `d=` custody descriptors, `dh=` digests) and `tools/tzsataitw.py` (a toy asymmetric text watermark, zero-width and homoglyph channels, for exercising the publish-key-in-DNS / verify-across-organizations loop end to end).
