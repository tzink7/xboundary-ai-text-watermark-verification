# A DNS-Based Framework for Cross-Organization Verification of AI-Generated Text Watermarks

**Status:** Discussion draft (Informational, Independent Submission). Not for implementation as written. This is a proposal meant to be stress-tested, not a finished specification.

`draft-zink-xboundary-ai-text-watermark-verification-00`

---

## The problem, in one paragraph

At least one major AI provider (Anthropic, as of August 2026) now watermarks generated text in response to the EU AI Act's Transparency Code, and other signatories are expected to follow. But every deployed watermarking scheme is symmetric: the same secret key embeds the mark and detects it. That key can't be shared across organizations without also handing out the ability to forge and strip the mark — so today, a detector built by one provider can only verify that provider's own watermark. The obvious fallback, a detection API each provider exposes to the others, doesn't scale past a handful of participants: N providers means roughly N² call paths, run against a signal that's supposed to survive nothing more than a copy-paste.

## The proposal, in one paragraph

Borrow the architecture email already used to solve a version of this problem: DKIM's asymmetric signatures, DMARC's fixed DNS location, and ARC's chain-of-custody model. A provider publishes a public verification key at a predictable DNS location (`<selector>._watermark-text.<domain>`), and a model that revises already-watermarked text records the handoff instead of silently overwriting it. This only works with an **asymmetric, publicly-detectable** watermarking scheme — which is not what's deployed at production scale today, Anthropic's current implementation included. The draft is explicit about that dependency rather than assuming it away.

## Read this first

- **[Full draft](./draft-zink-xboundary-ai-text-watermark-verification-00.md)** — the specification itself
- [DNS-Based Framework for Cross-Organization Verification of AI-Generated Text Watermarks](https://docs.google.com/presentation/d/1ezyFW0LdVhTZ_UWJN1bCy3xGd1ajZ2QLacJlaD-82dg/edit?usp=sharing) (slide deck)
- **Plain-English companion** — [Zink's Thinks quick overview](https://zinksthinks.substack.com/p/theres-a-watermark-in-this-sentence)
- YouTube video explainer - Cross-organization verification of AI-generated Text watermarks (Coming soon)
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** — how to file feedback that's actually useful
- **[CHANGELOG.md](./CHANGELOG.md)** — what's changed between revisions

## What's in this repo

| File | What it is |
|---|---|
| `draft-zink-xboundary-ai-text-watermark-verification-00.md` | The specification: problem statement, architecture, DNS record syntax, multi-hop attestation, worked examples, security considerations, known limitations, and open questions |
| `README.md` | This file |
| `CONTRIBUTING.md` | How to file issues and PRs against the draft |
| `CHANGELOG.md` | Revision history |
| `tools/watermark_dns_tool.py` | Build, lint, and traverse `_watermark-text` DNS records; generate key pairs, `d=` custody descriptors, and `dh=` digests. Standard library only (shells out to `openssl` and `dig`) |
| `tools/tzsataitw.py` | An asymmetric text watermark (zero-width-character and homoglyph channels). Steganographic and short-text-capable, but trivially removed by text normalization — the complement to a statistical scheme, not a replacement |
| `tools/fairoze.py` | Verifier for `fairoze-1` — the [Fairoze23] publicly-detectable construction (Ed25519 variant). `--verify` a piece of text against a key from a file or DNS. Needs `reedsolo` (`tools/requirements.txt`) |
| `tools/fairoze_profile.py` | The `fairoze-1` parameter set — the shared contract between the verifier and the generator |
| `tools/fairoze_demo_edits.py` | Builds the two `fairoze-1` robustness-demo samples (one edit survives, one does not) |
| `tools/section_ref_checker.py` | Catches cross-reference drift when section numbers change on revision (optional, no dependencies beyond the Python standard library) |
| `tools/sample.txt`, `tools/sample.watermark.1.txt` | Sample plain and watermarked text used by the tools' examples |
| `tests/` | Test suites for the `fairoze-1` verifier (`python tests/test_fairoze_*.py`) |
| `samples/fairoze-1/` | Real `fairoze-1` watermarked passages, plus the public key and the DNS record they verify against |
| `colab/` | How to generate a `fairoze-1` watermark: a diff against the reference implementation (BLS → Ed25519) and Google Colab walkthroughs |
| `implementation-open-questions.md` | Working notes on gaps and contradictions found while building the tooling — seed document for an implementation/considerations working group. Not part of the draft |

## Where the draft is honest about its own gaps

This isn't a polished pitch — the draft flags its own weakest points on purpose:

- **§10.3 / §14** — The whole mechanism depends on an asymmetric watermarking scheme that isn't running in production yet. Deployed schemes (including Anthropic's SynthID-Text-based implementation) are symmetric.
- **§6.4 / §14** — Nothing here cryptographically proves a domain belongs to a legitimate provider. The seed-list bootstrap-trust problem is inherited, not solved.
- **§9.5 / §7.5(d)** — Multi-hop custody claims are self-attested. A verifier can confirm who signed a handoff, not whether the claim about where the text came from is true.
- **§14** — No revocation-propagation mechanism, no proposal for resolving conflicting custody claims between providers, and no treatment of the statistical effect of testing text against an ever-larger set of cached keys.

The full list is in [Section 14](./draft-zink-xboundary-ai-text-watermark-verification-00.md) of the draft, and each item is a candidate for its own GitHub Issue — see CONTRIBUTING.md.

## Status of this memo

This is a draft submitted for discussion and stress-testing. It is not affiliated with, endorsed by, or representative of any AI provider named as an example. References to specific companies describe publicly reported behavior as of the writing date and are used only to ground the proposal in current practice.

## License

Not yet decided. Treat the current text as "shared for discussion," not licensed for reuse, until this section is updated.

## Author

Terry Zink, Independent Researcher — [zinksthinks.substack.com](https://zinksthinks.substack.com) · tzink@terryzink.com
