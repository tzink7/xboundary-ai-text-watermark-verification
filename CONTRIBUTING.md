# Contributing

This is a discussion draft, not a finished specification. It's published to be stress-tested, and the most useful contributions are the ones that find where it breaks.

## Ways to contribute

- **Open an issue** for anything that's unclear, wrong, underspecified, or inconsistent with another part of the draft.
- **Open a pull request** for wording fixes, structural cleanup, or technical corrections.
- **Work an open question.** [Section 14](./draft-zink-xboundary-ai-text-watermark-verification-00.md) is effectively a pre-built backlog — each bullet there is a reasonable candidate for its own issue if one doesn't already exist.

## Filing a good issue

Include, where relevant:

- The section number the issue is about (e.g. "§7.2" or "the `d=` tag in §6.1")
- A short quote or paraphrase of the text in question
- What's wrong, ambiguous, or missing — a contradiction, a gap, a term used inconsistently, a worked example that doesn't match the tag definitions
- A suggested fix, if you have one — not required, but useful

Rough labels to use if the repo has them set up: `open-question` (tracking an item from §14), `bug` (an actual inconsistency or error), `editorial` (wording/grammar/structure), `discussion` (something that needs a decision before it can be fixed).

## Before filing

- Skim open issues and PRs for something that already covers it.
- If your change touches a section number (adding, removing, or reordering a section), the cross-references elsewhere in the document need to stay accurate. Run `python3 section_ref_checker.py draft-zink-xboundary-ai-text-watermark-verification-00.md` first — it flags references pointing at section numbers that no longer exist, and gives you a side-by-side view of every other reference so you can catch the ones that point at the *wrong* (but still existing) section. This has caught real bugs in earlier revisions; it's optional but recommended.

## Conventions worth keeping consistent

- **RFC-style keywords** (MUST, SHOULD, MAY, REQUIRED, OPTIONAL) are used deliberately and should stay consistent with how they're already used elsewhere in the draft — don't introduce a new keyword's meaning without flagging it explicitly.
- **JSON field names in worked examples** (§7.5) should match the schema defined in §7.2 exactly. An earlier revision had `selector`, `from_selector`, `ts`, and `effective` all referring to overlapping concepts across different examples — that inconsistency is fixed as of this revision, and new worked examples should reuse the same field names rather than inventing variants.
- **Section numbering.** If you add or remove a section, every forward and backward reference to a shifted section needs updating. This is the single most common source of drift in this document; see the section-ref-checker note above.

## What happens to your contribution

This is an individual Internet-Draft-style submission, not a working-group document — Terry Zink is the sole editor and retains final say on the primary draft text. Substantial contributions will be credited (in the document itself, in commit history, or both, depending on the size and nature of the contribution). If someone wants to contribute at a level that goes beyond issues and PRs — co-authorship, a parallel track, sustained editorial involvement — open an issue to start that conversation directly rather than assuming it through a large PR.

## Code of conduct

Be direct about the technical substance and generous about the person. Disagreement about the spec is the whole point of publishing it this way; personal attacks, bad-faith framing, or dismissiveness aren't. Assume good faith, and if you think something is actually wrong, say so plainly — vague or hedged feedback is harder to act on than a clear "this is broken and here's why."

## License

Not yet decided — see the note in README.md. Until that's resolved, treat contributions as offered for discussion in this repo rather than under any specific reuse license.
