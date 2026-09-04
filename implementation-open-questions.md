# Open questions surfaced by implementation

**Status:** working notes, not part of the draft. Started 2026-09-02 while building
`tools/watermark_dns_tool.py`, `tools/tzsataitw.py`, and the demo server; extended
2026-09-03 while implementing the `fairoze-1` verifier (`tools/fairoze.py`,
Steps 1-4). To be triaged later — some items belong in §14 (open questions), some
in §6/§7 as normative text, some in §13 (future expansion).

**2026-09-04:** Sections A and B, and D2, are now resolved into the draft --
each item below is marked **RESOLVED** with a pointer to where. C, D1/D3/D4/D5,
E, and F remain open by design: C is implementation choices worth noting but not
a spec conflict, D1/D3/D4/D5 are `fairoze-1`-specific and belong in a future
per-algorithm registry entry rather than core draft text, E is a project/demo
decision rather than draft text, and F is unbuilt working-group seed material.

Section references are to
`draft-zink-xboundary-ai-text-watermark-verification-00.md`.

---

## A. Internal contradictions (the draft disagrees with itself)

### A1. `s=deprecated` — §6.1 vs §9.2
- §6.1: `s=` values are `"active" or "revoked"`, no others.
- §9.2: on compromise, set `s=revoked` **"(or s=deprecated)"**.
- **Implementation:** `watermark_dns_tool.py` accepts `s=deprecated` and treats it
  as revoked-equivalent (`lint_record`, `is_key_valid_at`), but its `S-VALUE`
  error text still reads "must be 'active' or 'revoked'".
- **Resolution needed:** drop "(or s=deprecated)" from §9.2, **or** define
  `deprecated` in §6.1. If kept, it should mean something §6.1 can't already
  express — e.g. "MUST NOT sign new text under this selector, but text already
  signed inside its `nb`/`na` window still verifies" (a soft-retire distinct from
  both ordinary rotation and hard revocation).
- **RESOLVED (2026-09-04):** dropped "(or s=deprecated)" from §9.2's Key
  Lifecycle bullet. `s=` is `active`/`revoked` only, consistently.

### A2. Unrecognized `a=` — MUST vs SHOULD
- §6.1: an unregistered/unrecognized `a=` **"MUST cause a verifier to treat the
  record as unusable."**
- §15: verifiers **"SHOULD treat such records as unusable."**
- **Implementation:** `A-REGISTRY` finding is a `WARN`, not a hard failure —
  there is no "reject this record" path in the toolchain for an unknown `a=`.
- **Resolution needed:** one normative level. If MUST, a compliance check should
  reject the record; the draft should also acknowledge that no verifier can have
  a complete registry until the IANA registry (§15) exists, so "unrecognized"
  is under-defined in the interim.
- **RESOLVED (2026-09-04):** §6.1 now says SHOULD, matching §15 -- one
  normative level. §15 also gained an explicit carve-out: a verifier MAY treat
  an unrecognized `a=` as usable when experimenting with a new algorithm
  (one's own, or someone else's) to test end-to-end functionality.

---

## B. Gaps the implementation was forced to fill (belong in the draft)

### B1. Text canonicalization before verification — absent
The draft says nothing about how the text under verification is normalized:
Unicode normalization form, leading/trailing whitespace, line endings, stray
invisible characters.
- **Implementation:** `tzsataitw.py` defines `canonical_text()` =
  strip zero-width chars -> fold look-alike (homoglyph) letters to ASCII ->
  NFC -> `.strip()`. A trailing-newline difference (`printf` vs `echo`) was a
  real verification failure before this was pinned down.
- **Resolution needed:** either mandate a baseline canonicalization in the
  framework, or state explicitly that each `a=` registration defines its own and
  that a verifier MUST apply it before detection. Every concrete scheme needs
  this; leaving it unstated makes any two implementations non-interoperable.
- **RESOLVED (2026-09-04):** §6.1, right after the `a=` paragraph -- each `a=`
  registration defines its own canonicalization, and a verifier MUST apply it
  before detection (the second option above).

### B2. Source of the "text generation timestamp" — undefined
- §9.2: "Verifiers **MUST** evaluate text generation timestamps against these
  [`nb`/`na`] windows."
- §7.5(b): "the approximate time the text **appears** to have been produced."
- Nothing carries that timestamp: not the watermark payload, not the DNS record,
  not the `d=` descriptor (its `ts` is descriptor-publication time, not text
  generation time).
- **Implementation:** the verifier can only evaluate "valid now", or a manually
  supplied time (`--at` flag). The §9.2 MUST is otherwise unimplementable.
- **Resolution needed:** define where the timestamp comes from (watermark
  payload? out-of-band metadata? not available?), downgrade the MUST, or list it
  as an explicit §14 open question.
- **RESOLVED (2026-09-04):** sidesteps the undefined source entirely -- §9.2 now
  evaluates `nb=`/`na=` against the current time *at the moment of verification*
  ("time of detection"), not a generation timestamp nothing ever carried. §6.1's
  rationale for the window and §7.5's worked example were both reworded to match
  (they previously argued for the opposite, generation-time model -- a second,
  newly-introduced contradiction caught and fixed in the same pass). Tradeoff
  worth remembering: legitimately-generated text can now fail verification if
  checked after its key's `na` has passed, even though it was signed while the
  key was active -- a deliberate choice, not an oversight.

### B3. HTTP redirects on the `d=` fetch — unspecified
- §7.2.2: "Perform an HTTP GET ... Compute the digest of the exact raw response
  body bytes." No mention of redirects.
- **Implementation:** hosting a `d=` document on Google Drive returns 302s across
  hosts (`drive.google.com` -> `drive.usercontent.google.com`). The demo server
  follows redirects (cap 5), re-applying the https-only + public-IP SSRF checks
  on every hop, and digests the **final** response body. The CLI follows
  redirects via `urllib` defaults.
- **Resolution needed:** state whether redirects are followed, a hop cap, and
  that `dh=` covers the final response. Intersects §9.4 (descriptor tampering /
  SSRF surface) and §B.4 (HTTP-origin fragility).
- **RESOLVED (2026-09-04):** §7.2.2 now says redirects are permitted, with no
  mandated cap but "a reasonable starting point is no more than 5" -- matching
  what the tooling already does.

### B4. `dh=` encoding — padding and alphabet not nailed down
- §6.1: "modeled after the W3C Subresource Integrity / SRI syntax" (SRI uses
  **standard** base64, padded) **and** "Base64URL encoding (RFC 4648)" (different
  alphabet). Padding is never stated.
- **Implementation:** `compute_dh()` emits **base64url with `=` padding** by
  default (`--no-pad` to strip).
- **Resolution needed:** pick exactly one alphabet and one padding rule. Two
  implementations disagreeing on padding fail every digest comparison.
- **RESOLVED (2026-09-04):** §6.1 now specifies Base64URL **without** padding
  (RFC4648 §3.2) -- padding is unnecessary once each tag's value is already
  delimited by `;`, and dropping it avoids an `=` inside a `tag=value;` grammar
  that already uses `=` as its own delimiter. Generator SHOULD omit padding;
  verifier MUST accept either way, since existing tooling has been inconsistent.
  **Follow-up not yet done:** `compute_dh()` in `watermark_dns_tool.py` still
  defaults to `pad=True` (padded), which now disagrees with the spec's SHOULD --
  worth flipping the default, or at least noting it, before this ships anywhere
  that matters.

### B5. `d=` descriptor JSON value types — unstated
- The draft's own examples show `"selector": "2"` and `"ts": "1785542400"` as
  JSON **strings** (a string timestamp is unusual).
- **Implementation:** the parser accepts string or number for both `selector`
  and `ts`.
- **Resolution needed:** state the JSON type of each field in the §7.2.1 schema.
- **RESOLVED (2026-09-04):** both `selector` and `ts` in the example schema now
  state "a literal number, either with or without double-quotes" -- a verifier
  MUST accept both forms for either field.

### B6. No verifier-side cap on the no-`r=` crawl
- §6.4 step 3 / §13 acknowledge the cost of "crawl until a query returns no
  record" but set no ceiling.
- **Implementation:** the demo caps the verify-time domain crawl at 10 selectors
  (`MAX_VERIFY_CRAWL`). Undocumented, and it would return a wrong "not found" for
  a legitimate provider with >10 selectors and no `r=`.
- **Resolution needed:** the draft should say a verifier MAY impose a sane cap,
  and that a provider past some selector count MUST publish `r=`. Defends against
  a hostile or misconfigured seed-list domain answering for a huge selector range.
- **RESOLVED (2026-09-04):** §6.4 step 3 now says a verifier MAY cap the no-`r=`
  crawl, suggests 50 as a starting point, and that a provider past that count
  MUST publish `r=`. **Not reconciled:** the spec's example number (50) and the
  demo/CLI's actual `MAX_VERIFY_CRAWL` (10) now disagree; the spec doesn't
  mandate a number so it's not a bug, just worth aligning eventually.

### B7. "Try each cached key" assumes a cryptographic detector, not a statistical one
- §14 already flags the aggregate false-positive problem for §6.4 step 5.
- **Implementation:** the demo's domain crawl is "try up to N keys, accept the
  first that verifies." Safe for an exact signature (tzsataitw / Ed25519),
  **unsafe** for a statistical scheme (fairoze-style) without adjusting the
  detection threshold for N trials.
- **Resolution needed:** make explicit that any N-key verification loop inherits
  the multiple-hypothesis-testing problem and that a statistical detector must
  adjust its threshold accordingly.
- **RESOLVED (2026-09-04):** §6.4 step 5 now states this explicitly, scoped
  correctly -- it does NOT apply to an exact cryptographic check (Ed25519), only
  to a statistical/threshold detector, which MUST account for the aggregate
  false-positive rate as the cached key set grows. The "how to compute the
  adjustment" question is left where it was, at the existing §14 bullet, which
  §6.4 now cross-references rather than duplicating.

---

## C. Implementation choices below the spec's abstraction (no conflict, but worth noting)

### C1. Algorithm binding in the signed message
`tzsataitw` signs `b"<algorithm>\n" + canonical_text`, so a signature for
`tzsataitw-1` cannot be replayed as `tzsataitw-2`. The draft is silent. Worth
**recommending** that registered algorithms bind their identifier into whatever
they sign/detect over.

### C2. In-band locator hint
`tzsataitw`'s frame carries an unsigned `"<selector>._watermark-text.<domain>"`
string so a verifier can do one targeted lookup instead of brute-forcing the
whole cache (§6.4 step 5). Real tradeoff: cheaper verification vs. an
unauthenticated field that discloses the claimed provider. Candidate for §13.

### C3. Hosting `d=` off the provider's domain
The demo hosts `d=` on Google Drive. Allowed by §6.1 ("an HTTPS URL"), but it is
exactly the HTTP-origin fragility §B.4 of the draft warns about, and it is what
motivated B3 above.

### C4. `tzsataitw` is a test fixture, not a §4.1 primitive
It is a detached Ed25519 signature hidden via steganography (zero-width chars /
homoglyphs), not a statistical / publicly-detectable watermark. It exists to
exercise the §6/§7 DNS + custody machinery end to end. Its frame format
(`MAGIC | version | payload_len | payload | CRC32`, payload =
`locator_len | locator | signature`) is not proposed for the draft.

---

## D. From implementing `fairoze-1` (2026-09-03)

D1, D3, D4, D5 are `fairoze-1`-specific implementation notes -- mask
construction, chained-hash fragility, offset-search convention -- and belong in
a future `fairoze-1` (or `fairoze-2`) IANA registry entry, not core draft text;
confirmed 2026-09-04, left open by design. D2 is the exception: it's a general
principle about how *any* `a=` registration works, not fairoze-specific, so it
was pulled out and added to the draft -- see below.

### D1. `p=` is not algorithm-neutral (Ed25519 chosen partly to sidestep this)
The reference Fairoze impl signs with BLS on a pairing curve (`bplib`/`petlib`).
BLS12-381 / BN256 public keys have no `openssl`-parseable SPKI, so §6.1's "base64
key material" is under-defined for them. `fairoze-1` swaps the signature to
Ed25519 (the construction only needs *any* EUF-CMA scheme; it uses sign/verify as
a black box, no aggregation, no pairing) so `p=` stays a stock 32-byte SPKI.
Still: the draft should say `p=` is `base64(raw key bytes)` with `a=` fixing the
interpretation, OR add a `pk=`/`ph=` key-by-reference pair for schemes whose keys
don't fit DNS. (See earlier discussion; not a field inside `d=`.)

### D2. Scheme parameters must reach the verifier
`fairoze-1` detection needs, besides `p=`: segment length (16 chars), bits per
segment (2), message length (8), RS error budget (2), the hashes (SHA-256
windows, SHAKE256 mask). The reference passes these as CLI flags / a `params`
pickle. A third-party verifier has no channel for them today. `fairoze-1`
resolves this the TLS-cipher-suite way — the `a=` token fully specifies every
constant, so recognizing `fairoze-1` is sufficient. The draft should state that
`a=` values are fully-specified parameter sets, not bare scheme names (kills the
need for a `pp=` tag).

**RESOLVED (2026-09-04):** added to §15's registry-entry paragraph -- each `a=`
identifier names a complete, versioned parameter set; a verifier that
recognizes the identifier needs no side channel beyond it plus `p=`.

### D3. Mask length bug in the reference, inherited if copied naively
`crypto.sign_and_encode_openssl` masks the codeword with `sha512(digest)` via
`zip(codeword, h, strict=False)`. For BLS (45-byte codeword < 64-byte SHA-512)
that's fine. Ed25519's codeword is 68 bytes, so `zip` silently drops the last 4
(RS parity) bytes from the mask AND from the decode path. `fairoze-1` specifies
`mask = SHAKE256(digest, RS_N)` instead. Any future `a=` that RS-encodes a
>64-byte signature hits the same trap — worth a note that the mask MUST cover the
whole codeword.

### D4. The chained-hash extraction makes `fairoze-1` fragile to edits before the tail
Detection extracts segment k's bits from `sha256(message + bits_so_far + w_k)` —
`bits_so_far` is every bit recovered before k. So a single edited character in
segment j corrupts segment j's bits AND, through the chain, every segment after
it. RS(68,64) corrects 2 symbol errors, which in practice only covers an edit in
the **last one or two segments** (~last 32 chars) plus generation-time "planted
errors". An edit anywhere earlier cascades far past the RS budget and the mark
fails. Confirmed by `tests/test_fairoze_verify.py`
(`test_edit_near_start_cascades_and_fails` vs `test_edit_in_final_segment_is_recovered`).

Implications:
- This is consistent with §10.2 ("does not improve robustness") but sharper than
  the draft implies: it's not "less robust than symmetric schemes", it's "one
  character anywhere but the end breaks it".
- The "robustness demo" idea (a sample with 1-2 chars changed that still
  verifies) only works if the edit is in the final segment. Better demo framing:
  show that an edit near the end survives, an edit anywhere else does not.
- The 2026 "robust digital signatures" work (Lin-Shahabi-Song, eprint 2026/282)
  is the fix — a non-chained construction whose signature verifies within a
  Hamming ball. A future `fairoze-2` / new `a=` would use it.

### D5. Verification offset search — contiguous vs cyclic
Reference `search_for_asymmetric_watermark` tries every **cyclic rotation** of
the text (`text[i:] + text[:i]`), O(n^2). `fairoze-1` / `tools/fairoze.py` treats
the watermark as a **contiguous span**: it scans offsets `0 .. n - MIN_CHARS`
only (one iteration when the pasted text is exactly the watermarked passage).
The draft doesn't discuss detection cost or whether a scheme's payload may be
cyclically wrapped; if it stays silent, each `a=` defines its own detector, and
`fairoze-1` should state "contiguous, scan from the start".

---

## E. Positioning / project decisions (not draft text)

### E1. `tzsataitw` is no longer "just a toy" — it is the short-text option
`fairoze-1` needs ~4360+ high-entropy characters (~700 words). It cannot mark a
chat reply, a headline, a tweet, a single paragraph, code, or any terse answer.
That is inherent to embedding a full signature statistically (D4 / §10.1), not a
tuning problem.

`tzsataitw` (a detached Ed25519 signature hidden via zero-width chars or
homoglyphs) has no such floor: `tzsataitw-1` marks anything with ~a sentence or
two of word gaps; `tzsataitw-2` needs ~1600 chars. It also works **post-hoc**,
on text the provider did not generate itself. For the short-text regime it is
the *only* thing that plugs into this framework.

The framework (DNS key distribution + `d=` custody) is agnostic to the embedding
mechanism, so this is a real, usable pairing — not a stand-in.

**But the tradeoffs are severe and must stay front and centre:**
- **Trivially strippable.** Unicode NFKC / whitespace normalization / homoglyph
  folding — all of which platforms do routinely — erase it completely. The
  draft's §3.2 laundering vulnerability is not "compounding degradation" here,
  it is total loss from one `.normalize()` call.
- **Not hidden.** The zero-width chars / Cyrillic letters are visible to anyone
  inspecting the bytes. No undetectability property.
- **Different guarantee.** It proves "this key signed this exact byte sequence",
  closer to an invisible/steganographic signature (C2PA soft-binding, leak-trace
  fingerprinting) than to a statistical LLM watermark.

**So the honest framing is: two complementary mechanisms.**

| | `fairoze-1` (statistical) | `tzsataitw-*` (steganographic) |
|---|---|---|
| min text | ~700 words, high-entropy | a sentence / ~1600 chars |
| when | generation time only | generation OR post-hoc |
| survives plain-text copy | yes | yes |
| survives normalization / reformatting | partly (edits near the tail) | **no — erased** |
| hidden from a byte inspector | yes | **no** |

**Actions:**
- ~~The demo page currently labels `tzsataitw-*` "Toy algorithms" in a
  callout.~~ **DONE** — demo callout now presents both mechanisms and their
  tradeoffs (Step 10).
- Revisit the earlier suggestion (A/§15 note) to relegate `tzsataitw-*` to an
  `x-` / experimental `a=` prefix — if it is the sanctioned short-text option it
  arguably deserves a normal identifier, still with the strippability caveat in
  its registry description. **Still open — not decided either way.**
- ~~`watermark_dns_tool.py` `KNOWN_ALGORITHMS` descriptions and the
  `tzsataitw-algorithm` project note both say "toy"~~ **DONE (2026-09-04)** —
  `KNOWN_ALGORITHMS` for `tzsataitw-1`/`tzsataitw-2` now say "steganographic
  short-text watermark ... trivially removed by text normalization".

---

## F. Layered detection architecture (working-group seed)

A deployment can stack more than one mark on the same text. Proposed layering,
outermost-first at verification time:

1. **A statistical mark** on long-form text: `fairoze-1` (>= ~700 high-entropy
   words; publicly verifiable) OR a symmetric scheme like SynthID (~150 words,
   NOT publicly verifiable -- see step 3).
2. **`tzsataitw-1`** (zero-width) double-signed over the same text. Steganographic,
   survives arbitrary editing, works on any length, but erased by normalization.
   Its frame carries a signed **verification manifest** (F2) -- the ordered
   recipe for checking every mark on the text.
3. **Discovery + procedure:** the manifest names each mark's DNS record and
   canonicalization. A symmetric mark can only carry a `verify_hint` URL. If the
   zero-width frame is gone, fall back to brute-forcing the cached key set with
   every scheme's detector (draft §6.4 step 5).
4. **Out of scope:** a generic AI-text classifier (e.g. Pangram) as a final
   "is this AI at all?" check. Different guarantee (probabilistic, no attribution,
   no non-repudiation), a paid API, and it reintroduces the walled-garden
   detection problem §3.1/§4.4 argue against. Belongs in a product pipeline,
   not this spec. The draft could add one scoping sentence (§1 or §10.2).

Why layer: the two marks fail to *different* attacks (see D4 and E1). An
adversary must both normalize *and* paraphrase to strip both.

### Decisions the WG inherits

**F1. Canonicalization coordination.** If zero-width layering is standard,
`fairoze-1`'s `canonicalize()` MUST strip U+200B/U+200C/U+200D/U+2060 before
window extraction -- interleaved zero-width chars otherwise shift every hash
window and Fairoze detection fails. This resolves the question deferred in
`tools/fairoze_profile.py`: the answer becomes "yes, strip them." Verification
order: parse the zero-width frame first, then run Fairoze on the stripped text.
`tzsataitw` already signs over `strip_marks(text)` and the statistical mark is
invisible at the character level, so that direction composes with no change.

**F2. The zero-width frame as a signed verification manifest.** `tzsataitw`'s
payload is `locator_len | locator | sig(64)` -- one unsigned locator. The
proposal (2026-09-03) is to make it an ordered, *signed* manifest that tells a
verifier exactly what to do:

```
version
marks: [
  { scheme: "tzsataitw-1", locator: "4._watermark-text.example.ai" },      # this frame
  { scheme: "fairoze-1",   locator: "3._watermark-text.example.ai",
                           canon:   "strip-zero-width" },
  { scheme: "synthid-1",   verify_hint: "https://example.ai/verify" },      # symmetric: can't
]                                                                          # publicly verify
sig(64)   # tzsataitw's Ed25519 sig, now covering the manifest AND the canonical text
```

Verifier procedure, in order (the ordering is normative -- steps 2-3 destroy the
mark verified in step 1):

1. Extract the zero-width frame. Verify its signature over
   `manifest || strip_marks(text)` against the `tzsataitw-1` locator's key.
2. For each further `fairoze-*` / other cryptographic entry: apply its stated
   `canon` (e.g. strip zero-width chars -> the Fairoze canonical form), fetch the
   named record's key, run that scheme's detection.
3. For a `verify_hint` entry (symmetric schemes like SynthID that a third party
   cannot verify locally): surface the URL to the user -- do not auto-fetch.

Open points:
- **Signing the manifest.** Today `tzsataitw`'s locator is unsigned (a tampered
  one just fetches the wrong key and fails). A multi-entry manifest that
  redirects the verifier deserves to be signed -- change `tzsataitw`'s signed
  message from `algorithm \n canonical_text` to `manifest \n canonical_text`.
  Worst case if unsigned: a tampered pointer degrades to brute-force, not to a
  false attribution (an attacker can't make their key verify Fairoze bits they
  didn't generate) -- so signing is defence-in-depth, not strictly required.
- `verify_hint` reintroduces the vendor-callback / walled-garden pattern §11.5
  argues against. It is a *graceful-degradation* pointer for the case where
  public verification is impossible by construction, not a primary mechanism.
  The WG decides whether the draft blesses the field or scopes it to deployment.
- Wire format: a `FRAME_VERSION` bump; needs a compact encoding (CBOR? a tag
  string?) that fits the zero-width channel's capacity, plus a migration story.
- Short text carries only the `tzsataitw-1` entry (+ optional `verify_hint`);
  the `fairoze-*` entry appears only when the text is long enough to also carry
  a Fairoze mark.

**F3. The manifest is an optimization, never load-bearing.** The zero-width
carrier is itself strippable, so a normalized copy loses the whole manifest.
Brute-forcing the key cache MUST remain the always-available path: try each
scheme's detection against each cached key, with each scheme's own
canonicalization. The tools don't have this yet -- `tzsataitw` has no
`--seed-file` cache mode, the `fairoze` verifier is single-key -- so a shared
cache/seed-list verifier that runs every scheme is its own work item.

**F4. Brute-force is safe for this stack** -- state it explicitly. Draft §14
flags multiple-hypothesis-testing as a hazard, but that is for *statistical*
detectors. Both layers here are cryptographic (Ed25519); trying N cached keys
cannot manufacture a false positive. The §14 concern does not apply.

**F5. Does double-signing need DNS/custody representation?** Two marks at one hop
is not a `d=` custody handoff. A verifier finding a `fairoze-1` mark from
`3._watermark-text.x` and a `tzsataitw-1` mark from `4._watermark-text.x` just
learns "x generated this, two ways." Probably no new tag -- but confirm §7.4's
composite-key discussion does not need to extend to same-hop multi-mechanism.

**F6. Optional: Fairoze message as a locator.** `fairoze-1`'s 8-byte embedded
message is currently a random nonce. It could instead be a short locator /
locator-hash so the statistical layer carries its own routing hint. No
robustness gain, saves one lookup. Open design choice.

### Membership / scope note
This is an *implementation & considerations* group -- composition, wire formats,
canonicalization, cache policy, deployment-pipeline scope. Distinct from changes
to the core draft (§6/§7 mechanism). Findings here feed the draft's §13/§14 or a
companion document, not §6.1 normative text directly.
