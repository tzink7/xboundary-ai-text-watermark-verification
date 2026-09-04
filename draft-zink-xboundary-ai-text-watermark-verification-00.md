%%%
title = "A DNS-Based Framework for Cross-Organization Verification of AI-Generated Text Watermarks"
abbrev = "xOrg verification of AI-text watermarks"
ipr = "trust200902"
area = "General"
workgroup = "Network Working Group"

[seriesInfo]
name = "Internet-Draft"
value = "draft-zink-xboundary-ai-text-watermark-verification-00"
stream = "IETF"
status = "standard"

[[author]]
initials = "T."
surname = "Zink"
fullname = "Terry Zink"
organization = "Independent Researcher"
email = "tzink@terryzink.com"
%%%

.# Abstract

This document proposes a decentralized framework for verifying statistical text watermarks across multiple AI model providers. Current text watermarking implementations are vendor-siloed: a detector built by one provider can verify only that provider's own marks. This document specifies a DNS-based key distribution mechanism -- using a fixed, well-known record location in the style of DMARC (RFC7489) and BIMI, with a key syntax in the style of DKIM (RFC6376) -- that allows any party to discover the public verification material for any participating provider's watermark. It further specifies a multi-hop custody mechanism in the style of ARC (RFC8617) for recording custody when text passes through more than one model. The document also discusses the "laundering" attack this framework is intended to make less economically attractive, and is explicit about its own dependencies -- most significantly, that its key-distribution mechanism requires and is designed for an asymmetric, publicly-detectable watermarking scheme, in place of the symmetric, secret-key schemes currently deployed at production scale, rather than a way to make those symmetric schemes safely cross-verifiable as published (see Section 4.1 and Section 10.3).

{mainmatter}

# Introduction

As of August 2026, at least one major AI provider has deployed statistical text watermarking at production scale across its entire product line, embedding an imperceptible pattern into generated text via biased token sampling. Other providers have indicated they are pursuing similar mechanisms, and cross-vendor watermark detection interoperability has been identified as a forthcoming regulatory checkpoint under EU AI Act-adjacent rulemaking, with a compliance target reported for February 2027.

No technical mechanism for that interoperability has been published by any provider or standards body as of this writing. The default expectation among industry observers is that providers will layer proprietary watermark schemes underneath the existing C2PA provenance standard rather than build a shared verification layer for the watermark signal itself. This document proposes an alternative: a lightweight, DNS-based key distribution and multi-hop attestation mechanism, independent of C2PA, that does for statistical text watermarks roughly what DKIM and ARC do for email authentication.

This is a discussion draft. It is intended to be stress-tested, not implemented as written.

# Terminology

* **Provider:** An organization that operates a large language model capable of generating watermarked text (e.g., an AI lab).

* **Hop:** A single instance of a model processing and re-emitting text, whether generating it originally or modifying existing text.

* **Custody Chain:** The ordered sequence of hops a piece of text has passed through, as attested by this framework.

* **Signing Key:** The private half of a provider's watermark key pair, used to embed a watermark at generation or re-signing time and never published. Referred to elsewhere in this document simply as a "private key"; this entry exists to pair explicitly with Verification Key, below, since the two are two halves of one key pair and this document refers to each individually throughout.

* **Verification Key:** The public half of a provider's watermark signing key pair, published via DNS as specified in Section 6.

* **Laundering**: The practice of passing watermarked text through one or more additional models with the intent of destroying the original watermark signal to evade detection.

# Problem Statement

## Vendor-Siloed Detection

A detector to verify text-based watermarks built by Provider A can, at present, verify only Provider A's own watermark. It has no defined mechanism to even determine whether text originated from Provider B, let alone verify a mark it does not recognize. This means comprehensive AI-text detection currently requires a platform to independently integrate with every provider's proprietary detection API, if one exists and is externally exposed at all.

## The Laundering Vulnerability

Statistical watermarks are carried in the token-selection distribution of the generating model. Passing watermarked text through a second model with a rewrite instruction resamples that distribution under a different (or absent) key, which degrades or eliminates the original signal. This is a known, acknowledged limitation of deployed statistical watermarking schemes generally, not specific to any one provider's implementation.

## Absence of Multi-Hop Lineage

No current production system records that text was, for example, drafted by Model A, edited by Model B, and polished by Model C. Existing marks are binary and single-source: either Provider A's mark is detected or it is not. There is no standardized way to represent or verify a chain of custody across multiple models.

# Relationship to Existing Work

## Statistical Watermarking (SynthID and Similar Schemes)

At least one major lab has published and open-sourced a reference implementation of a statistical text watermarking scheme. The published method operates by intercepting the model's raw next-token prediction scores and biasing token selection using a pseudorandom function parameterized by a secret key; detection reconstructs the expected pattern using that same key and computes a confidence score. Independent analysis [Gloaguen24] examining that deployed scheme specifically found that, despite introducing novel components, it still falls within the broader "Red-Green" family of watermarking schemes previously studied in the academic literature, when tested under that paper's detection methodology. That is evidence of shared underlying structure between at least one production system and a well-studied family of techniques -- not, on its own, a finding that multiple independently deployed production schemes cluster with each other -- but it is still a favorable precedent for a shared verification layer: it suggests production watermarking is not inventing an entirely new detection paradigm with each release.

A more precise statement is needed, however, about what kind of key this is, because it materially affects whether this document's core mechanism (Section 6) is viable as written.

Deployed statistical watermarking schemes of this kind are SYMMETRIC: the same secret key is used both to embed the watermark during generation and to detect it afterward. What this document's mechanism actually requires is an ASYMMETRIC or "publicly-detectable" watermarking scheme: a scheme in which a private key embeds the watermark, and a separate public key can verify it without being able to forge or strip it. Such schemes exist in the research literature -- notably a publicly-detectable protocol [fairoze23] that embeds a cryptographic signature into generated text using rejection sampling, proven unforgeable and undetectable without the public key -- but they are a distinct, less mature line of work from the symmetric schemes currently deployed at production scale. Recent work names the underlying dilemma directly: if a symmetric scheme's detection key remains secret, verification stays centralized with the issuing provider; if that same key is released to enable public detection, the same information that enables detection also enables forgery or evasion. Proposals to resolve this without moving to a fully asymmetric scheme -- for example, using zero-knowledge proofs so a symmetric detector's results can be publicly audited without revealing the secret key itself -- are an active, unsettled area of research rather than a deployed solution.

This document's "p=" key-distribution mechanism (Section 6) is therefore only sound if applied to an asymmetric, publicly-detectable watermarking scheme. It is NOT sound if applied naively to a currently-deployed symmetric scheme: doing so would not merely enable third-party verification, it would hand out the ability to forge and strip the watermark to anyone who queries the DNS record. This is a significant, unresolved gap between what this document assumes and what labs have actually shipped as of this writing; see Section 10.3.

This proposal does not invent a watermark embedding algorithm. It assumes providers adopt (or migrate to) an asymmetric, publicly-detectable embedding scheme, and addresses only key distribution and multi-hop attestation around such a scheme once adopted.

## C2PA and Content Credentials

The Coalition for Content Provenance and Authenticity (C2PA) is an existing, actively adopted, multi-organization standard for attaching cryptographically signed provenance metadata to media files. It is a real and relevant precedent for cross-vendor coalition-building around content authenticity. However, C2PA:

(a) is a metadata standard, not a content-embedded signal -- provenance data travels alongside the asset rather than within it, and is lost when metadata is stripped (e.g., by re-saving, format conversion, or screenshotting);

(b) is oriented toward image, video, and file provenance; several independent sources describe text provenance under C2PA as comparatively undeveloped; and

(c) uses a certificate-authority/PKI trust model, not a DNS-based key lookup.

Statistical text watermarks are the opposite of C2PA metadata: they are embedded in the content itself and travel with copy-paste, which is their advantage, but they currently have no equivalent of C2PA's cross-organization trust and discovery layer.

## Why Neither Solves Cross-Vendor Text Verification

Published industry commentary as of mid-2026 anticipates that providers will address interoperability by wrapping proprietary watermarks in C2PA manifests -- i.e., describing in metadata that a watermark is present, rather than making the watermark itself cross-verifiable. This preserves C2PA's known fragility (metadata stripping) as the weak link for exactly the signal (embedded text watermarking) that was designed to survive metadata loss. This document proposes a mechanism that keeps verification bound to the content-embedded signal rather than reintroducing a metadata dependency.

## Challenges with leveraging APIs exposed by providers

One alternative to C2PA watermarking is to provide an API from one vendor to another. That is, suppose Provider1.ai creates a paragraph of text. A user copy/pastes it into Provider2.ai and asks if it has been AI-generated. Provider2 calls an API by Provider1, sends the text to it, and receives a response - either “Yes, I created this” or “No, I didn’t”. This requires Provider2 to maintain credentials with every single potential AI-text provider, includes latency in every response, and - in the case of a zero-knowledge proof - adds additional computational overhead. 

This solution may work at a small scale, but does not work at Internet scale. Provider2 might be asked to check millions of pieces of text per day, and Provider1’s API might not only be called by Provider2 those same millions of times per day, but Provider1 might have to answer Provider3’s API calls, Provider4’s, and so forth. And, each Provider might have to answer each other's calls, that is, text-watermark verification can run both ways, doubling the number of calls.

This creates a DDOS problem, particularly if a scripted, adversarial service attempts to attack a Provider. This would create an escalating arms race between Providers and malicious abusers just to answer the question “Was this text generated by AI?”

The use of cross-provider APIs does not scale as the amount of usage grows.

# Architecture Overview

The framework has three components, and assumes a fourth (represented below as 0):

0. A text-watermarking scheme that uses asymmetric encryption. This document does not specify which algorithm to use. It assumes that text-generators leverage a private key to create their watermarks and distribute their key(s) securely within their own services, and rotate the keys periodically in accordance with best practices cryptographic functions.

1. A DNS-based public key directory (Section 6), allowing any verifier to discover a provider's current and historical watermark verification keys without a proprietary API.

2. A multi-hop attestation mechanism (Section 7), allowing a model that modifies existing watermarked text to record the handoff rather than silently overwrite the prior signal.

3. An explicit acknowledgment (Section 8) that heavily laundered text is expected to degrade in quality as a natural consequence of compounding constraints, and a discussion of why that is treated as an acceptable outcome rather than a flaw to be engineered away.

4. Verification key material and hop metadata are the objects this framework standardizes. It does not standardize, and takes no position on, the internal embedding algorithm any given provider uses.

# DNS Key Distribution

## Record Location and Syntax

Each participating provider publishes one or more TXT records at a single, well-known, fixed subdomain. This follows the discoverability convention established by DMARC ([@RFC7489]), which publishes policy at a fixed "_dmarc." location, and by BIMI, which publishes brand indicator records at a fixed "default._bimi." location. Both allow a verifier to find the relevant record without any prior negotiation or out-of-band selector exchange.

By contrast, ARC ([@RFC8617]) does not establish an equivalent fixed location: it reuses DKIM's own key-publication mechanism directly (an arbitrary selector under "_domainkey"), and the ARC specification explicitly declines to mandate any particular selector or subdomain convention, leaving that choice to the signing domain. This document follows the DMARC/BIMI pattern of a single, predictable, well-known location rather than ARC's open-ended approach, because predictable discovery without prior negotiation is a core design goal of this framework (see Section 6.3). The key-value syntax itself remains closer to DKIM's, per Section 6.1 below.

`<number>._watermark-text.<provider-domain>`

The "`-text`" suffix is deliberate: this document defines a namespace for text watermark verification specifically, not watermarking in general. AI providers may eventually watermark other modalities (audio, image, video) using entirely different underlying mechanisms -- perceptual hashing rather than statistical token-biasing, for instance -- which will likely need a different tag vocabulary than Section 6.1 below defines for text. Rather than overload one shared "`_watermark`" namespace with a modality tag inside the record (which would force every modality into the same schema even where that schema doesn't fit), this document reserves "`_watermark-text`" for its own scope and leaves "`_watermark-audio`", "`_watermark-image`", and similar as clean, independently-specifiable namespaces for future work, should it follow this document's general approach. This mirrors how DKIM, DMARC, and BIMI each occupy their own subdomain rather than sharing one record disambiguated by an internal type field.

Two further naming choices were considered and are worth recording, since neither is obvious from the result alone.

First, the ordering: "`_watermark-text`" rather than "`_text-watermark`". English usage arguably favors the latter -- "a text watermark" is the more natural phrase -- but leading with "`_watermark`" was chosen instead so that every future modality shares a common, greppable prefix ("`_watermark-text`", "`_watermark-audio`", "`_watermark-image`", ...), letting anyone auditing a zone find every record this framework or its successors define with a single substring match -- e.g., `grep watermark_` -- rather than needing to separately know and search for each modality's name. It also leaves the bare prefix, "_watermark." on its own, available for a possible future discovery record -- e.g., an index listing which modalities a given provider supports -- with no naming conflict. Leading with the modality instead would give up both properties: there would be no shared token to search on, and no natural place left for a cross-modality index.

Second, "`_watermark-text`" (one hyphenated label) rather than "`_watermark._text`" (two chained labels, in the style of SRV records' "`_service._proto`" convention). The chained form is legitimate DNS precedent and was not rejected as invalid, only as a worse fit here: it would turn every selector address in this document from three labels to four. Every example in this specification, and Section 6.4's procedure, assumes the three-label shape (".."). The single hyphenated label preserves that shape exactly while still achieving the same modality-scoping goal. However, this is simply a convention to simplify the DNS label depth and is a subject for future discussion. 

By default, in the absence of any other information, numbering begins at 1: a provider's primary record is published at "`1._watermark-text.`". Higher numbers are used for additional selectors -- key rotation, purpose-specific keys, or re-signing selectors -- as introduced in Section 6.2; nothing about the location pattern itself changes at that point, only how many records a verifier may find under it.

For example, a provider "example.ai" would publish its primary key at:

`1._watermark-text.example.ai`

The record value follows a tag-value syntax deliberately similar to DKIM ([@RFC6376]) and BIMI:

`v=1; a=<algorithm-id>; p=<key-material>; c=<sign|re-sign>; d=<https-URL>; dh=<algo>-<hash>; s=active; nb=<timestamp>; na=<timestamp>`

Where:

* v = REQUIRED. Protocol version (this document defines v=1).
* a  = REQUIRED. Algorithm identifier, naming the watermarking scheme this key applies to (e.g., "tzsataitw", "fairoze"). See below and Section 15 for the registry this tag depends on.
* p  = REQUIRED. Public key material, base64-encoded. This value is only safe to publish for an asymmetric, publicly-detectable watermarking scheme (Section 4.1); publishing a symmetric scheme's secret key under this tag exposes the ability to forge and strip the watermark, not merely verify it. See Section 10.3.
* c  = REQUIRED. Custody type for text signed under this selector: "sign" (fresh generation) or "re-sign" (this selector re-signs text that already carried a watermark from some prior hop, whether from the same provider, Section 7.2, or another provider, Section 7.1). Unlike most other tags in this record, "c=" has no default and MUST be present on every selector, since a verifier checking a match needs this distinction immediately, without an additional lookup, to interpret what it found.
   Generators: Generators MUST produce `c=re-sign` as the canonical value when re-signing upstream text. Generators MUST NOT emit c=resign in newly created DNS TXT records or JSON custody documents.
   Verifiers: Verifiers MUST accept `c=resign` as the standard action tag and MUST treat `c=resign` as an identical alias during record parsing to prevent validation failures caused by missing hyphens.
* d  = an HTTPS URL (HTTPS is REQUIRED; plain HTTP MUST NOT be used) pointing to a document that defines what this selector means in cross-vendor custody contexts. A machine-readable (JSON) form is normative and MUST be available; a human-readable rendering of the same content MAY also be served at the same URL via content negotiation. See Section 7.1. REQUIRED when "c=re-sign" and the re-sign is a cross-vendor handoff (Section 7.1); OPTIONAL when "c=sign", or when "c=re-sign" for a same-provider self-loop with no custody detail to convey beyond the flag itself (Section 7.2).
* dh = RECOMMENDED whenever d= is present, and REQUIRED when c=re-sign is used with a cross-vendor handoff. Hash of the d= file. The value format is modeled after the W3C Subresource Integrity / SRI syntax. The syntax is `dh=<algo>-<base64url-hash>;`. The primary algorithm is SHA-256 which provides standard 256-bit collision resistance without bloating the character count of the DNS TXT record. The hash's encoding uses Base64URL encoding ([@RFC4648]), **without** '=' padding characters (RFC4648 Section 3.2): padding is unnecessary here, since each tag's value is already delimited by ';' rather than needing a fixed-length frame, and omitting it avoids putting an '=' character inside a record syntax that already uses '=' as its own tag/value delimiter. A generator publishing a new record SHOULD omit padding; a verifier MUST accept the hash whether or not padding happens to be present, since third-party tooling has historically been inconsistent about stripping it. 
 * s  = OPTIONAL, default "active" when absent. Key status: "active" or "revoked". A revoked key MUST NOT be treated as valid for new verifications regardless of the nb=/na= window below; see Section 9.2. Unlike "c=", making this tag required would not add real safety: the danger is a provider failing to publish "s=revoked" after a compromise, which is exactly as possible whether the tag is required-with-a-default or optional-with-a-default -- requiring it on every ordinary, non-revoked key would add boilerplate without closing that gap.
 * nb = REQUIRED. "Not before" -- the start of this key's validitywindow, expressed as a Unix timestamp (seconds since the epoch). Unlike "s=" above, this tag has no safe default: the entire justification for the nb=/na= design (Section 6.1, below) is letting a verifier check whether a key was valid *when the text was generated*, not just whether it is valid now, and an absent "nb=" would leave that window open-ended on one side, defeating the mechanism the same way an absent "c=" would silently misrepresent custody.
* na = REQUIRED. "Not after" -- the end of this key's validity window, expressed the same way (Unix timestamp), or the literal value "ongoing" if the key remains the current active key for the provider; "ongoing" is a valid value for this tag, not an exemption from providing one. Beyond marking the validity window itself, "na=" also functions as a heuristic signal to verifiers for local cache eviction (Section 6.3): once a key's "na=" is far enough in the past that no plausible text signed under it remains in circulation, a verifier MAY drop it from its cache rather than retain every historical key indefinitely. na MUST always be equal to or higher than nb.

Unlike the eight tags above, which apply uniformly to every selector's record, one further tag is scoped to a single record only:

 * r  = SHOULD be present on selector 1's record only (Section 6.2). If an "r=" tag appears on any other selector's record, it MUST be ignored by a verifier -- it carries no meaning there, and its presence is not an error condition, just an extraneous value with no defined effect. States the total count of sequential selectors a provider has published (e.g., "r=3" means selectors 1 through 3 exist), letting a verifier following Section 6.4 step 3 know when it has crawled the full set rather than needing to guess or probe indefinitely for a selector that does not exist. This is a SHOULD, not a MUST: a verifier encountering no "r=" tag can still crawl forward until a query returns no record, at some added cost in unnecessary lookups; "r=" exists to make that crawl bounded and predictable rather than to be strictly required for the framework to function. 

 In the absence of a distinct `r=` value (wherein a verifier crawls records, incrementing by 1, and discovers additional records), a verifier MAY impose a maximum number of DNS crawls to avoid a hostile or misconfigured DNS record. This specification does not mandate a maximum, but a reasonable starting point is 50. Above 50, a provider MUST publish an `r=` value in its seed record (`1._watermark-text.<domain>`).

Provider identity was removed from this record in an earlier revision (rather than reintroduced under a different letter): the record's location already identifies the provider, since a verifier only reaches this record by querying a specific provider's zone in the first place. Restating that identity inside the record itself adds no information a verifier doesn't already have. Provider identity is not needed anywhere else in the base record; where it does matter -- cross-vendor custody claims -- it is carried explicitly in the "d=" document's "provider" and "received_from" fields (Section 7.1), which is a better fit since that is the one place a verifier needs to reason about more than one provider's identity at once.

The nb=/na= pair, rather than a bare active/inactive boolean, is used deliberately: a verifier evaluates a watermark by checking whether the current time, at the moment of verification, falls within the key's nb=/na= window (Section 9.2) -- not by consulting a single active/revoked flag with no time bound of its own. A boolean state flag collapses "this key has a defined, bounded lifetime" and "this key is valid indefinitely" into the same signal, which a validity window avoids. A key rotated out of active use retains its nb=/na= record (with na= set to the rotation date) rather than being removed from DNS, so that a verifier querying that selector after rotation still resolves a defined, expired window rather than nothing. Revocation (s=revoked) is distinct from ordinary rotation and is treated as authoritative regardless of the stated window; see Section 9.2 for the unresolved question of how revocation is propagated and discovered.

The "a=" tag is deliberately modeled on DKIM's own use of "a=" in the DKIM-Signature header (e.g., "a=rsa-sha256"), which names the signing algorithm a verifier must use. This framework reuses that convention for the same reason DKIM has it: a verifier cannot correctly interpret key material without knowing what algorithm it belongs to, and allowing providers to use different underlying watermarking schemes (Section 4.1) requires that the scheme be named explicitly rather than assumed. Algorithm identifiers SHOULD include a version suffix (e.g., "fairoze-1" rather than bare "fairoze") so that a later, detection-incompatible revision of a scheme does not silently break existing verifiers expecting the earlier version. An unregistered or unrecognized "a=" value SHOULD cause a verifier to treat the record as unusable rather than guessing at compatibility; see Section 15.

This document does not propose a standardized canonicalization to apply to text before attempting verification (e.g., strip zero-width chars, fold linebreaks, etc.). Instead, each "a=" registration defines its own canonicalization, and a verifier MUST apply it prior to detection.

A verifier that detects a watermark signal in a piece of text but does not know its source queries the known set of provider records (Section 6.3) to find a matching key, analogous to how a DKIM verifier tries the selector named in the signature.

## Key Rotation and Multiple Records

Providers MAY publish multiple keys at sequential well-known locations to support key rotation or purpose-specific keys:

`2._watermark-text.example.ai   "v=1; a=fairoze-1; p=<key>; c=sign; s=active; nb=1780272000; na=ongoing"` 

`3._watermark-text.example.ai   "v=1; a=fairoze-1; p=<key>; c=sign; s=active; nb=1788220800; na=ongoing"`

When selector 3 becomes the current key, selector 2's record is updated to close its validity window (na= set to the rotation date) rather than deleted, so that text generated while selector 2 was active remains verifiable:

`2._watermark-text.example.ai   "v=1; a=fairoze-1; p=<key>; c=sign; s=active; nb=1780272000; na=1788220800"`

The first record (selector 1) SHOULD include an r= tag indicating how many total records exist, so a verifier knows when it has crawled the full set without guessing:

`v=1; a=fairoze-1; p=<key>; c=sign; r=3`

Selector numbers exist purely to make records easy to find -- increment by one, query the next location, stop when "r=" is reached (Section 6.4 step 3) -- and carry no meaning of their own beyond that. Rotation therefore always means publishing a new, higher-numbered selector; an existing selector's number is never reused or reassigned to a different key, only closed out via "na=" as shown above. 

This applies uniformly whether or not the selector being rotated carries a "d=" custody document (Section 7.1): a selector that means "received from Otherprovider.AI, re-signed" is rotated the same way as any other selector -- a new, higher-numbered selector is minted for the new key, and the old selector's number, key, and "d=" document all remain in DNS, closed out via "na=", so that text signed during its active window remains verifiable against the meaning it had at the time.

## Caching and Refresh Behavior

Because the set of participating providers is expected to remain small (on the order of tens, not thousands, in the near term), verifiers are expected to maintain a local cache of all known providers' records, refreshed on an interval (e.g., hourly or daily) via an offline job, rather than performing a DNS lookup synchronously for every verification event. This mirrors ARC's trusted-sealer-list model, and to a lesser extent BIMI's practice of maintaining a list of trusted Mark Verifying Authorities, more than it does DKIM or DMARC: a DKIM or DMARC verifier resolves a single domain named directly in the message it is checking, and has no need to pre-populate a cache of every domain it might ever hear from, whereas this framework's verifiers do, since watermarked text carries no equivalent self-describing sender field the way an email's headers do. This keeps per-text verification latency independent of DNS round-trip time. How a verifier's cache is initially populated -- bootstrapping the provider list itself, as opposed to refreshing an already-populated one -- is addressed separately in Section 6.4 and is explicitly out of scope for this document to solve, only to describe.


Refresh and eviction are distinct concerns. Refresh, above, keeps the cache current with newly published or rotated records. Eviction is the separate question of when a verifier can safely stop retaining an old, no-longer-active key at all, rather than holding every key any provider has ever published indefinitely. Selector numbers (Section 6.2) only ever increment -- a provider rotating a key publishes a new, higher-numbered selector rather than reusing or renumbering an old one, so a verifier's cache otherwise grows without bound over a provider's lifetime. The "na=" validity-window tag (Section 6.1) is what makes eviction possible: once a key's "na=" is far enough in the past that no plausible text signed under it remains in circulation, a verifier MAY drop it from its local cache. This document does not specify a particular retention period, since it depends on how long a verifier expects to encounter old text; it is a local policy decision "na=" enables rather than one this framework mandates.

## Provider Discovery and Bootstrap Procedure

This section describes, procedurally, how a verifier builds and uses the local cache introduced in Section 6.3.

1. **Seed list.** A verifier maintains a list of participating providers' domains (e.g., "myfrontieraiprovider.example", "anotherllm.example"). This document does not specify how the seed list itself is obtained or kept current; in the near term it MAY be maintained manually, given the small number of participating providers expected; or, it MAY be maintained by one, or a handful of, trusted maintainers. This is a bootstrap-trust problem this framework shares with ARC, whose receivers likewise maintain an externally-curated list of trusted sealing domains rather than deriving trust from the protocol itself; see the note at the end of this section.

2. **Initial key fetch.** For each domain in the seed list, the verifier performs a DNS query for "`1._watermark-text.`" and stores the returned record -- key material, algorithm identifier, status, and validity window (Section 6.1) -- in its local cache.

3. **Additional selectors.** If the fetched record includes an "r=" tag (Section 6.2), the verifier repeats step 2 for "`2._watermark-text.`" through "`<r>._watermark-text.`", caching each in turn, so that historical keys (retained for already-rotated-out validity windows) and purpose-specific keys are all available locally, not just the current one. If "r=" is absent, which Section 6.1 permits, the verifier MAY instead crawl forward from selector 2 until a query returns no record, treating that as the end of the set; this is more costly in unnecessary lookups than a known count, which is the reason "r=" is recommended even though it is not required. If a verifier crawls multiple key records and finds that some of them are expired or revoked, it is not required to store those invalid or historical records in its local cache.

4. **Repeat per provider.** Steps 2-3 are repeated for every domain in the seed list. The result is a local table of all known providers' selectors, keyed by (domain, selector number).

5. **Verification.** When checking a piece of text, a verifier that does not already know which provider generated it attempts verification against the cached keys. This MAY be done sequentially or in parallel across cached entries; this document does not mandate an order, though a verifier MAY choose to try the most recently active key per provider first as a performance optimization, since it is the most likely match for recently generated text. A verifier that exhausts the cache without a match returns a negative result; this is the expected outcome for text that was never watermarked under this framework at all, not necessarily an error condition.

    Each cached key checked against the same piece of text is a separate hypothesis test. For an algorithm whose detection is an exact cryptographic verification (e.g., checking an Ed25519 signature), trying additional keys carries no meaningful false-positive cost, since a forged or mismatched signature essentially never validates by chance. For a statistical, threshold-based detection scheme (Section 4.1), this is not true: a verifier MUST account for the aggregate false-positive rate across all keys tried, adjusting its detection threshold as the cached key set grows rather than applying a single-key threshold uniformly regardless of how many keys are checked. This document does not specify how that adjustment should be computed; see Section 14.

6. **Selector choice when generating (or re-signing) text.** When a provider is producing new watermarked text, or re-signing text under Section 7.2, it chooses which of its own selectors to sign under. Absent a more specific reason to do otherwise, a provider signs under its default selector ("1._watermark-text."). A same-provider self-loop re-sign (Section 7.2) is such a reason: the provider mints the next sequential selector with "c=re-sign" rather than reusing its default selector's number, since an existing selector's "c=" value is never changed once text may already be signed under it. 

    Where the text being produced is a re-signing of text received from a specific upstream provider (Section 7.1), the provider SHOULD instead sign under whichever of its own selectors it has already registered, via that selector's "d=" document, as meaning "received from that upstream provider and re-signed" -- i.e., consulting its own local lookup table (built via steps 1-4 above, which a provider maintains for its own outbound signing decisions just as a verifier does for inbound checking) to reuse an existing, already-documented selector rather than registering a new one for a custody pattern that has already occurred before.

Step 1's bootstrap-trust gap is worth stating plainly rather than glossing over: nothing in this framework cryptographically proves that a given domain belongs to a legitimate AI provider, or that a seed list has not been tampered with or omitted a participant. This document does not propose a solution and is listed as an open question in Section 14.

## Delegation

A provider may want its watermark records to live in a domain other than the one text was generated under -- for example, "example.ai" delegating to records actually maintained at "example.org", whether for organizational reasons or because a third party manages the records on the provider's behalf.

This document specifies CNAME as the delegation mechanism, applied directly to a selector:

`1._watermark-text.example.ai.   CNAME   1._watermark-text.example.org.`

A verifier performing an ordinary DNS lookup for "1._watermark-text.example.ai" follows this CNAME transparently, via standard DNS resolver behavior, and retrieves the TXT record actually published at "1._watermark-text.example.org" -- no framework-specific redirect tag, and no special handling in a verifier's own logic, is required. This also composes cleanly with Section 6.4's bootstrap procedure: because CNAME resolution happens at the resolver level, a verifier that looked up "example.ai" only because it was in its provider seed list still correctly resolves records actually held at "example.org", without needing "example.org" separately listed.

This document specifically avoids an SPF-style "redirect=" modifier ([@RFC7208]), despite SPF being an otherwise-relevant precedent elsewhere in this document. SPF's redirect exists because SPF evaluation is sequential and stateful -- mechanisms are evaluated in order, ending in an explicit "all" catch-all -- so a plain DNS alias cannot express "stop evaluating here, go evaluate that other domain's policy instead." This document's records have none of that sequential-evaluation complexity; a lookup either finds a matching key or it does not, which is exactly what CNAME already provides at the DNS layer. Using CNAME instead of a new tag also matches how DKIM delegation already works in production today: mailbox providers and email service providers commonly have customer domains CNAME their selector directly to the provider's own DKIM key (e.g., "`s1._domainkey.customer.example`" pointing to a record under the service provider's domain), entirely through ordinary DNS semantics, with no DKIM-specific delegation syntax involved. This document's selectors are well-suited to the same approach, since a selector is only ever expected to hold this framework's single TXT record, avoiding any conflict with CNAME's restriction against coexisting with other record types at the same name.

One gap this does not resolve: if "example.org" is not itself in a verifier's provider seed list (Section 6.4), the verifier may still correctly resolve the CNAME and retrieve a valid record, but has no independent way to know whether "example.org" is trusted to hold "example.ai"'s watermark keys, versus an unrelated domain that happens to be the CNAME target. This is a specific instance of the broader bootstrap-trust gap already noted above, not a new problem delegation introduces, but delegation does make it concrete: verifying a signature is not the same as verifying that delegating to that signer's domain was authorized. This is listed as an open question in Section 14.

# Multi-Hop Attestation

## Cross-Vendor Handoff

When Model B receives text already bearing Model A's watermark and modifies it, Model B SHOULD NOT simply overwrite Model A's signal with its own. Instead, following an ARC-like pattern ([@RFC8617]), Model B appends an attestation identifying the handoff: which provider preceded it. This produces an ordered, inspectable custody chain rather than a single overwritten mark that erases prior history.

A bare numbered selector (Section 6.2) is ambiguous on its own: "`2._watermark-text.example.ai`" tells a verifier nothing about what selector 2 represents for that provider unless that meaning is published somewhere. The same numeral carries no cross-provider meaning either -- "`2._watermark-text.example.ai`" and "`2._watermark-text.another.provider`" are unrelated assignments made independently by each provider's own zone, not a shared numbering space.

To resolve this, a selector used for a cross-vendor handoff MUST publish a "d=" tag (Section 6.1) pointing to an HTTPS document defining that selector's custody meaning. The document is a small, machine-readable (JSON) resource of the form:

`2._watermark-text.example.ai IN TXT "v=1; a=<algorithm-id>; p=<key-material>; c=re-sign; d=https://2._watermark-text.example.ai/desc.json; dh=<algo>-<hash>; s=active; nb=1785542400; na=ongoing"`

And then the JSON at https://2._watermark-text.example.ai/desc.json (see section 7.2 for a full explainer) :
```
{
"received_from": "otherprovider.ai",
"selector": "2",
"c": "re-sign",
"provider": "example.ai",
"ts": "1785542400"
}
```
In this example, a verifier hashes the JSON file using the algorithm specified in the dh= field DNS record and compares to the hash in that same field, and the two hashes should match. If they do not, the rest of this process may be exited early. The duplicated c= is used for debugging, and the ts field is a timestamp when the record was published, which is not necessarily the same as the nb or na fields in the DNS record.

The verifier that observes a chain ending in "`2._watermark-text.example.ai`" confirms from "`c=re-sign`" on the DNS record, and again from "c": "re-sign" in this file, that this is a re-sign, and learns -- from the file, not from the numeral -- that Example.AI's selector 2 represents "text received from Otherprovider.AI," effective from the given date (expressed as a Unix timestamp, matching the "nb="/"na=" convention in Section 6.1). A human-readable rendering of the same document MAY be served at the same URL via content negotiation, but the JSON form is normative for automated verifiers.

This is a self-attested claim, not an independently verified fact: Model B is asserting where it received the text from, and nothing in this framework cryptographically proves that claim against Model A's own records (Model A may not even participate in this framework). This mirrors the trust model DKIM verifiers already operate under: a valid signature proves the message passed through a domain that held the private key, not that the domain's stated identity or intent is honest. Similarly, a valid custody chain under this framework proves each hop was made by an entity holding the corresponding private key and choosing to publish a given custody claim -- not that the claim is accurate. Downstream verifiers and platforms MAY use custody attestations as they see fit (e.g., to weight trust, flag inconsistencies against other signals, or ignore entirely), in the same way DMARC-enabled receivers are free to set their own local policy on top of a DKIM/SPF result. See Section 9 for the security implications of this self-attested model.

## JSON Custody Descriptor Format (d=)

When a provider publishes a d= tag in its DNS TXT record, the referenced HTTPS URL MUST serve a UTF-8 encoded JSON document conforming to the schema below. This document provides explicit provenance tracing for text handoffs, re-signatures, and multi-model processing pipelines.

### Example Custody Document

Below is the format of a JSON descriptor  hosted at 
`https://2._watermark-text.example.ai/desc.json`:

```
{
  "received_from": "REQUIRED. Corresponds to the domain of the provider whose watermark was verified",
  "selector": "REQUIRED. Corresponds to the selector of the signing provider's DNS record. A literal number, either with or without double-quotes.",
  "provider": "REQUIRED. Corresponds to the domain of the signing provider",
  "c": "REQUIRED. Range of values are 'sign' or 're-sign'", 
  "ts": "REQUIRED. Corresponds to a UNIX epoch time stamp of when the record was published. A literal number, either with or without double-quotes." 
}
```

Other text MAY be included in the record so long as they do not collide with the other fields.

Below is an example:

```
{
"received_from": "otherprovider.ai",
"selector": "2",
"c": "re-sign",
"provider": "example.ai",
"ts": "1785542400",
"comments": "Our first watermark corresponding to text generated in North America"
}
```

This may be interpreted as example.ai receiving a piece of text with a watermark that they verified as originally coming from otherprovider.ai. Example.ai is re-generating the text using the key at 2._watermark-text.example.ai. The record was created on Saturday, August 1, 2026 at 12:00:00 AM. The organization is potentially leveraging different keys in different geographies, but this information need not be consumed by a downstream verifier. 

### Verification Mechanics (d=, dh=, and c=)

When evaluating a re-signed watermark chain where `c=re-sign` and `d=` are present, the verifier MUST execute the following validation procedure:

1. **Fetch & Digest Calculation:**
* Query the DNS selector TXT record to obtain `d=` and `dh=` (or, having already pulled this information via an asynchronous process, retrive it from a local storage lookup).
* Perform an HTTP GET request to the URL specified in `d=`.
* Compute the digest of the exact raw response body bytes using the hash algorithm specified in dh= (e.g., SHA-256).
* Compare the calculated digest against the value in `dh=`. If the digests do not match, the verifier MUST reject the custody document as modified or invalid.

Redirects are permitted as they allow signers flexibility on where they publish `d=` records. However, the number of redirects should be kept small. This specification does not mandate a maximum, but a reasonable starting point is no more than 5.

2. **`c=` Tag Matching**:

* Inspect the `c` property inside the fetched JSON document, and verify that it matches the `c=` tag in the DNS TXT record.
* If the DNS TXT record specifies `c=re-sign` (or `c=resign)`, the JSON action MUST be either "re-sign" or "resign". Any discrepancy between DNS `c=` and JSON action MUST result in a validation failure.

## Intra-Model (Self-Loop) Re-signing

When a model processes its own prior output (Model A revising Model A's earlier text), there is no other provider to attest a handoff from, so this is not a custody hop in the sense Section 7.1 describes. It still requires a new selector, however, following the same rule as any other rotation (Section 6.2): a provider does not change an existing selector's "c=" value after text may already have been signed under it, since doing so would retroactively misrepresent the custody of that earlier text, the same problem an omitted "c=" would cause. The provider therefore creates the next sequential selector with "c=re-sign" -- the same numbering rule as any other new selector, not a separate scheme -- optionally reusing the same underlying key material ("p=") under that new selector if no key rotation is otherwise needed:

`v=1; a=fairoze-1; p=<key>; c=re-sign; s=active; nb=1785542400; na=ongoing`

What distinguishes this case from Section 7.1's cross-vendor handoff is not the selector numbering, which is identical, but that a "d=" document is OPTIONAL here (Section 6.1) rather than REQUIRED: there is no "received_from" detail to convey when the prior hop was the same provider itself.

In practice, this means a self-loop re-sign selector will typically be numbered 2 or higher: a provider's selector 1 will ordinarily already exist as its default "c=sign" selector by the time any re-signing happens, since re-signing presupposes prior watermarked text to re-sign, which in turn presupposes the provider was already generating verifiable fresh text under this framework. This is a consequence of typical provider lifecycle, however, not a structural requirement this document enforces: nothing in the selector or "c=" rules above prevents selector 1 itself from being published as "c=re-sign" -- for example, a provider whose first-ever published record under this framework happens to be for a re-sign scenario, having generated text under some prior, unpublished key before it began participating in this framework at all. Verifiers MUST NOT assume a low-numbered selector, or selector 1 specifically, implies "c=sign" without checking the tag itself; "c=" exists precisely so this never needs to be inferred from the selector number.

## Composite Key Records for Chained Custody

Cross-vendor transitions MAY be recorded via composite key identifiers that reference the ordered provider sequence, allowing a verifier to reconstruct custody order from the DNS-published material plus in-text attestation, without requiring a centralized ledger.

The precise wire format for composite/chained attestations (analogous to ARC's AAR/AS/AMS header set) is left as an open design question for this draft; see Section 14.

A more elaborate design is conceivable, in which a provider pre-registers a full matrix of selectors, one for each other provider it might plausibly receive text from, each with its own "d=" document already in place (e.g., Example.AI maintaining distinct selectors for "received from Otherprovider.AI", "received from a third provider", and so on, ahead of time, rather than registering a selector's meaning only when a given handoff first occurs, as described in Section 7.1 and Section 6.4 step 6). This document does not specify such a matrix and considers it out of scope: it adds real complexity -- a selector space that grows with the number of other participating providers, rather than with the number of custody patterns a given provider actually encounters -- without a clear corresponding benefit over the simpler, register-on-first-use approach already described. If a concrete need for pre-registered, comprehensive custody matrices emerges from implementation experience, it can be specified in a later revision; this draft deliberately keeps Section 7's mechanism to the minimum needed to represent the custody chains described in Section 7.5's worked examples.

## Worked Examples

This section walks through four scenarios end to end, using the procedure in Section 6.4 and the mechanisms in Sections 6-7. All four use the same two providers introduced in Section 7.1: "example.ai" and "otherprovider.ai".

**(a) A provider verifying its own text.** 

Example.AI generates a piece of text and, later, wants to confirm it was the one that generated it (for example, to avoid retraining on its own prior output when scraping the web).

Under this framework, this would mean checking the text against Example.AI's own published key at "`1._watermark-text.example.ai`" -- the same lookup any other verifier would perform. 

The verifier is saying "This piece of text contains a watermark from myself, example.ai."

In practice, as of this writing, this is NOT how self-verification actually happens: currently-deployed watermarking schemes are symmetric (Section 4.1), so a provider checking its own output already holds the one key needed to do so directly   and has no reason to query DNS at all. This framework adds nothing for the self-verification case. It becomes relevant once a provider is using an asymmetric scheme (Section 10.3) and wants a third party -- not just itself -- to be able to run the same check; case (a) is included here mainly to make clear what this framework does NOT change, before cases (b)  through (d) show what it does.

**(b) Verifying someone else's text (no modification).**  

A verifier -- a platform, a researcher, anyone other than the originating provider -- receives a piece of text and wants to know whether an AI provider generated it, without knowing which one.

Following Section 6.4: the verifier has already cached key records for its known provider seed list, including Otherprovider.AI's "`1._watermark-text.otherprovider.ai`". It   attempts detection against each cached key in turn (or in parallel) until one matches. 

Suppose it matches Otherprovider.AI's selector 1. The verifier now knows:

* Otherprovider.AI generated this text, and
* under a key whose nb=/na= window covers the current time, at the moment the verifier is checking (Section 9.2), and 
* whose "s=" status is "active". No custody chain is involved -- this is a single, unmodified hop.

The verifier is saying "This piece of text contains a watermark from otherprovider.ai."

**(c) Verifying, then re-signing, someone else's text.**

Example.AI receives the text from case (b) -- already carrying Otherprovider.AI's mark -- and is asked to revise it (e.g., translate or edit it).

First, Example.AI performs the same detection as case (b) and confirms the incoming text carries Otherprovider.AI's mark. This step matters: it is how Example.AI knows what to   claim in the attestation it is about to publish, rather than guessing or trusting an unverified claim from whoever handed it the text.

Example.AI then produces its revised output. Rather than simply embedding its own mark under its default selector (which would silently erase the fact that this text has a prior hop at all, per Section 7.1), it selects a previously existing selector (or creates a new one) documenting the handoff, publishing a "d=" document such as:

```
{    
    "received_from": "otherprovider.ai",
    "selector": "2",
    "provider": "example.ai",
    "c": "re-sign",
    "ts": "1785542400"
}
```

It signs the revised text under "`2._watermark-text.example.ai`", whose DNS record points ("d=") to that document. Per Section 6.4 step 6, if Example.AI has already registered a selector for "received from Otherprovider.AI, re-signed" from an earlier occasion, it reuses that selector rather than creating a new one.

The verifier is saying "This piece of text contains a watermark from otherprovider.ai, and I am re-signing it from myself, example.ai."

**(d) Verifying a piece of text that already went through case (c).**

A different verifier later receives the output of case (c) and wants to know its full history, not just its most recent hop.

This is the important mechanical point this example exists to illustrate: the verifier does NOT find two overlapping, independently detectable watermarks (one from Otherprovider.AI, one from Example.AI) in the same text. Per the laundering   vulnerability described in Section 3.2, Example.AI's rewrite generally overwrites Otherprovider.AI's original statistical signal rather than preserving it alongside its own. What survives is Example.AI's mark alone, under selector 2.

The custody history is recovered not from the text itself but from the metadata trail: the verifier detects Example.AI's mark, notes it was signed under selector 2 rather than the default selector 1, queries "`2._watermark-text.example.ai`", follows its "d=" URL, and reads the JSON document from case (c) -- learning that this text is claimed to have been received from Otherprovider.AI and re-signed.

The verifier is saying "This piece of text contains a watermark from example.ai, and they say that it originally contained a watermark from otherprovider.ai." 

As Section 7.1 already states, this is a self-attested claim by Example.AI, not something the verifier can independently confirm against Otherprovider.AI's own records. A verifier performing case (d) is trusting Example.AI's account of where the text came from; it has no way to check that account against the (likely destroyed) original signal. What this framework provides in case (d) is a documented claim of custody, not cryptographic proof that the claim is accurate.

Section 14 lists this as an open question in the case where two providers' claims about the same handoff disagree.

**(e) Verifying a piece of text that already went through multiple re-signing hops.**

In the case that an initial provider creates and watermarks a piece of text, and a verifier verifies the initial provider created it and then re-signs it (case (d) above), and a second verifier verifies the newly re-signed version and determines it was signed by the second provider (first verifier) who first determined it was signed by the first provider, and then itself re-signs it, this can go on and on. In this case, there are multiple options:

* **Option 1**. Create an ever-expanding list of records containing multiple combinations. This option very quickly becomes non-scalable as the number of providers increases unless automation is used to manage additional keys and DNS zones, though it is not clear of the benefits of a proliferating combination of providers. A sample a d= record might look like the following:

```
{
    "received_from": "otherprovider.ai via simplewriter.llm",
    "selector": "10",
    "provider": "example.ai",
    "c": "re-sign",
    "ts": "1785542400"
}
```    

A verifier would interpret this as "This piece of text contains a watermark from example.ai, and they say that it originally contained a watermark from otherprovider.ai who said it originally contained a watermark from simplewriter.llm." Whether or not the verifier trusts example.ai is outside the scope of this document. Similarly, what the verifier does with this information if they do trust example.ai is outside the scope of this document.

* **Option 2**. Create a single re-signing record that applies to all watermarked text, without distinction as to the original text creator. This would be included in the d= record.

`2._watermark-text.example.ai IN TXT v=1; a=fairoze-1; p=<key>; c=re-sign; s=active; nb=1785542400; na=ongoing; d=https://2._watermark-text.example.ai/watermarkdescriptions.html; dh=sha-256-<...hash...>`

The d= record:
```
{
    "received_from": "all other text watermark services",
    "selector": "2",
    "provider": "example.ai",
    "c": "re-sign",
    "ts": "1785542400"
}
```
In this case, example.ai is saying "I received this piece of text that I verified was created by another AI, but I'm not saying who it was. I made some changes and I've re-signed it."

* **Option 3**. A combination of Options 1 and 2. A provider may at first try to keep track of who initially created a piece of text and try to correspond that to a handful of initial providers, publishing DNS keys for each one. However, if the number of text-generation services increases, the service eventually says "This is too much to keep up with. We'll keep the first few keys and the rest all fall under a generic bucket of a single record/signing key.

**(f) Publishing a single record with "c=sign"**

In the case that a provider decides that it's too much work to sign with multiple keys, they may just publish a single public key:

`1._watermark-text.simple.ai IN TXT v=1; a=fairoze-1; p=<key>; c=sign; s=active; nb=1785542400; na=ongoing;`

Subsequent crawling of DNS records at 2., 3., etc., yields no records.

In this case, any provider that receives a piece of text and determines that simple.ai watermarked it has no way of determining whether simple.ai created the text originally, or passed it on from either itself or another AI-text generator. Because the DNS record says "c=sign" it would be reasonable, though not required, for another AI text watermark verifier to assume that simple.ai created the text, made very minimal changes to existing text, or is comfortable asserting either of those two scenarios.

**(g) Publishing a single record with "c=re-sign" WITH a "d=" record**

A  *single* `_watermark-text` record, with an associated d= record, can lead to confusion:

`1._watermark-text.example.ai IN TXT v=1; a=fairoze-1; p=<key>; c=re-sign; s=active; nb=1785542400; na=ongoing; d=https://1._watermark-text.example.ai/watermarkdescriptions.html; dh=sha-256-<...hash...>; r=1`

In this case, the r=1 indicates it is a single DNS record and is here for illustrative purposes, it is not required.

The d= record:
```
{
    "received_from": "all other text watermark services",
    "selector": "1",
    "provider": "example.ai",
    "c": "re-sign",
    "ts": "1785542400"
}
```

This record, as interpreted, indicates that the simple.ai doesn't generate any text from scratch, it only modifies (re-signs) previously existing text. It would be odd for a text-generator to only modify existing text and not actually generate it.

This document does not specify how a verifier might interpret this record, but they may choose to interpret it as "This piece of text contains a watermark from simple.ai, and they say that it originally contained a watermark from another AI service." But the verifier might also say "But, simple.ai says they don't actually watermark anything from scratch. Maybe they do, maybe they don't. We'll treat both cases the same - simple.ai is taking ownership of this text."

**(h) Publishing a single record with "c=re-sign" WITHOUT "d=" record**

A  `_watermark-text` record with "c=re-sign" that contains no d= record is only valid when a provider is re-signing its own generated text: 

`1._watermark-text.simple.ai IN TXT v=1; a=fairoze-1; p=<key>; c=re-sign; s=active; nb=1785542400; na=ongoing;`

Similar to case (g), this particular case causes ambiguity: because its the `1._watermark-text` DNS record, but is re-signing (presumably after first verifying), a downstream verifier may interpret this case as simple.ai modified text generated by a previous provider, but it doesn't generate any original text from scratch, which would be unusual.

 The tools for creating the DNS record should flag this as an error or warning, and recommend publishing at `2._watermark-text` or higher unless the provider is certain this is the intent.

**(i) Publishing a _watermark record where the "d=" record doesn't match the DNS record**

Suppose a _watermark record is the following:

`1._watermark-text.simple.ai IN TXT v=1; a=fairoze-1; p=<key>; c=sign; s=active; nb=1785542999; na=ongoing; d=https://1._watermark-text.example.ai/watermarkdescriptions.html; dh=sha-256-<...hash...>; r=1`

The d= record:

```
{
    "received_from": "all other text watermark services",
    "selector": "1",
    "provider": "simple.ai",
    "c": "re-sign",
    "ts": "1785542400"
}
```

The c=sign in the DNS record doesn't match the c=re-sign in the d= page. Similar to case (f), a provider may still choose to verify it, and may choose to interpret it as Case 5. Or, it may choose to not verify it and treat is as an error, or unwatermarked text. However, tools for creating the DNS record should flag this as an error and prevent its publishing.

If the DNS record said "c=resign" and the d= record said "c=re-sign", this would be acceptable per section 6.1.

**(j) Publishing a _watermark record where the "d=" record doesn't match the hash**

Suppose a _watermark record is the following:

`1._watermark-text.simple.ai IN TXT v=1; a=fairoze-1; p=<key>; c=sign; s=active; nb=1785542999; na=ongoing; d=https://1._watermark-text.example.ai/watermarkdescriptions.html; dh=sha-256-HASH1; r=1`

The d= record:

```
{
    "received_from": "all other text watermark services",
    "selector": "1",
    "provider": "simple.ai",
    "c": "re-sign",
    "ts": "1785542400"
    "comments": "Comments added on 1785546400"
}
```

In this case, the actual d= record hashes to HASH2, whereas the dh record says it should hash to HASH1. Looking through the above, one potential scenario is that the d= record had the "comments" field subsequently added without re-hashing and updating the DNS record.

In any case, a verifier MUST exit and treat this as a failed verification for this particular record.

# The Laundering Tax

Rather than attempting to make multi-model transformation lossless with respect to watermark survival -- which would require solving the underlying erasure problem described in Section 3.2 -- this framework treats compounding degradation as an acceptable, even desirable, side effect. Each additional hop through a watermark-constrained model is expected to impose incremental linguistic constraint. Text laundered through several hops in an attempt to strip attribution is expected to become progressively more stilted or generic, raising the operational cost of evasion without requiring the framework to prevent evasion outright.

This is explicitly not a claim that laundering can be made impossible, nor that all adversaries are quality-sensitive. See Section 10 and Section 11 for the limits of this argument.

# Security Considerations

This specification defines a public key distribution and provenance tracking framework for AI-generated text watermarks. Verifiers and implementers MUST account for the following security boundary conditions and threat vectors.

## DNS Integrity and DNSSEC Dependence

Because public verification keys are fetched over DNS, adversaries capable of cache poisoning, DNS spoofing, or man-in-the-middle (MitM) attacks can substitute forged public keys to either cause legitimate watermarks to fail verification or validate unauthorized text.

* **DNSSEC Enforcement:** Domain owners publishing _watermark-text TXT records SHOULD implement DNSSEC ([@RFC4033]). Verifying resolvers MUST perform DNSSEC validation where available to guarantee record authenticity and origin integrity.

* **Cache Lifetime Boundaries:** Verifiers MUST respect the DNS record TTL (Time to Live) and MUST NOT cache public keys past their authoritative expiration unless explicit offline caching policies apply.

## Key Lifecycle, Compromise, and Rotation

A compromised private signing key allows an attacker to inject statistical watermarks into arbitrary text payloads, falsely attributing generation or re-signing to the victim domain.

* **Validity Windows** `(nb= / na=)`: Public key TXT records MUST include validity parameters (nb= for Not Before, na= for Not After). Verifiers MUST evaluate text watermarks by taking the current timestamp (time of detection) against these nb/na windows, and reject signatures evaluated outside an active key's operational lifespan. Watermark implementers SHOULD avoid creating new watermarks that are too close to the `na` final end time to avoid publishing watermarks that are likely to be verified outside that window given a small time delay.

* **Revocation Status** `(s=)`: If a private key is compromised, the publishing domain MUST immediately update the selector record status tag to s=revoked. Verifiers MUST treat records marked with s=revoked as invalid for all verification attempts, including historical text.

* **Key Separation:** Domain administrators MUST use dedicated key pairs for text watermarking and MUST NOT reuse DNS keys configured for DKIM, BIMI, SSH, or TLS.

## Replay Attacks and Context Stripping

A statistical text watermark asserts origin and key possession; it does not inherently bind text to a specific recipient, session, or publication context.

* **Snippet Replay:** An attacker can excerpt validly watermarked text from a benign AI response and embed it into malicious, deceptive, or out-of-context documents.

* **Scope Limits:** Verifiers MUST recognize that a successful watermark verification confirms which entity generated or re-signed the text, but does NOT guarantee that the text has not been spliced, rearranged, or presented in a misleading context.

## Custody Descriptor Tampering `(dh=)`

When text undergoes multi-hop handoffs (`c=re-sign`), the downstream provider hosts a JSON descriptor at a d= HTTPS URL. Transport security (TLS) guarantees origin at fetch time but does not protect against retroactive descriptor modification or deletion by a compromised or malicious host.

* **Cryptographic Content Binding:** To prevent retroactive history alteration, generators MUST include the Subresource Integrity digest tag (dh=) in the DNS record whenever d= is present.

* **Digest Enforcement:** Verifiers MUST compute the digest of the raw JSON response payload and reject any custody descriptor whose computed hash fails to match the Base64URL-encoded digest declared in dh=.

## Non-Repudiation and Semantic Truth Boundaries

* **Self-Attestation Limit:** Custody chains rely on cryptographic self-attestation. A valid `c=re-sign` chain proves that an entity possessing the private key executed a re-signature step, but it cannot independently prove the truthfulness or factual accuracy of upstream claims.

* **Asymmetric Non-Repudiation:** Provided private keys remain secure, the asymmetric property ensures that a domain cannot plausibly deny having generated a validly detected statistical watermark matching its published DNS public key.

## Non-Adoption and the Open-Weights Gap

This framework depends entirely on voluntary provider participation. It provides no mechanism to compel a model operator to embed a watermark, publish a key, or honor multi-hop attestation, and it has no answer for locally-run open-weight models, which can be operated without any of the infrastructure this document assumes (a maintained domain, a public DNS presence, or any incentive to cooperate). The framework's value is therefore bounded to the set of providers who choose to participate, and non-participation by a subset of the market does not invalidate participation by the rest, but it does mean this is a partial solution by construction, not a comprehensive one.

# Known Limitations

## Signal Capacity of Statistical Watermarks

Statistical text watermarks carry limited payload capacity relative to the structured data this framework's custody chain wants to convey (provider identity, hop order, re-sign markers, content hashes). A short response provides few sampling decisions to bias, constraining how much attestation metadata can plausibly be carried in-band without degrading fluency or requiring impractically long text before a signal is reliably detectable. This is a real constraint on the design, not a solved problem, and is flagged here for reviewer attention rather than resolved.

## This Framework Does Not Create Detectability

This document specifies key distribution and custody attestation. It does not improve the underlying detectability or robustness of any provider's watermark against paraphrase, translation, or heavy editing. A watermark that a given provider's own detector cannot recover after aggressive rewriting will not become recoverable merely because its key is now published in DNS.

## This Framework Requires a Cryptographic Primitive Not Yet Deployed at Scale

This is the most consequential dependency in this document, and is given its own subsection rather than folded into the others. It is framed here as a dependency rather than a limitation of the mechanism's own design, deliberately: the paragraphs below show that publishing a symmetric scheme's key was never a viable path to cross-vendor verification in the first place, so this framework does not fall short of an achievable goal by requiring something else. It requires and is built for a different cryptographic foundation than what is deployed today, in place of it, not alongside it.

As discussed in Section 4.1, this framework's entire premise -- that a "p=" value can be published in DNS and used by any third party to verify a watermark -- requires an asymmetric, publicly-detectable watermarking scheme, in which the key that verifies cannot be used to forge or strip. Deployed statistical watermarking schemes as of this writing, including the best-documented production system referenced in Section 4.1, are symmetric: the same key embeds and detects. Publishing a symmetric scheme's key under this framework's DNS mechanism would not achieve cross-vendor verification; it would hand third parties the ability to forge and strip that provider's watermark entirely, which is a strictly worse outcome than the vendor siloing this document sets out to fix in Section 3.1.

This document therefore has an unresolved dependency: it assumes providers adopt or migrate to a publicly-detectable watermarking scheme, which is presently a research-stage line of work with documented practical costs (e.g., substantially higher computational cost for certain operations, and less real-world deployment experience than symmetric schemes have accumulated), rather than something already running in production. Nothing in this document should be read as claiming otherwise, and nothing in this document's DNS or custody-chain design (Sections 6-7) solves, or attempts to solve, the underlying cryptographic problem of building a fast, robust, publicly-detectable watermarking scheme in the first place. That work belongs to a different, ongoing line of research this document depends on but does not contribute to.

# Incentive Analysis

Providers currently have limited direct incentive to publish keys, support verification by competitors' tooling, or honor multi-hop attestation from other providers' models. This mirrors the position image and audio watermarking occupied prior to regulatory and reputational pressure normalizing it; providers adopted visible and invisible marking for those modalities before it was strictly mandated, in part to avoid being conspicuously the one major provider without it. Whether that dynamic repeats for cross-vendor text verification specifically, given the harder technical constraints described in Section 10.1, is not something this document can establish and is offered as a hypothesis, not a prediction.

## Possible use cases

This document does not determine how text watermark verification SHOULD be used, nor does it assert whether or not it is a good idea in general. Instead, it provides a framework for how to deploy it cross-organizationally at scale. However, a handful of examples are provided below, each with merits and drawbacks.

## Potential use case - transparency in social media feeds

Article 26 of the European Union Digital Services Act requires advertisements to disclose who paid for the ad. In the absence of legislation requiring it, providers may choose to detect that text within an advertisement or organic content contains AI-generated text.

## Potential use case - transparency in community-sourced knowledge bases

AI-generated text that is copy/pasted into a community-sourced knowledge base may choose to leverage that information by surfacing that information to the reader -- e.g., as a footnote or other UX-based indicator.

## Potential use case - as contrast from other types of text

As the use of AI-generated text increases, this may be contrasted against purely user-generated text that does not use AI (or minimizes its use in the creation of text). This document does not specify how to determine that text is primarily human-generated. In the absence of a signal of AI-generated or human-generated text, that is also a potential signal to the consumer of the text. This document does not comment on the merits of this approach.

## Regulatory considerations

* **Interoperable Auditability (Article 50(2))**: Regulators and market surveillance authorities need to verify compliance without relying on proprietary, closed-door vendor APIs. DNS-native key distribution allows public auditors to verify claims locally using open internet infrastructure.

* **Avoidance of Walled Gardens:** Without an open RFC standard, compliance defaults to fragmented, proprietary detection portals (e.g., every provider running a walled-garden verification API). Standardizing key discovery at _watermark-text aligns with some regulatory jurisdictions preferences for open, vendor-neutral internet standards.

* **GDPR & Zero-Telemetry Verification:** Because key lookup occurs via standard DNS and verification happens client-side, verifiers do not need to submit user text payloads back to model vendors for checking—eliminating significant data exposure and privacy friction under EU law.

# Performance considerations

An advantage of symmetric key watermark generation is that it is computationally less expensive than alternatives, both for generation and for verification. However, it does not allow for cross-organizational watermark verification absent very complicated private-key sharing frameworks, additional overhead of zero-knowledge proof computations, or semi-public APIs that must be maintained (i.e., frameworks for granting access). The latter two of these options do not scale to the size of the Internet given the amount of data that must be transmitted back and forth.

The advantage of asymmetric watermark generation is that it allows for cross-organizational watermark verification, and watermark verification is relatively computationally inexpensive. However, watermark generation is computationally expensive.

Therefore, whichever method is selected, there are technical challenges to address and come with a set of tradeoffs. These tradeoffs may be better addressed in future proposals, either building on this document or those produced independently. Or, they may be seen as acceptable tradeoffs.

# Future specification expansion

* **No way to tell a verifier where to start picking up the keys.** If a provider has many keys, hundreds or thousands, it only has the ability to tell a provider how many keys are in a DNS record with the `r=<number>` tag. If a provider has 1000 keys but the first 500 are invalid, a provider still has to iterate over the first 500, inspect the records for if the key is still valid or revoked, to get to the second 500.

  In the interest of simplicity, this document does not contain a tag for telling verifiers to start counting from a numbered DNS record other than 1.
* **No "metadata" master record**. This document does not specify a master record, e.g., `_watermark-text.<domain>` that contains all the information such as the number of records, where to start, the d= location, the dh hash, etc. Instead, the first record, 1, implicitly contains this information, and subsequent DNS records may have additional d= tags.


# Open Questions for Review

This section lists unresolved issues this draft does not claim to have solved, intended as the starting point for stress-testing:

* Most significantly: this framework depends on providers using an asymmetric, publicly-detectable watermarking scheme, which is not what is currently deployed at production scale (Section 10.3). Whether, when, or how providers might migrate from symmetric schemes to a publicly-detectable one -- and whether current publicly-detectable schemes are practical at the scale and latency production text generation requires -- is entirely unresolved and outside this document's scope.
* Wire format for chained/composite custody attestation (Section 7.3) is unspecified.
* No revocation mechanism for compromised keys is defined (Section 9.2).
* The interaction between this framework and C2PA (should they be layered? mutually exclusive? cross-referenced?) is unresolved; note the "Integrity Clash" failure mode identified in independent research, where C2PA and watermark signals can be made to disagree because neither currently conditions on the other.
* Payload budget for in-band custody metadata (Section 10.1) has not been quantified against any specific provider's actual watermarking scheme.
* No proposal is made here for how a verifier should weight or resolve conflicting attestations from different providers.
* Establishment and stewardship of the "a=" algorithm registry (Section 15) is unresolved, including who is positioned to register algorithm identifiers for schemes that already exist but were not designed with this framework in mind.
* No mechanism is defined for how a verifier's provider seed list (Section 6.4) is itself obtained, authenticated, or kept current; this framework inherits rather than solves the equivalent bootstrap-trust problem long-standing in ARC deployment (trusted-sealer lists), and a manually-maintained list, while workable at current provider counts, does not obviously scale or resist tampering or omission.
* CNAME delegation (Section 6.5) lets a verifier correctly resolve a key held at a domain outside its provider seed list, but provides no way to confirm that domain was authorized to receive the delegation in the first place; this is a concrete instance of the bootstrap-trust gap above, not a separately solved problem.
* No treatment is given to the statistical effect of testing a piece of text against every cached key rather than a single known one (Section 6.4, step 5). Each cached selector represents a separate hypothesis test against the same detector; as the number of participating providers and retained historical selectors grows, this document does not specify whether or how a verifier should adjust its detection threshold to control the aggregate false-positive rate, rather than applying a single-key threshold across an arbitrarily large cached key set.


# IANA Considerations

This document defines a DNS TXT record format under a provider-controlled subdomain and does not currently request any IANA registry actions for the tag-value parameters generally, pending further development of this proposal.

It does, however, identify one registry as a functional prerequisite rather than a future nicety: the "a=" algorithm identifier (Section 6.1). A verifier that encounters an "a=" value it does not recognize has no principled way to decide whether that value names a real, interoperable watermarking scheme it simply hasn't implemented yet, or a typo, or a provider-invented identifier no other party will ever recognize. Unlike most of this document's tags, "a=" only functions as intended if its value space is a closed, shared list rather than an arbitrary string each provider defines unilaterally -- which requires a registry, not merely a convention.

This document therefore proposes that a future revision request establishment of an IANA-maintained "AI Text Watermark Algorithm Identifiers" registry, structured similarly to existing IANA registries for cryptographic algorithm identifiers (e.g., the TLS Cipher Suites registry). Each entry would record: the algorithm identifier string (e.g., "synthid-1"), a reference to its public specification, and the organization or individual that registered it. Each "a=" identifier names a complete, versioned parameter set, not merely a bare scheme name -- a verifier that recognizes the identifier needs no side channel, out-of-band configuration, or additional tag to learn the scheme's constants (segment lengths, hash choices, error budgets, or any other detection parameter); the identifier alone, together with "p=", is sufficient. Registration would follow Specification Required policy ([@RFC8126]): a value is only registrable if a public technical description of the algorithm exists, consistent with this document's position (Section 4.1) that watermark embedding algorithms need not be secret, only their keys. A provider using an unregistered, undocumented algorithm may still publish an "a=" value, but verifiers are not obligated to attempt interoperation with it, and SHOULD treat such records as unusable per Section 6.1. 

One example of where a verifier MAY treat it as usable is if they are experimenting with a new algorithm, either their own or someone else's, and are testing the end-to-end functionality. In such a scenario, attempting to sign or verify against an unrecognized algorithm is acceptable.

Establishing this registry, and determining who is positioned to act as registrant for schemes already deployed by third parties (e.g., SynthID), is left as an open question for further discussion; see Section 14.

{backmatter}

# Appendix A.  Design Note: Avoiding DKIM Tag-Letter Collisions

This appendix is informative and not required reading to understand or implement this specification. It documents a drafting practice followed while assigning tag letters in Section 6.1, for the benefit of future editors extending this document.

This specification borrows its record syntax style from DKIM ([@RFC6376]), but DKIM itself uses some tag letters differently depending on where they appear: a letter can mean one thing in a DKIM-Signature email header and something else in a DKIM key record published in DNS. Two examples came up during drafting:

* "p=": In an email's DKIM-Signature header, there is no "p=" tag. But in a DKIM key record (the DNS TXT record DKIM verifiers actually query, which is the closest analog to this document's own records), "p=" holds the public key material itself. An early draft of this document used "p=" for provider identity instead, which collided with that meaning. The tag was reassigned: provider identity was removed from the record entirely (Section 6.1), and "p=" was given DKIM's own meaning (public key material).

* "t="/"x=": In a DKIM-Signature header, "t=" and "x=" are Unix timestamps marking when a signature was created and when it expires. But in a DKIM key record, "t=" already means something unrelated: a flag field (for example, "t=y" marks a key as being used in testing mode). This document needed a validity window (Section 6.1's "nb="/"na=" tags) and adopted DKIM's Unix-timestamp format for it, but deliberately did not reuse the letters "t="/"x=" themselves, since this document's records are structurally key records, not signature headers, and "t=" already means something else in that context.

The general practice, for anyone adding a new tag to this specification later: before assigning a letter, check what that letter means in both a DKIM-Signature header AND a DKIM key record, since they are not the same, and this document's own records are key records. A letter that is unused in a DKIM key record specifically is safe to reuse for a related purpose; a letter that is unused only in the signature header is not, since readers already familiar with DKIM key records are this document's most likely audience for close reading.

# Appendix B.  Design Alternatives Considered: Monolithic Key JSON vs. Per-Selector DNS Records

This appendix is informative and documents an architectural trade-off evaluated during the design of this specification: specifically, why this framework publishes public key material directly in per-selector DNS TXT records (`<selector>._watermark-text.<domain>`) rather than using a single, static DNS pointer (`_watermark-text.<domain>`) that references an HTTPS-hosted JSON document containing all active and historical key material.

## Evaluated Alternative Architecture

Under the evaluated alternative:

* A provider publishes exactly one DNS TXT record at a static location:

* `_watermark-text.example.ai IN TXT "v=1; d=https://_watermark-text.example.ai/keys.json; dh=sha256-<hash>"`

* The referenced keys.json file contains a structured array or dictionary of all public verification keys (p=), algorithm identifiers (a=), validity windows (nb=/na=), and custody markers (c=).

While this model appears appealing because it collapses DNS management to a single static record, it introduces five severe operational, cryptographic, and architectural drawbacks that make it unsuitable for internet-scale deployment.

## The dh= Invalidation Cascade (The DNS Update Paradox)

The primary operational motivation for placing keys in an HTTPS JSON document is avoiding frequent DNS record updates during key lifecycle events (rotation, revocation, or adding purpose-specific keys).

However, to prevent retroactive tampering or silent history alteration of the hosted JSON document (Section 9.4), the DNS record MUST include a Subresource Integrity digest tag (dh=).

* Any modification to the key set—such as publishing a new selector, closing out a validity window, or revoking a compromised key—alters the raw byte content of keys.json.

* Altering the JSON content changes its computed cryptographic digest (dh=).

* Therefore, the publishing domain MUST still update its DNS TXT record every single time a key operation occurs to publish the new dh= hash.

The monolithic JSON architecture fails to eliminate DNS zone updates; it merely adds an extra HTTPS indirection step to execute what direct DNS record updates achieve natively.

## Destruction of Granular DNS Delegation (CNAMEs)

Enterprise AI deployments frequently involve third-party platforms, multi-cloud SaaS partners, or distinct business units generating watermarked text on behalf of a parent domain.

* **Per-Selector Model (Section 6.5)**: The parent domain delegates individual key selectors via standard DNS CNAME records without exposing its entire key infrastructure:

  `3._watermark-text.example.ai. CNAME 3._watermark-text.vendor.example.`

* **Monolithic JSON Model**: Granular delegation is impossible at the DNS layer. The parent domain must build and maintain an internal aggregation pipeline to fetch, validate, and merge every external vendor's public keys into one single keys.json file served from its root domain.

## Shift from Resilient DNS Edge to Vulnerable HTTP Origins

DNS key distribution relies on global Anycast networks and recursive resolver caching (e.g., Cloudflare, Google Public DNS, ISP resolvers). In the per-selector model:

* Public key lookups are served at the DNS edge with sub-millisecond latency.

* Key resolution survives web server outages and network partition events.

* Verifiers testing millions of candidate snippets absorb lookup overhead within distributed DNS caches rather than hitting origin infrastructure.

In the monolithic JSON model, key retrieval shifts to HTTP application servers. Any web origin outage, TLS certificate expiration, CORS misconfiguration, or HTTP 5xx error directly collapses global watermark verification for that provider. Furthermore, an adversary submitting high volumes of text to automated verifiers creates an indirect Distributed Denial of Service (DDoS) vector against the provider's HTTPS web origin.

## Payload Bloat and Bandwidth Inefficiency

Over years of continuous operation, a provider's key inventory grows across active keys, rotated historical keys, and custody re-signing selectors.

* Under the per-selector model, a verifier queries only the specific key record it needs (a compact response of ~200 bytes).

* Under the monolithic JSON model, a verifier must fetch the entire historical key manifest—potentially hundreds of kilobytes—just to verify a single recent snippet of text.

## Alignment with Proven Email Infrastructure (The DKIM Precedent)

This framework intentionally mirrors DKIM ([@RFC6376]), which evaluated this exact trade-off two decades ago. Email authentication standards explicitly chose per-selector DNS records (`<selector>._domainkey.<domain>`) over URI key directories because DNS is fundamentally designed as a low-latency, highly distributed, public-key lookup system. Retaining per-selector records ensures that text watermark verification inherits the established operational patterns, caching guarantees, and tooling of global DNS infrastructure.

Author's Address

Terry Zink Independent Researcher Email: tzink@terryzink.com



# Normative References

# Informative References

[BIMI]: https://en.wikipedia.org/wiki/Brand_Indicators_for_Message_Identification "Brand Indicators for Message Identification (BIMI)"
[C2PA]: https://spec.c2pa.org/specifications/specifications/2.4/index.html "Coalition for Content Provenance and Authenticity"
[SynthID]: https://deepmind.google/models/synthid/ "Scalable watermarking for identifying large language model outputs"
[fairoze23]: https://arxiv.org/pdf/2310.18491 "Publicly-Detectable Watermarking for Language Models"
[Gloaguen24]: https://arxiv.org/abs/2405.20777 "Black-Box Detection of Language Model Watermarks"
