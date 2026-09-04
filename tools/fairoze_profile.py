#!/usr/bin/env python3
"""
fairoze_profile.py -- the `fairoze-1` algorithm profile (Step 0 of the build plan).

This is the *shared contract* between two codebases:

  * the generator  -- a patched clone of github.com/jfairoze/publicly-detectable-watermark
                      run in Colab (BLS -> Ed25519), used only to produce watermarked text
  * the verifier   -- tools/fairoze.py in this repo (CPU-only, stdlib + reedsolo)

Both sides MUST import these constants and use `canonicalize()` verbatim. If the
generator embeds bits over one canonical form and the verifier extracts over a
different one, every verification silently fails -- this is open question B1 in
implementation-open-questions.md, made concrete for one algorithm.

Standard library only, so it can be dropped into a Colab notebook as-is.

Status of the numbers below:
  FIRM      -- our design decisions, not expected to change
  REFERENCE -- copied from the reference implementation's defaults; CONFIRM
               bit-exactly during Step 6/7 and update here if the reference
               actually does something different
"""

from __future__ import annotations


# --------------------------------------------------------------------------- #
# identifier                                                                   #
# --------------------------------------------------------------------------- #

ALGORITHM_ID = "fairoze-1"
CONSTRUCTION = "publicly-detectable watermarking via rejection-sampling signature embedding [Fairoze23]"

# --------------------------------------------------------------------------- #
# signature scheme                                            (FIRM)           #
# --------------------------------------------------------------------------- #

SIGNATURE_ALGORITHM = "ed25519"        # RFC 8032, deterministic
SIGNATURE_LEN = 64                     # bytes, Ed25519 signature
PUBKEY_RAW_LEN = 32                    # bytes, Ed25519 public key

# p= tag encoding: base64(SubjectPublicKeyInfo DER), standard alphabet, padded.
# This is a stock Ed25519 SPKI -- openssl parses it, and watermark_dns_tool.py's
# inspect_spki() already handles it. No p= redefinition needed for this profile.
PUBKEY_ENCODING = "spki-der-base64"

# --------------------------------------------------------------------------- #
# hashing                                                     (FIRM)           #
# --------------------------------------------------------------------------- #

PAYLOAD_HASH = "sha256"    # maps each SEGMENT_LEN-char window -> BITS_PER_SEGMENT bits
                           # (the FIRST BITS_PER_SEGMENT bits of the sha256 digest, MSB-first)
MESSAGE_HASH = "sha256"    # message chars -> 32-byte digest; that digest is what Ed25519 signs

# One-time-pad mask over the RS codeword (undetectability). The reference uses
# sha512(message_digest) -- 64 bytes, which happens to cover its 45-byte BLS
# codeword. Our Ed25519 codeword is RS_N = 68 bytes, so sha512 would leave the
# last 4 (parity) bytes unmasked. `fairoze-1` therefore specifies a SHAKE256 XOF
# of exactly RS_N bytes:  mask = shake256(message_digest, RS_N)          (FIRM)
MASK_XOF = "shake256"

# --------------------------------------------------------------------------- #
# error-correcting code                                                        #
# --------------------------------------------------------------------------- #

RS_FIELD = 256                            # Reed-Solomon over GF(2^8)  (FIRM)
MAX_PLANTED_ERRORS = 2                    # (REFERENCE) reference default
RS_PARITY_BYTES = 2 * MAX_PLANTED_ERRORS  # corrects up to MAX_PLANTED_ERRORS symbol errors
RS_K = SIGNATURE_LEN                      # 64 data bytes  (the signature)
RS_N = RS_K + RS_PARITY_BYTES             # 68 total bytes

# --------------------------------------------------------------------------- #
# character-level embedding                                                    #
# --------------------------------------------------------------------------- #
# Confirmed against the reference detect.py extraction loop (Step 3):
#
#   message  = text[:MESSAGE_LEN]                       -- the literal leading chars,
#                                                          NOT hash-embedded
#   for each contiguous SEGMENT_LEN-char window w_k of text[MESSAGE_LEN:]:
#       bits_k = first BITS_PER_SEGMENT bits of
#                sha256( message.encode()
#                        + bits_so_far.encode()        -- the "01" string built so far
#                        + w_k.encode() )
#   stop after CODEWORD_BITS // BITS_PER_SEGMENT windows
#
# The hash is CHAINED on bits_so_far, so extraction is strictly sequential --
# and one edited character corrupts its segment plus every later segment, so
# fairoze-1 tolerates edits only in the final segment or two (see
# implementation-open-questions.md D4).
#
# Alignment is unknown to the verifier. fairoze-1 treats the mark as a
# CONTIGUOUS span (not cyclically wrapped, unlike the reference), so the verifier
# scans offsets 0 .. n-MIN_WATERMARK_CHARS -- a single iteration when the pasted
# text is exactly the watermarked passage. `windows_to_bits()` assumes aligned
# text; `verify_text()` does the scan.

SEGMENT_LEN = 16          # characters per signature segment      (REFERENCE default)
BITS_PER_SEGMENT = 2      # bits taken from each segment's hash   (REFERENCE default)
MESSAGE_LEN = SEGMENT_LEN // BITS_PER_SEGMENT   # 8; the reference derives it this way

# --------------------------------------------------------------------------- #
# canonicalization                                            (FIRM)           #
# --------------------------------------------------------------------------- #
# The verifier runs canonicalize() before extraction. Its ONLY job is to undo
# damage that copy/paste and file handling inflict on the character sequence --
# NOT to impose a form the generator didn't produce. The reference detector does
# only `text.rstrip("\n")`; we add the two other transforms that a browser
# textarea / editor commonly applies:
#
#   - strip a leading/anywhere BOM (editors and some copy paths insert one)
#   - CRLF / CR  ->  LF        (Windows, and many paste paths, rewrite newlines)
#   - rstrip "\n"              (trailing newlines from the file/paste)
#
# NOT done, on purpose:
#   - NFC / any Unicode normalization -- would substitute characters the model
#     may have actually emitted, shifting every downstream window. The generator
#     embeds over its raw token output; the verifier must match that byte-for-byte.
#   - stripping leading whitespace -- message = text[:MESSAGE_LEN]; touching the
#     leading edge changes the message.
#   - internal-whitespace collapsing / case folding -- the mark lives in the spaces.
#
# Whether to also strip zero-width chars (U+200B/C/D, U+2060) is deferred to
# Step 6: only safe if the generator's sampler can never emit them.

_BOM = "﻿"


def canonicalize(text: str) -> str:
    """Undo copy/paste damage to the character sequence -- nothing more."""
    text = text.replace(_BOM, "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.rstrip("\n")

# --------------------------------------------------------------------------- #
# derived quantities (informational)                                           #
# --------------------------------------------------------------------------- #

CODEWORD_BITS = RS_N * 8                                # 544  (== SIGNATURE_LEN*8 + 8*2*MAX_PLANTED_ERRORS)
SEGMENTS_NEEDED = CODEWORD_BITS // BITS_PER_SEGMENT     # 272  (the extraction loop's stop count)
MIN_WATERMARK_CHARS = MESSAGE_LEN + SEGMENTS_NEEDED * SEGMENT_LEN   # 8 + 272*16 = 4360
# => a fairoze-1 watermark needs at least this many characters of sufficiently
#    high-entropy generated text; shorter or low-entropy text carries no mark.
#    CONFIRMED 2026-09-03: a real sample from the patched generator was 4361 raw
#    chars / 4360 canonical -- exact. detect.py and tools/fairoze.py agree.

assert CODEWORD_BITS % BITS_PER_SEGMENT == 0, "codeword must divide evenly into segments"


def summary() -> str:
    return (
        f"{ALGORITHM_ID}: {SIGNATURE_ALGORITHM} sig ({SIGNATURE_LEN}B) | "
        f"{PAYLOAD_HASH} windows | RS({RS_N},{RS_K}) corrects<={MAX_PLANTED_ERRORS} | "
        f"seg={SEGMENT_LEN}c bits={BITS_PER_SEGMENT} msg={MESSAGE_LEN}c | "
        f"{SEGMENTS_NEEDED} segments, ~{MIN_WATERMARK_CHARS} chars minimum"
    )


DNS_RECORD_EXAMPLE = (
    "3._watermark-text.demo.terryzink.com  IN TXT  "
    '"v=1; a=fairoze-1; p=<base64 Ed25519 SPKI>; c=sign; '
    'nb=<unix>; na=ongoing"'
)


if __name__ == "__main__":
    print(summary())
    print()
    for name, val in sorted(globals().items()):
        if name.isupper() and not name.startswith("_"):
            print(f"  {name:22} {val!r}")
    print()
    print("canonicalize() self-check (BOM + CRLF + trailing newlines):")
    probe = "﻿  keep leading spaces\r\nsecond line\n\n"
    print(f"  in : {probe!r}")
    print(f"  out: {canonicalize(probe)!r}")
