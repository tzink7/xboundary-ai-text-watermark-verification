#!/usr/bin/env python3
"""
synthid_profile.py -- the `synthid-1` algorithm profile.

`synthid-1` is Google DeepMind's SynthID-Text (Dathathri et al., Nature 2024) as
plugged into this framework. It is here as the *symmetric, statistical* point of
comparison against the asymmetric schemes (`fairoze-1`, `tzsataitw-*`), NOT as a
full framework citizen -- see the caveats below.

Unlike the other profiles, the real contract for `synthid-1` is a *data* file,
not this module: the generator and the verifier must share one
`synthid-1.config.json` (tokenizer id, vocab_size, ngram_len, sampling table
params) plus the secret `keys`. This module only holds the identifier, the
defaults `SynthIDTextWatermarkingConfig()` would use, the shared `canonicalize()`,
and the documentation of why `synthid-1` does not fit the DNS `p=` model.

Standard library only.

--------------------------------------------------------------------------------
WHY synthid-1 IS NOT A NORMAL `a=` ALGORITHM
--------------------------------------------------------------------------------
1. SYMMETRIC. The `keys` list is the whole secret. It is used identically at
   generation and detection; anyone who holds it can forge marks in the
   provider's name and strip them. So there is NO public key -- nothing to put
   in `p=`. This collides head-on with draft Section 6.1's "p= REQUIRED".
   Representing synthid-1 in the framework needs either a p=-exemption or a
   `verify_hint`-style pointer to a verification service the key holder runs.
   (Logged in implementation-open-questions.md.)

2. STATISTICAL. Detection is a score vs. a calibrated threshold, not a
   deterministic pass/fail. Output carries a false-positive rate. This is the
   multiple-hypothesis-testing hazard the draft flags for Section 6.4 step 5
   (open question B7) -- it genuinely applies here, unlike for a signature check.

3. NEEDS THE TOKENIZER + PARAMS, NOT JUST A KEY. The g-function hashes token
   n-grams; the detector must use the exact same tokenizer, vocab_size, and
   sampling-table parameters as the generator or every score is wrong. That is
   what `synthid-1.config.json` carries.

Detection still needs NO GPU and NO model weights -- just the tokenizer, the
config, the keys, and CPU arithmetic (open question: this is the one nice
property it shares with the asymmetric schemes).
"""

from __future__ import annotations


# --------------------------------------------------------------------------- #
# identifier                                                                   #
# --------------------------------------------------------------------------- #

ALGORITHM_ID = "synthid-1"
CONSTRUCTION = "SynthID-Text tournament sampling [Dathathri et al., Nature 2024]"
KEY_MODEL = "symmetric"          # the keys list is secret; no public key
DETECTION = "statistical"        # score vs. calibrated threshold

# --------------------------------------------------------------------------- #
# generation / detection parameters                                            #
# --------------------------------------------------------------------------- #
# These are the defaults `transformers.SynthIDTextWatermarkingConfig()` applies.
# The ACTUAL values in force come from synthid-1.config.json, which the generator
# writes and the verifier reads -- both sides MUST agree or detection silently
# fails (same failure mode as fairoze-1's B1). Do not hard-code these into the
# verifier; read the config.

NGRAM_LEN = 5                 # n-gram context length; larger = more detectable,
                             # more brittle. HF-recommended default. Must be >= 2.
CONTEXT_HISTORY_SIZE = 1024  # ring buffer of recent contexts (repetition mask)
SAMPLING_TABLE_SEED = 0
SAMPLING_TABLE_SIZE = 2 ** 16   # transformers dataclass default (NOTE: the
                                # DeepMind reference uses 2**24 -- whichever the
                                # generator used MUST be recorded in the config)
SKIP_FIRST_NGRAM_CALLS = False

N_KEYS_RECOMMENDED = (20, 30)   # HF guidance: 20-30 unique random ints.
                                # len(keys) == watermarking depth == tournament layers.

# --------------------------------------------------------------------------- #
# detector                                                                     #
# --------------------------------------------------------------------------- #
# tools/synthid.py uses the training-free "masked mean" detector: mean of the
# per-(position, layer) g-values over unmasked positions. For unwatermarked text
# the g-values are ~Bernoulli(0.5), so the null score is ~0.5; watermarked text
# scores higher. There is no universal threshold -- it MUST be calibrated against
# a non-watermarked corpus for the target false-positive rate.

DETECTOR = "masked-mean"
NULL_SCORE = 0.5
DEFAULT_FPR = 1e-2

# --------------------------------------------------------------------------- #
# canonicalization                                            (FIRM)           #
# --------------------------------------------------------------------------- #
# SynthID works on TOKENS, so the verifier detokenize/retokenize path already
# absorbs most character-level noise, and the scheme tolerates light edits far
# better than fairoze-1. canonicalize() here does the same minimal copy/paste
# repair as fairoze_profile.canonicalize() and nothing more -- no NFC, no
# whitespace collapsing (those would re-tokenize differently).

_BOM = "﻿"


def canonicalize(text: str) -> str:
    """Undo copy/paste damage to the character sequence -- nothing more."""
    text = text.replace(_BOM, "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.rstrip("\n")


# --------------------------------------------------------------------------- #
# example config + DNS record                                                  #
# --------------------------------------------------------------------------- #

CONFIG_EXAMPLE = {
    "algorithm": ALGORITHM_ID,
    "tokenizer": "Qwen/Qwen2.5-3B",
    "vocab_size": 151936,
    "ngram_len": NGRAM_LEN,
    "context_history_size": CONTEXT_HISTORY_SIZE,
    "sampling_table_seed": SAMPLING_TABLE_SEED,
    "sampling_table_size": SAMPLING_TABLE_SIZE,
    "detector": DETECTOR,
    "threshold": None,          # set by `synthid.py --calibrate`
    "fpr_target": DEFAULT_FPR,
    # "keys": [ ... ]           # SECRET -- keep out of the committed config;
    #                           # pass --keys FILE or set SYNTHID_KEYS_JSON
}

# No p= -- symmetric. A verifier is pointed at the provider's own check.
DNS_RECORD_EXAMPLE = (
    "4._watermark-text.demo.terryzink.com  IN TXT  "
    '"v=1; a=synthid-1; c=sign; d=https://demo.terryzink.com/verify; '
    'nb=<unix>; na=ongoing"'
)


def summary() -> str:
    return (
        f"{ALGORITHM_ID}: {CONSTRUCTION} | {KEY_MODEL} key, {DETECTION} detection | "
        f"ngram={NGRAM_LEN} | detector={DETECTOR}, null~{NULL_SCORE}, "
        f"threshold calibrated per-deployment"
    )


if __name__ == "__main__":
    print(summary())
    print()
    for name, val in sorted(globals().items()):
        if name.isupper() and not name.startswith("_"):
            print(f"  {name:24} {val!r}")
    print()
    probe = "﻿  keep leading spaces\r\nsecond line\n\n"
    print("canonicalize() self-check (BOM + CRLF + trailing newlines):")
    print(f"  in : {probe!r}")
    print(f"  out: {canonicalize(probe)!r}")
