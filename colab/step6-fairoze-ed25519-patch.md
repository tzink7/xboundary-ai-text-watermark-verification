# Step 6 — patch the Fairoze reference for `fairoze-1` (Ed25519)

**This directory's own content is original to this repo. The files it tells you
to patch belong to `github.com/jfairoze/publicly-detectable-watermark`, which is
GPL-3.0 — a modified copy of that code is a GPL-3.0 derivative. Keep the patched
clone in Colab / a scratch checkout; do not vendor it into this repo without
deciding the repo's license first.**

Goal: swap the reference implementation's BLS signature primitive for Ed25519 so
`p=` stays a stock SPKI, matching `tools/fairoze_profile.py`. CPU only — no model.

Done and verified on 2026-09-03 (see "Verification" below). Step 7 (Colab, GPU)
then just checks that `generate.py` on a real model produces text this
already-proven detection stack finds.

## Setup (Colab or a local checkout)

```bash
git clone --depth 1 https://github.com/jfairoze/publicly-detectable-watermark.git
cd publicly-detectable-watermark
pip install bitstring reedsolo numpy scipy         # the only crypto/detect deps after the patch
```

You do NOT need `bplib`, `bls-lib`, `petlib`, or `msgpack` any more — those were
the pairing-curve stack. (`generate.py` still needs `torch` + `transformers` for
Step 7.)

## Patch 1 — `crypto.py` (replace the whole file)

Take `crypto.py` from the scratch checkout produced in this session, or reproduce
these changes against upstream:

- imports: drop `bls.scheme`, `bplib.bp`, `petlib.pack`; add `os`, `subprocess`,
  `tempfile`
- `SIGNATURE_LENGTH: 328 -> 512`  (bits; Ed25519 signature is 64 bytes)
- `bls_generate_openssl()` -> Ed25519 keypair, returns
  `(sk_pem_bytes, pk_spki_der_bytes, None)`
- `bls_sign_openssl(message, sk, params=None)` -> raw 64-byte Ed25519 sig via
  `openssl pkeyutl -sign -rawin`
- `bls_verify_openssl(message, signature, pk, params=None)` -> bool via
  `openssl pkeyutl -verify -pubin -keyform DER -rawin`
- `sign_and_encode_openssl` / `decode_and_verify_openssl`: the one-time-pad mask
  changes from `hashlib.sha512(message)` (64 bytes — silently truncates a
  >64-byte codeword via `zip(strict=False)`) to
  `hashlib.shake_256(message).digest(len(codeword_bytes))` — extended to exactly
  the codeword length. (open-questions D3)
- function **names are unchanged**, so `generate.py` / `detect.py` need no edits
  to their `crypto.*` calls. The `params` argument is vestigial (Ed25519 needs no
  group params); pass `None`.

Everything else (Reed-Solomon layer, `unkeyed_hash_*`, the symmetric path) is
upstream, untouched.

## Patch 2 — `detect.py` (key loading only)

- imports: drop `bls.utils`, `bplib.bp`, `petlib.pack`; add `base64`
- new `_load_pk(path)` — accepts a PEM `PUBLIC KEY`, a raw DER file, or a base64
  SPKI string; returns SPKI DER bytes
- `main()`: `pk = _load_pk(args.pk)`, `params = None` (no more pickle loads)
- `--params` becomes optional / ignored; `validate_args` and the `parser.error`
  now require only `--pk`
- `G2Elem` type hints on `search_for_asymmetric_watermark` /
  `detect_asymmetric_watermark` -> `bytes`
- upstream bug fixed in passing: `choices=("asymmetric")` (a string!) ->
  `choices=("asymmetric", "symmetric")`

## Patch 3 — `generate.py`

- key handling: writes the Ed25519 private PEM to `--sk` and the SPKI DER to
  `--pk` instead of BLS pickles; `--params` ignored
- imports: drop `bplib.bp`, `petlib.pack`; the `tuple[BpGroup, ...]` return hint
  -> `tuple`
- **modern-transformers fixes** (the reference targets `transformers==4.38.1`,
  which won't install on Colab's Python 3.13):
  - `from_pretrained(..., load_in_4bit=...)` — kwarg removed — now builds a
    `BitsAndBytesConfig` only when `--load-in-4bit` is passed
  - `torch_dtype` -> `dtype` rename — detected via `inspect.signature`
  - the manual sampling loop rewinds the KV cache to checkpoints
    (`past = past_before_signature_sampling`), which only worked with the
    pre-4.36 **legacy tuple** cache. Modern `DynamicCache` mutates in place, so a
    bare `= past` is not a snapshot. Fix: keep the cache **on** (for speed) but
    `copy.deepcopy(past)` at each checkpoint and each restore, and use
    `if past is not None:` for the presence check. Verified on CPU with
    transformers 5.16 + a tiny model: deepcopy checkpoint/restore of a
    `DynamicCache` reproduces logits bit-exactly and matches an uncheckpointed
    run.
  - needs `accelerate` (for `device_map="auto"`).

`generate.py` can only be run in Colab (needs a model), but it parses and the
non-model parts (key handling) are exercised by the wire-compat checks below.

## Verification (all CPU, no model)

1. **Reference's own `test_crypto.py`** — patched `from bls.scheme import *` out;
   6/6 relevant tests pass (`test_bls_openssl`, `test_bls_rsc_combination`,
   `test_bls_rsc_combination_with_hashing_openssl`, `test_reedsolo_error_correction`,
   both `unkeyed_hash_to_float` shape/determinism tests). The 1M-iteration
   `test_unkeyed_hash_to_float_is_uniform` is unchanged upstream code — skipped
   for time.

2. **Wire-compat with `tools/fairoze.py`:**
   - reference `sign_and_encode_openssl` output -> our `decode_payload` +
     `fz_verify` -> **True**
   - our `encode_payload` output -> reference `decode_and_verify_openssl` -> **True**
   - byte-identical 544-bit codewords for the same (signature, digest)

3. **Patched `detect.py` vs our verifier:** a `fairoze-1` watermark built with
   our `_debug_embed()` (no model) is detected by patched `detect.py` (`True`
   with the right key, `False` with a wrong key) and by
   `tools/fairoze.py verify_text` (`True`).

So the crypto + detection stack is proven end to end before any GPU is involved.
