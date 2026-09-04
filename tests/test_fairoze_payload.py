#!/usr/bin/env python3
"""
Step 2 gate: the Reed-Solomon + SHAKE256-mask payload pipeline in tools/fairoze.py.

Needs `reedsolo` (see tools/requirements.txt). If it is missing this prints
setup instructions and skips -- run it inside the venv to actually gate.

    python3 -m venv .venv
    .venv/bin/pip install -r tools/requirements.txt
    .venv/bin/python tests/test_fairoze_payload.py
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

try:
    import reedsolo  # noqa: F401
except ImportError:
    print("SKIP  test_fairoze_payload -- 'reedsolo' not installed")
    print("      python3 -m venv .venv && .venv/bin/pip install -r tools/requirements.txt")
    sys.exit(0)

import fairoze as fz                                          # noqa: E402
from fairoze_profile import CODEWORD_BITS, MAX_PLANTED_ERRORS, SIGNATURE_LEN  # noqa: E402


def _sig_and_digest():
    priv, _pub = fz.fz_keygen()
    digest = hashlib.sha256(b"the leading message chars").digest()
    return fz.fz_sign(digest, priv), digest, priv


def _flip_bit_in_byte(bits: str, byte_index: int) -> str:
    i = byte_index * 8            # flip the MSB of that byte = one symbol error
    return bits[:i] + ("1" if bits[i] == "0" else "0") + bits[i + 1:]


def test_roundtrip():
    sig, digest, _ = _sig_and_digest()
    assert fz.decode_payload(fz.encode_payload(sig, digest), digest) == sig


def test_codeword_bit_length():
    sig, digest, _ = _sig_and_digest()
    assert len(fz.encode_payload(sig, digest)) == CODEWORD_BITS == 544


def test_mask_actually_changes_the_bits():
    sig, digest, _ = _sig_and_digest()
    masked = fz.encode_payload(sig, digest)
    rsc = reedsolo.RSCodec(MAX_PLANTED_ERRORS * 2)
    raw = fz._bytes_to_bits(bytes(rsc.encode(sig)))
    assert masked != raw
    assert sum(a != b for a, b in zip(masked, raw)) > 100   # ~half the bits differ


def test_wrong_digest_fails():
    sig, digest, _ = _sig_and_digest()
    cw = fz.encode_payload(sig, digest)
    other = hashlib.sha256(b"different").digest()
    try:
        fz.decode_payload(cw, other)
    except fz.PayloadError:
        return
    raise AssertionError("decode with the wrong digest should raise PayloadError")


def test_recovers_two_symbol_errors():
    sig, digest, _ = _sig_and_digest()
    cw = fz.encode_payload(sig, digest)
    cw = _flip_bit_in_byte(cw, 2)
    cw = _flip_bit_in_byte(cw, 55)
    assert fz.decode_payload(cw, digest) == sig


def test_three_symbol_errors_fail_cleanly():
    sig, digest, _ = _sig_and_digest()
    cw = fz.encode_payload(sig, digest)
    for b in (2, 30, 60):
        cw = _flip_bit_in_byte(cw, b)
    try:
        fz.decode_payload(cw, digest)
    except fz.PayloadError:
        return
    raise AssertionError("3 symbol errors exceed the budget and should raise")


def test_random_bits_fail_cleanly():
    _, digest, _ = _sig_and_digest()
    rand = "".join("01"[b & 1] for b in os.urandom(CODEWORD_BITS))
    try:
        fz.decode_payload(rand, digest)
    except fz.PayloadError:
        return
    raise AssertionError("random bits should raise PayloadError, not crash")


def test_malformed_bitstring():
    _, digest, _ = _sig_and_digest()
    for bad in ("0" * 100, "01201" * 20):   # not a byte multiple / non-binary
        try:
            fz.decode_payload(bad, digest)
        except fz.PayloadError:
            continue
        raise AssertionError(f"expected PayloadError for {bad[:10]!r}...")


def test_wrong_signature_length_rejected():
    _, digest, _ = _sig_and_digest()
    try:
        fz.encode_payload(b"\x00" * (SIGNATURE_LEN - 1), digest)
    except fz.PayloadError:
        return
    raise AssertionError("encode_payload should reject a short signature")


def test_real_ed25519_signature_still_verifies_after_roundtrip():
    priv, pub = fz.fz_keygen()
    digest = hashlib.sha256(b"end to end").digest()
    sig = fz.fz_sign(digest, priv)
    recovered = fz.decode_payload(fz.encode_payload(sig, digest), digest)
    assert fz.fz_verify(digest, recovered, pub) is True


# --------------------------------------------------------------------------- #

def _main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except Exception as exc:                       # noqa: BLE001
            failed += 1
            print(f"  FAIL  {t.__name__}: {exc!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
