#!/usr/bin/env python3
"""
Step 1 gate: Ed25519 signature primitives in tools/fairoze.py.

Run directly (`python3 tests/test_fairoze_crypto.py`) or under pytest.
No third-party dependencies; needs `openssl` on PATH.
"""

import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import fairoze as fz                          # noqa: E402
from fairoze_profile import SIGNATURE_LEN     # noqa: E402

MSG = bytes(range(32))          # stand-in for a 32-byte message digest
OTHER = b"\xaa" * 32


def test_keygen_shape():
    priv, pub = fz.fz_keygen()
    assert isinstance(priv, bytes) and priv.startswith(b"-----BEGIN PRIVATE KEY-----")
    der = base64.b64decode(pub, validate=True)
    assert len(der) == 44, f"Ed25519 SPKI should be 44 bytes, got {len(der)}"


def test_signature_is_64_bytes():
    priv, _ = fz.fz_keygen()
    assert len(fz.fz_sign(MSG, priv)) == SIGNATURE_LEN == 64


def test_sign_verify_roundtrip():
    priv, pub = fz.fz_keygen()
    sig = fz.fz_sign(MSG, priv)
    assert fz.fz_verify(MSG, sig, pub) is True


def test_tampered_message_fails():
    priv, pub = fz.fz_keygen()
    sig = fz.fz_sign(MSG, priv)
    assert fz.fz_verify(b"\x01" + MSG[1:], sig, pub) is False


def test_tampered_signature_fails():
    priv, pub = fz.fz_keygen()
    sig = bytearray(fz.fz_sign(MSG, priv))
    sig[0] ^= 0x01
    assert fz.fz_verify(MSG, bytes(sig), pub) is False


def test_wrong_key_fails():
    priv_a, _ = fz.fz_keygen()
    _, pub_b = fz.fz_keygen()
    sig = fz.fz_sign(MSG, priv_a)
    assert fz.fz_verify(MSG, sig, pub_b) is False


def test_ed25519_is_deterministic():
    priv, _ = fz.fz_keygen()
    assert fz.fz_sign(MSG, priv) == fz.fz_sign(MSG, priv)


def test_pubkey_derivation_matches_keygen():
    priv, pub = fz.fz_keygen()
    assert fz.fz_pubkey_b64(priv) == pub


def test_pubkey_serialization_is_stable():
    _, pub = fz.fz_keygen()
    assert base64.b64encode(base64.b64decode(pub)).decode("ascii") == pub


def test_short_signature_returns_false_not_raise():
    _, pub = fz.fz_keygen()
    assert fz.fz_verify(MSG, b"too short", pub) is False


def test_bad_pubkey_raises():
    priv, _ = fz.fz_keygen()
    sig = fz.fz_sign(MSG, priv)
    try:
        fz.fz_verify(MSG, sig, "not!base64!!")
    except RuntimeError:
        return
    raise AssertionError("expected RuntimeError for a malformed public key")


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
