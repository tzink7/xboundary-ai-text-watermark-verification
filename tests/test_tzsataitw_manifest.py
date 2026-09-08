#!/usr/bin/env python3
"""
tzsataitw double-signature manifest: pack/unpack, frame round-trip, sign/verify,
tamper detection.

Run directly (`python3 tests/test_tzsataitw_manifest.py`) or under pytest.
Needs `openssl` on PATH (Ed25519). No network, no DNS.
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import tzsataitw as tz                          # noqa: E402

MARKS = [("synthid-1", "4._watermark-text.demo.terryzink.com")]
SIG_LOC = "1._watermark-text.demo.terryzink.com"
TEXT = ("The two-bounce rule is the first thing that separates pickleball from "
        "tennis. " * 25)


def _keypair(tmp):
    priv = os.path.join(tmp, "k.priv.pem")
    pub = os.path.join(tmp, "k.pub.pem")
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", priv],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", priv, "-pubout", "-out", pub],
                   check=True, capture_output=True)
    return priv, pub


def test_prefix_roundtrip():
    prefix = tz.pack_manifest_prefix(MARKS, SIG_LOC)
    payload = prefix + b"\x00" * 64
    marks, sl, sig, pfx = tz.unpack_manifest(payload)
    assert marks == MARKS
    assert sl == SIG_LOC
    assert sig == b"\x00" * 64
    assert pfx == prefix


def test_multiple_marks():
    marks = [("synthid-1", "4._watermark-text.a.example"),
             ("fairoze-1", "3._watermark-text.b.example")]
    payload = tz.pack_manifest(marks, SIG_LOC, b"\x11" * 64)
    got, sl, _, _ = tz.unpack_manifest(payload)
    assert got == marks and sl == SIG_LOC


def test_truncated_payload_raises():
    payload = tz.pack_manifest_prefix(MARKS, SIG_LOC) + b"\x00" * 10   # short sig
    try:
        tz.unpack_manifest(payload)
    except ValueError:
        return
    raise AssertionError("expected ValueError on a truncated manifest")


def test_bad_version_raises():
    payload = bytes([2, 1]) + b"\x00" * 200
    try:
        tz.unpack_manifest(payload)
    except ValueError:
        return
    raise AssertionError("expected ValueError on an unknown manifest version")


def test_frame_extract_identifies_manifest():
    payload = tz.pack_manifest(MARKS, SIG_LOC, b"\x22" * 64)
    bits = tz._bytes_to_bits(tz.build_frame(tz.ZWM_MAGIC, payload))
    wm = tz.ZeroWidthChannel().embed(tz.strip_marks(TEXT), bits)
    frames = tz.extract_frames(wm)
    assert len(frames) == 1
    assert frames[0]["kind"] == "manifest"
    assert frames[0]["payload"] == payload


def test_plain_frame_still_signature_kind():
    payload = tz.pack_payload(SIG_LOC, b"\x33" * 64)
    bits = tz._bytes_to_bits(tz.build_frame(tz.ZeroWidthChannel().magic, payload))
    wm = tz.ZeroWidthChannel().embed(tz.strip_marks(TEXT), bits)
    frames = tz.extract_frames(wm)
    assert frames and all(f["kind"] == "signature" for f in frames)


def test_sign_verify_roundtrip():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        priv, pub = _keypair(tmp)
        canon = tz.canonical_text(TEXT)
        prefix = tz.pack_manifest_prefix(MARKS, SIG_LOC)
        sig = tz.ed25519_sign(priv, tz.manifest_signing_bytes(prefix, canon))
        assert tz.ed25519_verify(pub, tz.manifest_signing_bytes(prefix, canon), sig)


def test_tampered_text_breaks_signature():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        priv, pub = _keypair(tmp)
        prefix = tz.pack_manifest_prefix(MARKS, SIG_LOC)
        sig = tz.ed25519_sign(priv, tz.manifest_signing_bytes(prefix, tz.canonical_text(TEXT)))
        bad = tz.manifest_signing_bytes(prefix, tz.canonical_text(TEXT + " extra"))
        assert tz.ed25519_verify(pub, bad, sig) is False


def test_tampered_marks_break_signature():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        priv, pub = _keypair(tmp)
        canon = tz.canonical_text(TEXT)
        sig = tz.ed25519_sign(priv, tz.manifest_signing_bytes(
            tz.pack_manifest_prefix(MARKS, SIG_LOC), canon))
        forged = tz.pack_manifest_prefix(
            [("synthid-1", "9._watermark-text.attacker.example")], SIG_LOC)
        assert tz.ed25519_verify(pub, tz.manifest_signing_bytes(forged, canon), sig) is False


def test_co_sign_output_verifies_offline():
    """End-to-end: --co-sign a file, then verify it with --pubkey."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        priv, pub = _keypair(tmp)
        src = os.path.join(tmp, "in.txt")
        out = os.path.join(tmp, "double.txt")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(TEXT)
        cli = [sys.executable, os.path.join(os.path.dirname(__file__), "..", "tools", "tzsataitw.py")]
        r = subprocess.run(cli + ["--co-sign", "--input", src, "--privkey", priv,
                                  "--domain", "demo.terryzink.com", "--selector", "1",
                                  "--over", "synthid-1@4._watermark-text.demo.terryzink.com",
                                  "--out", out], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        v = subprocess.run(cli + ["--verify", "--input", out, "--pubkey", pub,
                                  "--inner-verify", "off", "--json"],
                           capture_output=True, text=True)
        assert v.returncode == 0, v.stdout + v.stderr
        import json
        d = json.loads(v.stdout)
        assert d["kind"] == "manifest"
        assert d["outer"]["verified"] is True
        assert d["marks"][0]["locator"] == "4._watermark-text.demo.terryzink.com"

        # tamper the visible text -> exit 2
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(" tampered.")
        t = subprocess.run(cli + ["--verify", "--input", out, "--pubkey", pub,
                                  "--inner-verify", "off"], capture_output=True, text=True)
        assert t.returncode == 2, f"expected exit 2, got {t.returncode}"


# --------------------------------------------------------------------------- #

def _main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except Exception as exc:                        # noqa: BLE001
            failed += 1
            print(f"  FAIL  {t.__name__}: {exc!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
