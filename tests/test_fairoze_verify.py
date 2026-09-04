#!/usr/bin/env python3
"""
Step 4 gate: the end-to-end verifier (verify_text + the --verify CLI).

Builds a real signed fairoze-1 watermark with the throwaway _debug_embed(), then
checks every verdict. Needs `reedsolo` -- skips cleanly without it.

    .venv/bin/python tests/test_fairoze_verify.py
"""

import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(__file__)
TOOLS = os.path.join(HERE, "..", "tools")
sys.path.insert(0, TOOLS)

try:
    import reedsolo  # noqa: F401
except ImportError:
    print("SKIP  test_fairoze_verify -- 'reedsolo' not installed")
    sys.exit(0)

import fairoze as fz                                          # noqa: E402
from fairoze_profile import MIN_WATERMARK_CHARS               # noqa: E402


def _make_watermark(message="verify01", before="", after=""):
    priv, pub = fz.fz_keygen()
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    sig = fz.fz_sign(digest, priv)
    text = fz._debug_embed(message, fz.encode_payload(sig, digest))
    return before + text + after, pub, priv, message


def _flip(s, i):
    return s[:i] + ("0" if s[i] != "0" else "1") + s[i + 1:]


# ---- verdicts ------------------------------------------------------------- #

def test_clean_watermark_verifies():
    text, pub, _, msg = _make_watermark()
    r = fz.verify_text(text, pub)
    assert r["verified"] and r["message"] == msg and r["offset"] == 0
    assert bytes.fromhex(r["signature_hex"])  # well-formed


def test_wrong_key_fails():
    text, _, _, _ = _make_watermark()
    _, other = fz.fz_keygen()
    assert fz.verify_text(text, other)["verified"] is False


def test_too_short_fails_with_reason():
    text, pub, _, _ = _make_watermark()
    r = fz.verify_text(text[:MIN_WATERMARK_CHARS - 100], pub)
    assert r["verified"] is False and "at least" in r["reason"]


def test_many_edits_fail():
    text, pub, _, _ = _make_watermark()
    b = list(text)
    for j in range(100, 4000, 111):
        b[j] = "0" if b[j] != "0" else "1"
    assert fz.verify_text("".join(b), pub)["verified"] is False


# ---- canonicalization --------------------------------------------------- #

def test_trailing_newlines_ok():
    text, pub, _, _ = _make_watermark(after="\n\n\n")
    assert fz.verify_text(text, pub)["verified"] is True


def test_bom_and_crlf_ok():
    text, pub, _, _ = _make_watermark()
    assert fz.verify_text("﻿" + text + "\r\n", pub)["verified"] is True


# ---- offset search ---------------------------------------------------------- #

def test_leading_junk_found_by_offset_scan():
    text, pub, _, _ = _make_watermark(before="X" * 20)
    r = fz.verify_text(text, pub)
    assert r["verified"] is True and r["offset"] == 20


def test_max_offsets_cap():
    text, pub, _, _ = _make_watermark(before="Z" * 30)
    assert fz.verify_text(text, pub, max_offsets=5)["verified"] is False
    assert fz.verify_text(text, pub, max_offsets=60)["verified"] is True


# ---- edit tolerance (documents the chained-hash behaviour) --------------- #

def test_edit_in_final_segment_is_recovered():
    # only the last segment: no chain cascade, <=1 symbol error -> RS fixes it
    text, pub, _, _ = _make_watermark()
    assert fz.verify_text(_flip(text, len(text) - 8), pub)["verified"] is True


def test_edit_near_start_cascades_and_fails():
    # editing an early segment corrupts every later segment via the chained hash.
    # find one early single-char edit that pushes past the RS budget, then assert
    # it fails (deterministic -- doesn't depend on which bits happen to flip).
    text, pub, _, _ = _make_watermark()
    _, clean = fz.windows_to_bits(fz.canonicalize(text))
    for i in range(8, 8 + 96):
        _, edited_bits = fz.windows_to_bits(fz.canonicalize(_flip(text, i)))
        sym_errors = sum(clean[k:k + 8] != edited_bits[k:k + 8]
                         for k in range(0, len(clean), 8))
        if sym_errors > 2:
            assert fz.verify_text(_flip(text, i), pub)["verified"] is False
            return
    raise AssertionError("expected an early char edit to cascade past the RS budget")


# ---- CLI ------------------------------------------------------------------- #

def test_cli_verify_exit_codes():
    text, pub, _, _ = _make_watermark()
    _, wrong = fz.fz_keygen()
    with tempfile.TemporaryDirectory() as d:
        tf = os.path.join(d, "wm.txt"); open(tf, "w").write(text)
        kf = os.path.join(d, "pk.b64"); open(kf, "w").write(pub)
        wf = os.path.join(d, "wrong.b64"); open(wf, "w").write(wrong)
        env = {**os.environ, "PYTHONPATH": TOOLS}
        ok = subprocess.run([sys.executable, os.path.join(TOOLS, "fairoze.py"),
                             "--verify", "--input", tf, "--pubkey", kf],
                            capture_output=True, text=True, env=env)
        assert ok.returncode == 0 and "VALID" in ok.stdout
        bad = subprocess.run([sys.executable, os.path.join(TOOLS, "fairoze.py"),
                              "--verify", "--input", tf, "--pubkey", wf],
                             capture_output=True, text=True, env=env)
        assert bad.returncode == 2 and "NOT VERIFIED" in bad.stdout


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
