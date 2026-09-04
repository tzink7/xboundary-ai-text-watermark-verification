#!/usr/bin/env python3
"""
Step 5 gate: `fairoze-1` in the DNS toolchain.

A `fairoze-1` record with an Ed25519 `p=` must lint clean -- `A-REGISTRY` as
INFO (recognized), `P-KEYINFO` as Ed25519 -- and `tools/fairoze.py` and
`tools/watermark_dns_tool.py` must agree on the `p=` wire format (both = base64
SPKI). No reedsolo needed; needs `openssl`.

    python3 tests/test_fairoze_dns.py
"""

import base64
import os
import subprocess
import sys
import tempfile
import time

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)

import fairoze as fz                        # noqa: E402
import watermark_dns_tool as wdt            # noqa: E402

PAST = int(time.time()) - 60 * 60 * 24 * 30   # 30 days ago


def _codes(f):
    return {code: (lvl, msg) for lvl, code, msg in f.items}


def test_fairoze1_is_registered():
    assert "fairoze-1" in wdt.KNOWN_ALGORITHMS
    assert "fairoze.py" in wdt.KNOWN_ALGORITHMS["fairoze-1"]


def test_fairoze1_ed25519_record_lints_clean():
    _priv, pub = fz.fz_keygen()
    record = f"v=1; a=fairoze-1; p={pub}; c=sign; nb={PAST}; na=ongoing"
    f = wdt.lint_record(record, selector=1, domain="demo.terryzink.com")
    codes = _codes(f)

    assert f.n_errors == 0, [i for i in f.items if i[0] == "ERROR"]
    assert codes["A-REGISTRY"][0] == "INFO"
    assert "fairoze" in codes["A-REGISTRY"][1].lower()
    assert codes["P-KEYINFO"][0] == "INFO"
    assert "Ed25519" in codes["P-KEYINFO"][1]
    assert codes["KEY-VALIDITY"][0] == "INFO"
    assert "VALID" in codes["KEY-VALIDITY"][1]


def test_unknown_algorithm_still_warns():
    _priv, pub = fz.fz_keygen()
    record = f"v=1; a=notreal-9; p={pub}; c=sign; nb={PAST}; na=ongoing"
    codes = _codes(wdt.lint_record(record, selector=1, domain="x.example"))
    assert codes["A-REGISTRY"][0] == "WARN"
    assert "not a recognized algorithm" in codes["A-REGISTRY"][1]


def test_pubkey_wire_format_agrees_between_tools():
    # watermark_dns_tool's own keygen and fairoze.py must produce the same
    # kind of p= value (base64 SPKI that inspect_spki reads as Ed25519, 44 bytes)
    kp = wdt.generate_keypair("ed25519")
    _priv, fz_pub = fz.fz_keygen()
    for label, b64 in (("wdt", kp["p"]), ("fairoze", fz_pub)):
        raw = base64.b64decode(b64, validate=True)
        assert len(raw) == 44, (label, len(raw))
        info = wdt.inspect_spki(raw)
        assert info["label"] == "Ed25519", (label, info)

    # and fairoze.py can round-trip wdt's key through pubkey derivation
    assert fz.fz_pubkey_b64(kp["private_pem"]) == kp["p"]


def test_make_record_cli_with_fairoze1():
    _priv, pub = fz.fz_keygen()
    env = {**os.environ, "PYTHONPATH": TOOLS}
    r = subprocess.run(
        [sys.executable, os.path.join(TOOLS, "watermark_dns_tool.py"),
         "--make-record", "--domain", "demo.terryzink.com", "--selector", "3",
         "--algorithm", "fairoze-1", "--p", pub, "--c", "sign",
         "--nb", str(PAST), "--na", "ongoing"],
        capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    assert "a=fairoze-1" in r.stdout
    assert "not a recognized algorithm" not in r.stdout


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
