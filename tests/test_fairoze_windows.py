#!/usr/bin/env python3
"""
Step 3 gate: the character-window codec in tools/fairoze.py.

`windows_to_bits()` must replicate the reference detect.py extraction, and the
throwaway `_debug_embed()` must be its exact inverse -- that pairing is what lets
the Step 4 verifier be tested with no model.

Run directly (`python3 tests/test_fairoze_windows.py`) or under pytest.
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import fairoze as fz                                          # noqa: E402
from fairoze_profile import (                                 # noqa: E402
    BITS_PER_SEGMENT, CODEWORD_BITS, MESSAGE_LEN, SEGMENT_LEN, SEGMENTS_NEEDED,
)

MSG = "msg:8chr"[:MESSAGE_LEN]


def _rand_bits(n=CODEWORD_BITS):
    return "".join("01"[b & 1] for b in os.urandom(n))


def test_hash_to_bits_matches_reference_formula():
    # reference: BitArray(bytes=sha256(data).digest()).bin[0:bit_size]
    # sha256(b"") starts 0xe3 = 0b11100011
    assert fz._hash_to_bits(b"", 1) == "1"
    assert fz._hash_to_bits(b"", 2) == "11"
    assert fz._hash_to_bits(b"", 3) == "111"
    assert fz._hash_to_bits(b"", 8) == "11100011"
    # cross-check against an independent MSB-first expansion
    for probe in (b"", b"abc", b"\x00\xff", bytes(range(20))):
        digest = hashlib.sha256(probe).digest()
        want = "".join(format(byte, "08b") for byte in digest)[:5]
        assert fz._hash_to_bits(probe, 5) == want


def test_debug_embed_then_extract_roundtrips():
    for _ in range(5):
        bits = _rand_bits()
        text = fz._debug_embed(MSG, bits)
        got_msg, got_bits = fz.windows_to_bits(text)
        assert got_msg == MSG
        assert got_bits == bits


def test_embedded_text_length():
    text = fz._debug_embed(MSG, _rand_bits())
    assert len(text) == MESSAGE_LEN + SEGMENTS_NEEDED * SEGMENT_LEN


def test_message_is_leading_chars_verbatim():
    for m in ("        ", "12345678", "a b c d "):
        text = fz._debug_embed(m[:MESSAGE_LEN], _rand_bits())
        assert fz.windows_to_bits(text)[0] == m[:MESSAGE_LEN]


def test_extraction_stops_at_segments_needed():
    bits = _rand_bits()
    text = fz._debug_embed(MSG, bits) + "9" * (SEGMENT_LEN * 5)   # trailing junk
    got_msg, got_bits = fz.windows_to_bits(text)
    assert got_msg == MSG
    assert got_bits == bits
    assert len(got_bits) == CODEWORD_BITS


def test_debug_embed_is_deterministic():
    bits = _rand_bits()
    assert fz._debug_embed(MSG, bits) == fz._debug_embed(MSG, bits)


def test_early_bit_change_diverges_from_that_segment_on():
    bits = list(_rand_bits())
    a = fz._debug_embed(MSG, "".join(bits))
    bits[4] = "1" if bits[4] == "0" else "0"       # flip a bit in segment 2
    b = fz._debug_embed(MSG, "".join(bits))
    # message + segments 0,1 unchanged; segment 2 (chars 8+32 .. 8+48) onward differs
    boundary = MESSAGE_LEN + 2 * SEGMENT_LEN
    assert a[:boundary] == b[:boundary]
    assert a[boundary:] != b[boundary:]


def test_short_text_returns_partial_not_crash():
    text = fz._debug_embed(MSG, _rand_bits())[: MESSAGE_LEN + 10 * SEGMENT_LEN]
    _, got_bits = fz.windows_to_bits(text)
    assert len(got_bits) == 10 * BITS_PER_SEGMENT < CODEWORD_BITS


def test_debug_embed_rejects_bad_input():
    for bad in [("toolong!!", _rand_bits()), (MSG, "0" * (CODEWORD_BITS - 1)),
                (MSG, "2" * CODEWORD_BITS)]:
        try:
            fz._debug_embed(*bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad[0]!r}, {len(bad[1])} bits")


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
