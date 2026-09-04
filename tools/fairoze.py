#!/usr/bin/env python3
"""
fairoze.py -- `fairoze-1` watermark verifier (and helpers).

Built in steps (see the build plan). This file currently contains:

  * Step 1 -- Ed25519 signature primitives
  * Step 2 -- Reed-Solomon + mask payload pipeline
  * Step 3 -- character-window codec (bit extraction + a throwaway test embedder)

Later steps add: the `--verify` CLI (Step 4).

The signature primitives here are the drop-in replacement for the reference
implementation's BLS functions (github.com/jfairoze/publicly-detectable-watermark,
`crypto.py`). The wire contract, shared with the Colab generator:

  * signature   -- raw 64 bytes, Ed25519 (RFC 8032), over whatever bytes are passed
  * public key  -- base64(SubjectPublicKeyInfo DER), the value that goes in `p=`
  * private key -- PEM (only the generator ever holds it)

Shells out to `openssl` like the rest of tools/. Step 2 additionally needs the
`reedsolo` package (the same library the reference uses) -- see tools/requirements.txt.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile

from fairoze_profile import (
    ALGORITHM_ID,
    BITS_PER_SEGMENT,
    CODEWORD_BITS,
    MAX_PLANTED_ERRORS,
    MESSAGE_LEN,
    MIN_WATERMARK_CHARS,
    PUBKEY_RAW_LEN,
    SEGMENT_LEN,
    SEGMENTS_NEEDED,
    SIGNATURE_LEN,
    canonicalize,
)

# --------------------------------------------------------------------------- #
# subprocess helpers (self-contained -- no coupling to tzsataitw.py)           #
# --------------------------------------------------------------------------- #


def _require_openssl():
    if shutil.which("openssl") is None:
        sys.exit("error: 'openssl' not found on PATH (needed for Ed25519).")


def _run(cmd, input_bytes=None):
    p = subprocess.run(cmd, input=input_bytes,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout, p.stderr


def _tmp(data: bytes = b"") -> str:
    fd, path = tempfile.mkstemp(prefix="fairoze_")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def _unlink(*paths):
    for p in paths:
        try:
            os.unlink(p)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Step 1 -- Ed25519 primitives                                                 #
# --------------------------------------------------------------------------- #


def fz_keygen() -> tuple[bytes, str]:
    """A fresh Ed25519 keypair.

    Returns (private_key_pem, public_key_spki_b64). Only the generator needs the
    private PEM; the verifier and the `p=` tag use the base64 public key.
    """
    _require_openssl()
    rc, priv_pem, err = _run(["openssl", "genpkey", "-algorithm", "ed25519"])
    if rc != 0:
        raise RuntimeError(f"openssl genpkey failed:\n{err.decode('utf-8', 'replace')}")
    return priv_pem, fz_pubkey_b64(priv_pem)


def fz_pubkey_b64(private_key_pem: bytes) -> str:
    """The base64 SPKI public key (the `p=` value) for a given Ed25519 private PEM."""
    _require_openssl()
    rc, der, err = _run(["openssl", "pkey", "-pubout", "-outform", "DER"],
                        input_bytes=private_key_pem)
    if rc != 0:
        raise RuntimeError(f"openssl pkey -pubout failed:\n{err.decode('utf-8', 'replace')}")
    return base64.b64encode(der).decode("ascii")


def fz_sign(message: bytes, private_key_pem: bytes) -> bytes:
    """Raw 64-byte Ed25519 signature over `message` (already-hashed bytes, per the
    profile -- this function does no hashing of its own)."""
    _require_openssl()
    kpath, mpath, spath = _tmp(private_key_pem), _tmp(message), _tmp()
    try:
        rc, _, err = _run(["openssl", "pkeyutl", "-sign", "-inkey", kpath,
                           "-rawin", "-in", mpath, "-out", spath])
        if rc != 0:
            raise RuntimeError(f"openssl signing failed:\n{err.decode('utf-8', 'replace')}")
        with open(spath, "rb") as fh:
            sig = fh.read()
        if len(sig) != SIGNATURE_LEN:
            raise RuntimeError(f"expected a {SIGNATURE_LEN}-byte Ed25519 signature, "
                               f"got {len(sig)}")
        return sig
    finally:
        _unlink(kpath, mpath, spath)


def fz_verify(message: bytes, signature: bytes, public_key_spki_b64: str) -> bool:
    """Verify a raw 64-byte Ed25519 signature over `message` against a base64 SPKI
    public key (the `p=` value). Returns False on any failure -- never raises for a
    bad signature, only for a malformed key or a missing openssl."""
    _require_openssl()
    if len(signature) != SIGNATURE_LEN:
        return False
    try:
        der = base64.b64decode(public_key_spki_b64, validate=True)
    except ValueError:
        raise RuntimeError("public key is not valid base64")
    kpath, mpath, spath = _tmp(der), _tmp(message), _tmp(signature)
    try:
        rc, _, _ = _run(["openssl", "pkeyutl", "-verify", "-pubin",
                         "-inkey", kpath, "-keyform", "DER",
                         "-rawin", "-in", mpath, "-sigfile", spath])
        return rc == 0
    finally:
        _unlink(kpath, mpath, spath)


# --------------------------------------------------------------------------- #
# Step 2 -- Reed-Solomon + mask payload pipeline                               #
# --------------------------------------------------------------------------- #
# Mirrors crypto.sign_and_encode_openssl / decode_and_verify_openssl, with two
# changes for fairoze-1:
#   * signature is 64-byte Ed25519 (reference: ~41-byte BLS)
#   * mask is SHAKE256(message_digest, RS_N) -- the reference's SHA-512 mask is
#     only 64 bytes and would leave our 68-byte codeword's last 4 (parity) bytes
#     unmasked (its zip() silently truncates).
#
# These functions are pure payload manipulation: bytes and "01" strings, no
# text and no keys.


class PayloadError(Exception):
    """Raised when a codeword cannot be un-masked / error-corrected back to a
    64-byte signature (too much corruption, or malformed input)."""


def _reedsolo():
    try:
        import reedsolo
    except ImportError:
        raise RuntimeError(
            "fairoze-1 payload coding needs the 'reedsolo' package (the same "
            "library the reference implementation uses).\n"
            "  python3 -m venv .venv && .venv/bin/pip install reedsolo\n"
            "  # or: python3 -m pip install --user reedsolo"
        )
    return reedsolo


def _bytes_to_bits(b: bytes) -> str:
    return "".join(f"{x:08b}" for x in b)


def _bits_to_bytes(bits: str) -> bytes:
    if len(bits) % 8 or set(bits) - {"0", "1"}:
        raise PayloadError("bit string is not a whole number of 0/1 bytes")
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def _mask(message_digest: bytes, nbytes: int) -> bytes:
    """SHAKE256 XOF keyed by the 32-byte message digest, extended to `nbytes`."""
    return hashlib.shake_256(message_digest).digest(nbytes)


def encode_payload(signature: bytes, message_digest: bytes,
                   max_errors: int = MAX_PLANTED_ERRORS) -> str:
    """64-byte Ed25519 signature -> Reed-Solomon codeword -> XOR-masked -> bit
    string (CODEWORD_BITS long for the default max_errors)."""
    if len(signature) != SIGNATURE_LEN:
        raise PayloadError(f"signature must be {SIGNATURE_LEN} bytes, got {len(signature)}")
    rs = _reedsolo()
    codeword = bytes(rs.RSCodec(max_errors * 2).encode(signature))
    masked = bytes(a ^ b for a, b in zip(codeword, _mask(message_digest, len(codeword))))
    return _bytes_to_bits(masked)


def decode_payload(codeword_bits: str, message_digest: bytes,
                   max_errors: int = MAX_PLANTED_ERRORS) -> bytes:
    """Inverse of encode_payload. Returns the 64-byte signature, or raises
    PayloadError if the codeword is corrupted beyond RS's correction budget
    (2 * max_errors // 2 = max_errors symbol errors) or malformed."""
    rs = _reedsolo()
    masked = _bits_to_bytes(codeword_bits)
    codeword = bytes(a ^ b for a, b in zip(masked, _mask(message_digest, len(masked))))
    try:
        decoded, _full, _errata = rs.RSCodec(max_errors * 2).decode(codeword)
    except rs.ReedSolomonError as exc:
        raise PayloadError(f"unrecoverable codeword: {exc}") from exc
    sig = bytes(decoded)
    if len(sig) != SIGNATURE_LEN:
        raise PayloadError(f"decoded {len(sig)} bytes, expected a "
                           f"{SIGNATURE_LEN}-byte signature")
    return sig


# --------------------------------------------------------------------------- #
# Step 3 -- character-window codec                                             #
# --------------------------------------------------------------------------- #
# Replicates the reference detect.py extraction (crypto.unkeyed_hash_to_bits +
# the detect_asymmetric_watermark loop), producing the raw pre-RS-decode bit
# string. RS decode + mask + Ed25519 verify are Step 2 / Step 4.


def _hash_to_bits(data: bytes, bit_size: int = BITS_PER_SEGMENT) -> str:
    """The first `bit_size` bits of sha256(data), MSB-first, as a '01' string.
    Matches `BitArray(bytes=sha256(data).digest()).bin[0:bit_size]`."""
    digest = hashlib.sha256(data).digest()
    return "".join(f"{b:08b}" for b in digest)[:bit_size]


def windows_to_bits(text: str) -> tuple[str, str]:
    """Extract (message, codeword_bits) from ALREADY-ALIGNED text.

    `message` is text[:MESSAGE_LEN] verbatim. `codeword_bits` is the chained-hash
    bit string of length CODEWORD_BITS (or shorter, if the text ran out -- then
    it is not a valid mark and Step 4's decode will reject it). Alignment (which
    rotation of the text to feed here) is the caller's problem -- see Step 4.
    """
    message = text[:MESSAGE_LEN]
    sig_str = text[MESSAGE_LEN:]
    msg_b = message.encode("utf-8")
    bits = ""
    for i in range(0, len(sig_str), SEGMENT_LEN):
        if len(bits) // BITS_PER_SEGMENT >= SEGMENTS_NEEDED:
            break
        segment = sig_str[i:i + SEGMENT_LEN]
        bits += _hash_to_bits(msg_b + bits.encode("utf-8") + segment.encode("utf-8"))
    return message, bits


def _debug_embed(message: str, codeword_bits: str, _cap: int = 200_000) -> str:
    """THROWAWAY (tests only). Build all-digit gibberish text whose
    windows_to_bits() returns exactly (message, codeword_bits).

    For each segment, brute-forces a 16-digit block until its chained hash
    yields the target bits (~2**BITS_PER_SEGMENT tries each). Lets the Step 4
    verifier be tested end to end with no model and no GPU.
    """
    if len(message) != MESSAGE_LEN:
        raise ValueError(f"message must be {MESSAGE_LEN} chars")
    if len(codeword_bits) != CODEWORD_BITS or set(codeword_bits) - {"0", "1"}:
        raise ValueError(f"codeword_bits must be {CODEWORD_BITS} chars of 0/1")

    msg_b = message.encode("utf-8")
    bits = ""
    out = [message]
    for k in range(SEGMENTS_NEEDED):
        target = codeword_bits[k * BITS_PER_SEGMENT:(k + 1) * BITS_PER_SEGMENT]
        for n in itertools.count():
            if n >= _cap:
                raise RuntimeError(f"no filler found for segment {k} in {_cap} tries")
            seg = f"{n:0{SEGMENT_LEN}d}"[:SEGMENT_LEN]
            if _hash_to_bits(msg_b + bits.encode("utf-8") + seg.encode("utf-8")) == target:
                out.append(seg)
                bits += target
                break
    return "".join(out)


# --------------------------------------------------------------------------- #
# Step 4 -- the verifier                                                       #
# --------------------------------------------------------------------------- #
# canonicalize -> for each candidate offset: windows_to_bits -> decode_payload
# -> fz_verify. decode_payload gates the (slow, subprocess) fz_verify call, so
# only offsets that yield a well-formed codeword ever reach openssl.
#
# fairoze-1 treats the watermark as a CONTIGUOUS span (not cyclically wrapped),
# so the offset search is range(0, n - MIN_WATERMARK_CHARS + 1). For text that
# is exactly the watermarked passage that is a single iteration.


def verify_text(text: str, pubkey_spki_b64: str, max_offsets: int | None = None) -> dict:
    """Check `text` for a fairoze-1 watermark verifiable under `pubkey_spki_b64`
    (a base64 SPKI Ed25519 key -- the `p=` value).

    Returns a dict: verified (bool), reason (str), and when verified also
    message, offset, signature_hex, message_digest_hex. `canonical_chars` and
    `offsets_scanned` are always present.
    """
    canon = canonicalize(text)
    n = len(canon)
    base = {"algorithm": ALGORITHM_ID, "canonical_chars": n}

    if n < MIN_WATERMARK_CHARS:
        return {**base, "verified": False, "offsets_scanned": 0,
                "reason": f"text is {n} chars; fairoze-1 needs at least "
                          f"{MIN_WATERMARK_CHARS}"}

    last_offset = n - MIN_WATERMARK_CHARS
    limit = last_offset if max_offsets is None else min(last_offset, max_offsets - 1)

    for offset in range(limit + 1):
        window = canon[offset:]
        message, bits = windows_to_bits(window)
        if len(bits) < CODEWORD_BITS:
            break                                   # not enough text left
        digest = hashlib.sha256(message.encode("utf-8")).digest()
        try:
            sig = decode_payload(bits, digest)
        except PayloadError:
            continue
        if fz_verify(digest, sig, pubkey_spki_b64):
            return {**base, "verified": True, "offset": offset, "message": message,
                    "signature_hex": sig.hex(), "message_digest_hex": digest.hex(),
                    "offsets_scanned": offset + 1,
                    "reason": "signature verifies under the given key"}

    return {**base, "verified": False, "offsets_scanned": limit + 1,
            "reason": f"no fairoze-1 watermark verifiable under this key "
                      f"(scanned {limit + 1} offset(s))"}


def load_pubkey_b64(path: str) -> str:
    """Read a public key file in any of the forms this toolchain emits:
    a PEM `PUBLIC KEY`, a raw DER blob (`openssl ... -outform DER`), or a bare
    base64 SPKI string (the `p=` value). Returns the base64 SPKI."""
    raw = open(path, "rb").read().strip()
    if raw.startswith(b"-----BEGIN"):
        body = raw.split(b"-----", 2)[2].rsplit(b"-----END", 1)[0]
        return "".join(body.decode("ascii").split())
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return base64.b64encode(raw).decode("ascii")     # raw DER bytes
    try:
        base64.b64decode("".join(text.split()), validate=True)
        return "".join(text.split())                      # already base64 SPKI
    except ValueError:
        return base64.b64encode(raw).decode("ascii")      # non-b64 bytes -> DER


def pubkey_from_dns(selector: int, domain: str) -> tuple[str, dict]:
    """Fetch the `p=` value published at <selector>._watermark-text.<domain>.
    Returns (pubkey_spki_b64, all_tags)."""
    import tzsataitw as tz
    name = f"{selector}.{tz.WELL_KNOWN_LABEL}.{domain.strip('.')}"
    records = tz.dig_txt(name)
    if not records:
        raise RuntimeError(f"no TXT record at {name}")
    for rec in records:
        tags = tz.parse_record_tags(rec)
        if tags.get("p"):
            return tags["p"], tags
    raise RuntimeError(f"no p= tag in the record at {name}")


def _read_input(path: str | None) -> str:
    if path and path != "-":
        return open(path, "r", encoding="utf-8").read()
    return sys.stdin.read()


def cmd_verify(args) -> int:
    text = _read_input(args.input)

    key_source = None
    record_algorithm = None
    if args.pubkey:
        pub = load_pubkey_b64(args.pubkey)
        key_source = f"file: {args.pubkey}"
    elif args.domain is not None and args.selector is not None:
        pub, tags = pubkey_from_dns(args.selector, args.domain)
        record_algorithm = tags.get("a")
        key_source = f"DNS: {args.selector}._watermark-text.{args.domain.strip('.')}"
    else:
        sys.exit("error: give --pubkey <file>, or --domain <d> and --selector <n>")

    res = verify_text(text, pub, max_offsets=args.max_offsets)
    res["key_source"] = key_source
    if record_algorithm is not None:
        res["record_algorithm"] = record_algorithm
        if record_algorithm != ALGORITHM_ID and res["verified"]:
            res["verified"] = False
            res["reason"] = (f"signature verifies, but the record publishes "
                             f"a={record_algorithm!r}, not {ALGORITHM_ID} -- rejected")

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        verdict = "VALID" if res["verified"] else "NOT VERIFIED"
        print(f"{ALGORITHM_ID}  --  {verdict}")
        print(f"  {res['reason']}")
        print(f"  canonical text : {res['canonical_chars']} chars")
        print(f"  offsets scanned: {res['offsets_scanned']}")
        if key_source:
            print(f"  key            : {key_source}")
        if record_algorithm is not None:
            print(f"  record a=      : {record_algorithm}")
        if res["verified"]:
            print(f"  message        : {res['message']!r}  (at offset {res['offset']})")
            print(f"  signature      : {res['signature_hex']}")

    return 0 if res["verified"] else 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="fairoze.py",
        description="fairoze-1 watermark verifier (and helpers). See the build plan.")
    p.add_argument("--verify", action="store_true", help="verify text for a fairoze-1 watermark")
    p.add_argument("--selfcheck", action="store_true", help="run the built-in Step 1-3 demo")
    p.add_argument("--input", metavar="FILE", help="text to check ('-' or omitted = stdin)")
    p.add_argument("--pubkey", metavar="FILE", help="PEM or base64-SPKI Ed25519 public key")
    p.add_argument("--domain", help="provider domain, for a DNS p= lookup")
    p.add_argument("--selector", type=int, help="selector number, with --domain")
    p.add_argument("--max-offsets", type=int, default=None,
                   help="cap the offset search (default: scan all)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)

    if args.verify:
        return cmd_verify(args)
    if args.selfcheck:
        return _selfcheck()
    p.print_help()
    return 1


def _selfcheck() -> int:
    priv, pub = fz_keygen()

    print("== Step 1: Ed25519 ==")
    d0 = b"\x00" * 32
    s0 = fz_sign(d0, priv)
    tampered = b"\x01" + d0[1:]
    print(f"  verify good/tamper/deterministic: "
          f"{fz_verify(d0, s0, pub)} / {fz_verify(tampered, s0, pub)} / "
          f"{fz_sign(d0, priv) == s0}")

    print("== Step 2: RS + mask payload ==")
    try:
        cw = encode_payload(s0, d0)
        print(f"  {len(cw)}-bit codeword, round-trip: {decode_payload(cw, d0) == s0}")
    except RuntimeError as exc:
        print(f"  skipped -- {exc.args[0].splitlines()[0]}")
        return 0

    print("== Steps 3 + 4: embed a debug watermark, then verify it ==")
    message = "selfchk!"
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    sig = fz_sign(digest, priv)
    text = _debug_embed(message, encode_payload(sig, digest))
    res = verify_text(text, pub)
    print(f"  {len(text)}-char text -> verified={res['verified']} "
          f"(offset {res.get('offset')}, message {res.get('message')!r})")
    print(f"  {res['reason']}")
    return 0 if res["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
