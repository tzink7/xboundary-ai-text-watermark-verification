#!/usr/bin/env python3
"""
tzsataitw.py -- Terry Zink's Super Awesome Test AI-Text Watermark generator

Standalone reference implementations of toy watermarking algorithms, for
exercising the DNS framework in draft-zink-xboundary-ai-text-watermark-
verification-01. Companion to watermark_dns_tool.py (which distributes keys and
checks records); this tool actually marks and verifies text.

    --generate     embed a watermark in text, using an Ed25519 private key
    --co-sign      "sign again": add a signed manifest over text that already
                   carries another mark (e.g. synthid-1) -- a double signature
    --verify       check a watermark or a manifest, using the matching public key
    --inspect      show the embedded payload(s), no crypto
    --walkthrough  how it works

--------------------------------------------------------------------------------
ALGORITHMS  (the "a=" value; the signature covers this name + the text)
--------------------------------------------------------------------------------
  tzsataitw-1   channel: invisible zero-width characters (U+200B = 0, U+200C = 1),
                a few after each word gap. Fixed cost (~76-110 bytes). Invisible
                to a reader; obvious in a hex dump.
  tzsataitw-2   channel: Cyrillic look-alike letters (a->a, e->e, o->o, ... ).
                One bit per swappable Latin letter, so it needs a LONG document
                (~1600+ chars for a bare signature). Changes the actual code
                points (breaks Ctrl-F, spellcheck, screen readers).

Both use the same frame and signed-message shape; only the channel differs.

FRAME (in the channel's bit stream)
  MAGIC(4) | version(1) | payload_len(2) | payload | CRC32(4)
  payload = locator_len(1) | locator | signature(64)
  MAGIC is "ZW1\0" for tzsataitw-1, "HG1\0" for tzsataitw-2 -- so a decoded
  frame self-identifies which algorithm made it.

MANIFEST FRAME (double signature -- zero-width only, MAGIC "ZWM\0")
  payload = mver(1) | n_marks(1)
            n_marks * ( scheme_len(1) | scheme | locator_len(1) | locator )
            sig_locator_len(1) | sig_locator | signature(64)
  --co-sign builds this over text that already carries another mark. The
  signature covers b"tzsataitw/manifest/v1\n" + (everything before the sig) +
  b"\0" + canonical_text. --verify checks the outer signature against the key at
  sig_locator, then (with --inner-verify) follows each referenced mark's DNS
  record. If the outer signature fails the manifest pointers are NOT trusted.

SIGNED MESSAGE (Ed25519, 64 bytes)
  b"<algorithm>\n" + canonical_text
  canonical_text = strip zero-width chars, fold look-alikes back to ASCII,
                   NFC-normalise, strip leading/trailing whitespace.
  The locator (<selector>._watermark-text.<domain>) is NOT signed -- it is an
  unsigned routing hint saying where the signer's public key is published, so a
  provider can move / rotate / renumber / delegate keys without invalidating
  past signatures. A tampered locator can't misattribute a mark: --verify just
  fetches the wrong key and the check fails.

VERIFY dispatch
  Try every channel's bit-extraction; whichever yields a MAGIC + CRC-valid frame
  is the mark (the 32-bit magic + 32-bit CRC make a wrong-channel read
  effectively never a false positive). Then recompute the signed message with
  that algorithm's name and Ed25519_verify against the key (--pubkey, or DNS
  "p=" at the locator / --domain+--selector).

Honest about what this is NOT (unlike a real statistical scheme, e.g. fairoze23):
  * NOT robust -- any rewrite, or a normalisation pass, removes the mark
  * NOT hidden from someone looking at the bytes
  * NOT a generator -- no language model; "generate" marks the text you give it

Dependencies: Python standard library, plus `openssl` (Ed25519) and `dig` (DNS
lookup for --verify without --pubkey). Both ship on macOS and typical Linux.

Usage:
    tzsataitw.py --generate --privkey 1._watermark-text.example.ai.private.pem < in.txt
    tzsataitw.py --generate --privkey KEY.pem --domain example.ai --selector 1 \\
        --algorithm tzsataitw-2 --input long-article.txt --out out.txt
    tzsataitw.py --verify < watermarked.txt
    tzsataitw.py --verify --pubkey KEY.pub.pem --input watermarked.txt
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import zlib

WELL_KNOWN_LABEL = "_watermark-text"

FRAME_VERSION = 2                        # v2: signed message is <algo> + text only
FRAME_FIXED = 4 + 1 + 2 + 4              # magic + ver + len(2) + crc32(4)
MAX_PAYLOAD = 4096
SIG_LEN = 64

# ---- double-signature manifest ("sign once, then sign again") ----------------
# A tzsataitw-1 frame whose payload is a signed *manifest* -- a list of the marks
# already on the text plus the locator of the key that signed the manifest. Used
# when one party watermarks with another scheme (e.g. synthid-1) and then signs
# the result with tzsataitw. The zero-width frame is the entry point: a verifier
# with only the raw text recovers where to check the signature AND where each
# referenced mark is verified. Carried in zero-width only (the homoglyph channel
# lacks the capacity).
ZWM_MAGIC = b"ZWM\x00"                   # distinct magic -> unambiguous vs a plain frame
MANIFEST_VERSION = 1
MANIFEST_DOMAIN_SEP = b"tzsataitw/manifest/v1\n"   # domain-separates the signed bytes

# ---- channel character sets ---------------------------------------------------

ZW_ZERO = "\u200b"   # ZERO WIDTH SPACE      -> bit 0
ZW_ONE = "\u200c"    # ZERO WIDTH NON-JOINER -> bit 1
ZW_RESERVED = frozenset("\u200b\u200c\u200d\u2060\ufeff")  # ZWSP ZWNJ ZWJ WJ ZWNBSP

# Latin -> visually identical Cyrillic. 0 = keep Latin, 1 = use the look-alike.
HOMOGLYPHS = {
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р",
    "x": "х", "y": "у", "i": "і", "j": "ј", "s": "ѕ",
    "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н",
    "K": "К", "M": "М", "O": "О", "P": "Р", "T": "Т",
    "X": "Х",
}
HOMOGLYPH_REVERSE = {v: k for k, v in HOMOGLYPHS.items()}

SAMPLE_TEXT = (
    "The two-bounce rule is the first thing that separates pickleball from tennis "
    "in the mind of a new player. After the serve, the receiving team must let the "
    "ball bounce once before returning it, and then the serving team must also let "
    "their return bounce before they may hit it. Only after those two bounces are "
    "players allowed to volley, meaning to strike the ball out of the air. The rule "
    "exists to blunt the advantage of a hard serve followed by a rush to the net, "
    "and it is the reason rallies in pickleball tend to start slowly and build. "
    "The non-volley zone, universally called the kitchen, is the seven-foot strip "
    "on each side of the net where volleying is forbidden. A player may step into "
    "the kitchen at any time, but may not be touching it, or any line bounding it, "
    "at the moment they volley the ball or in the follow-through of that swing. "
    "Momentum faults are common: a player volleys a ball from just behind the line "
    "and then drifts forward, and the paddle or a shoe clips the tape. The serve "
    "itself must be made underhand with the paddle head below the wrist, struck "
    "below the waist, and it travels cross-court, clearing the kitchen on the far "
    "side. Games are usually played to eleven points, win by two, and only the "
    "serving side can score. A side keeps serving, alternating servers, until it "
    "commits a fault, at which point the serve passes to the opponents. Because a "
    "point can only be won on serve, a long match can turn on a single stretch of "
    "clean serving late in a game, and experienced players talk about protecting "
    "the middle, keeping returns deep, and being patient in the kitchen exchange "
    "rather than trying to end every rally with power."
)


# --------------------------------------------------------------------------- #
# subprocess helpers                                                           #
# --------------------------------------------------------------------------- #

def _require(binary, why):
    if shutil.which(binary) is None:
        sys.exit(f"error: '{binary}' not found on PATH (needed for {why}).")


def _run(cmd, input_bytes=None):
    p = subprocess.run(cmd, input=input_bytes,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout, p.stderr


# --------------------------------------------------------------------------- #
# canonical text + signing message                                            #
# --------------------------------------------------------------------------- #

def strip_marks(text):
    """The visible text with every mark channel undone: zero-width chars removed,
    look-alike letters folded back to ASCII."""
    out = []
    for c in text:
        if c in ZW_RESERVED:
            continue
        out.append(HOMOGLYPH_REVERSE.get(c, c))
    return "".join(out)


def canonical_text(text):
    """The exact string that gets signed. strip_marks, then NFC, then strip
    leading/trailing whitespace so a newline or spaces added/removed in transit
    (editors, chat, `echo`) do not break the check."""
    return unicodedata.normalize("NFC", strip_marks(text)).strip()


def signing_message(algorithm, canon):
    """Ed25519 signs exactly these bytes: the algorithm name + the text. NOT the
    locator (that is unsigned routing metadata)."""
    return algorithm.encode("ascii") + b"\n" + canon.encode("utf-8")


def parse_locator(locator):
    """`<n>._watermark-text.<domain>` -> (selector:int|None, domain:str)."""
    m = re.match(r"^(\d+)\." + re.escape(WELL_KNOWN_LABEL) + r"\.(.+)$", locator)
    return (int(m.group(1)), m.group(2)) if m else (None, locator)


# --------------------------------------------------------------------------- #
# frame encode / decode (bit level)                                            #
# --------------------------------------------------------------------------- #

def _bytes_to_bits(data):
    return "".join(f"{b:08b}" for b in data)


def _bits_to_bytes(bits):
    n = len(bits) // 8
    return bytes(int(bits[i * 8:i * 8 + 8], 2) for i in range(n))


def build_frame(magic, payload):
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload too large")
    body = magic + bytes([FRAME_VERSION]) + len(payload).to_bytes(2, "big") + payload
    return body + (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "big")


def parse_frame(magic, data):
    """Return the payload if `data` starts with a valid frame for `magic`, else None."""
    if len(data) < FRAME_FIXED or data[:4] != magic:
        return None
    if data[4] != FRAME_VERSION:
        return None
    plen = int.from_bytes(data[5:7], "big")
    if plen > MAX_PAYLOAD:
        return None
    end = 7 + plen
    if len(data) < end + 4:
        return None
    if (zlib.crc32(data[:end]) & 0xFFFFFFFF) != int.from_bytes(data[end:end + 4], "big"):
        return None
    return data[7:end]


def pack_payload(locator, sig):
    lb = locator.encode("ascii")
    if len(lb) > 255:
        raise ValueError("locator too long")
    if len(sig) != SIG_LEN:
        raise ValueError(f"signature must be {SIG_LEN} bytes")
    return bytes([len(lb)]) + lb + sig


def unpack_payload(payload):
    if not payload:
        raise ValueError("empty payload")
    n = payload[0]
    if len(payload) < 1 + n + SIG_LEN:
        raise ValueError("payload truncated")
    return payload[1:1 + n].decode("ascii"), payload[1 + n:1 + n + SIG_LEN]


# --------------------------------------------------------------------------- #
# manifest payload (double-signature)                                          #
# --------------------------------------------------------------------------- #
# wire layout (inside a ZWM frame):
#   mver(1) | n_marks(1)
#   n_marks * ( scheme_len(1) | scheme | locator_len(1) | locator )
#   sig_locator_len(1) | sig_locator
#   signature(64)                       -- Ed25519 over MANIFEST_DOMAIN_SEP +
#                                          (everything above the signature) +
#                                          b"\0" + canonical_text(text)

def _lp(s):
    b = s.encode("ascii")
    if len(b) > 255:
        raise ValueError(f"manifest field too long (>255 bytes): {s!r}")
    return bytes([len(b)]) + b


def pack_manifest_prefix(marks, sig_locator):
    """The bytes before the signature: version, the marks list, sig_locator."""
    if not (1 <= len(marks) <= 255):
        raise ValueError("a manifest needs 1..255 marks")
    body = bytes([MANIFEST_VERSION, len(marks)])
    for scheme, locator in marks:
        body += _lp(scheme) + _lp(locator)
    body += _lp(sig_locator)
    return body


def manifest_signing_bytes(prefix, canon):
    return MANIFEST_DOMAIN_SEP + prefix + b"\x00" + canon.encode("utf-8")


def pack_manifest(marks, sig_locator, sig):
    if len(sig) != SIG_LEN:
        raise ValueError(f"signature must be {SIG_LEN} bytes")
    return pack_manifest_prefix(marks, sig_locator) + sig


def unpack_manifest(payload):
    """-> (marks[list of (scheme, locator)], sig_locator, sig, prefix_bytes)."""
    if len(payload) < 2:
        raise ValueError("manifest payload truncated")
    ver, n = payload[0], payload[1]
    if ver != MANIFEST_VERSION:
        raise ValueError(f"unsupported manifest version {ver}")
    i = [2]

    def take():
        if i[0] >= len(payload):
            raise ValueError("manifest field truncated")
        ln = payload[i[0]]
        i[0] += 1
        if i[0] + ln > len(payload):
            raise ValueError("manifest field truncated")
        s = payload[i[0]:i[0] + ln].decode("ascii")
        i[0] += ln
        return s

    marks = [(take(), take()) for _ in range(n)]
    sig_locator = take()
    prefix = payload[:i[0]]
    sig = payload[i[0]:]
    if len(sig) != SIG_LEN:
        raise ValueError(f"manifest signature is {len(sig)} bytes, expected {SIG_LEN}")
    return marks, sig_locator, sig, prefix


# --------------------------------------------------------------------------- #
# channels                                                                     #
# --------------------------------------------------------------------------- #

class CapacityError(Exception):
    pass


def _spread_zw(text, mark):
    """Distribute the zero-width `mark` string evenly across the word gaps."""
    if not mark:
        return text
    slots = [i + 1 for i, c in enumerate(text) if c == " "]
    if not slots:
        return (text[:1] + mark + text[1:]) if text else mark
    base, extra = divmod(len(mark), len(slots))
    out, prev, pos = [], 0, 0
    for i, slot in enumerate(slots):
        take = base + (1 if i < extra else 0)
        out.append(text[prev:slot])
        out.append(mark[pos:pos + take])
        prev, pos = slot, pos + take
    out.append(text[prev:])
    return "".join(out)


class ZeroWidthChannel:
    name = "tzsataitw-1"
    magic = b"ZW1\x00"
    # frames this channel can carry: a plain signature frame, or a manifest frame
    frame_specs = ((b"ZW1\x00", "signature"), (ZWM_MAGIC, "manifest"))
    summary = "invisible zero-width characters (U+200B = 0, U+200C = 1)"

    def embed(self, base_text, bits):
        mark = "".join(ZW_ONE if b == "1" else ZW_ZERO for b in bits)
        return _spread_zw(base_text, mark)

    def extract(self, text):
        return "".join("1" if c == ZW_ONE else "0"
                       for c in text if c in (ZW_ZERO, ZW_ONE))

    def capacity(self, base_text):
        return MAX_PAYLOAD * 8          # effectively unbounded

    def placement(self, base_text, nbits):
        return f"{nbits} zero-width chars, spread across the word gaps"


class HomoglyphChannel:
    name = "tzsataitw-2"
    magic = b"HG1\x00"
    frame_specs = ((b"HG1\x00", "signature"),)
    summary = "Cyrillic look-alike letters (a->а, e->е, o->о, ...)"

    def embed(self, base_text, bits):
        chars = list(base_text)
        slots = [i for i, c in enumerate(chars) if c in HOMOGLYPHS]
        if len(slots) < len(bits):
            raise CapacityError(len(bits), len(slots))
        for b, pos in zip(bits, slots):
            if b == "1":
                chars[pos] = HOMOGLYPHS[chars[pos]]
        return "".join(chars)

    def extract(self, text):
        out = []
        for c in text:
            if c in HOMOGLYPH_REVERSE:
                out.append("1")
            elif c in HOMOGLYPHS:
                out.append("0")
        return "".join(out)

    def capacity(self, base_text):
        return sum(1 for c in base_text if c in HOMOGLYPHS)

    def placement(self, base_text, nbits):
        return f"{nbits} of {self.capacity(base_text)} look-alike-swappable letters flipped"


ALGORITHMS = {c.name: c for c in (ZeroWidthChannel(), HomoglyphChannel())}


def extract_frames(text):
    """Every embedded frame, across all channels: list of dicts
    {algorithm, kind, magic, bit_offset, payload}. `kind` is "signature" or
    "manifest"."""
    out = []
    for name, ch in ALGORITHMS.items():
        bits = ch.extract(text)
        if not bits:
            continue
        for magic, kind in getattr(ch, "frame_specs", ((ch.magic, "signature"),)):
            magic_bits = _bytes_to_bits(magic)
            i = 0
            while True:
                j = bits.find(magic_bits, i)
                if j < 0:
                    break
                payload = parse_frame(magic, _bits_to_bytes(bits[j:]))
                if payload is not None:
                    out.append({"algorithm": name, "kind": kind, "magic": magic,
                                "bit_offset": j, "payload": payload})
                    i = j + 8
                else:
                    i = j + 1
    return out


# --------------------------------------------------------------------------- #
# Ed25519 via openssl                                                          #
# --------------------------------------------------------------------------- #

def _tmp(data=b""):
    fd, path = tempfile.mkstemp(prefix="tzsataitw_")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def ed25519_sign(priv_pem_path, msg):
    _require("openssl", "Ed25519 signing")
    mpath, spath = _tmp(msg), _tmp()
    try:
        rc, _, err = _run(["openssl", "pkeyutl", "-sign", "-inkey", priv_pem_path,
                           "-rawin", "-in", mpath, "-out", spath])
        if rc != 0:
            raise RuntimeError(f"openssl signing failed:\n{err.decode('utf-8', 'replace')}")
        with open(spath, "rb") as fh:
            sig = fh.read()
        if len(sig) != SIG_LEN:
            raise RuntimeError(f"expected a {SIG_LEN}-byte Ed25519 signature, got {len(sig)} "
                               f"-- is {priv_pem_path} an Ed25519 private key?")
        return sig
    finally:
        for p in (mpath, spath):
            try:
                os.unlink(p)
            except OSError:
                pass


def ed25519_verify(key_path, msg, sig, keyform="PEM"):
    _require("openssl", "Ed25519 verification")
    mpath, spath = _tmp(msg), _tmp(sig)
    try:
        cmd = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", key_path,
               "-rawin", "-in", mpath, "-sigfile", spath]
        if keyform == "DER":
            cmd += ["-keyform", "DER"]
        rc, _, _ = _run(cmd)
        return rc == 0
    finally:
        for p in (mpath, spath):
            try:
                os.unlink(p)
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# DNS: fetch the public key named by the locator                               #
# --------------------------------------------------------------------------- #

def dig_txt(name):
    _require("dig", "DNS lookup (or pass --pubkey to verify offline)")
    rc, out, err = _run(["dig", "+short", "TXT", name])
    records = []
    for line in out.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.startswith('"'):
            chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
            records.append("".join(c.replace('\\"', '"') for c in chunks))
    return records


def parse_record_tags(record):
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip()] = v.strip()
    return tags


def key_der_from_dns(locator):
    """Return (spki_der_bytes, record_tags) for the key published at `locator`."""
    records = dig_txt(locator)
    if not records:
        raise RuntimeError(f"no TXT record at {locator} (is the provider publishing, and is dig working?)")
    for rec in records:
        tags = parse_record_tags(rec)
        if tags.get("p"):
            try:
                return base64.b64decode(tags["p"], validate=True), tags
            except Exception:
                raise RuntimeError(f"p= at {locator} is not valid base64")
    raise RuntimeError(f"no p= tag in the record at {locator}")


# --------------------------------------------------------------------------- #
# I/O helpers                                                                  #
# --------------------------------------------------------------------------- #

def read_input_text(path, use_sample=False):
    if use_sample:
        return SAMPLE_TEXT
    if path:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    if sys.stdin.isatty():
        sys.exit("error: give --input FILE, pipe text on stdin, or (for --generate) pass --sample.")
    return sys.stdin.read()


def _locator_from_key_name(path):
    """A key from `watermark_dns_tool.py --keygen` is named
    `<selector>._watermark-text.<domain>.(private|public).pem`."""
    m = re.match(r"^(\d+)\." + re.escape(WELL_KNOWN_LABEL) + r"\.(.+)\.(?:private|public)\.pem$",
                 os.path.basename(path))
    return (int(m.group(1)), m.group(2)) if m else (None, None)


# --------------------------------------------------------------------------- #
# --generate                                                                   #
# --------------------------------------------------------------------------- #

def cmd_generate(args):
    if not args.privkey:
        sys.exit("error: --generate needs --privkey (an Ed25519 private key PEM)")
    if not os.path.isfile(args.privkey):
        sys.exit(f"error: private key file not found: {args.privkey}")

    algo = args.algorithm or "tzsataitw-1"
    if algo not in ALGORITHMS:
        sys.exit(f"error: --algorithm must be one of {', '.join(ALGORITHMS)}")
    ch = ALGORITHMS[algo]

    # locator: from --domain/--selector, else the key filename, else omit it
    selector, domain = args.selector, args.domain
    name_sel, name_dom = _locator_from_key_name(args.privkey)
    if selector is None:
        selector = name_sel
    if not domain:
        domain = name_dom
    if args.no_locator:
        selector, domain = None, None

    if selector is not None and domain:
        locator = f"{selector}.{WELL_KNOWN_LABEL}.{domain.strip('.')}"
        if name_dom and name_sel is not None and (name_dom != domain or name_sel != selector):
            print(f"# note: locator {locator} differs from the key filename "
                  f"({name_sel}.{WELL_KNOWN_LABEL}.{name_dom}); using the flags.", file=sys.stderr)
    else:
        locator = ""
        print("# note: no locator embedded -- bare signature; --verify will need --pubkey "
              "or --domain/--selector.", file=sys.stderr)

    raw = read_input_text(args.input, use_sample=args.sample)
    if args.sample:
        print("# --sample: watermarking the built-in sample paragraph.", file=sys.stderr)
    base_text = strip_marks(raw)
    if base_text != raw:
        print("# note: input already contained zero-width or look-alike chars; normalised first.",
              file=sys.stderr)

    canon = canonical_text(raw)
    sig = ed25519_sign(args.privkey, signing_message(algo, canon))
    frame_bits = _bytes_to_bits(build_frame(ch.magic, pack_payload(locator, sig)))

    try:
        watermarked = ch.embed(base_text, frame_bits)
    except CapacityError as exc:
        drop = f" drop the locator (--no-locator, saves {8 * (1 + len(locator))} bits);" if locator else ""
        sys.exit(
            f"error: {algo} needs {exc.args[0]} bit-positions but this text has only "
            f"{exc.args[1]} look-alike-swappable letters.\n"
            f"       Use a longer document;{drop} or use tzsataitw-1 (zero-width, fixed cost).")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(watermarked)
        dest = args.out
    else:
        sys.stdout.write(watermarked)
        if not watermarked.endswith("\n"):
            sys.stdout.write("\n")
        dest = "stdout"

    src = f"--input {args.out}" if args.out else "< the-text"
    print(f"# {algo}: {ch.placement(base_text, len(frame_bits))} "
          f"({len(frame_bits) // 8} bytes) -> {dest}", file=sys.stderr)
    print(f"#   channel: {ch.summary}", file=sys.stderr)
    print(f"#   locator: {locator or '(none -- bare signature)'}", file=sys.stderr)
    print(f"#   verify:  tzsataitw.py --verify {src}"
          + ("" if locator else "  --pubkey <public key>"), file=sys.stderr)


# --------------------------------------------------------------------------- #
# --co-sign  (the "sign again" half of a double signature)                     #
# --------------------------------------------------------------------------- #

def _write_text_out(text, out_path):
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return out_path
    sys.stdout.write(text if text.endswith("\n") else text + "\n")
    return "stdout"


def _parse_over(entries):
    marks = []
    for e in entries or []:
        scheme, sep, locator = e.partition("@")
        scheme, locator = scheme.strip(), locator.strip()
        if not sep or not scheme or not locator:
            sys.exit(f"error: --over expects SCHEME@LOCATOR, got {e!r}")
        marks.append((scheme, locator))
    return marks


def cmd_co_sign(args):
    if not args.privkey:
        sys.exit("error: --co-sign needs --privkey (the Ed25519 key for the outer signature)")
    if not os.path.isfile(args.privkey):
        sys.exit(f"error: private key file not found: {args.privkey}")

    marks = _parse_over(args.over)
    if not marks:
        sys.exit("error: --co-sign needs at least one --over SCHEME@LOCATOR -- the mark(s) "
                 "already on the text (e.g. synthid-1@4._watermark-text.example.ai)")

    selector, domain = args.selector, args.domain
    name_sel, name_dom = _locator_from_key_name(args.privkey)
    if selector is None:
        selector = name_sel
    if not domain:
        domain = name_dom
    if selector is None or not domain:
        sys.exit("error: --co-sign needs --domain and --selector (where the outer key is "
                 "published) -- the manifest signature is not verifiable without a locator")
    sig_locator = f"{selector}.{WELL_KNOWN_LABEL}.{domain.strip('.')}"

    raw = read_input_text(args.input, use_sample=args.sample)
    if args.sample:
        print("# --sample: co-signing the built-in sample paragraph (no inner mark on it -- "
              "for wiring tests only).", file=sys.stderr)
    prior = [f for f in extract_frames(raw) if f["algorithm"].startswith("tzsataitw")]
    if prior:
        print(f"# note: input already carries a tzsataitw {prior[0]['kind']} frame; "
              f"stripping it and re-marking.", file=sys.stderr)

    base = strip_marks(raw)
    canon = canonical_text(raw)
    prefix = pack_manifest_prefix(marks, sig_locator)
    sig = ed25519_sign(args.privkey, manifest_signing_bytes(prefix, canon))
    payload = prefix + sig
    frame_bits = _bytes_to_bits(build_frame(ZWM_MAGIC, payload))
    watermarked = ZeroWidthChannel().embed(base, frame_bits)

    dest = _write_text_out(watermarked, args.out)
    src = f"--input {args.out}" if args.out else "< the-text"
    print(f"# tzsataitw-1 manifest: {len(payload)}-byte payload, {len(frame_bits)} "
          f"zero-width chars -> {dest}", file=sys.stderr)
    print(f"#   signed by : {sig_locator}", file=sys.stderr)
    for s, loc in marks:
        print(f"#   over mark : {s} @ {loc}", file=sys.stderr)
    print(f"#   canonical : {len(canon)} chars, "
          f"sha256 {hashlib.sha256(canon.encode('utf-8')).hexdigest()[:16]}...", file=sys.stderr)
    print(f"#   verify    : tzsataitw.py --verify {src}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# --verify                                                                     #
# --------------------------------------------------------------------------- #

def _verify_one(text, algorithm, locator, sig, pubkey_path, key_locator=None):
    """`locator` / `key_locator` only choose which key to FETCH -- neither is part
    of the signed message, so a wrong one just fails against the wrong key."""
    canon = canonical_text(text)
    msg = signing_message(algorithm, canon)
    selector, domain = parse_locator(locator)
    lookup = key_locator or locator

    # Where the verifying key comes from is fully determined by the inputs, so
    # decide it up front -- it must still be reported even if the DNS lookup or
    # the openssl call below throws.
    if pubkey_path:
        key_origin, key_lookup = "file", pubkey_path
        key_source = f"local key file {pubkey_path}"
    elif not lookup:
        key_origin, key_lookup, key_source = "none", None, None
    elif not key_locator:
        key_origin, key_lookup = "embedded-locator", lookup
        key_source = (f"the public key in the DNS TXT record at {lookup} -- "
                      f"that name was read from the locator embedded in the watermark")
    elif key_locator == locator:
        key_origin, key_lookup = "user-supplied", lookup
        key_source = (f"the public key in the DNS TXT record at {lookup} -- you named that "
                      f"domain/selector, and it matches the locator embedded in the watermark")
    else:
        key_origin, key_lookup = "user-supplied", lookup
        key_source = (f"the public key in the DNS TXT record at {lookup} -- you named that "
                      f"domain/selector (the watermark's own embedded locator is "
                      f"{locator or '(none)'})")

    info = {
        "algorithm": algorithm,
        "locator": locator or None,
        "selector": selector,
        "provider": domain or None,
        "signature_hex": sig.hex(),
        "canonical_chars": len(canon),
        "canonical_sha256": hashlib.sha256(canon.encode("utf-8")).hexdigest(),
        "signature_ok": False,   # the raw Ed25519 result
        "verified": False,       # the overall verdict (signature_ok AND record authorizes this algo)
        "key_origin": key_origin,
        "key_lookup": key_lookup,
        "key_source": key_source,
    }
    try:
        if pubkey_path:
            info["signature_ok"] = ed25519_verify(pubkey_path, msg, sig, "PEM")
            info["verified"] = info["signature_ok"]
        elif not lookup:
            info["detail"] = ("this mark carries no locator (bare signature) -- pass --pubkey, "
                              "or --domain and --selector to name where the key is published")
        else:
            der, tags = key_der_from_dns(lookup)
            if key_locator and key_locator != locator:
                info["key_locator_note"] = (
                    f"key fetched from {lookup} (given); the mark's embedded locator is "
                    f"{locator or '(none)'}")
            info["record_algorithm"] = tags.get("a")
            kpath = _tmp(der)
            try:
                info["signature_ok"] = ed25519_verify(kpath, msg, sig, "DER")
            finally:
                try:
                    os.unlink(kpath)
                except OSError:
                    pass
            if tags.get("a") and tags["a"] != algorithm:
                # crypto may be fine, but the provider publishes this key for a
                # different algorithm -- the record does not authorize this mark
                info["algorithm_mismatch"] = (
                    f"the record at {lookup} publishes this key for a={tags['a']!r}, "
                    f"not {algorithm}")
                info["verified"] = False
            else:
                info["verified"] = info["signature_ok"]
    except (RuntimeError, FileNotFoundError) as exc:
        info["detail"] = str(exc)
    return info


def cmd_verify(args):
    for flag, val in (("--no-locator", args.no_locator), ("--algorithm", args.algorithm),
                      ("--privkey", args.privkey), ("--sample", args.sample), ("--out", args.out)):
        if val:
            print(f"# note: {flag} is a --generate option and has no effect on --verify "
                  f"(the locator, algorithm, etc. are read from the mark itself).", file=sys.stderr)

    text = read_input_text(args.input)
    frames = extract_frames(text)

    # a manifest frame (double signature) takes precedence over a plain one
    mf = next((f for f in frames if f["kind"] == "manifest"), None)
    if mf is not None:
        _verify_manifest(text, mf, args)
        return

    parsed = None
    for fr in frames:
        if fr["kind"] != "signature":
            continue
        try:
            locator, sig = unpack_payload(fr["payload"])
        except ValueError:
            continue
        parsed = (fr, locator, sig)
        break

    if parsed is None:
        _emit_verify({"mark_found": False,
                      "detail": "no readable tzsataitw watermark found in the text"}, args.json)
        sys.exit(1)

    fr, locator, sig = parsed
    result = {
        "mark_found": True,
        "channel": ALGORITHMS[fr["algorithm"]].summary,
        "bit_offset": fr["bit_offset"],
        "payload_bytes": len(fr["payload"]),
    }

    key_locator = None
    if (args.domain is None) != (args.selector is None):
        sys.exit("error: --domain and --selector must be given together")
    if args.domain and args.selector is not None:
        key_locator = f"{args.selector}.{WELL_KNOWN_LABEL}.{args.domain.strip('.')}"

    result.update(_verify_one(text, fr["algorithm"], locator, sig, args.pubkey, key_locator))

    _emit_verify(result, args.json)
    if "detail" in result:
        sys.exit(3)
    sys.exit(0 if result.get("verified") else 2)


# --------------------------------------------------------------------------- #
# --verify: the double-signature manifest path                                 #
# --------------------------------------------------------------------------- #

_ZW_ONLY = re.compile("[​‌‍⁠]")


def _canon_tokens(text, tokens):
    """Apply a Section 6.6 `canonicalization` array (for an inner k=symmetric
    verify-endpoint call)."""
    for t in tokens or []:
        if t == "strip-zero-width":
            text = _ZW_ONLY.sub("", text)
        elif t == "nfc":
            text = unicodedata.normalize("NFC", text)
        elif t == "trim":
            text = text.strip()
        else:
            raise ValueError(f"unknown canonicalization token {t!r}")
    return text


def _http_bytes(url, data=None, timeout=8):
    import urllib.request
    headers = {"User-Agent": "tzsataitw", "Accept": "application/json, */*"}
    if data is not None:
        headers["Content-Type"] = "text/plain; charset=utf-8"
        data = data.encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310 (user's own machine)
        return resp.read(1_000_000)


def _verify_inner(scheme, locator, stripped_text, mode):
    """Check one referenced mark. `mode`: 'dns' (resolve + report) or 'endpoint'
    (also call a k=symmetric verify endpoint)."""
    out = {"scheme": scheme, "locator": locator, "verified": None}
    try:
        recs = dig_txt(locator)
    except (RuntimeError, FileNotFoundError) as exc:
        return {**out, "verified": False, "detail": str(exc)}
    tags = next((t for t in (parse_record_tags(r) for r in recs) if t.get("a")), None)
    if tags is None:
        return {**out, "verified": False, "detail": f"no _watermark-text record at {locator}"}
    out["record_algorithm"] = tags.get("a")
    if tags.get("a") != scheme:
        return {**out, "verified": False,
                "detail": f"record says a={tags.get('a')!r}, the manifest claims {scheme!r}"}
    out["k"] = tags.get("k")
    out["d"] = tags.get("d")

    if mode != "endpoint":
        if tags.get("k") == "symmetric":
            out["note"] = (f"k=symmetric -- verify at the endpoint in {tags.get('d')} "
                           f"(re-run with --inner-verify endpoint, or POST the "
                           f"canonicalized text there yourself)")
        else:
            out["note"] = (f"run: tzsataitw.py --verify (for tzsataitw-*) or the scheme's "
                           f"own verifier against {locator}")
        return out

    if tags.get("k") != "symmetric" or not tags.get("d"):
        return {**out, "detail": f"{scheme} at {locator} is not k=symmetric with a d= "
                                 f"document; use that scheme's own verifier"}
    try:
        doc = json.loads(_http_bytes(tags["d"]))
        ctext = _canon_tokens(stripped_text, doc.get("canonicalization") or [])
        resp = json.loads(_http_bytes(doc["verify"], data=ctext))
    except Exception as exc:                              # noqa: BLE001
        return {**out, "verified": False, "detail": f"verify-endpoint call failed: {exc}"}
    out.update(verified=bool(resp.get("watermarked")), score=resp.get("score"),
               threshold=resp.get("threshold"), verify_endpoint=doc.get("verify"),
               via="d= verify endpoint")
    return out


def _verify_manifest(text, frame, args):
    try:
        marks, sig_locator, sig, prefix = unpack_manifest(frame["payload"])
    except ValueError as exc:
        _emit_manifest({"mark_found": True, "kind": "manifest",
                        "detail": f"manifest payload is malformed: {exc}"}, args.json)
        sys.exit(3)

    canon = canonical_text(text)
    msg = manifest_signing_bytes(prefix, canon)

    key_locator = sig_locator
    if (args.domain is None) != (args.selector is None):
        sys.exit("error: --domain and --selector must be given together")
    if args.domain and args.selector is not None:
        key_locator = f"{args.selector}.{WELL_KNOWN_LABEL}.{args.domain.strip('.')}"

    outer = {"sig_locator": sig_locator, "key_lookup": key_locator,
             "signature_hex": sig.hex(), "canonical_chars": len(canon),
             "canonical_sha256": hashlib.sha256(canon.encode("utf-8")).hexdigest(),
             "signature_ok": False, "verified": False}
    try:
        if args.pubkey:
            outer["signature_ok"] = ed25519_verify(args.pubkey, msg, sig, "PEM")
            outer["verified"] = outer["signature_ok"]
            outer["key_source"] = f"local key file {args.pubkey}"
        else:
            der, tags = key_der_from_dns(key_locator)
            outer["record_algorithm"] = tags.get("a")
            outer["key_source"] = f"the DNS TXT record at {key_locator}"
            kpath = _tmp(der)
            try:
                outer["signature_ok"] = ed25519_verify(kpath, msg, sig, "DER")
            finally:
                try:
                    os.unlink(kpath)
                except OSError:
                    pass
            if tags.get("a") and not str(tags["a"]).startswith("tzsataitw"):
                outer["algorithm_mismatch"] = (
                    f"the record at {key_locator} publishes this key for a={tags['a']!r}, "
                    f"not a tzsataitw algorithm")
                outer["verified"] = False
            else:
                outer["verified"] = outer["signature_ok"]
    except (RuntimeError, FileNotFoundError) as exc:
        outer["detail"] = str(exc)

    result = {
        "mark_found": True, "kind": "manifest",
        "channel": ALGORITHMS["tzsataitw-1"].summary,
        "bit_offset": frame["bit_offset"], "payload_bytes": len(frame["payload"]),
        "outer": outer,
        "marks": [{"scheme": s, "locator": loc} for s, loc in marks],
    }

    if outer["verified"] and args.inner_verify != "off":
        stripped = strip_marks(text)
        result["marks"] = [_verify_inner(m["scheme"], m["locator"], stripped, args.inner_verify)
                           for m in result["marks"]]
    elif not outer["verified"]:
        result["inner_skipped"] = ("the outer signature did not verify -- the manifest's "
                                   "pointers are untrusted and were not followed")

    _emit_manifest(result, args.json)
    if outer.get("detail"):
        sys.exit(3)
    ok = outer["verified"]
    if args.inner_verify == "endpoint":
        ok = ok and all(m.get("verified") for m in result["marks"])
    sys.exit(0 if ok else 2)


def _emit_manifest(result, as_json):
    if as_json:
        print(json.dumps(result, indent=2))
        return
    print("tzsataitw-1 manifest  --  double-signature verification")
    if "detail" in result and "outer" not in result:
        print(f"  => {result['detail']}")
        return

    o = result["outer"]
    if o.get("detail"):
        outer_cell = f"could not check ({o['detail']})"
    elif o.get("signature_ok") and o.get("verified"):
        outer_cell = "VALID"
    elif o.get("signature_ok"):
        outer_cell = f"signature valid, but {o.get('algorithm_mismatch', 'the record rejects it')}"
    else:
        outer_cell = "INVALID -- does not verify"
    rows = [
        ("outer signature", outer_cell),
        ("signed by", o["sig_locator"]),
        ("verified against", o.get("key_source", "-")),
    ]
    if o.get("record_algorithm"):
        rows.append(("record a=", o["record_algorithm"]))
    rows.append(("canonical text", f"{o['canonical_chars']} chars, "
                                   f"sha256 {o['canonical_sha256'][:16]}..."))
    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"  {k.ljust(width)} : {v}")

    print(f"  referenced marks ({len(result['marks'])}):")
    for m in result["marks"]:
        line = f"    - {m['scheme']} @ {m['locator']}"
        if m.get("verified") is True:
            extra = ""
            if m.get("score") is not None:
                extra = f" (score {m['score']:.4f} >= {m.get('threshold', 0):.4f})"
            line += f"  -> VALID{extra}"
        elif m.get("verified") is False:
            line += f"  -> NOT VERIFIED ({m.get('detail', 'failed')})"
        elif m.get("note"):
            line += f"\n        {m['note']}"
        print(line)
    if result.get("inner_skipped"):
        print(f"  ! {result['inner_skipped']}")

    print()
    if o.get("verified"):
        n_ok = sum(1 for m in result["marks"] if m.get("verified") is True)
        n_checked = sum(1 for m in result["marks"] if m.get("verified") is not None)
        tail = (f"; {n_ok}/{n_checked} referenced mark(s) verified" if n_checked
                else "; referenced marks not checked (see above)")
        print(f"  reads as: this text was double-signed -- a VALID tzsataitw-1 manifest "
              f"from {o['sig_locator']}{tail}")
    elif o.get("signature_ok"):
        print(f"  reads as: REJECTED -- {o.get('algorithm_mismatch', 'the record does not authorize this')}")
    else:
        print("  reads as: the manifest signature does NOT verify -- forged, corrupted, "
              "or the visible text changed after signing")


def _emit_verify(result, as_json):
    if as_json:
        print(json.dumps(result, indent=2))
        return

    algo = result.get("algorithm", "tzsataitw")
    print(f"{algo}  --  watermark verification")
    if not result.get("mark_found"):
        print("  mark found     : no")
        print(f"  => {result.get('detail', 'no watermark')}")
        return

    if "detail" in result:
        sig_cell = "not checked (no key)"
    elif result.get("signature_ok"):
        sig_cell = "VALID" if result.get("verified") else "VALID, but the record rejects this use"
    else:
        sig_cell = "INVALID"
    rows = [
        ("mark found", f"yes  ({algo}, {result['payload_bytes']}-byte payload at bit "
                       f"offset {result['bit_offset']})"),
        ("signature", sig_cell),
        ("verified against", result.get("key_source") or "-- (no key to check against)"),
        ("channel", result.get("channel", "-")),
        ("locator", result.get("locator") or "(none -- bare signature)"),
        ("provider", result.get("provider") or "(not stated in the mark)"),
        ("selector", "-" if result.get("selector") is None else str(result["selector"])),
    ]
    if result.get("record_algorithm"):
        rows.append(("record a=", result["record_algorithm"]))
    rows.append(("canonical text", f"{result.get('canonical_chars', '?')} chars, "
                                   f"sha256 {result.get('canonical_sha256', '')[:16]}..."))
    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"  {k.ljust(width)} : {v}")

    if result.get("key_locator_note"):
        print(f"  ! {result['key_locator_note']}")
    if result.get("algorithm_mismatch"):
        print(f"  ! {result['algorithm_mismatch']}")

    origin = result.get("key_origin")
    lookup = result.get("key_lookup", "")
    if origin in ("embedded-locator", "user-supplied"):
        sel, dom = parse_locator(lookup)
        who = f"{dom} (selector {sel})" if sel is not None else dom
        if origin == "embedded-locator":
            who += ", found via the locator embedded in the watermark"
        else:
            who += ", the domain/selector you supplied"
    elif origin == "file":
        who = f"the key in {os.path.basename(lookup)}"
    else:
        who = "the key it was checked against"

    print()
    if "detail" in result:
        print(f"  => could not verify: {result['detail']}")
    elif result.get("verified"):
        print(f"  reads as: this text carries a VALID {algo} watermark from {who}")
    elif result.get("signature_ok"):
        print(f"  reads as: REJECTED -- the Ed25519 signature is valid, but {result['algorithm_mismatch']}, "
              f"so the record does not authorize a {algo} mark under this key")
    else:
        print(f"  reads as: a {algo} mark is present, but the signature does NOT verify "
              f"against {who} -- forged, corrupted, or the visible text was changed "
              f"after signing")


# --------------------------------------------------------------------------- #
# --inspect                                                                    #
# --------------------------------------------------------------------------- #

def cmd_inspect(args):
    text = read_input_text(args.input)
    frames = extract_frames(text)
    counts = {
        "tzsataitw-1 (zero-width) data chars": sum(1 for c in text if c in (ZW_ZERO, ZW_ONE)),
        "tzsataitw-2 (look-alike) swapped letters": sum(1 for c in text if c in HOMOGLYPH_REVERSE),
    }
    out = {"channel_chars": counts, "frames": []}
    for fr in frames:
        entry = {"algorithm": fr["algorithm"], "kind": fr["kind"],
                 "bit_offset": fr["bit_offset"],
                 "payload_bytes": len(fr["payload"]), "payload_hex": fr["payload"].hex()}
        try:
            if fr["kind"] == "manifest":
                marks, sig_locator, sig, _ = unpack_manifest(fr["payload"])
                entry["marks"] = [{"scheme": s, "locator": loc} for s, loc in marks]
                entry["sig_locator"] = sig_locator
                entry["signature_hex"] = sig.hex()
                entry["signature_b64"] = base64.b64encode(sig).decode("ascii")
                entry["signed_over"] = ('tzsataitw/manifest/v1 + marks + sig_locator + '
                                        'canonical_text  (use --verify to check)')
            else:
                locator, sig = unpack_payload(fr["payload"])
                entry["locator"] = locator
                entry["signature_hex"] = sig.hex()
                entry["signature_b64"] = base64.b64encode(sig).decode("ascii")
                entry["signed_over"] = f'b"{fr["algorithm"]}\\n" + canonical_text  ' \
                                       f'(use --verify to compute & check)'
        except ValueError as exc:
            entry["error"] = str(exc)
        out["frames"].append(entry)

    if args.json:
        print(json.dumps(out, indent=2))
        return
    print("tzsataitw  --  inspect (no crypto)")
    for k, v in counts.items():
        print(f"  {k}: {v}")
    print(f"  frames recovered: {len(frames)}")
    for i, entry in enumerate(out["frames"], 1):
        print(f"  [{i}] {entry['algorithm']} {entry['kind']}, bit offset "
              f"{entry['bit_offset']}, {entry['payload_bytes']} bytes")
        if entry.get("error"):
            print(f"      error     : {entry['error']}")
        elif entry["kind"] == "manifest":
            print(f"      signed by      : {entry['sig_locator']}")
            for m in entry["marks"]:
                print(f"      over mark      : {m['scheme']} @ {m['locator']}")
            print(f"      signed over    : {entry['signed_over']}")
            print(f"      signature b64  : {entry['signature_b64']}")
        else:
            print(f"      locator        : {entry['locator'] or '(none -- bare signature)'}")
            print(f"      signed over    : b\"{entry['algorithm']}\\n\" + canonical_text")
            print(f"      signature hex  : {entry['signature_hex']}")
            print(f"      signature b64  : {entry['signature_b64']}")
    if not frames and any(counts.values()):
        print("  (channel characters are present but none form a valid frame)")


# --------------------------------------------------------------------------- #
# --walkthrough                                                                #
# --------------------------------------------------------------------------- #

WALKTHROUGH = r"""
================================================================================
  tzsataitw.py -- toy asymmetric text watermarks
================================================================================

WHAT IT IS
  A private key embeds an Ed25519 signature into text; the matching public key
  (from --pubkey, or DNS "p=" at <selector>._watermark-text.<domain> per the
  xboundary draft) verifies it. Anyone can verify; nobody can forge.

WHAT IT IS NOT
  * Not robust: a rewrite, or a normalisation pass, destroys the mark. A real
    statistical scheme (e.g. fairoze23) survives light editing.
  * Not hidden from someone looking at the bytes.
  * Not a text generator: no language model; "generate" marks the text you give
    it (or the built-in --sample paragraph).

ALGORITHMS  (pick with --algorithm on --generate; --verify auto-detects)
  tzsataitw-1   invisible zero-width chars (U+200B = 0, U+200C = 1), a few after
                each word gap. Fixed cost (~76-110 bytes). Invisible; obvious in
                a hex dump. Works on any text.
  tzsataitw-2   Cyrillic look-alike letters (a->a, e->e, o->o, i->i, s->s, ...).
                One bit per swappable Latin letter -> needs a LONG document
                (~1600+ chars for a bare signature; more with a locator). Changes
                the code points, so Ctrl-F / spellcheck / screen readers break.

FRAME  (carried in the channel's bit stream)
  MAGIC(4) | version(1) | payload_len(2) | payload | CRC32(4)
  payload = locator_len(1) | locator | signature(64)
  MAGIC = "ZW1\0" (tzsataitw-1) or "HG1\0" (tzsataitw-2), so a decoded frame
  says which algorithm made it.

SIGNED MESSAGE  (Ed25519, 64 bytes)
  b"<algorithm>\n" + canonical_text
  canonical_text = strip zero-width chars, fold look-alikes to ASCII, NFC,
                   strip leading/trailing whitespace.
  The locator is NOT signed -- it is an unsigned hint ("the key is published
  here"), so the provider can move / rotate / renumber / delegate keys without
  breaking past signatures. A tampered locator can't misattribute a mark: the
  verifier just fetches the wrong key and the check fails.

VERIFY DISPATCH
  Try each channel's bit-extraction; the one that yields a MAGIC + CRC-valid
  frame is the mark (32-bit magic + 32-bit CRC => a wrong-channel read is never
  a false positive). The frame's magic already names the algorithm, so no
  --algorithm is needed. Recompute the signed message with that name, fetch the
  key, Ed25519_verify. When the key came from DNS, the record's a= must also
  match the mark's algorithm -- if it doesn't, the mark is REJECTED even though
  the raw signature is valid (the provider publishes that key for a different
  algorithm). So "try all channels" is not redundant with the DNS a=: you need a
  channel to extract the frame (which holds the locator) before you can do the
  DNS lookup at all.

DOUBLE SIGNATURE ("sign once, then sign again")
  --co-sign takes text that already carries another watermark (e.g. a synthid-1
  statistical mark from generation) and adds a signed tzsataitw-1 *manifest*: a
  zero-width frame listing that mark plus the locator of the key signing the
  manifest. The manifest is the entry point -- a verifier with only the raw text
  recovers where to check the signature AND where each referenced mark is
  verified, with no out-of-band "which provider?" input.

  tzsataitw.py --co-sign --input generated.txt --privkey KEY.pem \
      --domain example.ai --selector 1 \
      --over synthid-1@4._watermark-text.model.example --out double.txt

  tzsataitw.py --verify --input double.txt                    # outer sig + resolve marks
  tzsataitw.py --verify --input double.txt --inner-verify endpoint   # + call the mark's verify endpoint

  The two layers are cryptographically bound: the outer signature covers the
  text INCLUDING the synthid statistical bias, so paraphrasing enough to wash
  out the inner mark also breaks the outer signature.

COMMANDS
  # tzsataitw-1, locator read from the key filename
  tzsataitw.py --generate --privkey 1._watermark-text.example.ai.private.pem \
      --input article.txt --out article.wm.txt

  # tzsataitw-2, needs a long document
  tzsataitw.py --generate --privkey KEY.pem --domain example.ai --selector 1 \
      --algorithm tzsataitw-2 --input book-chapter.txt --out chapter.wm.txt

  tzsataitw.py --verify --input article.wm.txt                 # key from DNS
  tzsataitw.py --verify --pubkey KEY.pub.pem --input article.wm.txt   # offline
  tzsataitw.py --verify --input bare.wm.txt --domain example.ai --selector 1
  tzsataitw.py --inspect --input article.wm.txt
  tzsataitw.py --co-sign --input generated.txt --privkey KEY.pem \
      --domain example.ai --selector 1 --over synthid-1@4._watermark-text.model.example
================================================================================
"""


def cmd_walkthrough(args):
    print(WALKTHROUGH.strip())


# --------------------------------------------------------------------------- #
# argument parsing                                                             #
# --------------------------------------------------------------------------- #

MODE_HANDLERS = [
    ("walkthrough", cmd_walkthrough),
    ("generate", cmd_generate),
    ("co_sign", cmd_co_sign),
    ("verify", cmd_verify),
    ("inspect", cmd_inspect),
]


def build_parser():
    p = argparse.ArgumentParser(
        prog="tzsataitw.py",
        description="tzsataitw: toy asymmetric text watermarks (zero-width, look-alike). "
                    "Companion to watermark_dns_tool.py.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Every option is a '--' flag; choose exactly one mode.\n"
               "  tzsataitw.py --walkthrough\n"
               "  tzsataitw.py --generate --privkey KEY.pem --domain example.ai --selector 1 < in.txt\n"
               "  tzsataitw.py --verify < watermarked.txt",
    )
    mode = p.add_argument_group("mode (choose exactly one)")
    m = mode.add_mutually_exclusive_group()
    m.add_argument("--walkthrough", action="store_true", help="explain the algorithms")
    m.add_argument("--generate", action="store_true",
                   help="embed a watermark (needs --privkey; locator from --domain/--selector "
                        "or the key filename)")
    m.add_argument("--co-sign", action="store_true",
                   help="add a signed tzsataitw-1 manifest over text that already carries "
                        "another mark -- the 'sign again' half of a double signature (needs "
                        "--privkey, --domain/--selector, and --over)")
    m.add_argument("--verify", action="store_true",
                   help="verify a watermark or a double-signature manifest (auto-detected; "
                        "key from DNS or --pubkey)")
    m.add_argument("--inspect", action="store_true",
                   help="show the embedded payload(s) without checking the signature")

    g = p.add_argument_group("options")
    g.add_argument("--algorithm", "--algo", dest="algorithm",
                   help=f"--generate: {' or '.join(ALGORITHMS)} (default tzsataitw-1)")
    g.add_argument("--privkey", help="--generate: Ed25519 private key PEM")
    g.add_argument("--pubkey", help="--verify: Ed25519 public key PEM (skip the DNS lookup)")
    g.add_argument("--domain",
                   help="provider domain. --generate: the locator to embed (default: from the "
                        "key filename). --verify: where to fetch the key (if the mark has no "
                        "locator, or to override it)")
    g.add_argument("--selector", type=int, help="selector number, paired with --domain")
    g.add_argument("--no-locator", action="store_true",
                   help="--generate: embed a bare signature, no locator (smaller mark)")
    g.add_argument("--over", action="append", metavar="SCHEME@LOCATOR",
                   help="--co-sign: a mark already on the text, e.g. "
                        "synthid-1@4._watermark-text.example.ai (repeatable)")
    g.add_argument("--inner-verify", choices=("off", "dns", "endpoint"), default="dns",
                   help="--verify (manifest): how far to check the referenced marks. "
                        "off = outer signature only; dns = resolve each record (default); "
                        "endpoint = also call a k=symmetric mark's verify endpoint (network)")
    g.add_argument("--input", help="read text from this file (default: stdin)")
    g.add_argument("--sample", action="store_true",
                   help="--generate / --co-sign: use the built-in sample paragraph")
    g.add_argument("--out", help="--generate / --co-sign: write here (default: stdout)")
    g.add_argument("--json", action="store_true", help="--verify / --inspect: machine-readable output")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    chosen = [(name, fn) for name, fn in MODE_HANDLERS if getattr(args, name)]
    if not chosen:
        cmd_walkthrough(args)
        print()
        build_parser().print_help()
        return 0
    try:
        chosen[0][1](args)
    except KeyboardInterrupt:
        return 130
    except (RuntimeError, FileNotFoundError, ValueError) as exc:
        sys.exit(f"error: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
