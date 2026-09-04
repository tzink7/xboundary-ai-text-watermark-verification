#!/usr/bin/env python3
"""
watermark_dns_tool.py

Reference tooling for draft-zink-xboundary-ai-text-watermark-verification-00
("A DNS-Based Framework for Cross-Organization Verification of AI-Generated
Text Watermarks").

This is a DISCUSSION-DRAFT helper, not a production verifier. It exists to make
the draft concrete: to let a reader generate the exact artifacts the draft
describes, check them against the draft's own rules, and walk a provider's
published records the way Section 6.4 says a verifier should.

What it does
------------
Every mode is a "--" flag; give exactly one.

  --walkthrough       Print an end-to-end explanation of the workflow (start here).
  --create            Step-by-step prompts that run (a)-(d) for one selector.
  --keygen            (a) Generate an asymmetric key pair for a selector.
  --make-record       (b) Build the `_watermark-text` DNS TXT record string.
  --make-descriptor   (c) Build the d= JSON custody descriptor file.
  --dh                (d) Compute the dh= Subresource-Integrity digest of a file/URL.
  --lint              Error-check a DNS record: a literal string, one fetched live,
                      or (with --crawl) every selector a provider publishes.
  --traverse          Crawl a provider's full selector set per Section 6.4.

Design constraints (matching tools/section_ref_checker.py in this repo)
---------------------------------------------------------------------
  * Python standard library only.
  * Shells out to `openssl` for key generation (asymmetric crypto is not in the
    stdlib) and to `dig` for DNS lookups (there is no stdlib resolver). Both are
    present by default on macOS and typical Linux. Nothing else is required.

Important scope note (draft Section 4.1 / 10.3)
----------------------------------------------
The draft's `p=` mechanism is only sound for an ASYMMETRIC, publicly-detectable
watermarking scheme. This tool generates real asymmetric key pairs (Ed25519 by
default), which is the right SHAPE, but it does not implement any watermark
embedding or detection algorithm, and it takes no position on which `a=` scheme
you name. Do not publish a symmetric scheme's key under `p=`.

Usage:
    python3 watermark_dns_tool.py --walkthrough
    python3 watermark_dns_tool.py --create
    python3 watermark_dns_tool.py --keygen --domain example.ai --selector 1
    python3 watermark_dns_tool.py --help
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
import time
import urllib.request
from collections import OrderedDict

WELL_KNOWN_LABEL = "_watermark-text"
PROTOCOL_VERSION = "1"

# Hash algorithms the draft's dh= tag allows. The draft names SHA-256 as
# primary (Section 6.1) and models the syntax on W3C SRI, which also defines
# sha384/sha512. Keys are the dh= algo token; values are (hashlib name, digest
# length in bytes).
DH_ALGOS = OrderedDict([
    ("sha-256", ("sha256", 32)),
    ("sha-384", ("sha384", 48)),
    ("sha-512", ("sha512", 64)),
    # SRI / Appendix B spelling, accepted on parse, not emitted by default:
    ("sha256", ("sha256", 32)),
    ("sha384", ("sha384", 48)),
    ("sha512", ("sha512", 64)),
])

REQUIRED_RECORD_TAGS = ["v", "a", "p", "c", "nb", "na"]
KNOWN_RECORD_TAGS = {"v", "a", "p", "c", "d", "dh", "s", "nb", "na", "r"}
DESCRIPTOR_REQUIRED_FIELDS = ["received_from", "selector", "provider", "c", "ts"]

# There is no IANA "a=" registry yet (Section 15). This is the local stand-in --
# the algorithm ids this toolchain recognizes:
KNOWN_ALGORITHMS = {
    "fairoze-1": "publicly-detectable watermarking [Fairoze23], Ed25519-signature "
                 "variant -- the asymmetric scheme this draft is designed around "
                 "(Section 4.1); verify with tools/fairoze.py",
    "tzsataitw-1": "toy asymmetric watermark, zero-width channel -- see tools/tzsataitw.py",
    "tzsataitw-2": "toy asymmetric watermark, look-alike-letter channel -- see tools/tzsataitw.py",
}


# --------------------------------------------------------------------------- #
# Small result type for diagnostics                                            #
# --------------------------------------------------------------------------- #

class Findings:
    """Collects ERROR / WARN / INFO lines with a stable ordering."""

    def __init__(self):
        self.items = []  # (level, code, message)
        self.descriptor = None  # populated when a d= document was fetched + read
        self.record_summary = None  # one-line plain-English reading of the record

    def error(self, code, message):
        self.items.append(("ERROR", code, message))

    def warn(self, code, message):
        self.items.append(("WARN", code, message))

    def info(self, code, message):
        self.items.append(("INFO", code, message))

    @property
    def n_errors(self):
        return sum(1 for lvl, _, _ in self.items if lvl == "ERROR")

    @property
    def n_warnings(self):
        return sum(1 for lvl, _, _ in self.items if lvl == "WARN")

    def extend(self, other, prefix=""):
        for lvl, code, msg in other.items:
            self.items.append((lvl, code, prefix + msg if prefix else msg))
        if getattr(other, "descriptor", None) and not self.descriptor:
            self.descriptor = other.descriptor
        if getattr(other, "record_summary", None) and not self.record_summary:
            self.record_summary = other.record_summary

    def render(self, indent=""):
        out = []
        for lvl, code, msg in self.items:
            out.append(f"{indent}{lvl:5s} [{code}] {msg}")
        return "\n".join(out)

    def as_dicts(self):
        return [{"level": l, "code": c, "message": m} for l, c, m in self.items]


# --------------------------------------------------------------------------- #
# subprocess helpers                                                           #
# --------------------------------------------------------------------------- #

def _require(binary):
    if shutil.which(binary) is None:
        sys.exit(
            f"error: '{binary}' not found on PATH. This tool needs it "
            f"({'key generation' if binary == 'openssl' else 'DNS lookups'})."
        )


def _run(cmd, input_bytes=None):
    proc = subprocess.run(
        cmd, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return proc.returncode, proc.stdout, proc.stderr


# --------------------------------------------------------------------------- #
# DNS name helpers                                                             #
# --------------------------------------------------------------------------- #

def selector_name(selector, domain):
    """`<selector>._watermark-text.<domain>` (Section 6.1)."""
    return f"{selector}.{WELL_KNOWN_LABEL}.{domain.strip('.')}"


def dig_txt(name):
    """Return list of fully-reassembled TXT record strings for `name`.

    `dig +short TXT` prints one record per line; a single long record is split
    into several quoted <=255-byte chunks on that line which must be
    concatenated with no separator (RFC 6376 / RFC 7489 convention).
    CNAMEs are followed transparently by the resolver (draft Section 6.5).
    """
    _require("dig")
    rc, out, err = _run(["dig", "+short", "TXT", name])
    records = []
    for line in out.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or not line.startswith('"'):
            continue
        chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
        reassembled = "".join(c.replace('\\"', '"').replace("\\\\", "\\") for c in chunks)
        records.append(reassembled)
    return records


def dig_cname(name):
    _require("dig")
    rc, out, err = _run(["dig", "+short", "CNAME", name])
    val = out.decode("utf-8", "replace").strip().splitlines()
    return val[0].rstrip(".") if val else None


def dig_status(name, rtype="TXT"):
    """Return the DNS response code string (NOERROR / NXDOMAIN / ...) and
    whether the AD (authenticated data, i.e. DNSSEC-validated) flag is set."""
    _require("dig")
    rc, out, err = _run(["dig", "+dnssec", rtype, name])
    text = out.decode("utf-8", "replace")
    m = re.search(r"status:\s*([A-Z]+)", text)
    status = m.group(1) if m else "UNKNOWN"
    flags_m = re.search(r"flags:\s*([a-z ]+);", text)
    ad = bool(flags_m and " ad" in " " + flags_m.group(1))
    return status, ad


# --------------------------------------------------------------------------- #
# Record + descriptor parsing                                                  #
# --------------------------------------------------------------------------- #

def parse_record(text):
    """Parse a tag=value record string into (OrderedDict, Findings).

    Tolerant of surrounding whitespace, a trailing ';', and spaces around '='
    and ';', consistent with DKIM/DMARC tag-value syntax.
    """
    f = Findings()
    tags = OrderedDict()
    seen = set()
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            f.error("SYNTAX", f"segment without '=': {part!r}")
            continue
        key, _, value = part.partition("=")
        key = key.strip()
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key):
            f.error("SYNTAX", f"invalid tag name {key!r}")
            continue
        if key in seen:
            f.error("DUP-TAG", f"tag {key!r} appears more than once")
            continue
        seen.add(key)
        tags[key] = value
    return tags, f


def _strip_zone_comment(line):
    """Drop an unquoted ';' comment from a zone-file line."""
    out, in_q = [], False
    for i, ch in enumerate(line):
        if ch == '"' and (i == 0 or line[i - 1] != "\\"):
            in_q = not in_q
        elif ch == ";" and not in_q:
            break
        out.append(ch)
    return "".join(out)


_ZONE_TXT_RE = re.compile(
    r"^\s*(?P<name>[^\s;]+)?\s+(?:\d+\s+)?(?:(?:IN|CH|HS)\s+)?TXT\s+(?P<data>.+)$",
    re.IGNORECASE,
)


def parse_zone_records(text, default_domain=None):
    """Pull watermark-text records out of zone-file-ish text.

    Returns a list of {name, selector, domain, record}. Tolerates full RRs
    (`1._watermark-text.example.ai. IN TXT "v=1; ..."`), missing TTL/class,
    `$ORIGIN` directives with relative owner names, character-strings split
    across several quoted chunks on one line, bare quoted strings (e.g. saved
    `dig +short TXT` output), `;` comments, and blank lines. Any line whose
    reassembled string has no `v=` tag is skipped.

    Note: TXT data MUST be quoted, as in real zone files -- an unquoted
    `v=1; a=...` line is treated as `v=1` followed by a `;` comment. (When the
    text comes from `--record input` / stdin, cmd_lint separately falls back to
    treating a single unquoted line as one bare record.)
    """
    origin = (default_domain or "").strip(".")
    out = []
    for raw in text.splitlines():
        line = _strip_zone_comment(raw).strip()
        if not line:
            continue
        upper = line.upper()
        if upper.startswith("$ORIGIN"):
            parts = line.split(None, 1)
            if len(parts) == 2:
                origin = parts[1].strip().rstrip(".")
            continue
        if upper.startswith("$TTL") or upper.startswith("$INCLUDE"):
            continue

        name, data = None, None
        m = _ZONE_TXT_RE.match(line)
        if m:
            name, data = m.group("name"), m.group("data")
            if name and name.upper() in ("IN", "CH", "HS", "TXT"):
                name = None
        elif upper.startswith("TXT "):
            data = line[4:]
        elif line.startswith('"'):
            data = line
        else:
            continue

        chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', data or "")
        if chunks:
            record = "".join(c.replace('\\"', '"').replace("\\\\", "\\") for c in chunks)
        else:
            record = (data or "").strip().strip('"')
        if "v=" not in record:
            continue

        fqdn = selector = domain = None
        if name and name != "@":
            fqdn = name.rstrip(".") if name.endswith(".") else (
                f"{name}.{origin}" if origin else name)
        elif name == "@" and origin:
            fqdn = origin
        elif origin:
            fqdn = origin

        if fqdn:
            mm = re.match(r"^(\d+)\." + re.escape(WELL_KNOWN_LABEL) + r"\.(.+)$", fqdn)
            if mm:
                selector = int(mm.group(1))
                domain = mm.group(2)
            else:
                domain = fqdn

        out.append({"name": fqdn, "selector": selector, "domain": domain, "record": record})
    return out


def parse_dh(value):
    """Split a dh= value into (algo_token, raw_digest_bytes).

    NOTE ON AMBIGUITY: the draft writes dh= as `<algo>-<base64url-hash>`, but the
    primary algo token 'sha-256' itself contains a hyphen, and a base64url hash
    can contain '-' and '_'. Splitting on '-' is therefore ambiguous. This
    parser resolves it by matching a known algo prefix from DH_ALGOS; the
    remainder is the hash. This ambiguity is worth raising against the draft
    (Section 6.1) -- W3C SRI uses 'sha256-' precisely to avoid it.
    """
    for token in DH_ALGOS:
        prefix = token + "-"
        if value.startswith(prefix):
            b64 = value[len(prefix):]
            try:
                raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
            except Exception:
                try:
                    raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
                except Exception:
                    return token, None
            return token, raw
    return None, None


def normalize_c(value):
    """Fold the c= alias: the draft (Section 6.1) says verifiers MUST treat
    'resign' as an identical alias of 're-sign'. Returns 'sign' or 're-sign'
    or the original (unrecognized) value."""
    v = value.strip().lower()
    if v in ("re-sign", "resign"):
        return "re-sign"
    if v == "sign":
        return "sign"
    return value


# --------------------------------------------------------------------------- #
# public-key (p=) inspection -- a minimal DER / SubjectPublicKeyInfo reader     #
# --------------------------------------------------------------------------- #

def _der_tlv(buf, i):
    """Read one DER TLV at offset i; return (tag, contents_bytes, next_offset)."""
    tag = buf[i]
    length = buf[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    return tag, bytes(buf[i:i + length]), i + length


def _decode_oid(b):
    if not b:
        return ""
    parts = [str(b[0] // 40), str(b[0] % 40)]
    val = 0
    for byte in b[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


_EDDSA_OIDS = {
    "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
    "1.3.101.110": "X25519", "1.3.101.111": "X448",
}
_EC_CURVE_OIDS = {
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
    "1.3.132.0.10": ("secp256k1", 256),
}


def inspect_spki(raw):
    """Best-effort parse of a SubjectPublicKeyInfo DER blob (the form this tool
    and DKIM put in p=). Returns {kind, label, bits} or None if `raw` is not a
    recognizable SPKI structure.
      kind: 'eddsa' | 'rsa' | 'ec' | 'other'
    """
    try:
        tag, spki, _ = _der_tlv(raw, 0)
        if tag != 0x30:
            return None
        atag, algid, after_alg = _der_tlv(spki, 0)
        if atag != 0x30:
            return None
        otag, oid, after_oid = _der_tlv(algid, 0)
        if otag != 0x06:
            return None
        oid_str = _decode_oid(oid)
        params = algid[after_oid:]
        btag, bitstr, _ = _der_tlv(spki, after_alg)
        if btag != 0x03 or not bitstr:
            return None
        key_bytes = bitstr[1:]  # first octet is the unused-bit count

        if oid_str in _EDDSA_OIDS:
            return {"kind": "eddsa", "label": _EDDSA_OIDS[oid_str],
                    "bits": len(key_bytes) * 8}
        if oid_str == "1.2.840.113549.1.1.1":  # rsaEncryption
            _, seq, _ = _der_tlv(key_bytes, 0)
            _, modulus, _ = _der_tlv(seq, 0)
            bits = len(modulus.lstrip(b"\x00")) * 8
            return {"kind": "rsa", "label": f"RSA-{bits}", "bits": bits}
        if oid_str == "1.2.840.10045.2.1":  # id-ecPublicKey
            curve = ""
            if params:
                ctag, curve_oid, _ = _der_tlv(params, 0)
                if ctag == 0x06:
                    curve = _decode_oid(curve_oid)
            name, bits = _EC_CURVE_OIDS.get(curve, ("EC (unknown curve)", 0))
            return {"kind": "ec", "label": name, "bits": bits}
        return {"kind": "other", "label": f"algorithm OID {oid_str}",
                "bits": len(key_bytes) * 8}
    except (IndexError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# (d) dh= digest computation                                                   #
# --------------------------------------------------------------------------- #

def compute_dh(data_bytes, algo_token="sha-256", pad=True):
    if algo_token not in DH_ALGOS:
        raise ValueError(f"unsupported dh algorithm {algo_token!r}")
    hashlib_name, _ = DH_ALGOS[algo_token]
    digest = hashlib.new(hashlib_name, data_bytes).digest()
    b64 = base64.urlsafe_b64encode(digest).decode("ascii")
    if not pad:
        b64 = b64.rstrip("=")
    return f"{algo_token}-{b64}"


def load_bytes_from_arg(location, findings=None):
    """`location` is a local path or an https:// URL. Returns raw bytes."""
    if location.startswith(("http://", "https://")):
        if location.startswith("http://") and findings is not None:
            findings.error("D-SCHEME", "d= document fetched over plain HTTP; the draft REQUIRES HTTPS")
        req = urllib.request.Request(location, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read()
    with open(location, "rb") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# (a) keygen                                                                   #
# --------------------------------------------------------------------------- #

KEY_TYPES = {
    "ed25519": ["-algorithm", "ed25519"],
    "ed448": ["-algorithm", "ed448"],
    "rsa2048": ["-algorithm", "rsa", "-pkeyopt", "rsa_keygen_bits:2048"],
    "rsa3072": ["-algorithm", "rsa", "-pkeyopt", "rsa_keygen_bits:3072"],
    "rsa4096": ["-algorithm", "rsa", "-pkeyopt", "rsa_keygen_bits:4096"],
}


def generate_keypair(key_type):
    """Return {'key_type', 'private_pem', 'public_pem', 'p'} using openssl."""
    _require("openssl")
    if key_type not in KEY_TYPES:
        raise ValueError(f"--key-type must be one of {', '.join(KEY_TYPES)}")

    rc, priv_pem, err = _run(["openssl", "genpkey"] + KEY_TYPES[key_type])
    if rc != 0:
        raise ValueError(f"openssl genpkey failed:\n{err.decode('utf-8', 'replace')}")

    rc, pub_pem, err = _run(["openssl", "pkey", "-pubout"], input_bytes=priv_pem)
    if rc != 0:
        raise ValueError(f"openssl pkey -pubout failed:\n{err.decode('utf-8', 'replace')}")

    rc, pub_der, err = _run(
        ["openssl", "pkey", "-pubout", "-outform", "DER"], input_bytes=priv_pem
    )
    if rc != 0:
        raise ValueError(f"openssl pkey (DER) failed:\n{err.decode('utf-8', 'replace')}")

    # p= carries the SubjectPublicKeyInfo DER, base64 (standard alphabet),
    # matching how a DKIM key record publishes p= (RFC 6376).
    return {
        "key_type": key_type,
        "private_pem": priv_pem,
        "public_pem": pub_pem,
        "p": base64.b64encode(pub_der).decode("ascii"),
    }


def keypair_stem(selector, domain, out_prefix=None):
    if out_prefix:
        return out_prefix
    if domain:
        return f"{selector}.{WELL_KNOWN_LABEL}.{domain.strip('.')}"
    return f"selector{selector}"


def write_keypair(kp, stem):
    """Write private/public PEM files for a keypair dict; return (priv, pub)."""
    import os
    priv_path = f"{stem}.private.pem"
    pub_path = f"{stem}.public.pem"
    with open(priv_path, "wb") as fh:
        fh.write(kp["private_pem"])
    with open(pub_path, "wb") as fh:
        fh.write(kp["public_pem"])
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass
    return priv_path, pub_path


def cmd_keygen(args):
    selector = args.selector if args.selector is not None else 1
    try:
        kp = generate_keypair(args.key_type)
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    p_value = kp["p"]

    stem = keypair_stem(selector, args.domain, args.out_prefix)
    priv_path = pub_path = None
    if not args.print_only:
        priv_path, pub_path = write_keypair(kp, stem)

    result = {
        "key_type": args.key_type,
        "selector": selector,
        "domain": args.domain,
        "record_name": selector_name(selector, args.domain) if args.domain else None,
        "p": p_value,
        "private_key_file": None if args.print_only else priv_path,
        "public_key_file": None if args.print_only else pub_path,
    }

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"# Key pair generated ({args.key_type})")
    if not args.print_only:
        print(f"#   private key : {priv_path}   (chmod 600; never publish, never commit)")
        print(f"#   public key  : {pub_path}")
    if args.domain:
        print(f"#   record name : {result['record_name']}")
    print()
    print("# p= value for the DNS record (base64 SubjectPublicKeyInfo):")
    print(f"p={p_value}")
    print()
    print("# Next: build the TXT record, e.g.")
    dom = args.domain or "example.ai"
    print(
        f"#   python3 {sys.argv[0].split('/')[-1]} --make-record --selector {selector} "
        f"--domain {dom} --algorithm fairoze-1 --pubkey {pub_path if not args.print_only else 'PUB.pem'} "
        f"--c sign --nb now --na ongoing" + (f" --r {selector}" if selector == 1 else "")
    )
    print()
    print("# Reminder (draft Section 4.1 / 10.3): only publish p= for an asymmetric,")
    print("# publicly-detectable watermarking scheme. Do NOT publish a symmetric key here.")


# --------------------------------------------------------------------------- #
# timestamp helper                                                             #
# --------------------------------------------------------------------------- #

def parse_ts(value, allow_ongoing=False):
    if value is None:
        return None
    v = value.strip()
    if allow_ongoing and v.lower() == "ongoing":
        return "ongoing"
    if v.lower() == "now":
        return int(time.time())
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    # ISO-8601 date or datetime
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return int(time.mktime(time.strptime(v, fmt)))
        except ValueError:
            continue
    raise ValueError(f"cannot parse timestamp {value!r} (use unix seconds, 'now', ISO date, or 'ongoing')")


def _fmt_ts(n):
    """A unix timestamp as a readable UTC string; falls back to str() on junk."""
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(n)))
    except (ValueError, OverflowError, OSError):
        return str(n)


def _fmt_date(n):
    """A unix timestamp as a bare UTC date (for terse one-liners)."""
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(int(n)))
    except (ValueError, OverflowError, OSError):
        return str(n)


def _fmt_dt(n):
    """A unix timestamp as 'YYYY-MM-DD HH:MM:SS' UTC -- the ISO form with the
    'T' separator and trailing 'Z' dropped, for table cells."""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(n)))
    except (ValueError, OverflowError, OSError):
        return str(n)


# --------------------------------------------------------------------------- #
# (c) make-descriptor                                                          #
# --------------------------------------------------------------------------- #

def build_descriptor(received_from, selector, provider, c, ts, extra=None, compact=False):
    obj = OrderedDict()
    obj["received_from"] = received_from
    obj["selector"] = str(selector)
    obj["provider"] = provider
    obj["c"] = normalize_c(c)
    obj["ts"] = str(ts)
    for k, v in (extra or {}):
        if k in obj:
            raise ValueError(f"extra field {k!r} collides with a required field")
        obj[k] = v
    if compact:
        body = json.dumps(obj, separators=(",", ":"))
    else:
        body = json.dumps(obj, indent=2)
    return obj, body.encode("utf-8")


def cmd_make_descriptor(args):
    missing = [name for name, val in (
        ("--received-from", args.received_from),
        ("--selector", args.selector),
        ("--provider", args.provider),
    ) if val is None]
    if missing:
        sys.exit(f"error: --make-descriptor requires {', '.join(missing)}")

    extra = []
    for pair in args.extra or []:
        if "=" not in pair:
            sys.exit(f"error: --extra expects key=value, got {pair!r}")
        k, _, v = pair.partition("=")
        extra.append((k.strip(), v.strip()))

    ts = parse_ts(args.ts) if args.ts else int(time.time())
    obj, body = build_descriptor(
        args.received_from, args.selector, args.provider, args.c or "re-sign", ts,
        extra=extra, compact=args.compact,
    )

    f = Findings()
    validate_descriptor_obj(obj, f, expected_selector=str(args.selector),
                            expected_provider=args.provider, dns_c=None)

    if not args.print_only:
        with open(args.out, "wb") as fh:
            fh.write(body)

    dh = compute_dh(body, args.dh_algo, pad=not args.no_pad)

    if args.json:
        print(json.dumps({
            "descriptor": obj,
            "bytes_written": None if args.print_only else args.out,
            "byte_length": len(body),
            "dh": dh,
            "findings": f.as_dicts(),
        }, indent=2))
        return

    print("# d= custody descriptor (draft Section 7.2)")
    print(body.decode("utf-8"))
    print()
    if not args.print_only:
        print(f"# written to: {args.out}   ({len(body)} bytes)")
    print(f"# dh= value (digest of exactly these bytes):")
    print(f"dh={dh}")
    print()
    print("# Serve the EXACT bytes above at your d= HTTPS URL. Any later edit")
    print("# (even adding a 'comments' field) changes the hash -> case (j) failure.")
    if f.items:
        print()
        print(f.render())


def validate_descriptor_obj(obj, f, expected_selector=None, expected_provider=None, dns_c=None):
    for field in DESCRIPTOR_REQUIRED_FIELDS:
        if field not in obj or obj[field] in (None, ""):
            f.error("D-MISSING", f"descriptor missing required field {field!r} (Section 7.2)")

    if "c" in obj:
        cval = normalize_c(str(obj["c"]))
        if cval not in ("sign", "re-sign"):
            f.error("D-C-VALUE", f"descriptor 'c' must be 'sign' or 're-sign', got {obj['c']!r}")
        if dns_c is not None:
            if normalize_c(dns_c) != cval:
                # Section 7.5(i): DNS c= vs JSON c= mismatch -> failure.
                # But DNS 'c=resign' vs JSON 'c=re-sign' is explicitly OK.
                f.error("D-C-MISMATCH",
                        f"DNS c={dns_c!r} does not match descriptor c={obj['c']!r} "
                        f"(Section 7.5 case (i) -- MUST fail verification / MUST NOT publish)")

    if expected_selector is not None and str(obj.get("selector")) != str(expected_selector):
        f.warn("D-SELECTOR",
               f"descriptor selector={obj.get('selector')!r} does not match the "
               f"queried selector {expected_selector!r}")
    if expected_provider is not None and obj.get("provider") not in (None, expected_provider):
        f.warn("D-PROVIDER",
               f"descriptor provider={obj.get('provider')!r} does not match the "
               f"queried zone {expected_provider!r}")

    if "ts" in obj:
        try:
            int(str(obj["ts"]))
        except (TypeError, ValueError):
            f.warn("D-TS", f"descriptor 'ts' should be a unix epoch integer, got {obj['ts']!r}")


# --------------------------------------------------------------------------- #
# (b) make-record  +  the linter                                               #
# --------------------------------------------------------------------------- #

def resolve_pubkey_to_p(pubkey_arg):
    """Accept a PEM path, a DER path, or a literal base64 string; return the
    base64 SubjectPublicKeyInfo string for p=."""
    import os
    candidate = pubkey_arg.strip()
    if not os.path.exists(pubkey_arg) and not candidate.lower().endswith((".pem", ".der")):
        # treat as a literal base64 SPKI value
        try:
            raw = base64.b64decode(candidate, validate=True)
            if raw and len(candidate) % 4 == 0:
                return candidate
        except Exception:
            pass
    with open(pubkey_arg, "rb") as fh:
        blob = fh.read()
    if b"-----BEGIN" in blob:
        _require("openssl")
        rc, der, err = _run(
            ["openssl", "pkey", "-pubin", "-pubout", "-outform", "DER"], input_bytes=blob
        )
        if rc != 0:
            # maybe it's a private key PEM
            rc, der, err = _run(
                ["openssl", "pkey", "-pubout", "-outform", "DER"], input_bytes=blob
            )
        if rc != 0:
            sys.exit(f"could not extract public key from {pubkey_arg}:\n{err.decode('utf-8','replace')}")
        return base64.b64encode(der).decode("ascii")
    return base64.b64encode(blob).decode("ascii")


def build_record(tags):
    ordered = ["v", "a", "p", "c", "d", "dh", "s", "nb", "na", "r"]
    parts = []
    for key in ordered:
        if key in tags and tags[key] is not None:
            parts.append(f"{key}={tags[key]}")
    for key, val in tags.items():
        if key not in ordered and val is not None:
            parts.append(f"{key}={val}")
    return "; ".join(parts)


def cmd_make_record(args):
    f = Findings()

    missing = [name for name, val in (
        ("--selector", args.selector),
        ("--algorithm", args.algorithm),
        ("--c", args.c),
        ("--nb", args.nb),
        ("--na", args.na),
    ) if val is None]
    if missing:
        sys.exit(f"error: --make-record requires {', '.join(missing)}")

    p_value = args.p
    if args.pubkey:
        p_value = resolve_pubkey_to_p(args.pubkey)
    if not p_value:
        sys.exit("error: --make-record requires --pubkey or --p")

    dh_value = args.dh_value
    if args.d_file and not dh_value:
        raw = load_bytes_from_arg(args.d_file, f)
        dh_value = compute_dh(raw, args.dh_algo, pad=not args.no_pad)

    tags = OrderedDict()
    tags["v"] = args.v
    tags["a"] = args.algorithm
    tags["p"] = p_value
    tags["c"] = normalize_c(args.c)
    if args.d:
        tags["d"] = args.d
    if dh_value:
        tags["dh"] = dh_value
    if args.s:
        tags["s"] = args.s
    tags["nb"] = str(parse_ts(args.nb))
    tags["na"] = str(parse_ts(args.na, allow_ongoing=True))
    if args.r is not None:
        tags["r"] = str(args.r)

    record = build_record(tags)

    lint_findings = lint_record(
        record, selector=args.selector, domain=args.domain, is_make=True
    )
    f.extend(lint_findings)

    record_name = selector_name(args.selector, args.domain) if args.domain else None

    hard_stop = f.n_errors > 0 and not args.force

    if args.json:
        print(json.dumps({
            "record_name": record_name,
            "record": record,
            "zonefile": f'{record_name}. IN TXT "{record}"' if record_name else None,
            "reads_as": f.record_summary,
            "findings": f.as_dicts(),
            "emitted": not hard_stop,
        }, indent=2))
        sys.exit(1 if hard_stop else 0)

    print("# DNS TXT record (draft Section 6.1)")
    if record_name:
        print(f"#   name: {record_name}")
    print()
    if f.items:
        print(f.render())
        print()
    if hard_stop:
        print("# NOT EMITTING: the record has ERROR-level problems above.")
        print("# Fix them, or re-run with --force if you are certain (e.g. case (h) intent).")
        sys.exit(1)
    print(record)
    if f.record_summary:
        print(f"# reads as: {f.record_summary}")
    if record_name:
        print()
        print("# zone-file line:")
        print(f'{record_name}. IN TXT "{record}"')


def lint_record(record_text, selector=None, domain=None, is_make=False,
                fetch_d=False, descriptor_bytes=None, at_time=None):
    """Check one record string against the draft's rules. Returns Findings.

    selector/domain are optional context: some rules (case (h), r= placement)
    depend on knowing the selector number. at_time (unix seconds) is the moment
    the key-validity verdict is evaluated against; None means "now".
    """
    f = Findings()
    tags, parse_findings = parse_record(record_text)
    f.extend(parse_findings)
    key_label = None       # captured for the one-line record summary
    validity_word = None

    # ---- required tags -----------------------------------------------------
    for tag in REQUIRED_RECORD_TAGS:
        if tag not in tags:
            f.error("MISSING", f"required tag '{tag}=' is absent (Section 6.1)")

    # ---- v ---------------------------------------------------------------
    if "v" in tags and tags["v"] != PROTOCOL_VERSION:
        f.error("V-VALUE", f"v={tags['v']!r}; this tool implements v={PROTOCOL_VERSION}")

    # ---- a ---------------------------------------------------------------
    if "a" in tags:
        if not tags["a"]:
            f.error("A-EMPTY", "a= is empty")
        elif not re.search(r"-\d+$", tags["a"]):
            f.warn("A-VERSION",
                   f"a={tags['a']!r} has no version suffix; the draft SHOULD-recommends "
                   f"e.g. '{tags['a']}-1' (Section 6.1)")
        if tags["a"] in KNOWN_ALGORITHMS:
            f.info("A-REGISTRY", f"a={tags['a']!r}: {KNOWN_ALGORITHMS[tags['a']]}")
        else:
            f.warn("A-REGISTRY",
                   f"a={tags['a']!r} is not a recognized algorithm "
                   f"(known: {', '.join(KNOWN_ALGORITHMS)}). No IANA registry exists yet "
                   f"(Section 15); a verifier MUST reject an unrecognized value.")

    # ---- p ---------------------------------------------------------------
    if "p" in tags:
        if not tags["p"]:
            f.error("P-EMPTY", "p= is empty (that would mean a revoked key in DKIM; use s=revoked here)")
        else:
            raw = None
            try:
                raw = base64.b64decode(tags["p"], validate=True)
            except Exception:
                f.error("P-B64", "p= is not valid base64")
            if raw is not None:
                key = inspect_spki(raw)
                key_label = key["label"] if key else "non-SPKI key"
                if key is None:
                    f.warn("P-NOT-SPKI",
                           f"p= is valid base64 ({len(raw)} bytes) but is not a recognizable "
                           f"SubjectPublicKeyInfo (DER) structure. This tool and DKIM put an "
                           f"SPKI blob in p=; the draft (Section 6.1) leaves p='s exact form to "
                           f"the a= scheme, so key type and size cannot be checked here. If p= "
                           f"is a raw symmetric key, publishing it exposes forge/strip, not just "
                           f"verify (Section 10.3).")
                else:
                    f.info("P-KEYINFO",
                           f"p= is {key['label']} ({key['bits']}-bit public key), "
                           f"SPKI DER, {len(raw)} bytes")
                    if key["kind"] == "rsa" and key["bits"] < 2048:
                        f.warn("P-WEAK-KEY",
                               f"p= is RSA-{key['bits']}; use at least 2048-bit (3072+ to match "
                               f"Ed25519's ~128-bit strength)")
                    if key["kind"] == "ec" and key["bits"] and key["bits"] < 256:
                        f.warn("P-WEAK-KEY", f"p= is {key['label']} (< 256-bit)")
                    if key["kind"] == "eddsa" and key["label"] == "Ed25519" and key["bits"] != 256:
                        f.warn("P-KEY-MALFORMED",
                               f"p= claims Ed25519 but the key body is {key['bits']} bits, not 256")

    # ---- c ---------------------------------------------------------------
    c_norm = None
    if "c" in tags:
        raw_c = tags["c"].strip()
        c_norm = normalize_c(raw_c)
        if c_norm not in ("sign", "re-sign"):
            f.error("C-VALUE", f"c={raw_c!r} is not 'sign', 're-sign', or the 'resign' alias (Section 6.1)")
        elif raw_c.lower() == "resign":
            if is_make:
                f.error("C-CANONICAL",
                        "generators MUST emit c=re-sign, not c=resign (Section 6.1); "
                        "the 'resign' spelling is a verifier-side accept-only alias")
            else:
                f.info("C-ALIAS", "c=resign accepted as an alias for c=re-sign (Section 6.1)")

    # ---- s ---------------------------------------------------------------
    s_val = tags.get("s", "active")
    if "s" in tags and tags["s"] not in ("active", "revoked", "deprecated"):
        f.error("S-VALUE", f"s={tags['s']!r} must be 'active' or 'revoked' (Section 6.1)")

    # ---- nb / na -------------------------------------------------------
    nb_val = na_val = None
    if "nb" in tags:
        if re.fullmatch(r"\d+", tags["nb"]):
            nb_val = int(tags["nb"])
        else:
            f.error("NB-VALUE", f"nb={tags['nb']!r} must be a unix timestamp (seconds)")
    if "na" in tags:
        if tags["na"].lower() == "ongoing":
            na_val = "ongoing"
        elif re.fullmatch(r"\d+", tags["na"]):
            na_val = int(tags["na"])
        else:
            f.error("NA-VALUE", f"na={tags['na']!r} must be a unix timestamp or the literal 'ongoing'")
    if isinstance(nb_val, int) and isinstance(na_val, int) and na_val < nb_val:
        f.error("NA-BEFORE-NB", f"na ({na_val}) is earlier than nb ({nb_val}); the draft requires na >= nb (Section 6.1)")

    # ---- key-validity verdict at a wall-clock time --------------------
    now = at_time if at_time is not None else int(time.time())
    when = "now" if at_time is None else f"as of {_fmt_ts(now)}"
    if s_val in ("revoked", "deprecated"):
        validity_word = "revoked"
        f.warn("KEY-VALIDITY",
               f"key status: REVOKED (s={s_val}) -- verifiers MUST NOT treat it as valid "
               f"for any verification, including historical text (Section 9.2)")
    elif isinstance(nb_val, int) and now < nb_val:
        validity_word = "not yet valid"
        f.warn("KEY-VALIDITY",
               f"key status: NOT YET VALID {when} -- the nb start time is in the future")
    elif isinstance(na_val, int) and now > na_val:
        validity_word = "expired"
        f.warn("KEY-VALIDITY",
               f"key status: EXPIRED {when} -- the na end time has passed "
               f"(text signed inside its window may still verify; new use MUST NOT)")
    elif isinstance(nb_val, int) and na_val is not None:
        validity_word = "valid"
        f.info("KEY-VALIDITY", f"key status: VALID {when}")

    # ---- d / dh -------------------------------------------------------
    has_d = "d" in tags and tags["d"]
    has_dh = "dh" in tags and tags["dh"]
    if has_d:
        if not tags["d"].lower().startswith("https://"):
            f.error("D-SCHEME", f"d={tags['d']!r}: HTTPS is REQUIRED, plain HTTP MUST NOT be used (Section 6.1)")
        if not has_dh:
            if c_norm == "re-sign":
                f.error("DH-REQUIRED",
                        "dh= is REQUIRED when c=re-sign is used with a d= document "
                        "(Section 6.1 / 9.4)")
            else:
                f.warn("DH-RECOMMENDED", "dh= is RECOMMENDED whenever d= is present (Section 6.1)")
    if has_dh:
        algo, raw = parse_dh(tags["dh"])
        if algo is None:
            f.error("DH-FORMAT",
                    f"dh={tags['dh']!r}: expected '<algo>-<base64url>' with algo in "
                    f"{sorted(set(DH_ALGOS))} (Section 6.1)")
        elif raw is None:
            f.error("DH-B64", f"dh= hash portion is not decodable base64/base64url")
        else:
            _, expected_len = DH_ALGOS[algo]
            if len(raw) != expected_len:
                f.error("DH-LEN",
                        f"dh= digest is {len(raw)} bytes; {algo} produces {expected_len}")
        if not has_d:
            f.warn("DH-NO-D", "dh= present without d=; nothing to hash")

    # ---- r ---------------------------------------------------------------
    if "r" in tags:
        if not re.fullmatch(r"\d+", tags["r"]):
            f.error("R-VALUE", f"r={tags['r']!r} must be a positive integer")
        if selector is not None and selector != 1:
            f.warn("R-PLACEMENT",
                   f"r= appears on selector {selector}; the draft says it SHOULD be on "
                   f"selector 1 only and MUST be ignored elsewhere (Section 6.1)")
        elif selector is None:
            f.info("R-PLACEMENT", "r= should appear on selector 1 only (Section 6.1)")
    elif selector == 1:
        f.info("R-ABSENT",
               "no r= on selector 1: verifiers must crawl forward until a lookup "
               "fails rather than knowing the selector count up front (Section 6.2)")

    # ---- unknown tags -------------------------------------------------
    for key in tags:
        if key not in KNOWN_RECORD_TAGS:
            f.warn("UNKNOWN-TAG", f"tag {key!r} is not defined by the draft; a verifier will ignore it")

    # ---- case (h): selector 1 + c=re-sign + no d= --------------------
    if selector == 1 and c_norm == "re-sign" and not has_d:
        f.warn("CASE-H",
               "selector 1 with c=re-sign and no d= (case (h)): a downstream verifier "
               "cannot tell self-loop re-signing from 'modifies others' text but never "
               "generates'. The draft says tooling should flag this and recommend "
               "publishing at 2._watermark-text or higher unless this is truly intended.")
        if is_make:
            f.error("CASE-H-BLOCK",
                    "refusing to emit case (h) by default; pass --force if selector 1 "
                    "c=re-sign with no d= is really what you want")

    # ---- case (g): single re-sign record WITH d= ---------------------
    if selector == 1 and c_norm == "re-sign" and has_d and tags.get("r") in ("1", None):
        f.warn("CASE-G",
               "selector 1, c=re-sign, with d= (case (g)): implies this provider only "
               "ever modifies existing text and never generates from scratch, which the "
               "draft notes 'would be odd'. Verifiers may still accept it.")

    # ---- fetch the d= document, verify it, read its contents (cases i, j) ----
    if has_d and (fetch_d or descriptor_bytes is not None):
        origin = "local file" if descriptor_bytes is not None else tags["d"]
        try:
            body = descriptor_bytes if descriptor_bytes is not None else load_bytes_from_arg(tags["d"], f)
        except Exception as exc:
            f.error("D-FETCH", f"could not fetch d= document {tags['d']!r}: {exc}")
            body = None
        if body is not None:
            # case (j): the document MUST hash to dh=
            digest_ok = None
            if has_dh:
                algo, raw = parse_dh(tags["dh"])
                if algo and raw is not None:
                    hashlib_name, _ = DH_ALGOS[algo]
                    actual = hashlib.new(hashlib_name, body).digest()
                    digest_ok = actual == raw
                    if not digest_ok:
                        f.error("CASE-J",
                                f"d= document does not hash to dh= (case (j)): "
                                f"computed {algo}-{base64.urlsafe_b64encode(actual).decode()} "
                                f"-- a verifier MUST treat this as a failed verification")
                    else:
                        f.info("DH-OK", "d= document matches dh= digest")

            # parse the contents
            try:
                parsed = json.loads(body)
            except Exception as exc:
                f.error("D-JSON", f"d= document is not valid JSON: {exc}")
                parsed = None
            if parsed is not None and not isinstance(parsed, dict):
                f.error("D-JSON", f"d= document must be a JSON object, got {type(parsed).__name__}")
                parsed = None

            # check the contents against the Section 7.2 schema + cases i/g
            if isinstance(parsed, dict):
                validate_descriptor_obj(
                    OrderedDict(parsed), f,
                    expected_selector=str(selector) if selector is not None else None,
                    expected_provider=domain,
                    dns_c=tags.get("c"),
                )
                extras = [k for k in parsed if k not in DESCRIPTOR_REQUIRED_FIELDS]
                if extras:
                    f.info("D-EXTRA",
                           f"descriptor carries non-schema field(s): {', '.join(extras)} "
                           f"(allowed by Section 7.2 as long as they don't collide)")
                if normalize_c(str(parsed.get("c", ""))) == "sign" \
                        and str(parsed.get("received_from", "")).strip():
                    f.warn("D-SIGN-SOURCE",
                           f"descriptor says c=sign but also names received_from="
                           f"{parsed.get('received_from')!r}; c=sign means fresh generation "
                           f"with no upstream source")

            # attach the fetched document so callers can print its contents
            f.descriptor = {
                "origin": origin,
                "url": tags["d"],
                "bytes": len(body),
                "is_json": isinstance(parsed, dict),
                "json": parsed if isinstance(parsed, dict) else None,
                "raw": body.decode("utf-8", "replace"),
                "digest_ok": digest_ok,
                "fields": (_descriptor_field_rows(parsed, tags, selector, domain)
                           if isinstance(parsed, dict) else None),
                "reads_as": describe_custody(parsed, selector) if isinstance(parsed, dict) else None,
            }

    f.record_summary = describe_record(tags, selector, domain, key_label, validity_word,
                                       nb_val, na_val)
    return f


def describe_record(tags, selector, domain, key_label, validity_word, nb_val, na_val):
    """One-line plain-English reading of a _watermark-text record."""
    if "v" not in tags or "c" not in tags:
        return None  # too broken to summarize
    who = domain or "this provider"
    if selector is not None:
        subject = f"{who} selector {selector}"
        if selector == 1 and re.fullmatch(r"\d+", tags.get("r", "")):
            subject += f" of {tags['r']}"
    else:
        subject = who

    c = normalize_c(tags.get("c", ""))
    has_d = bool(tags.get("d"))
    role = {
        "sign": "signs fresh text",
        "re-sign": ("re-signs prior watermarked text (custody document attached)"
                    if has_d else "re-signs its own earlier text"),
    }.get(c, "custody type unclear")

    seg = f"{key_label or 'key'}, {role}"

    if validity_word == "revoked":
        val = "REVOKED"
    elif validity_word == "not yet valid":
        val = (f"not yet valid (starts {_fmt_date(nb_val)})"
               if isinstance(nb_val, int) else "not yet valid")
    elif validity_word == "expired":
        val = (f"EXPIRED (window ended {_fmt_date(na_val)})"
               if isinstance(na_val, int) else "EXPIRED")
    elif validity_word == "valid":
        if isinstance(nb_val, int):
            end = "ongoing" if na_val == "ongoing" else (
                _fmt_date(na_val) if isinstance(na_val, int) else "?")
            val = f"valid ({_fmt_date(nb_val)} -> {end})"
        else:
            val = "valid"
    else:
        val = None

    return f"{subject} -- {seg}" + (f"; {val}" if val else "")


GENERIC_SOURCE_PHRASES = {
    "all other text watermark services", "all other watermark services",
    "all other services", "any other provider", "another ai",
    "another ai service", "unspecified", "unknown",
}


def describe_custody(obj, selector=None):
    """A plain-English reading of a custody descriptor, following the wording of
    the draft's Section 7.5 worked examples."""
    if not isinstance(obj, dict):
        return None
    provider = obj.get("provider") or "this provider"
    sel = obj.get("selector") or selector
    rf = str(obj.get("received_from") or "").strip()
    c = normalize_c(str(obj.get("c") or ""))

    # where the re-signing key lives: <selector>._watermark-text.<provider>
    key_loc = (f"{sel}.{WELL_KNOWN_LABEL}.{provider}"
               if sel is not None and provider != "this provider" else None)
    with_key = f" with the key at {key_loc}" if key_loc else ""

    # ts is when the d= descriptor was published -- not the key window, not
    # necessarily when the re-signing happened (Section 7.1 / 7.2).
    ts = obj.get("ts")
    ts_note = ""
    if ts is not None and re.fullmatch(r"-?\d+", str(ts)):
        ts_note = f"; this custody descriptor was published {_fmt_ts(ts)}"

    if c == "sign":
        return f"text generated fresh by {provider} under selector {sel}{ts_note}"

    if not rf:
        body = f"{provider} re-signed this text{with_key} but names no upstream source"
    elif rf.lower() in GENERIC_SOURCE_PHRASES:
        body = (f"{provider} verified this text was AI-generated by some other service "
                f"(deliberately unnamed) and re-signed it{with_key}")
    elif " via " in rf:
        hops = [h.strip() for h in rf.split(" via ")]
        chain = hops[0]
        for h in hops[1:]:
            chain += f", which said it came from {h}"
        body = (f"watermark from {provider} (re-signed{with_key}), which says the text "
                f"came from {chain}")
    else:
        body = (f"watermark from {provider}, which says it received the text from {rf} "
                f"and re-signed it{with_key}")
    return body + ts_note


def format_descriptor_block(desc, indent=""):
    """Render a fetched d= document (dict from lint_record's f.descriptor):
    a header line, the field-by-field table, then the plain-English reading."""
    if not desc:
        return ""
    lines = [f"{indent}d= document -- {desc['url']}  ({desc['bytes']} bytes)"]
    if not desc["is_json"]:
        lines.append(f"{indent}  not a JSON object -- the normative d= form is JSON (Section 7.2)")
        for pl in desc["raw"][:600].splitlines():
            lines.append(f"{indent}  | {pl}")
        return "\n".join(lines)
    if desc.get("fields"):
        inner = indent + "  "
        labelw = max([len("d= field")] + [len(r[0]) for r in desc["fields"]])
        lines.append(render_box_table(
            ["d= field", "status", "comment"], desc["fields"], inner,
            max_widths=[None, None, _comment_cap(inner, labelw)]))
    if desc["reads_as"]:
        lines.append(f"{indent}  reads as: {desc['reads_as']}")
    return "\n".join(lines)


def _unwrap_record(text):
    """Reduce a single line to its bare tag-value record: join quoted
    character-strings if present (handles `name IN TXT "..."` and `"..."`),
    otherwise return the text unchanged."""
    text = text.strip()
    chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
    if chunks:
        return "".join(c.replace('\\"', '"').replace("\\\\", "\\") for c in chunks)
    return text


def cmd_lint(args):
    at = parse_ts(args.at) if args.at else None  # key-validity evaluated at this time

    # ---- 1. --record: a zone file by path, or 'input' to read one from stdin ----
    if args.record:
        if args.crawl:
            print("# note: --crawl ignored with --record", file=sys.stderr)
        if args.record == "input":
            src = "<stdin>"
            try:
                if sys.stdin.isatty():
                    print("# type or paste the record(s), then Enter (Ctrl-C to cancel):",
                          file=sys.stderr)
                    lines = [sys.stdin.readline()]
                    # a multi-line paste arrives all at once; drain whatever else is
                    # already buffered, but don't wait around for a human to type more
                    try:
                        import select
                        while select.select([sys.stdin], [], [], 0.1)[0]:
                            nxt = sys.stdin.readline()
                            if not nxt:
                                break
                            lines.append(nxt)
                    except (OSError, ValueError):
                        pass
                    raw = "".join(lines)
                else:
                    raw = sys.stdin.read()
            except KeyboardInterrupt:
                sys.exit("\ncancelled")
        elif os.path.isfile(args.record):
            with open(args.record, encoding="utf-8", errors="replace") as fh:
                raw, src = fh.read(), args.record
        else:
            sys.exit(f"error: --record must be a path to a zone file, or the word "
                     f"'input' to read one from stdin (got {args.record!r})")

        entries = parse_zone_records(raw, default_domain=args.domain)
        if not entries and args.record == "input":
            # stdin convenience: also accept a single unquoted record string
            one = _unwrap_record(raw)
            if "v=" in one:
                entries = [{"name": None, "selector": args.selector,
                            "domain": args.domain.strip(".") if args.domain else None,
                            "record": one}]
        if not entries:
            sys.exit(f"no watermark-text TXT records found in {src} "
                     f"(in a zone file the TXT data must be quoted)")

        descriptor_bytes = load_bytes_from_arg(args.d_file) if args.d_file else None
        results = []
        for e in entries:
            sel = e["selector"] if e["selector"] is not None else args.selector
            dom = e["domain"] or (args.domain.strip(".") if args.domain else None)
            results.append((e["record"],
                            lint_record(e["record"], selector=sel, domain=dom,
                                        fetch_d=args.verify_d,
                                        descriptor_bytes=descriptor_bytes, at_time=at)))
        _emit_lint_file(src, entries, results, args.json)
        sys.exit(0 if all(f.n_errors == 0 for _, f in results) else 1)

    # ---- 2/3. a live DNS lookup keyed on --domain ----
    if not args.domain:
        sys.exit("error: give --record, or --domain (optionally with --selector and/or --crawl)")
    domain = args.domain.strip(".")

    if not args.crawl:
        # single selector: the one named by --selector, or 1._watermark-text by default
        selector = args.selector if args.selector is not None else 1
        name = selector_name(selector, domain)
        cname = dig_cname(name)
        records = dig_txt(name)
        if not records:
            status, _ = dig_status(name)
            sys.exit(f"no TXT record at {name} (DNS status: {status})")
        if len(records) > 1:
            print(f"# note: {len(records)} TXT records at {name}; linting each", file=sys.stderr)
        results = [(rec, lint_record(rec, selector=selector, domain=domain,
                                     fetch_d=args.verify_d, at_time=at))
                   for rec in records]
        _emit_lint_results(name, cname, results, args.json)
        sys.exit(0 if all(f.n_errors == 0 for _, f in results) else 1)

    # ---- 4. crawl and lint every selector ----
    start = args.selector if args.selector is not None else 1
    crawl = lint_crawl(domain, start, fetch_d=args.verify_d,
                       max_selectors=args.max_selectors, at_time=at)
    _emit_lint_crawl(crawl, args.json)
    found_any = any(not e["missing"] for e in crawl["selectors"].values())
    any_err = any(f.n_errors for entry in crawl["selectors"].values()
                  for _, f in entry["results"])
    sys.exit(0 if found_any and not any_err else 1)


def lint_crawl(domain, start, fetch_d=False, max_selectors=50, at_time=None):
    """Walk a provider's selectors upward from `start`, linting each.

    start == 1  -- if selector 1 carries an r= tag, crawl 1..r (a selector inside
                   that range with no record is reported as a GAP); otherwise
                   auto-increment from 1 until a lookup returns nothing.
    start >= 2  -- auto-increment from `start` until a lookup returns nothing.
                   r= lives on selector 1 only, so it is not consulted here.

    Returns a dict: {domain, start, mode ('r-tag'|'auto-increment'), r_declared,
    selectors (OrderedDict[int -> entry]), stopped (human message)}. Each entry:
    {name, cname, results ([(record_str_or_None, Findings)]), missing, status}.
    """
    selectors = OrderedDict()
    r_declared = None
    mode = "auto-increment"

    def fetch(n):
        name = selector_name(n, domain)
        return name, dig_cname(name), dig_txt(name)

    def lint_all(n, recs):
        return [(r, lint_record(r, selector=n, domain=domain, fetch_d=fetch_d, at_time=at_time))
                for r in recs]

    if start == 1:
        name, cname, recs = fetch(1)
        if not recs:
            status, _ = dig_status(name)
            selectors[1] = {"name": name, "cname": cname, "results": [],
                            "missing": True, "status": status}
            return {"domain": domain, "start": 1, "mode": mode, "r_declared": None,
                    "selectors": selectors,
                    "stopped": f"no record at {name} (DNS status {status}); "
                               f"provider does not publish under this framework"}
        selectors[1] = {"name": name, "cname": cname, "results": lint_all(1, recs),
                        "missing": False, "status": "NOERROR"}
        tags, _ = parse_record(recs[0])
        if "r" in tags and re.fullmatch(r"\d+", tags["r"]):
            r_declared = int(tags["r"])
            mode = "r-tag"
        next_n = 2
    else:
        next_n = start

    if mode == "r-tag":
        upper = min(r_declared, max_selectors)
        gaps = []
        for n in range(2, upper + 1):
            name, cname, recs = fetch(n)
            if not recs:
                status, _ = dig_status(name)
                f = Findings()
                f.error("GAP", f"selector {n} is within the declared r={r_declared} range "
                               f"but has no TXT record (DNS status {status})")
                selectors[n] = {"name": name, "cname": cname, "results": [(None, f)],
                                "missing": True, "status": status}
                gaps.append(n)
            else:
                selectors[n] = {"name": name, "cname": cname, "results": lint_all(n, recs),
                                "missing": False, "status": "NOERROR"}
        stopped = f"reached declared r={r_declared}"
        if r_declared > max_selectors:
            stopped += f" (stopped early at --max-selectors={max_selectors})"
        if gaps:
            stopped += f"; missing selector(s): {', '.join(map(str, gaps))}"
        return {"domain": domain, "start": start, "mode": mode, "r_declared": r_declared,
                "selectors": selectors, "stopped": stopped}

    # auto-increment
    highest = max(selectors) if selectors else None
    n = next_n
    limit = next_n + max_selectors
    while n < limit:
        name, cname, recs = fetch(n)
        if not recs:
            status, _ = dig_status(name)
            last = highest if highest is not None else "none"
            return {"domain": domain, "start": start, "mode": mode, "r_declared": None,
                    "selectors": selectors,
                    "stopped": f"no record at {name} (DNS status {status}); crawl only "
                               f"goes up to the last selector found: {last}"}
        selectors[n] = {"name": name, "cname": cname, "results": lint_all(n, recs),
                        "missing": False, "status": "NOERROR"}
        highest = n
        n += 1
    return {"domain": domain, "start": start, "mode": mode, "r_declared": None,
            "selectors": selectors,
            "stopped": f"stopped at --max-selectors={max_selectors} without an empty "
                       f"lookup (highest selector found: {highest})"}


# Which table row each finding code belongs to. Codes not listed fall back to
# their prefix (before the first '-'), lowercased, or to "other".
_ROW_FOR_CODE = {
    "V-VALUE": "v",
    "A-EMPTY": "a", "A-VERSION": "a", "A-REGISTRY": "a",
    "P-EMPTY": "p", "P-B64": "p", "P-NOT-SPKI": "p", "P-WEAK-KEY": "p",
    "P-KEY-MALFORMED": "p", "P-KEYINFO": "p",
    "C-VALUE": "c", "C-CANONICAL": "c", "C-ALIAS": "c", "D-C-MISMATCH": "c",
    "S-VALUE": "s",
    "NB-VALUE": "nb",
    "NA-VALUE": "na", "NA-BEFORE-NB": "na",
    "D-SCHEME": "d", "D-FETCH": "d", "D-JSON": "d",
    "DH-REQUIRED": "dh", "DH-RECOMMENDED": "dh", "DH-FORMAT": "dh", "DH-B64": "dh",
    "DH-LEN": "dh", "DH-NO-D": "dh", "DH-OK": "dh", "CASE-J": "dh",
    "R-VALUE": "r", "R-PLACEMENT": "r", "R-ABSENT": "r",
    "KEY-VALIDITY": "validity",
    "CASE-G": "custody", "CASE-H": "custody", "CASE-H-BLOCK": "custody",
    "SYNTAX": "syntax", "DUP-TAG": "syntax",
    "D-MISSING": "d= doc", "D-C-VALUE": "d= doc", "D-SELECTOR": "d= doc",
    "D-PROVIDER": "d= doc", "D-TS": "d= doc", "D-EXTRA": "d= doc",
    "D-SIGN-SOURCE": "d= doc",
}
_TABLE_ROW_ORDER = ["syntax", "v", "a", "p", "c", "d", "dh", "s", "nb", "na",
                    "validity", "r", "custody", "d= doc", "other"]
_LEVEL_RANK = {"OK": 0, "INFO": 1, "WARN": 2, "ERROR": 3}


# When a d= document was fetched, these findings are shown in the dedicated
# descriptor table instead of the record table, so the record table drops them.
_DESCRIPTOR_COVERED = {
    "D-MISSING", "D-C-VALUE", "D-SELECTOR", "D-PROVIDER", "D-TS", "D-EXTRA",
    "D-SIGN-SOURCE", "D-C-MISMATCH", "D-JSON",
}


def _finding_row(code, message):
    if code in _ROW_FOR_CODE:
        return _ROW_FOR_CODE[code]
    if code == "MISSING":
        m = re.search(r"tag '([a-z]+)=", message)
        return m.group(1) if m else "other"
    if code == "UNKNOWN-TAG":
        m = re.search(r"tag '([^']+)'", message)
        return m.group(1) if m else "other"
    prefix = code.split("-", 1)[0].lower()
    return prefix if prefix in _TABLE_ROW_ORDER else "other"


def _comment_cap(indent, label_w, status_w=6):
    """Terminal-aware width for the last (comment) column of a 3-column table."""
    try:
        cols = shutil.get_terminal_size((100, 24)).columns
    except (ValueError, OSError):
        cols = 100
    return max(40, min(100, cols - len(indent) - label_w - status_w - 10))


_STATUS_DISPLAY = {"OK": "ok", "INFO": "info"}  # WARN / ERROR stay upper-case


def _clean_comment(tag, tags):
    """What to show in the comment column of a row that has no findings: the
    tag's own value (decoded, where that helps) rather than a bare 'n/a'.
    nb/na also show '(YYYY-MM-DD HH:MM:SS)'. The validity row is synthesized
    from KEY-VALIDITY and never reaches here."""
    if tag in ("nb", "na"):
        raw = tags.get(tag)
        if raw is None:
            return "n/a"
        if tag == "na" and raw.lower() == "ongoing":
            return "ongoing"
        if re.fullmatch(r"\d+", raw):
            return f"{raw}  ({_fmt_dt(raw)})"
        return raw
    if tag in ("v", "c", "d", "dh", "s", "r", "a", "p"):
        return tags.get(tag) or "n/a"
    return "n/a"


def _descriptor_field_rows(parsed, record_tags, selector, domain):
    """Rows for the d= descriptor table: (field, status, comment), covering the
    five Section 7.2 fields plus any extra fields. (The digest check stays on the
    record table's dh= row.)"""
    rows = []
    rec_c = normalize_c(record_tags.get("c", ""))
    doc_c = normalize_c(str(parsed.get("c", "")))
    for key in DESCRIPTOR_REQUIRED_FIELDS:
        val = parsed.get(key)
        if val in (None, ""):
            rows.append((key, "ERROR", "missing -- required by Section 7.2"))
        elif key == "c":
            if rec_c and doc_c != rec_c:
                rows.append(("c", "ERROR",
                             f'"{val}" but the record says c={record_tags.get("c")!r} -- '
                             f'case (i): MUST fail verification / MUST NOT publish'))
            elif doc_c not in ("sign", "re-sign"):
                rows.append(("c", "ERROR", f'"{val}" is not "sign" or "re-sign"'))
            else:
                rows.append(("c", "ok", f'"{val}" (matches the record\'s c=)'))
        elif key == "selector":
            if selector is not None and str(val) != str(selector):
                rows.append(("selector", "WARN",
                             f'"{val}" -- does not match the queried selector {selector}'))
            else:
                rows.append(("selector", "ok", f'"{val}"'))
        elif key == "provider":
            if domain and str(val) != str(domain):
                rows.append(("provider", "WARN",
                             f'"{val}" -- does not match the queried zone "{domain}"'))
            else:
                rows.append(("provider", "ok", f'"{val}"'))
        elif key == "ts":
            if re.fullmatch(r"-?\d+", str(val)):
                rows.append(("ts", "ok", f"{val}  ({_fmt_dt(val)})"))
            else:
                rows.append(("ts", "WARN", f'"{val}" -- should be a unix epoch integer'))
        else:  # received_from
            if doc_c == "sign" and str(val).strip():
                rows.append((key, "WARN",
                             f'"{val}" -- but c=sign means fresh generation, no upstream source'))
            else:
                rows.append((key, "ok", f'"{val}"'))

    for k, v in parsed.items():
        if k not in DESCRIPTOR_REQUIRED_FIELDS:
            rows.append((k, "info", f'"{v}" -- non-schema field (allowed, Section 7.2)'))
    return rows


def _wrap_cell(text, width):
    """Break `text` to fit `width`, on spaces where possible. Returns >=1 lines."""
    text = str(text)
    if len(text) <= width:
        return [text]
    lines, cur = [], ""
    for word in text.split(" "):
        piece = word if not cur else cur + " " + word
        if len(piece) <= width:
            cur = piece
            continue
        if cur:
            lines.append(cur)
            cur = ""
        while len(word) > width:              # a single over-long token
            lines.append(word[:width])
            word = word[width:]
        cur = word
    if cur:
        lines.append(cur)
    return lines or [""]


def render_box_table(headers, rows, indent="", max_widths=None):
    """A psql-style bordered table. Cells wider than max_widths[i] are wrapped
    onto extra physical lines; the right border stays aligned."""
    ncol = len(headers)
    max_widths = (max_widths or [None] * ncol)
    widths = []
    for i in range(ncol):
        natural = max([len(str(headers[i]))] + [len(str(r[i])) for r in rows])
        widths.append(min(natural, max_widths[i]) if max_widths[i] else natural)

    rule = indent + "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def emit(cells):
        wrapped = [_wrap_cell(cells[i], widths[i]) for i in range(ncol)]
        height = max(len(w) for w in wrapped)
        out = []
        for li in range(height):
            cols = []
            for i in range(ncol):
                seg = wrapped[i][li] if li < len(wrapped[i]) else ""
                cols.append(" " + seg.ljust(widths[i]) + " ")
            out.append(indent + "|" + "|".join(cols) + "|")
        return out

    lines = [rule, *emit(headers), rule]
    for r in rows:
        lines.extend(emit(r))
    lines.append(rule)
    return "\n".join(lines)


def render_findings_table(f, record_str, indent=""):
    """One row per expected value: | tag | OK/INFO/WARN/ERROR | comment |.
    Required tags always appear; optional tags (d, dh, s, r) only when present;
    synthesized rows (validity, custody, syntax, d= doc) only when they have
    something to say. 'n/a' comment means nothing to report for that tag."""
    tags, _ = parse_record(record_str)
    covered = _DESCRIPTOR_COVERED if f.descriptor is not None else set()
    grouped = OrderedDict()
    for lvl, code, msg in f.items:
        if code in covered:
            continue  # shown in the d= descriptor table instead
        grouped.setdefault(_finding_row(code, msg), []).append((lvl, msg))

    order = ["v", "a", "p", "c", "nb", "na"]
    order += [t for t in ("d", "dh", "s", "r") if t in tags]
    order += [r for r in grouped if r not in order]
    order = ([r for r in _TABLE_ROW_ORDER if r in order]
             + [r for r in order if r not in _TABLE_ROW_ORDER])

    rows = []
    for row in order:
        finds = grouped.get(row, [])
        if not finds:
            rows.append((row, "ok", _clean_comment(row, tags)))
        else:
            worst = max(finds, key=lambda lm: _LEVEL_RANK.get(lm[0], 0))[0]
            rows.append((row, _STATUS_DISPLAY.get(worst, worst),
                         "; ".join(m for _, m in finds)))

    tagw = max([len("tag")] + [len(r[0]) for r in rows])
    return render_box_table(["tag", "status", "comment"], rows, indent,
                            max_widths=[None, None, _comment_cap(indent, tagw)])


def _emit_lint_file(path, entries, results, as_json):
    """Render lint results for a batch of records parsed from a zone file."""
    if as_json:
        print(json.dumps({
            "source_file": path,
            "records": [
                {"name": e["name"], "selector": e["selector"], "domain": e["domain"],
                 "record": rec, "findings": f.as_dicts(),
                 "errors": f.n_errors, "warnings": f.n_warnings,
                 "descriptor": f.descriptor, "reads_as": f.record_summary}
                for e, (rec, f) in zip(entries, results)
            ],
        }, indent=2))
        return
    print(f"# {path} -- {len(results)} record(s)")
    for e, (rec, f) in zip(entries, results):
        print()
        print(f"# {e['name'] or '(unnamed record)'}")
        print(f"  {rec}")
        if f.record_summary:
            print(f"  reads as: {f.record_summary}")
        print()
        print(render_findings_table(f, rec, indent="  "))
        if f.descriptor:
            print()
            print(format_descriptor_block(f.descriptor, indent="  "))
        print(f"  => {f.n_errors} error(s), {f.n_warnings} warning(s)")
    te = sum(f.n_errors for _, f in results)
    tw = sum(f.n_warnings for _, f in results)
    print()
    print(f"# total: {len(results)} record(s), {te} error(s), {tw} warning(s)")


def _emit_lint_crawl(crawl, as_json):
    if as_json:
        print(json.dumps({
            "domain": crawl["domain"],
            "start": crawl["start"],
            "mode": crawl["mode"],
            "r_declared": crawl["r_declared"],
            "stopped": crawl["stopped"],
            "selectors": {
                str(n): {
                    "name": e["name"], "cname": e["cname"],
                    "missing": e["missing"], "status": e["status"],
                    "records": [
                        {"record": rec, "findings": f.as_dicts(),
                         "errors": f.n_errors, "warnings": f.n_warnings,
                         "descriptor": f.descriptor, "reads_as": f.record_summary}
                        for rec, f in e["results"]
                    ],
                } for n, e in crawl["selectors"].items()
            },
        }, indent=2))
        return

    src = "r= tag on selector 1" if crawl["mode"] == "r-tag" else "auto-increment"
    print(f"# {crawl['domain']} -- linting selectors from {crawl['start']} ({src})")
    for n, e in crawl["selectors"].items():
        print()
        print(f"# [{n}] {e['name']}")
        if e["cname"]:
            print(f"#     CNAME -> {e['cname']}  (resolves, but authorization unproven -- Section 6.5)")
        if e["missing"] and not e["results"]:
            print("#     (no record)")
        for rec, f in e["results"]:
            if rec is None:  # a declared-but-missing selector: just its GAP finding
                if f.items:
                    print(f.render(indent="  "))
                print(f"  => {f.n_errors} error(s), {f.n_warnings} warning(s)")
                continue
            print(f"  {rec}")
            if f.record_summary:
                print(f"  reads as: {f.record_summary}")
            print()
            print(render_findings_table(f, rec, indent="  "))
            if f.descriptor:
                print()
                print(format_descriptor_block(f.descriptor, indent="  "))
            print()
            print(f"  => {f.n_errors} error(s), {f.n_warnings} warning(s)")
    total_err = sum(f.n_errors for e in crawl["selectors"].values() for _, f in e["results"])
    total_warn = sum(f.n_warnings for e in crawl["selectors"].values() for _, f in e["results"])
    print()
    print(f"# crawl stopped: {crawl['stopped']}")
    print(f"# total: {len(crawl['selectors'])} selector(s) visited, "
          f"{total_err} error(s), {total_warn} warning(s)")


def _emit_lint_results(name, cname, results, as_json):
    if as_json:
        print(json.dumps({
            "record_name": name,
            "cname": cname,
            "records": [
                {"record": rec, "findings": f.as_dicts(),
                 "errors": f.n_errors, "warnings": f.n_warnings,
                 "descriptor": f.descriptor, "reads_as": f.record_summary}
                for rec, f in results
            ],
        }, indent=2))
        return
    if name:
        print(f"# {name}")
    if cname:
        print(f"# CNAME -> {cname}")
        print(f"#   (delegation resolves, but nothing proves {cname} was authorized to")
        print(f"#    hold these keys -- draft Section 6.5 / open question Section 14)")
    for rec, f in results:
        print()
        print(f"  {rec}")
        if f.record_summary:
            print(f"  reads as: {f.record_summary}")
        print()
        print(render_findings_table(f, rec, indent="  "))
        if f.descriptor:
            print()
            print(format_descriptor_block(f.descriptor, indent="  "))
        print()
        print(f"  => {f.n_errors} error(s), {f.n_warnings} warning(s)")


# --------------------------------------------------------------------------- #
# traverse (Section 6.4)                                                       #
# --------------------------------------------------------------------------- #

def format_traverse_report(domain, res, at=None):
    """Render one domain's traverse_provider() result as the same text block
    cmd_traverse prints -- per-selector findings tables and d= descriptor
    blocks. Shared so the web demo shows byte-for-byte what the CLI shows."""
    out = [f"=== {domain} ==="]
    for note in res["notes"]:
        out.append(f"  note: {note}")
    if not res["selectors"]:
        out.append("  (no _watermark-text records found; provider not participating "
                   "or misconfigured)")
        return "\n".join(out)

    for sel, entry in res["selectors"].items():
        fnd = entry["findings"]
        out.append("")
        out.append(f"  [{sel}] {entry['name']}")
        if entry["cname"]:
            out.append(f"      CNAME -> {entry['cname']}")
        out.append(f"      DNSSEC-validated (AD): {'yes' if entry['dnssec_ad'] else 'no'}"
                   f"   usable{' at ' + at if at else ' now'}: {entry['usable']}")
        if entry["record"]:
            out.append(f"      {entry['record']}")
            if fnd.record_summary:
                out.append(f"      reads as: {fnd.record_summary}")
            out.append("")
            out.append(render_findings_table(fnd, entry["record"], indent="      "))
            if fnd.descriptor:
                out.append("")
                out.append(format_descriptor_block(fnd.descriptor, indent="      "))
        elif fnd.items:
            out.append(fnd.render(indent="      "))
        out.append(f"      => {fnd.n_errors} error(s), {fnd.n_warnings} warning(s)")
    out.append("")
    out.append(f"  crawl stopped: {res['stopped_because']}")
    return "\n".join(out)


def cmd_traverse(args):
    domains = []
    if args.seed_file:
        with open(args.seed_file) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
    if args.domain:
        domains.append(args.domain)
    if not domains:
        sys.exit("error: give --domain or --seed-file")

    all_results = OrderedDict()
    for domain in domains:
        all_results[domain] = traverse_provider(
            domain, max_selectors=args.max_selectors, fetch_d=args.verify_d,
            at_time=parse_ts(args.at) if args.at else None,
        )

    if args.json:
        print(json.dumps({
            dom: {
                "selectors": {
                    str(sel): {
                        "name": entry["name"],
                        "cname": entry["cname"],
                        "record": entry["record"],
                        "dnssec_ad": entry["dnssec_ad"],
                        "findings": entry["findings"].as_dicts(),
                        "usable_now": entry["usable"],
                        "descriptor": entry["findings"].descriptor,
                    } for sel, entry in res["selectors"].items()
                },
                "r": res["r"],
                "stopped_because": res["stopped_because"],
                "notes": res["notes"],
            } for dom, res in all_results.items()
        }, indent=2))
        return

    for domain, res in all_results.items():
        print(format_traverse_report(domain, res, at=args.at))
        print()


def traverse_provider(domain, max_selectors=50, fetch_d=False, at_time=None):
    domain = domain.strip(".")
    selectors = OrderedDict()
    notes = []
    r_count = None

    def fetch_selector(n):
        name = selector_name(n, domain)
        cname = dig_cname(name)
        status, ad = dig_status(name)
        records = dig_txt(name)
        return name, cname, status, ad, records

    # step 2: selector 1
    name, cname, status, ad, records = fetch_selector(1)
    if not records:
        notes.append(f"1.{WELL_KNOWN_LABEL}.{domain}: no TXT record (DNS status {status}). "
                     f"Per Section 6.4 the provider is treated as not participating.")
        return {"selectors": selectors, "r": None, "stopped_because": f"no selector 1 ({status})", "notes": notes}

    def record_entry(n, name, cname, ad, records):
        rec = records[0]
        if len(records) > 1:
            notes.append(f"selector {n}: {len(records)} TXT records present; using the first, "
                         f"flagging the rest")
        f = lint_record(rec, selector=n, domain=domain, fetch_d=fetch_d, at_time=at_time)
        usable = record_usable(rec, at_time)
        return {"name": name, "cname": cname, "record": rec, "dnssec_ad": ad,
                "findings": f, "usable": usable}

    selectors[1] = record_entry(1, name, cname, ad, records)
    tags, _ = parse_record(records[0])
    if "r" in tags and re.fullmatch(r"\d+", tags["r"]):
        r_count = int(tags["r"])
        notes.append(f"selector 1 declares r={r_count}; crawling selectors 2..{r_count}")

    # step 3: additional selectors
    stopped = None
    if r_count is not None:
        upper = min(r_count, max_selectors)
        if r_count > max_selectors:
            notes.append(f"r={r_count} exceeds --max-selectors={max_selectors}; stopping early")
        for n in range(2, upper + 1):
            nm, cn, st, adf, recs = fetch_selector(n)
            if not recs:
                selectors[n] = {"name": nm, "cname": cn, "record": None, "dnssec_ad": adf,
                                "findings": _gap_finding(n, st), "usable": False}
                continue
            selectors[n] = record_entry(n, nm, cn, adf, recs)
        stopped = f"reached declared r={r_count}"
    else:
        notes.append("no r= tag on selector 1; crawling forward until a lookup returns nothing "
                     "(Section 6.4 step 3 -- more lookups, which is why r= is RECOMMENDED)")
        n = 2
        while n <= max_selectors:
            nm, cn, st, adf, recs = fetch_selector(n)
            if not recs:
                stopped = f"selector {n} absent (DNS status {st})"
                break
            selectors[n] = record_entry(n, nm, cn, adf, recs)
            n += 1
        else:
            stopped = f"hit --max-selectors={max_selectors} without an empty lookup"

    return {"selectors": selectors, "r": r_count, "stopped_because": stopped, "notes": notes}


def _gap_finding(n, status):
    f = Findings()
    f.error("GAP", f"selector {n} is declared by r= but has no TXT record (DNS status {status})")
    return f


def record_usable(record_text, at_time):
    """True if the record would be usable for a verification (optionally at a
    given epoch time): status not revoked, and at_time within [nb, na]."""
    tags, _ = parse_record(record_text)
    if tags.get("s") in ("revoked", "deprecated"):
        return False
    if at_time is None:
        at_time = int(time.time())
    nb = tags.get("nb")
    na = tags.get("na")
    if nb and re.fullmatch(r"\d+", nb) and at_time < int(nb):
        return False
    if na and na.lower() != "ongoing" and re.fullmatch(r"\d+", na) and at_time > int(na):
        return False
    return True


# --------------------------------------------------------------------------- #
# walkthrough                                                                  #
# --------------------------------------------------------------------------- #

WALKTHROUGH = r"""
================================================================================
  watermark_dns_tool.py -- what this does and the order to do it in
  draft-zink-xboundary-ai-text-watermark-verification-00
================================================================================

This tool builds and checks the concrete artifacts the draft describes. There
are four things you produce, plus two things you check. Every mode is a "--"
flag; give exactly one per invocation.

To be prompted step by step through (a)-(d) instead of running each command
by hand:  python3 watermark_dns_tool.py --create

--------------------------------------------------------------------------------
THE MODEL (draft Sections 6-7), in brief
--------------------------------------------------------------------------------
A participating provider publishes one or more TXT records at a fixed, well-known
DNS location:

    <selector>._watermark-text.<provider-domain>

    e.g.   1._watermark-text.example.ai

Each record is DKIM-style tag=value text:

    v=1; a=<algo-id>; p=<public-key-b64>; c=<sign|re-sign>; d=<https-URL>;
    dh=<algo>-<b64url-hash>; s=active; nb=<unix-ts>; na=<unix-ts|ongoing>; r=<n>

  v   protocol version (always 1 here)                         REQUIRED
  a   watermarking scheme id, e.g. fairoze-1  (SHOULD be versioned)   REQUIRED
  p   PUBLIC verification key, base64 SubjectPublicKeyInfo      REQUIRED
  c   'sign' (fresh generation) or 're-sign' (modified prior watermarked text)
                                                               REQUIRED, no default
  d   HTTPS URL of a JSON custody descriptor    REQUIRED for a cross-vendor re-sign
  dh  digest of the d= document, SRI-style      RECOMMENDED w/ d=, REQUIRED w/ re-sign
  s   'active' (default) or 'revoked'                           OPTIONAL
  nb  not-before, unix seconds                                  REQUIRED
  na  not-after, unix seconds, or literal 'ongoing'             REQUIRED (na >= nb)
  r   total selector count; put on selector 1 only              SHOULD (selector 1)

Selectors are just increasing integers. Rotation = publish a higher-numbered
selector; never renumber or change an existing selector's c=. Old selectors stay
in DNS with na= closed to the rotation date so old text still verifies.

--------------------------------------------------------------------------------
(a) GENERATE A KEY PAIR                                            --keygen
--------------------------------------------------------------------------------
The draft needs an ASYMMETRIC, publicly-detectable scheme (Section 4.1): a
private key embeds the mark, a separate public key verifies it and CANNOT forge
or strip it. This tool makes real asymmetric key pairs (Ed25519 by default) so
you have the right shape -- it does NOT implement watermark embedding/detection.
Ed25519 is the right default; only move to RSA-3072+ for a verifier that cannot
do EdDSA. In a real deployment the key type is dictated by the a= scheme anyway.

    python3 watermark_dns_tool.py --keygen --domain example.ai --selector 1

  -> example.ai selector 1: private.pem (keep secret!), public.pem, and the
     p= value to paste into the record.

  Do NOT publish a symmetric scheme's key here -- that hands out forge/strip
  ability, which is strictly worse than today's vendor siloing (Section 10.3).

--------------------------------------------------------------------------------
(c) BUILD THE d= CUSTODY DESCRIPTOR  (only for re-sign)       --make-descriptor
--------------------------------------------------------------------------------
When your model modifies text that already carried another provider's watermark,
you don't overwrite silently -- you re-sign under a selector whose d= URL serves
this JSON (Section 7.2):

    python3 watermark_dns_tool.py --make-descriptor \
        --received-from otherprovider.ai --provider example.ai \
        --selector 2 --c re-sign --ts now --out desc.json

  Required fields: received_from, selector, provider, c, ts. Extra fields are
  allowed (--extra key=value) as long as they don't collide.
  The command prints the dh= value for exactly the bytes it wrote. If you edit
  the file afterwards (even adding a comment), re-run and update dh= or you get
  a case (j) verification failure.

--------------------------------------------------------------------------------
(d) COMPUTE THE dh= DIGEST                                         --dh
--------------------------------------------------------------------------------
Standalone digest of any file or URL, SRI-style (default sha-256, base64url):

    python3 watermark_dns_tool.py --dh --input desc.json
    python3 watermark_dns_tool.py --dh --input https://.../desc.json

--------------------------------------------------------------------------------
(b) BUILD THE DNS TXT RECORD                                       --make-record
--------------------------------------------------------------------------------
    # fresh generation, selector 1
    python3 watermark_dns_tool.py --make-record --selector 1 --domain example.ai \
        --algorithm fairoze-1 --pubkey public.pem --c sign \
        --nb now --na ongoing --r 1

    # cross-vendor re-sign, selector 2, hash computed from the local descriptor
    python3 watermark_dns_tool.py --make-record --selector 2 --domain example.ai \
        --algorithm fairoze-1 --pubkey public.pem --c re-sign \
        --d https://2._watermark-text.example.ai/desc.json --d-file desc.json \
        --nb now --na ongoing

  --make-record runs the full linter on its own output and REFUSES to emit a
  record with ERROR-level problems (e.g. case (h), case (i)) unless you pass
  --force.

--------------------------------------------------------------------------------
CHECK: LINT RECORDS                                                --lint
--------------------------------------------------------------------------------
    # a zone file: every watermark-text TXT record in it is linted, selector
    # and domain read from each record's owner name
    python3 watermark_dns_tool.py --lint --record ./example.ai.zone

    # ...or pipe the same zone content in via stdin ('input', not a dash)
    dig +short TXT 1._watermark-text.example.ai | \
        python3 watermark_dns_tool.py --lint --record input --domain example.ai

    # --domain alone: fetch and lint 1._watermark-text.<domain>
    python3 watermark_dns_tool.py --lint --domain example.ai

    # --selector N: fetch and lint N._watermark-text.<domain>
    python3 watermark_dns_tool.py --lint --domain example.ai --selector 2 --verify-d

    # --crawl: lint every selector, not just one
    python3 watermark_dns_tool.py --lint --domain example.ai --crawl
    #   from selector 1: follow r= if present, else auto-increment (1, 2, 3, ...)
    #     and stop at the last selector that exists, reporting that number
    #   from selector 2+: auto-increment from there and stop the same way

    # --verify-d: also fetch each d= document, verify its hash + contents,
    #   and print the descriptor with a plain-English reading of the custody claim
    python3 watermark_dns_tool.py --lint --domain example.ai --crawl --verify-d

  Catches: missing required tags, bad v=, unversioned a=, non-base64 p=,
  p= that isn't a SubjectPublicKeyInfo / is weak (RSA < 2048), bad c=,
  na < nb, plain-HTTP d=, missing/malformed dh=, r= on the wrong selector,
  the case (g)/(h) ambiguities, DNS-vs-JSON c= mismatch (case (i)),
  d= document hash mismatch (case (j)), and (with --crawl) gaps inside a
  declared r= range. With --verify-d it also checks the d= document against the
  Section 7.2 schema and prints its contents.

  Every record also gets a KEY-VALIDITY line: VALID (now within nb..na),
  NOT YET VALID (before nb), EXPIRED (after na), or REVOKED (s=revoked).
  Use --at <unix-ts|ISO-date> to evaluate that against another moment, e.g.
  when a piece of text was generated.

  Each record (whether from --record, a single --domain lookup, --crawl, or
  --traverse) is followed by a one-line "reads as:" gloss (provider, selector,
  key type, what c= means, validity), then a bordered table -- one row per
  expected value (tag | ok/info/WARN/ERROR | comment), required tags always
  shown, optional tags only when present, comments wrapped to terminal width. With
  --verify-d the fetched d= document gets its own table (received_from,
  selector, provider, c, ts, plus any extra fields), printed after the record
  table and before its "reads as:" line. --json is unchanged (full findings).

--------------------------------------------------------------------------------
CHECK: TRAVERSE A PROVIDER'S RECORDS (Section 6.4)                 --traverse
--------------------------------------------------------------------------------
    python3 watermark_dns_tool.py --traverse --domain example.ai --verify-d
    python3 watermark_dns_tool.py --traverse --seed-file providers.txt --json

  Does what a verifier's bootstrap job does:
    1. query 1._watermark-text.<domain>  (CNAME delegation followed by resolver)
    2. read r= if present
    3. crawl 2..r  (or forward until an empty lookup if r= is absent)
    4. lint every selector, note DNSSEC AD flag, flag gaps
    5. with --verify-d, fetch each d= document, verify hash + schema, and print
       its contents with a plain-English reading of the custody claim
  Use --at <unix-ts|ISO-date> to ask "which keys were usable when this text was
  made" rather than "now".

--------------------------------------------------------------------------------
WHAT THIS TOOL DELIBERATELY DOES NOT DO
--------------------------------------------------------------------------------
  * No watermark embedding or detection -- out of scope by the draft itself.
  * No seed-list trust: it cannot tell you a domain is a legitimate provider,
    or that a CNAME target was authorized (Section 6.4 / 6.5 / open questions).
  * No revocation propagation -- undefined in the draft (Section 9.2 / 14).
  * No conflicting-attestation resolution (Section 14).
================================================================================
"""


def cmd_walkthrough(args):
    print(WALKTHROUGH.strip())


def cmd_dh(args):
    if not args.input:
        sys.exit("error: --dh requires --input (a local path or https:// URL)")
    f = Findings()
    raw = load_bytes_from_arg(args.input, f)
    value = compute_dh(raw, args.dh_algo, pad=not args.no_pad)
    if args.json:
        print(json.dumps({"input": args.input, "byte_length": len(raw), "dh": value,
                          "findings": f.as_dicts()}, indent=2))
        return
    if f.items:
        print(f.render())
    print(f"dh={value}")


# --------------------------------------------------------------------------- #
# interactive wizard                                                           #
# --------------------------------------------------------------------------- #

class _Abort(Exception):
    pass


def _ask(text, default=None):
    suffix = f" [{default}]" if default not in (None, "") else ""
    try:
        raw = input(f"{text}{suffix}: ").strip()
    except EOFError:
        raise _Abort("no more input")
    if not raw:
        return default if default is not None else ""
    return raw


def _ask_nonempty(text, default=None):
    while True:
        val = _ask(text, default)
        if val:
            return val
        print("  (required)")


def _ask_choice(text, choices, default=None):
    while True:
        val = _ask(f"{text} ({'/'.join(choices)})", default)
        if val in choices:
            return val
        print(f"  answer one of: {', '.join(choices)}")


def _ask_yesno(text, default="y"):
    while True:
        val = _ask(f"{text} (y/n)", default).lower()
        if val in ("y", "yes"):
            return True
        if val in ("n", "no"):
            return False


def _ask_int(text, default=None):
    while True:
        val = _ask(text, str(default) if default is not None else None)
        try:
            return int(val)
        except (TypeError, ValueError):
            print("  enter a whole number")


def cmd_interactive(args):
    try:
        _run_wizard(args)
    except _Abort as exc:
        print(f"\naborted ({exc})")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\naborted")
        sys.exit(130)


def _run_wizard(args):
    import os

    print("=" * 72)
    print("  watermark_dns_tool.py --create -- interactive record builder")
    print("  Builds one selector end to end: key -> descriptor -> hash -> record.")
    print("  Press Ctrl-C at any prompt to abort. Nothing is written until the end")
    print("  unless a step says otherwise.")
    print("=" * 72)
    print()

    # --- identity -------------------------------------------------------
    domain = _ask_nonempty("Provider domain (e.g. example.ai)").strip(".")
    selector = _ask_int("Selector number", 1)

    print()
    print("Custody type for text signed under this selector (draft Section 6.1):")
    print("  sign     - this provider GENERATED the text fresh")
    print("  re-sign  - this provider MODIFIED text that already carried a watermark")
    c = _ask_choice("c=", ["sign", "re-sign"], "sign")

    # --- d= descriptor decision (may bump the selector) ----------------
    want_d = False
    handoff_kind = None
    if c == "re-sign":
        print()
        print("A re-sign selector can point (d=) to a JSON custody descriptor:")
        print("  cross-vendor - the text came from a DIFFERENT provider  -> d= REQUIRED")
        print("  self-loop    - you are re-signing your OWN earlier text  -> d= optional")
        handoff_kind = _ask_choice("Which is this?", ["cross-vendor", "self-loop"], "cross-vendor")
        if handoff_kind == "cross-vendor":
            want_d = True
        else:
            want_d = _ask_yesno("Attach a d= descriptor anyway?", "n")
    else:
        want_d = _ask_yesno("Attach a d= descriptor? (unusual for c=sign)", "n")

    if selector == 1 and c == "re-sign" and not want_d:
        print()
        print("  WARNING (draft case (h)): selector 1 + c=re-sign + no d= is ambiguous --")
        print("  a verifier can't tell 'self-loop re-sign' from 'only ever modifies")
        print("  others' text, never generates'. The draft says tooling should steer you")
        print("  to selector 2 or higher unless this is genuinely intended.")
        if _ask_yesno("Use selector 2 instead?", "y"):
            selector = 2

    # --- key material -------------------------------------------------
    print()
    print(f"Key material for {selector}._{WELL_KNOWN_LABEL.lstrip('_')}.{domain}:")
    print("  1) generate a new asymmetric key pair now")
    print("  2) use an existing public key file (PEM or DER)")
    print("  3) paste a p= value directly")
    kchoice = _ask_choice("Choose", ["1", "2", "3"], "1")

    p_value = None
    priv_path = pub_path = None
    if kchoice == "1":
        key_type = _ask_choice("Key type", list(KEY_TYPES), "ed25519")
        default_stem = keypair_stem(selector, domain)
        stem = _ask("Output filename stem", default_stem)
        if os.path.exists(f"{stem}.private.pem") and not _ask_yesno(
            f"{stem}.private.pem exists -- overwrite?", "n"
        ):
            raise _Abort("would overwrite an existing private key")
        kp = generate_keypair(key_type)
        priv_path, pub_path = write_keypair(kp, stem)
        p_value = kp["p"]
        print(f"  wrote {priv_path} (chmod 600) and {pub_path}")
    elif kchoice == "2":
        path = _ask_nonempty("Path to public key file")
        p_value = resolve_pubkey_to_p(path)
        pub_path = path
    else:
        while True:
            raw = _ask_nonempty("Paste p= value (base64)")
            raw = raw[2:] if raw.lower().startswith("p=") else raw
            try:
                base64.b64decode(raw, validate=True)
                p_value = raw
                break
            except Exception:
                print("  that is not valid base64")

    # --- algorithm id ----------------------------------------------
    print()
    algorithm = _ask("Watermarking algorithm id (a=)", "fairoze-1")
    if not re.search(r"-\d+$", algorithm):
        print(f"  '{algorithm}' has no version suffix; the draft SHOULD-recommends one.")
        if _ask_yesno(f"Use '{algorithm}-1'?", "y"):
            algorithm = f"{algorithm}-1"

    # --- validity window -----------------------------------------
    print()
    nb = parse_ts(_ask("nb= not-before (unix / 'now' / ISO date)", "now"))
    while True:
        na = parse_ts(_ask("na= not-after (unix / ISO date / 'ongoing')", "ongoing"),
                      allow_ongoing=True)
        if na == "ongoing" or not isinstance(nb, int) or na >= nb:
            break
        print(f"  na ({na}) must be >= nb ({nb})")

    status = _ask_choice("s= status", ["active", "revoked"], "active")
    if status == "revoked":
        print("  note: a revoked key is not valid for ANY new verification (Section 9.2).")

    # --- descriptor build --------------------------------------
    d_url = dh_value = descriptor_path = None
    if want_d:
        print()
        print("d= custody descriptor (draft Section 7.2):")
        rf_default = "otherprovider.ai" if handoff_kind == "cross-vendor" else "self"
        received_from = _ask_nonempty(
            "received_from (upstream provider domain, or free text)", rf_default)
        provider = _ask("provider (this signing provider's domain)", domain)
        ts = parse_ts(_ask("ts (descriptor publish time: unix / 'now' / ISO date)", "now"))
        extra = []
        while _ask_yesno("Add an extra field to the descriptor?", "n"):
            k = _ask_nonempty("  field name")
            v = _ask_nonempty("  field value")
            extra.append((k, v))
        compact = _ask_yesno("Minified JSON? (default: indented)", "n")
        descriptor_path = _ask("Descriptor output path", "desc.json")
        _, body = build_descriptor(received_from, selector, provider, c, ts, extra, compact)
        with open(descriptor_path, "wb") as fh:
            fh.write(body)
        dh_algo = _ask_choice("dh= hash algorithm", ["sha-256", "sha-384", "sha-512"], "sha-256")
        dh_value = compute_dh(body, dh_algo, pad=True)
        print(f"  wrote {descriptor_path} ({len(body)} bytes); dh={dh_value}")
        default_url = f"https://{selector}.{WELL_KNOWN_LABEL}.{domain}/{os.path.basename(descriptor_path)}"
        d_url = _ask_nonempty("d= HTTPS URL that will serve those exact bytes", default_url)

    # --- r= (selector 1 only) -------------------------------------
    r_value = None
    if selector == 1:
        print()
        if _ask_yesno("Set r= (total selector count) on this record? (recommended on selector 1)", "y"):
            r_value = _ask_int("r= total number of sequential selectors you publish", 1)

    # --- assemble + lint ----------------------------------------
    tags = OrderedDict()
    tags["v"] = PROTOCOL_VERSION
    tags["a"] = algorithm
    tags["p"] = p_value
    tags["c"] = c
    if d_url:
        tags["d"] = d_url
    if dh_value:
        tags["dh"] = dh_value
    if status != "active":
        tags["s"] = status
    tags["nb"] = str(nb)
    tags["na"] = str(na)
    if r_value is not None:
        tags["r"] = str(r_value)

    record = build_record(tags)
    findings = lint_record(record, selector=selector, domain=domain, is_make=True,
                           descriptor_bytes=None)

    record_name = selector_name(selector, domain)
    print()
    print("=" * 72)
    print("  RESULT")
    print("=" * 72)
    print(f"  record name : {record_name}")
    if priv_path:
        print(f"  private key : {priv_path}   (keep secret; never commit)")
    if pub_path:
        print(f"  public key  : {pub_path}")
    if descriptor_path:
        print(f"  descriptor  : {descriptor_path}   (serve verbatim at {d_url})")
    print()
    if findings.items:
        print(findings.render(indent="  "))
        print()
    print(f"  => {findings.n_errors} error(s), {findings.n_warnings} warning(s)")
    print()

    if findings.n_errors and not _ask_yesno("Record has errors. Show/keep it anyway?", "n"):
        raise _Abort("record has unresolved errors")

    print("  DNS TXT record:")
    print()
    print(f"  {record}")
    print()
    print("  zone-file line:")
    print(f'  {record_name}. IN TXT "{record}"')
    print()

    if _ask_yesno("Save the record to a file?", "y"):
        out = _ask("Record output path", f"{keypair_stem(selector, domain)}.record.txt")
        with open(out, "w") as fh:
            fh.write(f"; {record_name}\n")
            fh.write(f'{record_name}. IN TXT "{record}"\n')
        print(f"  wrote {out}")

    print()
    print("  Next steps:")
    print(f"    1. Publish the TXT record at {record_name}")
    if d_url:
        print(f"    2. Host the descriptor bytes at {d_url} over HTTPS (exact bytes)")
        print(f"    3. Verify:  python3 {os.path.basename(sys.argv[0])} --lint "
              f"--selector {selector} --domain {domain} --verify-d")
    else:
        print(f"    2. Verify:  python3 {os.path.basename(sys.argv[0])} --lint "
              f"--selector {selector} --domain {domain}")
    if selector == 1:
        print(f"    +. Traverse: python3 {os.path.basename(sys.argv[0])} --traverse --domain {domain}")
    print()
    print("  Reminder (Section 4.1 / 10.3): p= is only safe to publish for an")
    print("  asymmetric, publicly-detectable scheme -- never a symmetric key.")


# --------------------------------------------------------------------------- #
# argument parsing                                                             #
# --------------------------------------------------------------------------- #

# Mode flags: attribute name -> handler. Exactly one may be given; each is a
# plain "--" option (no positional subcommands), per this tool's CLI style.
MODE_HANDLERS = [
    ("walkthrough", cmd_walkthrough),
    ("create", cmd_interactive),
    ("keygen", cmd_keygen),
    ("make_record", cmd_make_record),
    ("make_descriptor", cmd_make_descriptor),
    ("dh", cmd_dh),
    ("lint", cmd_lint),
    ("traverse", cmd_traverse),
]


def build_parser():
    p = argparse.ArgumentParser(
        prog="watermark_dns_tool.py",
        description="Reference tooling for draft-zink-xboundary-ai-text-watermark-verification-00.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Every option is a '--' flag. Run --walkthrough first for the full explanation.\n"
               "Examples:\n"
               "  watermark_dns_tool.py --walkthrough\n"
               "  watermark_dns_tool.py --create\n"
               "  watermark_dns_tool.py --keygen --domain example.ai --selector 1\n"
               "  watermark_dns_tool.py --lint --selector 2 --domain example.ai --verify-d\n"
               "  watermark_dns_tool.py --traverse --domain example.ai",
    )

    mode = p.add_argument_group("mode (choose exactly one)")
    m = mode.add_mutually_exclusive_group()
    m.add_argument("--walkthrough", action="store_true",
                   help="print the end-to-end explanation (start here)")
    m.add_argument("--create", action="store_true",
                   help="step-by-step prompts: key -> descriptor -> hash -> record")
    m.add_argument("--keygen", action="store_true",
                   help="(a) generate an asymmetric key pair for a selector")
    m.add_argument("--make-record", action="store_true",
                   help="(b) build the _watermark-text DNS TXT record")
    m.add_argument("--make-descriptor", action="store_true",
                   help="(c) build the d= JSON custody descriptor")
    m.add_argument("--dh", action="store_true",
                   help="(d) compute the dh= digest of a file or URL")
    m.add_argument("--lint", action="store_true",
                   help="error-check a single DNS record")
    m.add_argument("--traverse", action="store_true",
                   help="crawl a provider's full selector set (Section 6.4)")

    common = p.add_argument_group("common")
    common.add_argument("--domain", help="provider domain")
    common.add_argument("--selector", type=int, help="selector number (default 1 for --keygen)")
    common.add_argument("--json", action="store_true", help="machine-readable JSON output")
    common.add_argument("--dh-algo", default="sha-256", help="dh= hash algorithm (default sha-256)")
    common.add_argument("--no-pad", action="store_true",
                        help="emit dh= base64url without '=' padding")

    g = p.add_argument_group("--keygen")
    g.add_argument("--key-type", default="ed25519",
                   help=f"one of: {', '.join(KEY_TYPES)} (default ed25519)")
    g.add_argument("--out-prefix", help="output filename stem (default derived from domain/selector)")
    g.add_argument("--print-only", action="store_true",
                   help="print, do not write files (--keygen and --make-descriptor)")

    g = p.add_argument_group("--make-record")
    g.add_argument("--algorithm", "--a", dest="algorithm", help="a= value, e.g. fairoze-1  (REQUIRED)")
    g.add_argument("--pubkey", help="public key: PEM path, DER path, or literal base64")
    g.add_argument("--p", help="p= value directly (base64 SPKI), instead of --pubkey")
    g.add_argument("--c", help="c= custody type: sign | re-sign  (REQUIRED for --make-record)")
    g.add_argument("--d", help="d= HTTPS URL")
    g.add_argument("--dh-value", help="dh= value directly (otherwise computed from --d-file)")
    g.add_argument("--d-file",
                   help="local path or URL of the d= document; dh= is computed from it "
                        "(also used by --lint to check a record against a local descriptor)")
    g.add_argument("--s", help="s= status (active|revoked); omit for default 'active'")
    g.add_argument("--nb", help="not-before: unix seconds, 'now', or ISO date  (REQUIRED)")
    g.add_argument("--na", help="not-after: unix seconds, ISO date, or 'ongoing'  (REQUIRED)")
    g.add_argument("--r", type=int, help="r= selector count (selector 1 only)")
    g.add_argument("--v", default=PROTOCOL_VERSION, help=argparse.SUPPRESS)
    g.add_argument("--force", action="store_true", help="emit even with ERROR-level lint findings")

    g = p.add_argument_group("--make-descriptor")
    g.add_argument("--received-from", help="upstream provider domain, or free text  (REQUIRED)")
    g.add_argument("--provider", help="this (signing) provider's domain  (REQUIRED)")
    g.add_argument("--ts", help="publish timestamp: unix seconds, 'now', ISO date (default now)")
    g.add_argument("--extra", action="append", help="extra field key=value (repeatable)")
    g.add_argument("--out", default="desc.json", help="descriptor output path (default desc.json)")
    g.add_argument("--compact", action="store_true", help="minified JSON instead of indented")

    g = p.add_argument_group("--dh")
    g.add_argument("--input", help="local path or https:// URL to hash  (REQUIRED for --dh)")

    g = p.add_argument_group("--lint / --traverse")
    g.add_argument("--record",
                   help="--lint: path to a zone file -- every watermark-text TXT record in "
                        "it is linted (selector/domain read from each owner name). Use the "
                        "word 'input' to read the zone content from stdin instead "
                        "(piped, or typed/pasted then Enter).")
    g.add_argument("--crawl", action="store_true",
                   help="--lint: walk every selector, not just one. From selector 1, follow "
                        "r= if present, else auto-increment until a lookup fails. From "
                        "selector 2+, auto-increment from there.")
    g.add_argument("--verify-d", "--fetch-d", dest="verify_d", action="store_true",
                   help="--lint / --traverse: fetch the d= document, verify it "
                        "(digest vs dh= = case j; JSON c vs record c= = case i; "
                        "Section 7.2 schema), and print its contents plus a "
                        "plain-English reading. (--fetch-d is a kept alias.)")
    g.add_argument("--seed-file",
                   help="--traverse: file of provider domains, one per line ('#' comments ok)")
    g.add_argument("--at",
                   help="--lint / --traverse: evaluate the key-validity verdict at this time "
                        "(unix ts / ISO date) instead of now -- e.g. 'was this key valid when "
                        "the text was generated?'")
    g.add_argument("--max-selectors", type=int, default=50,
                   help="--traverse and --lint --crawl: crawl safety cap (default 50)")

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    chosen = [(name, fn) for name, fn in MODE_HANDLERS if getattr(args, name)]
    if not chosen:
        cmd_walkthrough(args)
        print()
        parser.print_help()
        return 0
    try:
        chosen[0][1](args)
    except KeyboardInterrupt:
        return 130
    except (ValueError, FileNotFoundError) as exc:
        sys.exit(f"error: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
