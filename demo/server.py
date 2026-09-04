#!/usr/bin/env python3
"""
server.py -- a small public demo server for the xboundary AI-text-watermark tools.

Reuses ../tools/watermark_dns_tool.py and ../tools/tzsataitw.py directly.
Standard library only (the tools shell out to `openssl` and `dig`).

Four things the page can do:
  (a) watermark pasted text with one of this operator's DEMO keys
  (b) verify pasted text against tzsataitw-1 / tzsataitw-2, key fetched from DNS
      (optionally at a domain / selector you name)
  (c) build a _watermark-text TXT record plus a private key you can download
  (d) validate every _watermark-text record published for a domain you name

    python3 server.py [--host 127.0.0.1] [--port 8080] [--keys ./keys]

For a real public deployment, run it behind nginx/caddy with TLS, and keep the
demo keys DEDICATED (never your production signing keys).
"""

import argparse
import base64
import collections
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import tzsataitw as tz                       # noqa: E402
import watermark_dns_tool as wdt             # noqa: E402

try:                                          # fairoze needs `reedsolo`
    import fairoze as fz                     # noqa: E402
    import fairoze_profile as fzp             # noqa: E402
except ImportError:
    fz = fzp = None

# --------------------------------------------------------------------------- #
# limits                                                                       #
# --------------------------------------------------------------------------- #

MAX_BODY = 250_000        # request body bytes
MAX_TEXT = 100_000        # pasted-text characters
MAX_D_DOC = 65_536        # bytes read from a d= URL
FETCH_TIMEOUT = 5         # seconds for a d= fetch
RATE_N, RATE_WINDOW = 60, 60   # requests per IP per window (seconds)
MAX_SELECTORS = 25       # cap for feature (d)
MAX_VERIFY_CRAWL = 10    # selectors to try in feature (b) when only a domain is given
MAX_FAIROZE_OFFSETS = 200  # cap the fairoze-1 offset search

FAIROZE_SAMPLES_DIR = os.path.join(HERE, "..", "samples", "fairoze-1")

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$")
KEY_ID_RE = re.compile(r"^\d{1,6}\._watermark-text\.[a-zA-Z0-9.\-]{1,253}\.private\.pem$")

KEYS_DIR = os.path.join(HERE, "keys")


# --------------------------------------------------------------------------- #
# SSRF-safe replacement for wdt.load_bytes_from_arg (d= document fetch)         #
# --------------------------------------------------------------------------- #

def _resolves_public(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for *_rest, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return False
    return bool(infos)


MAX_REDIRECTS = 5   # hosts like Google Drive bounce a share link 1-3 times


class _CapturedRedirect(Exception):
    def __init__(self, newurl):
        self.newurl = newurl


class _CaptureRedirect(urllib.request.HTTPRedirectHandler):
    """Don't follow the redirect inside urllib -- hand the target back so
    safe_fetch can re-run its https / public-IP checks on every hop."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise _CapturedRedirect(newurl)


_OPENER = urllib.request.build_opener(_CaptureRedirect)


def _vet_fetch_url(location):
    u = urlparse(str(location))
    if u.scheme != "https":
        raise RuntimeError(f"refusing to fetch a non-https d= URL ({location!r})")
    if not u.hostname or not _resolves_public(u.hostname):
        raise RuntimeError(f"refusing to fetch a d= URL that does not resolve to a "
                           f"public address ({u.hostname})")


def safe_fetch(location, findings=None):
    """https only, public IPs only, small and time-bounded. Redirects ARE
    followed (up to MAX_REDIRECTS), but the https + public-IP checks are
    re-applied to each hop so a redirect can't bounce us onto a private host."""
    url = str(location)
    chain = []
    for _ in range(MAX_REDIRECTS + 1):
        _vet_fetch_url(url)
        chain.append(url)
        req = urllib.request.Request(url, headers={
            "Accept": "application/json, */*", "User-Agent": "tzsataitw-demo"})
        try:
            with _OPENER.open(req, timeout=FETCH_TIMEOUT) as resp:
                return resp.read(MAX_D_DOC + 1)[:MAX_D_DOC]
        except _CapturedRedirect as r:
            url = urljoin(url, r.newurl)
    raise RuntimeError(f"d= document exceeded {MAX_REDIRECTS} redirects "
                       f"({' -> '.join(chain)})")


wdt.load_bytes_from_arg = safe_fetch


# --------------------------------------------------------------------------- #
# rate limiter                                                                 #
# --------------------------------------------------------------------------- #

_hits = {}
_hits_lock = threading.Lock()


def rate_ok(ip):
    now = time.time()
    with _hits_lock:
        q = _hits.setdefault(ip, [])
        q[:] = [t for t in q if now - t < RATE_WINDOW]
        if len(q) >= RATE_N:
            return False
        q.append(now)
        return True


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #

def findings_to_dict(f, record_str=None):
    d = {
        "items": [{"level": lvl, "code": code, "message": msg} for lvl, code, msg in f.items],
        "errors": f.n_errors,
        "warnings": f.n_warnings,
        "descriptor": getattr(f, "descriptor", None),
        "reads_as": getattr(f, "record_summary", None),
    }
    if record_str is not None:
        table = wdt.render_findings_table(f, record_str)
        if getattr(f, "descriptor", None):
            table += "\n\n" + wdt.format_descriptor_block(f.descriptor)
        d["table"] = table
    return d


def _install_env_keys():
    """Cloud Run / Render inject secrets as env vars, not files. For each of
    DEMO_PRIVATE_KEY_PEM[_N] (+ matching DEMO_KEY_LOCATOR[_N]), drop the PEM into
    KEYS_DIR as <locator>.private.pem so the rest of the code is unchanged. The
    keys never land in the image or the repo."""
    global KEYS_DIR
    installed = []
    for suffix in ("", "_2", "_3", "_4", "_5"):
        pem = os.environ.get("DEMO_PRIVATE_KEY_PEM" + suffix)
        locator = (os.environ.get("DEMO_KEY_LOCATOR" + suffix) or "").strip().rstrip(".")
        if not pem:
            continue
        if not re.match(r"^\d{1,6}\._watermark-text\.[a-zA-Z0-9.\-]{1,253}$", locator):
            print(f"DEMO_PRIVATE_KEY_PEM{suffix} is set but DEMO_KEY_LOCATOR{suffix} is "
                  f"missing/invalid (want e.g. '1._watermark-text.demo.example.com') "
                  f"-- ignoring", file=sys.stderr)
            continue
        if not installed and (
                not os.access(os.path.dirname(KEYS_DIR) or ".", os.W_OK)
                or (os.path.isdir(KEYS_DIR) and not os.access(KEYS_DIR, os.W_OK))):
            KEYS_DIR = "/tmp/demo-keys"
        os.makedirs(KEYS_DIR, exist_ok=True)
        path = os.path.join(KEYS_DIR, f"{locator}.private.pem")
        with open(path, "w") as fh:
            fh.write(pem if pem.endswith("\n") else pem + "\n")
        os.chmod(path, 0o600)
        installed.append(locator)
    if installed:
        print(f"installed {len(installed)} demo key(s) from env: {', '.join(installed)}",
              file=sys.stderr)


_algo_cache = {}
_algo_cache_lock = threading.Lock()


def algo_for_locator(locator):
    """The `a=` algorithm published in DNS at `locator`, cached for the process
    lifetime (Cloud Run restarts often enough; demo records don't churn)."""
    with _algo_cache_lock:
        if locator in _algo_cache:
            return _algo_cache[locator]
    algo = None
    try:
        for rec in tz.dig_txt(locator):
            tags = tz.parse_record_tags(rec)
            if tags.get("a"):
                algo = tags["a"]
                break
    except Exception:
        algo = None
    with _algo_cache_lock:
        _algo_cache[locator] = algo
    return algo


def list_demo_keys():
    out = []
    if os.path.isdir(KEYS_DIR):
        for fn in sorted(os.listdir(KEYS_DIR)):
            if not fn.endswith(".private.pem"):
                continue
            sel, dom = tz._locator_from_key_name(fn)
            if sel is None:
                continue
            locator = f"{sel}.{wdt.WELL_KNOWN_LABEL}.{dom}"
            algo = algo_for_locator(locator)
            out.append({"id": fn, "kind": "signing", "selector": sel, "domain": dom,
                        "locator": locator, "algorithm": algo,
                        "usable": algo in tz.ALGORITHMS})
    fzs = _fairoze_samples()
    if fzs:
        out.append({"id": "fairoze-1-samples", "kind": "samples",
                    "locator": fzs["locator"], "algorithm": "fairoze-1", "usable": True})
    return out


_fzs_cache = None


def _fairoze_samples():
    """The fairoze-1 sample manifest (from samples/fairoze-1/samples.json), with
    each sample's text loaded. Returns None if fairoze isn't available."""
    global _fzs_cache
    if _fzs_cache is not None:
        return _fzs_cache or None
    manifest = os.path.join(FAIROZE_SAMPLES_DIR, "samples.json")
    if fz is None or not os.path.isfile(manifest):
        _fzs_cache = {}
        return None
    with open(manifest, encoding="utf-8") as fh:
        m = json.load(fh)
    samples = []
    for entry in m.get("samples", []):
        path = os.path.join(FAIROZE_SAMPLES_DIR, entry["file"])
        if not os.path.isfile(path):
            continue
        text = open(path, encoding="utf-8").read()
        samples.append({"id": entry["file"], "title": entry["title"],
                        "chars": len(fzp.canonicalize(text)), "text": text})
    _fzs_cache = {"algorithm": m["algorithm"], "locator": m["locator"],
                  "samples": samples}
    return _fzs_cache


def _need_text(body):
    text = body.get("text", "")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("no text given")
    if len(text) > MAX_TEXT:
        raise ValueError(f"text is too long ({len(text)} chars; limit {MAX_TEXT})")
    return text


# --------------------------------------------------------------------------- #
# (a) watermark                                                                #
# --------------------------------------------------------------------------- #

def api_watermark(body):
    text = _need_text(body)
    key_id = body.get("key_id", "")
    if not KEY_ID_RE.match(key_id or ""):
        return 400, {"error": "pick a demo key"}
    path = os.path.join(KEYS_DIR, key_id)
    if not os.path.isfile(path):
        return 404, {"error": "no such demo key on this server"}

    sel, dom = tz._locator_from_key_name(key_id)
    full_locator = f"{sel}.{wdt.WELL_KNOWN_LABEL}.{dom}"
    # The algorithm is whatever the key's DNS record publishes -- not the
    # caller's choice. Signing with a mismatched algorithm would just fail
    # verification (a= mismatch).
    algo = algo_for_locator(full_locator)
    if algo is None:
        return 400, {"error": f"could not read the a= tag from DNS at {full_locator} "
                              f"-- is the record published?"}
    if algo not in tz.ALGORITHMS:
        return 400, {"error": f"the key at {full_locator} is published for a={algo!r}, "
                              f"which this demo can't generate (only tzsataitw-1 / "
                              f"tzsataitw-2)"}

    locator = "" if body.get("no_locator") else full_locator
    ch = tz.ALGORITHMS[algo]
    canon = tz.canonical_text(text)
    sig = tz.ed25519_sign(path, tz.signing_message(algo, canon))
    frame_bits = tz._bytes_to_bits(tz.build_frame(ch.magic, tz.pack_payload(locator, sig)))
    try:
        watermarked = ch.embed(tz.strip_marks(text), frame_bits)
    except tz.CapacityError as exc:
        return 400, {"error": f"{algo} needs {exc.args[0]} bit positions but this text has only "
                              f"{exc.args[1]} look-alike-swappable letters. Paste a longer text, "
                              f"or use tzsataitw-1 (zero-width, fixed cost)."}
    return 200, {
        "watermarked": watermarked,
        "algorithm": algo,
        "channel": ch.summary,
        "locator": locator or None,
        "frame_bytes": len(frame_bits) // 8,
        "signature_hex": sig.hex(),
        "signature_b64": base64.b64encode(sig).decode("ascii"),
        "canonical_chars": len(canon),
        "canonical_sha256": hashlib.sha256(canon.encode("utf-8")).hexdigest(),
        "signed_over": f'b"{algo}\\n" + canonical_text',
    }


# --------------------------------------------------------------------------- #
# (b) verify                                                                   #
# --------------------------------------------------------------------------- #

def _more_informative(a, b):
    """Rank verify results so the best failure is what we report when nothing
    verifies: a valid-but-rejected signature beats a bad signature, which beats
    'no key found'."""
    def score(r):
        if r.get("verified"):
            return 4
        if r.get("signature_ok"):
            return 3
        if r.get("mark_found"):        # the mark's own scheme was tried and failed
            return 2                   # -- more useful than "no mark here" from
        if "detail" not in r:          #    a record for some other scheme
            return 1
        return 0
    return score(a) > score(b)


def _tz_frame(text):
    """First readable tzsataitw frame: (fr, embedded_locator, sig) or None."""
    for fr in tz.extract_frames(text):
        try:
            loc, sig = tz.unpack_payload(fr["payload"])
            return fr, loc, sig
        except ValueError:
            continue
    return None


def _fairoze_result(vt, record_locator):
    r = {"mark_found": True, "algorithm": "fairoze-1",
         "channel": "publicly-detectable statistical watermark (Fairoze)",
         "canonical_chars": vt["canonical_chars"], "record_locator": record_locator,
         "record_algorithm": "fairoze-1"}
    if vt["verified"]:
        r.update(verified=True, signature_ok=True, message=vt.get("message"),
                 signature_hex=vt.get("signature_hex"), offset=vt.get("offset"))
    else:
        r.update(verified=False, signature_ok=False, detail=vt["reason"])
        if fzp and vt["canonical_chars"] < fzp.MIN_WATERMARK_CHARS:
            r["mark_found"] = False
    return r


def _verify_against_record(text, tz_frame, loc, tags):
    """Run whichever detector the record's a= names, against this text."""
    a = tags.get("a", "")
    if a in ("tzsataitw-1", "tzsataitw-2"):
        if tz_frame is None:
            return {"mark_found": False, "algorithm": a, "record_locator": loc,
                    "record_algorithm": a,
                    "detail": f"{loc} publishes a={a}, but there is no tzsataitw "
                              f"watermark in this text"}
        fr, emb, sig = tz_frame
        r = tz._verify_one(text, fr["algorithm"], emb, sig, None, loc)
        r.update(mark_found=True, channel=tz.ALGORITHMS[fr["algorithm"]].summary,
                 record_locator=loc, record_algorithm=a)
        return r
    if a == "fairoze-1":
        if fz is None:
            return {"mark_found": False, "algorithm": "fairoze-1", "record_locator": loc,
                    "record_algorithm": a,
                    "detail": "fairoze-1 verification is not available on this server"}
        vt = fz.verify_text(text, tags["p"], max_offsets=MAX_FAIROZE_OFFSETS)
        return _fairoze_result(vt, loc)
    return {"mark_found": False, "algorithm": a, "record_locator": loc,
            "record_algorithm": a,
            "detail": f"{loc} publishes a={a!r} -- not a scheme this demo checks"}


def _record_with_p(loc):
    for rec in tz.dig_txt(loc):
        tags = tz.parse_record_tags(rec)
        if tags.get("p"):
            return tags
    return None


def api_verify(body):
    text = _need_text(body)
    domain = (body.get("domain") or "").strip().rstrip(".")
    selector = body.get("selector")
    selector = None if selector in (None, "", "null") else selector

    if domain and not DOMAIN_RE.match(domain):
        return 400, {"error": f"that does not look like a domain: {domain!r}"}
    if selector is not None:
        if not domain:
            return 400, {"error": "a selector needs a domain to go with it"}
        try:
            selector = int(selector)
        except (TypeError, ValueError):
            return 400, {"error": "selector must be a number"}

    tz_frame = _tz_frame(text)
    canon_len = len(fzp.canonicalize(text)) if fzp else len(text)

    # ---- a domain is named: try whatever algorithm each of its records publishes
    if domain:
        if selector is not None:
            locs, crawled = [f"{selector}.{wdt.WELL_KNOWN_LABEL}.{domain}"], False
        else:
            locs = [f"{n}.{wdt.WELL_KNOWN_LABEL}.{domain}"
                    for n in range(1, MAX_VERIFY_CRAWL + 1)]
            crawled = True

        best, tried = None, []
        for loc in locs:
            tags = _record_with_p(loc)
            if tags is None:
                if crawled:
                    break
                best = best or {"mark_found": bool(tz_frame),
                                "detail": f"no _watermark-text record at {loc}"}
                continue
            tried.append({"locator": loc, "algorithm": tags.get("a", "?")})
            r = _verify_against_record(text, tz_frame, loc, tags)
            if best is None or _more_informative(r, best):
                best = r
            if r.get("verified"):
                break

        if best is None:
            best = {"mark_found": False,
                    "detail": f"no _watermark-text records with a p= found at {domain}"}
        best["tried"] = tried
        best["key_origin"] = "domain-crawl" if crawled else "domain-selector"
        hit = next((t for t in tried if t["locator"] == best.get("record_locator")), None)
        if best.get("verified") and hit:
            best["key_source"] = (f"{domain}: {hit['locator']} (a={hit['algorithm']}) "
                                  f"verified the mark")
        elif not tried:
            best["key_source"] = f"{domain}: no _watermark-text records found"
        else:
            names = ", ".join(sorted({t['algorithm'] for t in tried}))
            best["key_source"] = (f"{domain}: tried {len(tried)} record(s) [{names}], "
                                  f"none verified")
        return 200, best

    # ---- no domain: only an embedded locator can save us
    if tz_frame is not None:
        fr, emb, sig = tz_frame
        info = tz._verify_one(text, fr["algorithm"], emb, sig, None, None)
        info.update(mark_found=True, channel=tz.ALGORITHMS[fr["algorithm"]].summary)
        if info.get("detail", "").startswith("this mark carries no locator"):
            info["detail"] = ("this tzsataitw mark has no embedded locator -- enter a "
                              "domain (and optionally a selector) above")
        return 200, info

    if fz is not None and canon_len >= fzp.MIN_WATERMARK_CHARS:
        return 200, {
            "mark_found": False, "hint": "fairoze-needs-domain",
            "detail": (f"No tzsataitw watermark here, and this text is long enough to "
                       f"carry a fairoze-1 mark -- but fairoze marks embed NO locator. "
                       f"Enter the provider's domain (and selector) above. That is the "
                       f"point: an independent verifier cannot check a fairoze mark "
                       f"without being told which provider generated the text."),
        }
    return 200, {"mark_found": False,
                 "detail": "no readable watermark found in this text"}


# --------------------------------------------------------------------------- #
# (c) build a TXT record + private key                                         #
# --------------------------------------------------------------------------- #

def api_make_record(body):
    domain = (body.get("domain") or "").strip().rstrip(".")
    selector = body.get("selector")
    algo = body.get("algorithm", "tzsataitw-1")
    key_type = body.get("key_type", "ed25519")
    c = body.get("c", "sign")
    nb = body.get("nb") or "now"
    na = body.get("na") or "ongoing"
    r = body.get("r")

    if not DOMAIN_RE.match(domain):
        return 400, {"error": f"that does not look like a domain: {domain!r}"}
    try:
        selector = int(selector)
    except (TypeError, ValueError):
        return 400, {"error": "selector must be a number"}
    if not (1 <= selector <= 100000):
        return 400, {"error": "selector out of range"}
    if key_type not in wdt.KEY_TYPES:
        return 400, {"error": f"key type must be one of {', '.join(wdt.KEY_TYPES)}"}
    if c not in ("sign", "re-sign"):
        return 400, {"error": "c must be 'sign' or 're-sign'"}
    try:
        nb_ts = wdt.parse_ts(nb)
        na_ts = wdt.parse_ts(na, allow_ongoing=True)
    except ValueError as exc:
        return 400, {"error": str(exc)}

    kp = wdt.generate_keypair(key_type)
    tags = collections.OrderedDict()
    tags["v"] = "1"
    tags["a"] = algo
    tags["p"] = kp["p"]
    tags["c"] = c
    tags["nb"] = str(nb_ts)
    tags["na"] = str(na_ts)
    if r not in (None, "", 0, "0"):
        try:
            tags["r"] = str(int(r))
        except (TypeError, ValueError):
            return 400, {"error": "r must be a number"}

    record = wdt.build_record(tags)
    name = wdt.selector_name(selector, domain)
    lint = wdt.lint_record(record, selector=selector, domain=domain, is_make=False)
    return 200, {
        "record_name": name,
        "record": record,
        "zonefile": f'{name}. IN TXT "{record}"',
        "private_pem": kp["private_pem"].decode("ascii"),
        "public_pem": kp["public_pem"].decode("ascii"),
        "p": kp["p"],
        "key_type": key_type,
        "lint": findings_to_dict(lint, record_str=record),
    }


# --------------------------------------------------------------------------- #
# (d) validate a domain's records                                              #
# --------------------------------------------------------------------------- #

def api_lint_domain(body):
    domain = (body.get("domain") or "").strip().rstrip(".")
    at = body.get("at")
    if not DOMAIN_RE.match(domain):
        return 400, {"error": f"that does not look like a domain: {domain!r}"}
    at_ts = None
    if at:
        try:
            at_ts = wdt.parse_ts(at)
        except ValueError as exc:
            return 400, {"error": str(exc)}

    res = wdt.traverse_provider(domain, max_selectors=MAX_SELECTORS, fetch_d=True, at_time=at_ts)
    selectors = {}
    tot_err = tot_warn = 0
    for n, e in res["selectors"].items():
        f = e["findings"]
        tot_err += f.n_errors
        tot_warn += f.n_warnings
        selectors[str(n)] = {
            "name": e["name"],
            "usable": e["usable"],
            "errors": f.n_errors,
            "warnings": f.n_warnings,
        }
    return 200, {
        "domain": domain,
        "report": wdt.format_traverse_report(domain, res, at=at if at else None),
        "selectors": selectors,
        "selectors_seen": len(selectors),
        "r": res["r"],
        "errors": tot_err,
        "warnings": tot_warn,
        "stopped_because": res["stopped_because"],
        "notes": res["notes"],
    }


# --------------------------------------------------------------------------- #
# HTTP                                                                         #
# --------------------------------------------------------------------------- #

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
POST_ROUTES = {
    "/api/watermark": api_watermark,
    "/api/verify": api_verify,
    "/api/make-record": api_make_record,
    "/api/lint-domain": api_lint_domain,
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = "tzsataitw-demo"
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj=None, *, raw=None, ctype="application/json"):
        body = raw if raw is not None else json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _ip(self):
        fwd = self.headers.get("X-Forwarded-For", "")
        return fwd.split(",")[0].strip() or self.client_address[0]

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in STATIC:
            fname, ctype = STATIC[path]
            try:
                with open(os.path.join(HERE, fname), "rb") as fh:
                    return self._send(200, raw=fh.read(), ctype=ctype)
            except OSError:
                return self._send(404, {"error": "not found"})
        if path == "/api/keys":
            return self._send(200, {"keys": list_demo_keys(),
                                    "algorithms": list(tz.ALGORITHMS),
                                    "key_types": list(wdt.KEY_TYPES),
                                    "homoglyphs": "".join(sorted(tz.HOMOGLYPH_REVERSE))})
        if path == "/api/fairoze-samples":
            fzs = _fairoze_samples()
            if not fzs:
                return self._send(200, {"available": False})
            return self._send(200, {"available": True,
                                    "algorithm": fzs["algorithm"],
                                    "locator": fzs["locator"],
                                    "samples": fzs["samples"]})
        return self._send(404, {"error": "not found"})

    do_HEAD = do_GET

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        fn = POST_ROUTES.get(path)
        if fn is None:
            return self._send(404, {"error": "not found"})
        if not rate_ok(self._ip()):
            return self._send(429, {"error": "too many requests -- slow down for a minute"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, {"error": "bad Content-Length"})
        if n > MAX_BODY:
            return self._send(413, {"error": "request body too large"})
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw or b"{}")
            if not isinstance(data, dict):
                raise ValueError
        except (json.JSONDecodeError, ValueError):
            return self._send(400, {"error": "expected a JSON object"})
        try:
            code, obj = fn(data)
        except (RuntimeError, ValueError, FileNotFoundError) as exc:
            return self._send(400, {"error": str(exc)})
        except Exception:                                   # noqa: BLE001
            traceback.print_exc()
            return self._send(500, {"error": "internal error"})
        return self._send(code, obj)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{time.strftime('%H:%M:%S')} {self._ip()} {fmt % args}\n")


def main():
    global KEYS_DIR
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    # A PaaS (Cloud Run, Render, ...) injects PORT and expects 0.0.0.0.
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    ap.add_argument("--keys", default=os.environ.get("DEMO_KEYS_DIR", KEYS_DIR),
                    help="directory of demo *.private.pem keys")
    args = ap.parse_args()
    KEYS_DIR = os.path.abspath(args.keys)
    _install_env_keys()

    for tool in ("openssl", "dig"):
        if not __import__("shutil").which(tool):
            print(f"warning: '{tool}' not on PATH -- some features will fail", file=sys.stderr)

    keys = list_demo_keys()
    print(f"demo keys ({KEYS_DIR}): "
          + (", ".join(k["locator"] for k in keys) if keys
             else "NONE -- feature (a) is disabled. Put <selector>._watermark-text.<domain>"
                  ".private.pem files here (see keys/README.md)."))
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("note: binding a non-loopback address -- put this behind a TLS reverse proxy, "
              "and make sure the keys/ dir holds DEDICATED demo keys only.", file=sys.stderr)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"listening on http://{args.host}:{args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
