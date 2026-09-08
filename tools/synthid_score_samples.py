#!/usr/bin/env python3
"""
synthid_score_samples.py -- (re)build samples/synthid-1/verify-scores.json.

The demo server can't run SynthID detection inline (no torch in the image), so
it answers its `verify` endpoint from a pre-computed table: sha256 of the
canonicalized text -> {score, watermarked}. This script scores every
samples/synthid-1/*.txt and controls/*.txt with tools/synthid.py and writes that
table, using the same canonicalization as the Section 6.6 d= document
(["strip-zero-width", "nfc", "trim"]).

    python tools/synthid_score_samples.py --keys ~/synthid-keys/synthid-1.keys.json

Needs torch + transformers (tools/requirements-synthid.txt) and the operator's
secret keys. Run it whenever the samples or synthid-1.config.json change.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
import unicodedata
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "samples", "synthid-1")
sys.path.insert(0, HERE)

_ZW_RE = re.compile("[​‌‍⁠]")
CANON = ["strip-zero-width", "nfc", "trim"]


def canon(text: str) -> str:
    text = _ZW_RE.sub("", text)
    text = unicodedata.normalize("NFC", text)
    return text.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=os.path.join(ROOT, "synthid-1.config.json"))
    ap.add_argument("--keys", help="secret keys JSON (or set SYNTHID_KEYS_JSON)")
    ap.add_argument("--out", default=os.path.join(ROOT, "verify-scores.json"))
    args = ap.parse_args()

    import synthid

    cfg = synthid.load_config(args.config, args.keys)
    tok, proc = synthid._load_everything(cfg)
    thr = cfg["threshold"]

    scores: "OrderedDict[str, dict]" = OrderedDict()
    files = (sorted(glob.glob(os.path.join(ROOT, "sample-*.txt")))
             + sorted(glob.glob(os.path.join(ROOT, "controls", "*.txt"))))
    for path in files:
        raw = open(path, encoding="utf-8").read()
        r = synthid.score_text(raw, cfg, tokenizer=tok, processor=proc)
        h = hashlib.sha256(canon(raw).encode("utf-8")).hexdigest()
        kind = "sample" if os.sep + "sample-" in path else "control"
        scores[h] = {"score": round(r["score"], 6), "tokens": r["tokens_scored"],
                     "kind": kind, "watermarked": r["score"] >= thr,
                     "file": os.path.basename(path)}
        print(f"  {os.path.basename(path):16} {r['score']:.4f} "
              f"{'WM' if r['score'] >= thr else '--'}  {kind}")

    doc = OrderedDict([
        ("algorithm", "synthid-1"),
        ("threshold", thr),
        ("canonicalization", CANON),
        ("detector", "masked-mean"),
        ("note", "Pre-computed detector scores for the demo verify endpoint -- this "
                 "server cannot run SynthID detection inline (it needs the tokenizer + "
                 "transformers). Key = sha256 of the text after applying "
                 "canonicalization. Rebuild with tools/synthid_score_samples.py."),
        ("scores", scores),
    ])
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    n_wm = sum(1 for v in scores.values() if v["kind"] == "sample" and v["watermarked"])
    print(f"\nwrote {args.out}: {len(scores)} entries, samples watermarked {n_wm}/"
          f"{sum(1 for v in scores.values() if v['kind'] == 'sample')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
