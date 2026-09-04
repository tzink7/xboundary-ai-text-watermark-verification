#!/usr/bin/env python3
"""
fairoze_demo_edits.py -- build the two robustness-demo samples from sample-01.

`fairoze-1` tolerates an edit only in the last segment or two: the detector's
chained hash means an edit anywhere earlier cascades and breaks the mark
(implementation-open-questions.md D4). This makes that concrete:

  samples/fairoze-1/sample-01-edited-tail.txt   -- 1 char changed in the last
                                                   segment -> still VALID
  samples/fairoze-1/sample-01-edited-early.txt  -- 1 char changed near the start
                                                   -> NOT VERIFIED

Run from the repo root:  python tools/fairoze_demo_edits.py
Needs the venv (reedsolo) -- e.g.  ~/.venvs/fairoze/bin/python tools/fairoze_demo_edits.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import fairoze as fz                              # noqa: E402
import fairoze_profile as P                       # noqa: E402

SAMPLES = os.path.join(HERE, "..", "samples", "fairoze-1")
SRC = os.path.join(SAMPLES, "sample-01.txt")
PUB = os.path.join(SAMPLES, "fairoze-1.pub")


def _flip(s: str, i: int) -> str:
    return s[:i] + ("x" if s[i] != "x" else "y") + s[i + 1:]


def main() -> int:
    if not os.path.exists(SRC) or not os.path.exists(PUB):
        sys.exit(f"need {SRC} and {PUB} first (Step 7 / Step 8)")

    pub = fz.load_pubkey_b64(PUB)
    canon = P.canonicalize(open(SRC, encoding="utf-8").read())

    if not fz.verify_text(canon, pub)["verified"]:
        sys.exit("sample-01 does not verify clean -- fix that before making edits")

    # (a) edit inside the LAST segment: no chain cascade, <=1 symbol error, RS fixes it
    tail = _flip(canon, len(canon) - 8)

    # (b) edit near the start: find one whose flip actually pushes past the RS budget
    _, clean_bits = fz.windows_to_bits(canon)
    early = None
    for i in range(P.MESSAGE_LEN, P.MESSAGE_LEN + 96):
        cand = _flip(canon, i)
        _, cb = fz.windows_to_bits(cand)
        sym_errs = sum(clean_bits[k:k + 8] != cb[k:k + 8]
                       for k in range(0, len(clean_bits), 8))
        if sym_errs > P.MAX_PLANTED_ERRORS:
            early = cand
            break
    if early is None:
        sys.exit("could not find an early edit that cascades -- unexpected")

    out_tail = os.path.join(SAMPLES, "sample-01-edited-tail.txt")
    out_early = os.path.join(SAMPLES, "sample-01-edited-early.txt")
    open(out_tail, "w", encoding="utf-8").write(tail)
    open(out_early, "w", encoding="utf-8").write(early)

    r_tail = fz.verify_text(tail, pub)
    r_early = fz.verify_text(early, pub)
    print(f"sample-01-edited-tail.txt   -> {'VALID' if r_tail['verified'] else 'NOT VERIFIED'}"
          f"   (want VALID)   {r_tail['reason']}")
    print(f"sample-01-edited-early.txt  -> {'VALID' if r_early['verified'] else 'NOT VERIFIED'}"
          f"   (want NOT VERIFIED)   {r_early['reason']}")

    ok = r_tail["verified"] and not r_early["verified"]
    print("\n" + ("both as expected" if ok else "!! unexpected result"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
