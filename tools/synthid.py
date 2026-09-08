#!/usr/bin/env python3
"""
synthid.py -- `synthid-1` (SynthID-Text) watermark verifier.

The symmetric, statistical counterpart to tools/fairoze.py. It exists so the demo
and the write-up can show all three points of the design space side by side:

    tzsataitw-*   stego signature   -- asymmetric, deterministic, short text, strippable
    fairoze-1     rejection-sampled -- asymmetric, deterministic, ~700 words, edit-fragile
    synthid-1     tournament sample -- SYMMETRIC, STATISTICAL, ~700 words, edit-robust

What "verify" means here is different from the other two. SynthID's `keys` are the
whole secret -- there is no public key, so nobody but the key holder can run this
check. The demo server holds the keys the way it holds the tzsataitw signing keys.
See synthid_profile.py for why synthid-1 is not a normal `a=` algorithm.

--------------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------------
    # verify a piece of text (needs a calibrated threshold in the config)
    synthid.py --verify --input sample.txt \
        --config synthid-1.config.json --keys synthid-1.keys.json

    # calibrate the threshold against a non-watermarked corpus, then save it
    synthid.py --calibrate --config synthid-1.config.json --keys synthid-1.keys.json \
        --negatives 'negatives/*.txt' --fpr 0.01 --write

    # smoke test (no model, no network)
    synthid.py --selfcheck

The keys may live inline in the config (dev), in a separate --keys FILE, or in
the SYNTHID_KEYS_JSON env var (deployment). The non-secret config -- tokenizer id,
vocab_size, ngram_len, sampling-table params, threshold -- is committable.

--------------------------------------------------------------------------------
DEPENDENCIES
--------------------------------------------------------------------------------
This is the heaviest dependency in the repo: `torch` + `transformers`. They are
needed because SynthID's g-function is defined by the reference logits-processor
implementation and because detection needs the exact generation tokenizer -- a
from-scratch reimplementation would risk disagreeing with the generator. Detection
still uses NO GPU and NO model weights. See tools/requirements-synthid.txt; the
import is lazy, so the rest of tools/ is unaffected if it is not installed.
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import sys

from synthid_profile import ALGORITHM_ID, DEFAULT_FPR, NULL_SCORE, canonicalize

_DEP_HINT = ("synthid-1 verification needs `torch` and `transformers`:\n"
            "    pip install -r tools/requirements-synthid.txt")


def _warn(msg: str) -> None:
    print(f"synthid: {msg}", file=sys.stderr)


def _require_deps():
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError as exc:
        sys.exit(f"error: {exc.name} not installed.\n{_DEP_HINT}")


# --------------------------------------------------------------------------- #
# config + keys                                                                #
# --------------------------------------------------------------------------- #

def load_config(config_path: str, keys_path: str | None = None) -> dict:
    """Merge the (committable) config with the (secret) keys.

    keys precedence: --keys FILE  >  SYNTHID_KEYS_JSON env  >  inline in config.
    """
    with open(config_path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)

    keys = cfg.get("keys")
    if keys_path:
        with open(keys_path, "r", encoding="utf-8") as fh:
            keys = json.load(fh)["keys"]
    elif os.environ.get("SYNTHID_KEYS_JSON"):
        keys = json.loads(os.environ["SYNTHID_KEYS_JSON"])["keys"]

    if not keys:
        sys.exit("error: no watermark keys -- put a \"keys\" list in the config, "
                 "pass --keys FILE, or set SYNTHID_KEYS_JSON")
    if not all(isinstance(k, int) for k in keys):
        sys.exit("error: every entry in \"keys\" must be an integer")

    cfg["keys"] = keys
    cfg.setdefault("ngram_len", 5)
    cfg.setdefault("context_history_size", 1024)
    cfg.setdefault("sampling_table_seed", 0)
    cfg.setdefault("sampling_table_size", 2 ** 16)
    cfg.setdefault("skip_first_ngram_calls", False)
    if "tokenizer" not in cfg:
        sys.exit("error: config needs a \"tokenizer\" (the HF id used at generation)")
    return cfg


# --------------------------------------------------------------------------- #
# processor + tokenizer                                                        #
# --------------------------------------------------------------------------- #

def _build_processor(cfg: dict, vocab_size: int):
    import torch
    from transformers import SynthIDTextWatermarkingConfig

    wm = SynthIDTextWatermarkingConfig(
        ngram_len=cfg["ngram_len"],
        keys=cfg["keys"],
        context_history_size=cfg["context_history_size"],
        sampling_table_seed=cfg["sampling_table_seed"],
        sampling_table_size=cfg["sampling_table_size"],
        skip_first_ngram_calls=cfg["skip_first_ngram_calls"],
    )
    return wm.construct_processor(vocab_size, torch.device("cpu"))


def _load_everything(cfg: dict):
    """Returns (tokenizer, processor). Mutates cfg['vocab_size'] if it was absent."""
    _require_deps()
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(cfg["tokenizer"])

    vocab_size = cfg.get("vocab_size")
    if not vocab_size:
        vocab_size = len(tokenizer)
        cfg["vocab_size"] = vocab_size
        _warn(f"config has no vocab_size; using len(tokenizer)={vocab_size}. This "
              f"MUST equal the model's config.vocab_size at generation or every "
              f"score is wrong -- record it in the config.")
    return tokenizer, _build_processor(cfg, vocab_size)


# --------------------------------------------------------------------------- #
# scoring                                                                      #
# --------------------------------------------------------------------------- #

def score_text(text: str, cfg: dict, *, tokenizer, processor) -> dict:
    """Masked-mean g-value score for one piece of text.

    Returns {score, tokens_scored, depth, z_null, canonical_chars} -- or, when
    the text is too short to score, {score: None, reason, canonical_chars}.

    `score` ~ NULL_SCORE (0.5) for unwatermarked text, higher for watermarked.
    `z_null` is (score - 0.5) normalised by the independent-Bernoulli std -- it
    OVERSTATES confidence (g-values are correlated across layers and neighbours);
    use a threshold calibrated on real negatives for a true FPR.
    """
    import torch

    canon = canonicalize(text)
    ngram_len = cfg["ngram_len"]
    ids = tokenizer(canon, add_special_tokens=False, return_tensors="pt").input_ids
    n_tokens = int(ids.shape[1])
    if n_tokens <= ngram_len:
        return {"score": None, "tokens_scored": 0, "canonical_chars": len(canon),
                "reason": f"{n_tokens} tokens; need more than ngram_len ({ngram_len})"}

    eos_id = tokenizer.eos_token_id
    eos_id = eos_id if eos_id is not None else -1

    with torch.no_grad():
        eos_mask = processor.compute_eos_token_mask(
            input_ids=ids, eos_token_id=eos_id)[:, ngram_len - 1:]
        ctx_mask = processor.compute_context_repetition_mask(input_ids=ids)
        mask = (ctx_mask.bool() & eos_mask.bool()).float()      # [1, L']
        g = processor.compute_g_values(input_ids=ids).float()   # [1, L', depth]

    depth = int(g.shape[-1])
    num_unmasked = int(mask.sum().item())
    if num_unmasked == 0:
        return {"score": None, "tokens_scored": 0, "canonical_chars": len(canon),
                "reason": "no scorable positions (all masked -- text too repetitive?)"}

    total = (g * mask.unsqueeze(-1)).sum().item()
    score = total / (depth * num_unmasked)
    n_eff = depth * num_unmasked
    z_null = (score - NULL_SCORE) / math.sqrt(0.25 / n_eff)

    return {"score": score, "tokens_scored": num_unmasked, "depth": depth,
            "z_null": z_null, "canonical_chars": len(canon)}


def verify_text(text: str, cfg: dict, *, tokenizer=None, processor=None) -> dict:
    """One-shot verify. Loads the tokenizer/processor unless they are passed in."""
    if tokenizer is None or processor is None:
        tokenizer, processor = _load_everything(cfg)

    res = score_text(text, cfg, tokenizer=tokenizer, processor=processor)
    res["algorithm"] = ALGORITHM_ID
    thr = cfg.get("threshold")
    res["threshold"] = thr

    if res.get("score") is None:
        res["verified"] = False
        return res
    if thr is None:
        res["verified"] = False
        res["reason"] = ("no threshold in the config -- run `--calibrate` against a "
                         "non-watermarked corpus first")
        return res

    res["verified"] = res["score"] >= thr
    res["reason"] = (f"score {res['score']:.4f} "
                     f"{'>=' if res['verified'] else '<'} threshold {thr:.4f} "
                     f"({res['tokens_scored']} tokens scored)")
    return res


# --------------------------------------------------------------------------- #
# calibration                                                                  #
# --------------------------------------------------------------------------- #

def calibrate(paths: list[str], cfg: dict, fpr: float) -> dict:
    """Score a non-watermarked corpus; pick the threshold that lets through ~fpr
    of it. Returns a report including the suggested `threshold`."""
    tokenizer, processor = _load_everything(cfg)

    scores: list[float] = []
    skipped: list[list] = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as fh:
            r = score_text(fh.read(), cfg, tokenizer=tokenizer, processor=processor)
        if r.get("score") is None:
            skipped.append([os.path.basename(path), r.get("reason")])
        else:
            scores.append(r["score"])

    scores.sort()
    n = len(scores)
    if n == 0:
        sys.exit("error: no usable negatives -- every file was skipped")
    if n < 100:
        _warn(f"only {n} usable negatives; a {fpr:g} FPR estimate wants >= 100. "
              f"The threshold below is rough.")

    # threshold = smallest score such that at most fpr*n negatives exceed it
    idx = min(n - 1, max(0, math.ceil((1.0 - fpr) * n) - 1))
    threshold = scores[idx]

    return {
        "algorithm": ALGORITHM_ID,
        "negatives_scored": n,
        "negatives_skipped": skipped,
        "fpr_target": fpr,
        "score_min": scores[0],
        "score_p50": scores[n // 2],
        "score_p95": scores[min(n - 1, math.ceil(0.95 * n) - 1)],
        "score_max": scores[-1],
        "threshold": threshold,
        "note": ("threshold is the empirical (1 - fpr) quantile of the negative "
                 "scores; it is only as good as the corpus is representative"),
    }


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def _read_input(path: str | None) -> str:
    if path and path != "-":
        return open(path, "r", encoding="utf-8").read()
    return sys.stdin.read()


def _check_dns(domain: str, selector: int) -> dict:
    """Assert the domain publishes a=synthid-1 at this selector. There is no p= to
    fetch -- synthid-1 is symmetric -- so this only cross-checks the record."""
    import tzsataitw as tz
    name = f"{selector}.{tz.WELL_KNOWN_LABEL}.{domain.strip('.')}"
    records = tz.dig_txt(name)
    if not records:
        return {"record": name, "found": False}
    tags = tz.parse_record_tags(records[0])
    out = {"record": name, "found": True, "a": tags.get("a")}
    if tags.get("a") != ALGORITHM_ID:
        out["warning"] = f"record publishes a={tags.get('a')!r}, not {ALGORITHM_ID}"
    if tags.get("p"):
        out["warning"] = "record has a p= tag, but synthid-1 is symmetric (no public key)"
    return out


def cmd_verify(args) -> int:
    cfg = load_config(args.config, args.keys)
    text = _read_input(args.input)
    res = verify_text(text, cfg)

    if args.domain is not None and args.selector is not None:
        res["dns"] = _check_dns(args.domain, args.selector)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        verdict = "WATERMARKED" if res.get("verified") else "NOT DETECTED"
        print(f"{ALGORITHM_ID}  --  {verdict}")
        print(f"  {res.get('reason', '(no reason)')}")
        if res.get("score") is not None:
            print(f"  score          : {res['score']:.4f}   (null ~ {NULL_SCORE})")
            print(f"  threshold      : {res['threshold']}")
            print(f"  z vs null      : {res['z_null']:+.1f}  (optimistic -- assumes independence)")
            print(f"  tokens scored  : {res['tokens_scored']}  (depth {res['depth']})")
        print(f"  canonical text : {res['canonical_chars']} chars")
        if "dns" in res:
            d = res["dns"]
            print(f"  dns            : {d['record']} -> "
                  + ("a=" + str(d.get("a")) if d.get("found") else "no record"))
            if d.get("warning"):
                print(f"    warning: {d['warning']}")

    return 0 if res.get("verified") else 2


def cmd_calibrate(args) -> int:
    cfg = load_config(args.config, args.keys)
    paths = sorted(glob.glob(args.negatives))
    if not paths:
        sys.exit(f"error: --negatives matched no files: {args.negatives!r}")
    fpr = args.fpr if args.fpr is not None else DEFAULT_FPR

    report = calibrate(paths, cfg, fpr)
    print(json.dumps(report, indent=2))

    if args.write:
        with open(args.config, "r", encoding="utf-8") as fh:
            on_disk = json.load(fh)
        on_disk["threshold"] = report["threshold"]
        on_disk["fpr_target"] = fpr
        on_disk["calibrated_on"] = report["negatives_scored"]
        with open(args.config, "w", encoding="utf-8") as fh:
            json.dump(on_disk, fh, indent=2)
            fh.write("\n")
        _warn(f"wrote threshold={report['threshold']:.4f} into {args.config}")

    return 0


def _selfcheck() -> int:
    """No model, no network: build a processor with throwaway keys, score random
    tokens, and confirm the unwatermarked null score lands near 0.5."""
    _require_deps()
    import random

    import torch

    cfg = {
        "ngram_len": 5,
        "keys": [random.Random(0).randint(0, 2 ** 20) for _ in range(8)],
        "context_history_size": 1024,
        "sampling_table_seed": 0,
        "sampling_table_size": 2 ** 16,
        "skip_first_ngram_calls": False,
    }
    vocab_size = 32000
    processor = _build_processor(cfg, vocab_size)

    torch.manual_seed(0)
    ids = torch.randint(0, vocab_size, (1, 500))
    eos_mask = processor.compute_eos_token_mask(
        input_ids=ids, eos_token_id=-1)[:, cfg["ngram_len"] - 1:]
    ctx_mask = processor.compute_context_repetition_mask(input_ids=ids)
    mask = (ctx_mask.bool() & eos_mask.bool()).float()
    g = processor.compute_g_values(input_ids=ids).float()
    depth = int(g.shape[-1])
    n = max(1, int(mask.sum().item()))
    score = (g * mask.unsqueeze(-1)).sum().item() / (depth * n)

    print(f"== synthid-1 selfcheck ==")
    print(f"  processor built (depth {depth}, {n} scorable positions)")
    print(f"  random-token g-value mean: {score:.4f}   (expect ~{NULL_SCORE}: unwatermarked null)")
    ok = 0.42 <= score <= 0.58
    print("  OK" if ok else "  OUT OF RANGE -- pipeline or version mismatch")
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="synthid.py",
        description="synthid-1 (SynthID-Text) watermark verifier -- symmetric, statistical.")
    p.add_argument("--verify", action="store_true", help="verify text for a synthid-1 watermark")
    p.add_argument("--calibrate", action="store_true",
                   help="pick a detection threshold from a non-watermarked corpus")
    p.add_argument("--selfcheck", action="store_true", help="smoke test (no model, no network)")
    p.add_argument("--input", metavar="FILE", help="text to check ('-' or omitted = stdin)")
    p.add_argument("--config", metavar="FILE", help="synthid-1.config.json (tokenizer, params, threshold)")
    p.add_argument("--keys", metavar="FILE", help="JSON {\"keys\": [...]} -- the SECRET (else SYNTHID_KEYS_JSON, else inline)")
    p.add_argument("--negatives", metavar="GLOB", help="with --calibrate: non-watermarked .txt files")
    p.add_argument("--fpr", type=float, default=None, help=f"target false-positive rate (default {DEFAULT_FPR:g})")
    p.add_argument("--write", action="store_true", help="with --calibrate: write the threshold back into --config")
    p.add_argument("--domain", help="also assert this domain publishes a=synthid-1")
    p.add_argument("--selector", type=int, help="selector number, with --domain")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)

    if args.selfcheck:
        return _selfcheck()
    if args.verify:
        if not args.config:
            sys.exit("error: --verify needs --config")
        return cmd_verify(args)
    if args.calibrate:
        if not args.config or not args.negatives:
            sys.exit("error: --calibrate needs --config and --negatives")
        return cmd_calibrate(args)
    p.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
