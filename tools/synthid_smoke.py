#!/usr/bin/env python3
"""
synthid_smoke.py -- generate synthid-1 sample text locally, and smoke-test the
generate<->detect round trip.

SynthID generation is cheap (a small per-token overhead, no extra forward passes),
so unlike fairoze-1 this needs no GPU and no Colab -- a small model on a laptop
does it. Two modes:

  --smoke   quick sanity check: a few watermarked + plain pairs, report the score
            separation. Run this first.

  --build   the real thing: N watermarked demo samples + M unwatermarked controls
            into samples/synthid-1/, then calibrate the detection threshold on the
            controls and write samples/synthid-1/synthid-1.config.json. Resumable
            (skips files that already exist; --force to redo).

            The build runs for hours. If samples/ is on a cloud drive, pass
            --work-dir <path OUTSIDE the drive>: it generates there and copies the
            finished set in at the end, so the sync client can't move files out
            from under the run.

    ~/.venvs/fairoze/bin/python tools/synthid_smoke.py --smoke --keys ~/synthid-1.keys.json
    ~/.venvs/fairoze/bin/python tools/synthid_smoke.py --build --keys ~/synthid-1.keys.json \
        --work-dir ~/synthid-build

Needs torch + transformers (tools/requirements-synthid.txt). The `keys` list is
the secret -- pass --keys FILE or set SYNTHID_KEYS_JSON; it is never written into
the committable config.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import sys
import warnings

warnings.filterwarnings("ignore")
os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import synthid as sid                                              # noqa: E402
from synthid_profile import ALGORITHM_ID                           # noqa: E402

SAMPLES_DIR = os.path.normpath(os.path.join(_HERE, "..", "samples", ALGORITHM_ID))
DEFAULT_MODEL = "Qwen/Qwen2.5-0.5B-Instruct"
INTENDED_LOCATOR = "4._watermark-text.demo.terryzink.com"

# The watermarked demo samples -- topics parallel to samples/fairoze-1/ so the two
# sets sit side by side in the demo.
CONTENT_PROMPTS = [
    ("Pickleball", "the origins, culture, and rules of pickleball"),
    ("Coffee", "the history and culture of coffee"),
    ("Rivers and cities", "why so many cities grew up along rivers"),
    ("Long-distance hiking", "the appeal of long-distance hiking"),
    ("Board games", "how board games evolved over the centuries"),
    ("The second-hand book market", "the economics of the second-hand book market"),
    ("Public libraries", "what makes a good public library"),
    ("Amateur astronomy", "the rise of amateur astronomy as a hobby"),
    ("Bread baking", "bread baking at home and why people find it satisfying"),
    ("The bicycle", "the social history of the bicycle"),
    ("Lighthouses", "the decline of the manned lighthouse"),
    ("Tea", "the spread of tea drinking across the world"),
]

# Varied prompts for the unwatermarked calibration corpus -- cycled with different
# seeds to reach --controls.
CONTROL_PROMPTS = [
    "the history of the printing press", "how weather forecasting became reliable",
    "why people collect stamps", "the design of everyday road signs",
    "the culture of allotment gardening", "how paper money spread",
    "the appeal of cold-water swimming", "the history of street lighting",
    "why crosswords endure", "the economics of farmers' markets",
    "how the postal service shaped commerce", "the revival of vinyl records",
    "the history of the public bath", "why lists are satisfying to make",
    "the slow food movement", "how zoos changed over a century",
    "the culture of amateur radio", "the history of the ballpoint pen",
    "why people keep bees", "the design of the modern umbrella",
    "the history of canal boats", "how libraries chose their first books",
    "the appeal of jigsaw puzzles", "the history of the wristwatch",
    "why board games came back", "the culture of birdwatching",
]

_SYSTEM = "You are a helpful assistant that writes clear, detailed, well-organised essays."


def _resolve_keys(path: str | None) -> list[int]:
    if path:
        keys = json.load(open(path))["keys"]
    elif os.environ.get("SYNTHID_KEYS_JSON"):
        keys = json.loads(os.environ["SYNTHID_KEYS_JSON"])["keys"]
    else:
        keys = [11, 22, 33, 44, 55, 66, 77, 88]
        print("note: no --keys given, using 8 fixed test keys (smoke only, do not --build with these)")
    if not all(isinstance(k, int) for k in keys):
        sys.exit("error: every entry in \"keys\" must be an integer")
    return keys


def _pick_device(pref: str):
    """CUDA if asked and present; otherwise CPU. MPS is DELIBERATELY refused:
    the SynthID logits processor runs on MPS without error but produces
    effectively unwatermarked text (verified 2026-09-07) -- generation and
    detection then disagree and every sample fails. Use Colab/CUDA for speed."""
    import torch
    if pref in ("mps", "auto") and getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
        if pref == "mps":
            print("WARNING: --device mps ignored -- SynthID generation is broken on MPS "
                  "(produces unwatermarked text). Using CPU. For speed, generate on Colab.")
        return torch.device("cpu")
    if pref in ("auto", "cpu"):
        return torch.device("cpu")
    return torch.device(pref)          # cuda, etc. -- trusted as given


class _Gen:
    """Wraps a loaded model + the SynthID config + sampling params."""

    def __init__(self, model_id: str, keys: list[int], ngram_len: int,
                 num_tokens: int, device_pref: str):
        import torch
        import transformers
        from transformers import (AutoModelForCausalLM, AutoTokenizer,
                                  SynthIDTextWatermarkingConfig)

        transformers.logging.set_verbosity_error()
        self.torch = torch
        self.device = _pick_device(device_pref)
        dtype = torch.float16 if self.device.type == "cuda" else torch.float32
        self.tok = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModelForCausalLM.from_pretrained(model_id, dtype=dtype)
        self.model.to(self.device).eval()
        print(f"model {model_id} on {self.device} ({dtype})")
        if self.tok.pad_token_id is None:
            self.tok.pad_token = self.tok.eos_token
        self.is_chat = self.tok.chat_template is not None
        self.model_id = model_id
        self.wm = SynthIDTextWatermarkingConfig(keys=keys, ngram_len=ngram_len)
        self.gen_kwargs = dict(
            do_sample=True, max_new_tokens=num_tokens,
            min_new_tokens=max(400, num_tokens * 7 // 10),
            top_p=0.95, temperature=1.0, repetition_penalty=1.15,
            no_repeat_ngram_size=3, pad_token_id=self.tok.pad_token_id)

    def meta(self) -> dict:
        return {"tokenizer": self.model_id, "vocab_size": len(self.tok), "ngram_len": self.wm.ngram_len}

    def _prompt_ids(self, prompt: str):
        if self.is_chat:
            msgs = [{"role": "system", "content": _SYSTEM},
                    {"role": "user", "content": prompt}]
            text = self.tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        else:
            text = prompt + "\n\n"
        return self.tok(text, return_tensors="pt").to(self.device)

    def one(self, prompt: str, watermark: bool, seed: int) -> str:
        self.torch.manual_seed(seed)
        ids = self._prompt_ids(prompt)
        plen = ids.input_ids.shape[1]
        with self.torch.no_grad():
            out = self.model.generate(
                **ids, watermarking_config=(self.wm if watermark else None),
                **self.gen_kwargs)
        return self.tok.decode(out[0][plen:], skip_special_tokens=True).strip()


def _score_file(path, cfg, tokenizer, processor):
    with open(path, "r", encoding="utf-8") as fh:
        return sid.score_text(fh.read(), cfg, tokenizer=tokenizer, processor=processor)


# --------------------------------------------------------------------------- #
# --smoke                                                                      #
# --------------------------------------------------------------------------- #

def cmd_smoke(args) -> int:
    keys = _resolve_keys(args.keys)
    out = args.out or "smoke-synthid"
    gen = _Gen(args.model, keys, args.ngram_len, args.num_tokens, args.device)
    os.makedirs(os.path.join(out, "wm"), exist_ok=True)
    os.makedirs(os.path.join(out, "plain"), exist_ok=True)

    n = min(args.pairs, len(CONTENT_PROMPTS))
    print(f"generating {n} pairs on {gen.model_id} ({gen.device})...")
    for i in range(n):
        _, topic = CONTENT_PROMPTS[i]
        prompt = f"Write a long, detailed essay of at least 600 words about {topic}."
        for tag, wm in (("plain", False), ("wm", True)):
            path = os.path.join(out, tag, f"{i:02d}.txt")
            if not (args.force or not os.path.exists(path)):
                continue
            text = gen.one(prompt, wm, seed=100 + i)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"  {tag:5} {i:02d}: {len(text):5} chars")

    cfg = {**gen.meta(), "keys": keys, "context_history_size": 1024,
           "sampling_table_seed": 0, "sampling_table_size": 2 ** 16,
           "skip_first_ngram_calls": False}
    tokenizer, processor = sid._load_everything(cfg)

    plain = [(os.path.basename(p), _score_file(p, cfg, tokenizer, processor))
             for p in sorted(glob.glob(os.path.join(out, "plain", "*.txt")))]
    wm = [(os.path.basename(p), _score_file(p, cfg, tokenizer, processor))
          for p in sorted(glob.glob(os.path.join(out, "wm", "*.txt")))]

    ps = [r["score"] for _, r in plain if r.get("score") is not None]
    ws = [r["score"] for _, r in wm if r.get("score") is not None]
    if not ps or not ws:
        sys.exit("error: samples too short to score -- raise --num-tokens")
    sep = statistics.mean(ws) - statistics.mean(ps)
    print(f"\n  mean plain {statistics.mean(ps):.4f}  |  mean watermarked {statistics.mean(ws):.4f}"
          f"  |  separation {sep:+.4f}")
    if sep < 0.01:
        print("  WEAK/NO separation -- check the keys and ngram_len match between generate and detect.")
        return 1
    print("  round trip OK.")
    return 0


# --------------------------------------------------------------------------- #
# --build                                                                      #
# --------------------------------------------------------------------------- #

def cmd_build(args) -> int:
    if not args.keys and not os.environ.get("SYNTHID_KEYS_JSON"):
        sys.exit("error: --build needs real --keys (or SYNTHID_KEYS_JSON), not the smoke defaults")
    keys = _resolve_keys(args.keys)

    # Generation is slow (~hours). Doing it straight into a cloud-synced folder
    # invites the sync client to move files out from under the run. --work-dir
    # (a path OUTSIDE Drive) generates there, then copies the finished set into
    # samples/synthid-1/ at the end -- seconds of sync churn instead of hours.
    build_dir = os.path.abspath(args.work_dir) if args.work_dir else SAMPLES_DIR
    ctrl_dir = os.path.join(build_dir, "controls")
    os.makedirs(ctrl_dir, exist_ok=True)
    if build_dir != SAMPLES_DIR:
        print(f"working in {build_dir} (will copy into {SAMPLES_DIR} at the end)")

    n_samp = min(args.samples, len(CONTENT_PROMPTS))
    todo = []
    for i in range(n_samp):
        p = os.path.join(build_dir, f"sample-{i + 1:02d}.txt")
        if args.force or not os.path.exists(p):
            todo.append(("sample", i, p))
    for j in range(args.controls):
        p = os.path.join(ctrl_dir, f"ctrl-{j:03d}.txt")
        if args.force or not os.path.exists(p):
            todo.append(("control", j, p))

    if todo:
        print(f"generating {len(todo)} file(s) on {args.model} "
              f"(resumable -- {n_samp + args.controls - len(todo)} already present)")
        gen = _Gen(args.model, keys, args.ngram_len, args.num_tokens, args.device)
        for kind, k, path in todo:
            if kind == "sample":
                _, topic = CONTENT_PROMPTS[k]
                prompt = f"Write a long, detailed essay of at least 700 words about {topic}."
                text = gen.one(prompt, watermark=True, seed=1000 + k)
            else:
                topic = CONTROL_PROMPTS[k % len(CONTROL_PROMPTS)]
                prompt = f"Write a long, detailed essay of at least 500 words about {topic}."
                text = gen.one(prompt, watermark=False, seed=5000 + k)
            os.makedirs(os.path.dirname(path), exist_ok=True)   # sync may have raced it away
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"  {kind:7} {os.path.basename(path)}: {len(text)} chars")
        meta = gen.meta()
    else:
        print("all files already present; scoring + calibrating only")
        from transformers import AutoTokenizer
        meta = {"tokenizer": args.model,
                "vocab_size": len(AutoTokenizer.from_pretrained(args.model)),
                "ngram_len": args.ngram_len}

    cfg = {**meta, "keys": keys, "context_history_size": 1024,
           "sampling_table_seed": 0, "sampling_table_size": 2 ** 16,
           "skip_first_ngram_calls": False}
    tokenizer, processor = sid._load_everything(cfg)

    # calibrate on controls
    ctrl_scores = []
    for p in sorted(glob.glob(os.path.join(ctrl_dir, "*.txt"))):
        r = _score_file(p, cfg, tokenizer, processor)
        if r.get("score") is not None:
            ctrl_scores.append(r["score"])
    if len(ctrl_scores) < 20:
        sys.exit(f"error: only {len(ctrl_scores)} usable controls -- need more for a threshold")
    ctrl_scores.sort()
    idx = min(len(ctrl_scores) - 1,
              max(0, int(round((1 - args.fpr) * len(ctrl_scores))) - 1))
    threshold = ctrl_scores[idx]

    # verify the demo samples
    print(f"\n{'sample':16} {'score':>8}   verdict")
    print("-" * 40)
    sample_rows = []
    for i in range(n_samp):
        name = f"sample-{i + 1:02d}.txt"
        r = _score_file(os.path.join(build_dir, name), cfg, tokenizer, processor)
        s = r.get("score")
        ok = s is not None and s >= threshold
        sample_rows.append((name, s, ok))
        print(f"{name:16} {s:8.4f}   {'WATERMARKED' if ok else 'NOT DETECTED'}")

    hits = sum(ok for _, _, ok in sample_rows)
    print("-" * 40)
    print(f"controls scored     : {len(ctrl_scores)}  "
          f"(min {ctrl_scores[0]:.4f}  p50 {ctrl_scores[len(ctrl_scores)//2]:.4f}  max {ctrl_scores[-1]:.4f})")
    print(f"threshold (fpr {args.fpr:g}) : {threshold:.4f}")
    print(f"demo samples cleared: {hits}/{n_samp}")

    # write the committable config
    out_cfg = {
        "algorithm": ALGORITHM_ID,
        "tokenizer": meta["tokenizer"],
        "vocab_size": meta["vocab_size"],
        "ngram_len": meta["ngram_len"],
        "context_history_size": 1024,
        "sampling_table_seed": 0,
        "sampling_table_size": 2 ** 16,
        "detector": "masked-mean",
        "threshold": round(threshold, 6),
        "fpr_target": args.fpr,
        "calibrated_on": len(ctrl_scores),
        "generated_with": f"{args.model}, {args.num_tokens} tok, temp 1.0 top_p 0.95",
    }
    manifest = {
        "algorithm": ALGORITHM_ID,
        "locator": INTENDED_LOCATOR,
        "config_file": f"{ALGORITHM_ID}.config.json",
        "note": "symmetric watermark -- the demo server holds the keys; no p= in DNS",
        "samples": [{"file": f"sample-{i + 1:02d}.txt", "title": CONTENT_PROMPTS[i][0]}
                    for i in range(n_samp)],
    }

    # write config + manifest into the build dir, then land everything in samples/
    with open(os.path.join(build_dir, f"{ALGORITHM_ID}.config.json"), "w", encoding="utf-8") as fh:
        json.dump(out_cfg, fh, indent=2)
        fh.write("\n")
    with open(os.path.join(build_dir, "samples.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")

    cfg_path = os.path.join(SAMPLES_DIR, f"{ALGORITHM_ID}.config.json")
    if build_dir != SAMPLES_DIR:
        import shutil
        os.makedirs(os.path.join(SAMPLES_DIR, "controls"), exist_ok=True)
        for src in glob.glob(os.path.join(build_dir, "*.txt")) + \
                glob.glob(os.path.join(build_dir, "*.json")):
            shutil.copy2(src, os.path.join(SAMPLES_DIR, os.path.basename(src)))
        for src in glob.glob(os.path.join(ctrl_dir, "*.txt")):
            shutil.copy2(src, os.path.join(SAMPLES_DIR, "controls", os.path.basename(src)))
        print(f"\ncopied {n_samp} samples + {len(ctrl_scores)} controls + config into {SAMPLES_DIR}")

    print(f"\nwrote {cfg_path}")
    print(f"wrote {os.path.join(SAMPLES_DIR, 'samples.json')}")
    if hits < n_samp:
        print("\nWARNING: not every demo sample cleared the threshold -- raise --num-tokens "
              "or lower --fpr, or regenerate the weak ones with --force.")
        return 1
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="synthid_smoke.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--smoke", action="store_true", help="quick round-trip check")
    p.add_argument("--build", action="store_true", help="generate samples/synthid-1/ + calibrate")
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"HF model id (default: {DEFAULT_MODEL})")
    p.add_argument("--keys", metavar="FILE", help="JSON {\"keys\": [...]} -- the SECRET")
    p.add_argument("--device", default="auto", help="auto (mps if present, else cpu) | cpu | mps")
    p.add_argument("--num-tokens", type=int, default=700)
    p.add_argument("--ngram-len", type=int, default=5)
    p.add_argument("--force", action="store_true", help="regenerate files that already exist")
    # --smoke
    p.add_argument("--pairs", type=int, default=6, help="[--smoke] prompt pairs")
    p.add_argument("--out", help="[--smoke] output dir (default: smoke-synthid/)")
    # --build
    p.add_argument("--samples", type=int, default=10, help="[--build] watermarked demo samples")
    p.add_argument("--controls", type=int, default=50, help="[--build] unwatermarked calibration texts")
    p.add_argument("--fpr", type=float, default=0.02, help="[--build] target false-positive rate")
    p.add_argument("--work-dir", help="[--build] generate here first (use a path OUTSIDE Google "
                                     "Drive), then copy the finished set into samples/synthid-1/")
    args = p.parse_args(argv)

    sid._require_deps()
    if args.build:
        return cmd_build(args)
    if args.smoke:
        return cmd_smoke(args)
    p.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
