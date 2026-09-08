#!/usr/bin/env python3
"""
Gate for tools/synthid.py -- the synthid-1 (SynthID-Text) verifier.

The profile + config-loading checks run on the standard library. The scoring
checks need `torch` + `transformers` (tools/requirements-synthid.txt); if those
are missing they print instructions and skip.

    python3 -m venv .venv
    .venv/bin/pip install -r tools/requirements-synthid.txt
    .venv/bin/python tests/test_synthid.py
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import synthid_profile as prof                                   # noqa: E402
import synthid as sid                                            # noqa: E402

_HAVE_ML = True
try:
    import torch  # noqa: F401
    import transformers  # noqa: F401
except ImportError:
    _HAVE_ML = False


class TestProfile(unittest.TestCase):
    def test_identifier(self):
        self.assertEqual(prof.ALGORITHM_ID, "synthid-1")
        self.assertEqual(prof.KEY_MODEL, "symmetric")
        self.assertEqual(prof.DETECTION, "statistical")

    def test_canonicalize_matches_fairoze_shape(self):
        probe = "﻿  keep leading spaces\r\nsecond\n\n"
        self.assertEqual(prof.canonicalize(probe), "  keep leading spaces\nsecond")

    def test_null_score_is_half(self):
        self.assertEqual(prof.NULL_SCORE, 0.5)


class TestConfigLoading(unittest.TestCase):
    def _write(self, obj) -> str:
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(obj, fh)
        self.addCleanup(os.unlink, path)
        return path

    def test_inline_keys(self):
        p = self._write({"tokenizer": "gpt2", "keys": [1, 2, 3]})
        cfg = sid.load_config(p)
        self.assertEqual(cfg["keys"], [1, 2, 3])
        self.assertEqual(cfg["ngram_len"], 5)          # default filled in

    def test_keys_file_overrides_inline(self):
        cfg_path = self._write({"tokenizer": "gpt2", "keys": [1, 1, 1]})
        keys_path = self._write({"keys": [9, 8, 7]})
        cfg = sid.load_config(cfg_path, keys_path)
        self.assertEqual(cfg["keys"], [9, 8, 7])

    def test_env_var_keys(self):
        cfg_path = self._write({"tokenizer": "gpt2"})
        os.environ["SYNTHID_KEYS_JSON"] = json.dumps({"keys": [4, 5, 6]})
        self.addCleanup(os.environ.pop, "SYNTHID_KEYS_JSON", None)
        cfg = sid.load_config(cfg_path)
        self.assertEqual(cfg["keys"], [4, 5, 6])

    def test_missing_keys_exits(self):
        p = self._write({"tokenizer": "gpt2"})
        with self.assertRaises(SystemExit):
            sid.load_config(p)

    def test_missing_tokenizer_exits(self):
        p = self._write({"keys": [1, 2, 3]})
        with self.assertRaises(SystemExit):
            sid.load_config(p)

    def test_non_int_keys_exit(self):
        p = self._write({"tokenizer": "gpt2", "keys": [1, "two", 3]})
        with self.assertRaises(SystemExit):
            sid.load_config(p)


# A real, non-watermarked negative: a committed fairoze-1 sample (varied prose,
# ~4300 chars). It carries a fairoze-1 mark, not a SynthID one, so to synthid.py
# it is genuinely unwatermarked. Falls back to inline varied text if absent.
_NEG_SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "fairoze-1",
                           "sample-02.txt")
_NEG_FALLBACK = (
    "Coffee reached Europe by way of Venetian traders, and the first coffeehouses "
    "opened in the seventeenth century amid suspicion from both church and crown. "
    "Within decades they had become fixtures of urban life, places where merchants "
    "settled accounts, pamphleteers argued politics, and insurers first pooled risk. "
    "The bean itself travelled a stranger route, carried from the highlands of "
    "Ethiopia to the port of Mocha and from there, by smuggled cutting, to the "
    "botanical gardens of Amsterdam and the plantations of the Caribbean. Every cup "
    "since has been an accident of trade winds, colonial ambition, and the human "
    "preference for a mild and reliable stimulant over the alternatives then on offer. ")


def _negative_text() -> str:
    try:
        with open(_NEG_SAMPLE, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return _NEG_FALLBACK * 6


@unittest.skipUnless(_HAVE_ML, "torch + transformers not installed")
class TestScoring(unittest.TestCase):
    """Uses gpt2's tokenizer (small). Needs a one-time HF download."""

    @classmethod
    def setUpClass(cls):
        cls.cfg = {
            "tokenizer": "gpt2", "vocab_size": 50257, "ngram_len": 5,
            "context_history_size": 1024, "sampling_table_seed": 0,
            "sampling_table_size": 2 ** 16, "skip_first_ngram_calls": False,
            "keys": list(range(101, 125)),                # depth 24
        }
        cls.tok, cls.proc = sid._load_everything(dict(cls.cfg))
        cls.neg = _negative_text()

    def _score(self, text):
        return sid.score_text(text, self.cfg, tokenizer=self.tok, processor=self.proc)

    def test_unwatermarked_text_scores_near_half(self):
        r = self._score(self.neg)
        self.assertIsNotNone(r["score"])
        self.assertGreater(r["tokens_scored"], 200,
                           "need enough scorable positions for the null to concentrate")
        self.assertLess(abs(r["score"] - 0.5), 0.03,
                        f"unwatermarked null should be ~0.5, got {r['score']:.4f}")
        self.assertLess(abs(r["z_null"]), 4.0)
        self.assertEqual(r["depth"], 24)

    def test_short_text_is_rejected_not_crashed(self):
        r = self._score("only a few words here")
        self.assertIsNone(r["score"])
        self.assertIn("tokens", r["reason"])

    def test_verify_without_threshold_is_not_verified(self):
        cfg = dict(self.cfg)                              # no "threshold" key
        r = sid.verify_text(self.neg, cfg, tokenizer=self.tok, processor=self.proc)
        self.assertFalse(r["verified"])
        self.assertIn("threshold", r["reason"])

    def test_threshold_decides_verdict(self):
        base = self._score(self.neg)["score"]
        hi = dict(self.cfg, threshold=base + 0.05)
        lo = dict(self.cfg, threshold=base - 0.05)
        self.assertFalse(sid.verify_text(self.neg, hi, tokenizer=self.tok, processor=self.proc)["verified"])
        self.assertTrue(sid.verify_text(self.neg, lo, tokenizer=self.tok, processor=self.proc)["verified"])

    def test_calibrate_picks_a_threshold_within_the_score_range(self):
        # split the negative into chunks so there are several files to score
        chunk = max(1, len(self.neg) // 6)
        pieces = [self.neg[i:i + chunk] for i in range(0, len(self.neg), chunk)][:6]
        paths = []
        for i, t in enumerate(pieces):
            fd, p = tempfile.mkstemp(suffix=f"_{i}.txt")
            with os.fdopen(fd, "w") as fh:
                fh.write(t)
            paths.append(p)
            self.addCleanup(os.unlink, p)
        buf = io.StringIO()
        with redirect_stderr(buf):
            rep = sid.calibrate(paths, self.cfg, fpr=0.25)
        self.assertGreaterEqual(rep["negatives_scored"], 4)
        self.assertGreaterEqual(rep["threshold"], rep["score_p50"])
        self.assertLessEqual(rep["threshold"], rep["score_max"])

    def test_sampling_table_is_device_independent(self):
        """The whole point of make_device_independent(): the table must not depend
        on which device the processor was built on. Without the patch, a CUDA/MPS
        table differs from a CPU one and GPU-generated marks fail CPU detection."""
        import torch
        from transformers import SynthIDTextWatermarkingConfig
        sid.make_device_independent()
        c = SynthIDTextWatermarkingConfig(keys=list(range(101, 125)), ngram_len=5,
                                          sampling_table_seed=0, sampling_table_size=2 ** 16)
        p_cpu = c.construct_processor(50257, torch.device("cpu"))
        t_ref = torch.randint(0, 2, (2 ** 16,),
                              generator=torch.Generator(device="cpu").manual_seed(0))
        self.assertTrue(torch.equal(p_cpu.sampling_table.cpu(), t_ref),
                        "patched CPU table should equal a plain CPU-seeded randint")
        if torch.backends.mps.is_available():
            p_mps = c.construct_processor(50257, torch.device("mps"))
            self.assertTrue(torch.equal(p_mps.sampling_table.cpu(), t_ref),
                            "MPS table must match the CPU table after the patch")


def _run():
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    if not _HAVE_ML:
        print("NOTE  test_synthid -- torch/transformers missing; scoring tests skip")
        print("      .venv/bin/pip install -r tools/requirements-synthid.txt")
    sys.exit(_run())
