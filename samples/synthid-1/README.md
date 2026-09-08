# `synthid-1` sample watermarked texts

Real `synthid-1` watermarks (SynthID-Text, [Dathathri24]), generated once on an
open-weight model and served here so the demo can show the *symmetric* branch of
the framework: there is no public key, so DNS publishes a `k=symmetric` record
whose `d=` document names a `verify` endpoint the key holder runs.

`synthid-1` is a **statistical** mark spread across the whole text as a sampling
bias — detection is a score against a calibrated threshold, not a signature
check, and it needs the exact tokenizer + parameters in
`synthid-1.config.json`. It tolerates light edits far better than `fairoze-1`
but still degrades as the text is rewritten.

## The record

| | |
|---|---|
| DNS record | `4._watermark-text.demo.terryzink.com` |
| shape | `v=1; a=synthid-1; k=symmetric; c=sign; d=https://…/verify.json; dh=sha-256-…; nb=…; na=ongoing` |
| public key | **none** — symmetric scheme (draft §6.1 `k=symmetric`) |
| `d=` document | the draft §6.6 verification document: `algorithm`, `verify` endpoint, `canonicalization`, plus the tokenizer / threshold below |
| secret keys | **not in this repo** — held by the operator, used identically to generate and to detect |

## How they were generated

- **Scheme:** `synthid-1` — SynthID-Text tournament sampling. Parameter set in
  `tools/synthid_profile.py`; the values in force are in `synthid-1.config.json`.
- **Generator / detector:** `tools/synthid_smoke.py --build` and
  `tools/synthid.py` (HuggingFace `transformers` `SynthIDTextWatermark*`), with
  `synthid.make_device_independent()` so a mark embedded on GPU reads the same on
  a CPU verifier.
- **Model:** `Qwen/Qwen2.5-3B-Instruct`, ~650 new tokens, temp 1.0 / top-p 0.95.
- **Detector:** training-free masked-mean g-value. Null score ≈ 0.5; these
  samples score ≈ 0.55–0.60.
- **Threshold:** `0.509266`, the 98th-percentile score of the 40 non-watermarked
  `controls/` texts (target FPR 2%).
- **Seeds:** `sample-NN.txt` used generation seed `1000+N`; controls used `5000+k`.

| file | topic |
|---|---|
| `sample-01.txt` | pickleball |
| `sample-02.txt` | the history and culture of coffee |
| `sample-03.txt` | why so many cities grew up along rivers |
| `sample-04.txt` | the appeal of long-distance hiking |
| `sample-05.txt` | how board games evolved over the centuries |
| `sample-06.txt` | the economics of the second-hand book market |
| `sample-07.txt` | what makes a good public library |
| `sample-08.txt` | the rise of amateur astronomy as a hobby |
| `sample-09.txt` | bread baking at home |
| `sample-10.txt` | the social history of the bicycle |

`controls/ctrl-000.txt` … `ctrl-039.txt` are the non-watermarked texts the
threshold was calibrated on — kept so the calibration is reproducible:

```
python tools/synthid.py --calibrate --negatives 'samples/synthid-1/controls/*.txt' \
  --config samples/synthid-1/synthid-1.config.json --keys <secret keys file>
```

(needs `torch` + `transformers` — see `tools/requirements-synthid.txt`.)

## `verify-scores.json`

`verify-scores.json` is a pre-computed lookup the **demo server** uses to play the
`verify` endpoint without running the detector inline (the Cloud Run image has no
`torch`). It maps `sha256(canonicalized text)` → `{score, watermarked}` for the 10
samples and 40 controls, using the same `["strip-zero-width", "nfc", "trim"]`
canonicalization as the §6.6 `d=` document. Regenerate it whenever the samples or
`synthid-1.config.json` change (scoring script needs the operator keys).
