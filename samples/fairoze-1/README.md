# `fairoze-1` sample watermarked texts

Real `fairoze-1` watermarks, generated once on an open-weight model and served
here so the demo (and anyone) can paste them into a verifier and watch the
publish-key-in-DNS / verify-across-organizations loop close.

**These are not robust marks.** `fairoze-1` tolerates an edit only in the very
last segment (see `sample-01-edited-*` below and
`../../implementation-open-questions.md` D4). Reformat or lightly edit any of
these and verification fails. That is a true property of the scheme, shown on
purpose.

## The key

| | |
|---|---|
| DNS record | `3._watermark-text.demo.terryzink.com` |
| value | `v=1; a=fairoze-1; p=MCowBQYDK2VwAyEAPMU2u2tOXRYt6Zsx3nPlYxvM9XLO8LWwLe7I6crMjp8=; c=sign; nb=1788489559; na=ongoing` |
| public key | `fairoze-1.pub` — the base64 Ed25519 SPKI, i.e. the exact `p=` value above |
| private key | **not in this repo** — held offline by the operator; only used to sign these samples |

Verify any sample against the live DNS record:

```
python tools/fairoze.py --verify --input samples/fairoze-1/sample-01.txt \
  --domain demo.terryzink.com --selector 3
```

or offline against the bundled key:

```
python tools/fairoze.py --verify --input samples/fairoze-1/sample-01.txt \
  --pubkey samples/fairoze-1/fairoze-1.pub
```

(needs `reedsolo` — see `tools/requirements.txt`.)

## How they were generated

- **Scheme:** `fairoze-1` — the [Fairoze23] publicly-detectable construction with
  the BLS signature swapped for **Ed25519** (so `p=` is a stock SPKI). Full
  parameter set in `tools/fairoze_profile.py`: SHA-256 window hash, SHAKE256
  mask, Reed-Solomon RS(68,64), 16-char segments, 2 bits/segment, 8-char message.
- **Generator:** a patched clone of
  `github.com/jfairoze/publicly-detectable-watermark` run in Google Colab on a
  T4. Patch and walkthrough: `../../colab/`.
- **Model:** `Qwen/Qwen2.5-3B` (base), fp16. ~4 min per sample, **0 planted
  errors** on every run.
- **Seeds:** `sample-NN.txt` was generated with `--seed NN`.
- Every sample is **exactly 4360 canonical characters** — the payload floor. The
  generator stops the instant one message+signature pair is embedded.

| file | prompt | verifies |
|---|---|---|
| `sample-01.txt` | a free-flowing essay about pickleball — origins, culture, why people love it, how the rules work | VALID |
| `sample-02.txt` | the history and culture of coffee | VALID |
| `sample-03.txt` | why so many cities grew up along rivers | VALID |
| `sample-04.txt` | the appeal of long-distance hiking | VALID |
| `sample-05.txt` | how board games evolved over the centuries | VALID |
| `sample-06.txt` | the strange economics of the second-hand book market | VALID |
| `sample-07.txt` | what makes a good public library | VALID |
| `sample-08.txt` | the rise of amateur astronomy as a hobby | VALID |
| `sample-09.txt` | bread baking at home and why people find it satisfying | VALID |
| `sample-10.txt` | the social history of the bicycle | VALID |

## Robustness demo

Made from `sample-01.txt` by `tools/fairoze_demo_edits.py`:

| file | edit | verifies | why |
|---|---|---|---|
| `sample-01-edited-tail.txt` | one character in the **last** segment | VALID | isolated 1-symbol error, Reed-Solomon corrects it |
| `sample-01-edited-early.txt` | one character near the **start** | **NOT VERIFIED** | the detector's chained hash cascades — every later segment is corrupted too (D4) |
