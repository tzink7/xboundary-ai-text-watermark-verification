# Step 7 — generate one real `fairoze-1` sample in Google Colab

**You do not need to give anyone credentials.** Colab runs in *your* browser,
signed into *your* Google account. Nobody else can drive it — you paste the
cells below and run them yourself.

Goal: run the (patched) Fairoze generator on a real open-weight model, produce
one watermarked passage, and confirm the patched `detect.py` finds it. The
crypto and detection stack is already proven wire-compatible with
`tools/fairoze.py` (Step 6), so this step is only asking "does a real model
produce enough entropy to embed?".

---

## 0. One-time Colab orientation

1. Go to **colab.research.google.com** → sign in with your Google account.
2. **File → New notebook.**
3. **Runtime → Change runtime type → Hardware accelerator: T4 GPU → Save.**
   (Free tier gives a T4. If it says none available, try again later.)
4. Each grey box below is one **cell**. Click a cell, paste, press
   **Shift+Enter** to run it. Wait for the ▶ to finish before the next.
5. You need the patch file. Download **`GitHub/colab/fairoze-ed25519.patch`**
   from this repo to your laptop, then in Colab: left sidebar → the **folder
   icon** → **Upload** (the page-with-up-arrow icon) → pick `fairoze-ed25519.patch`.
   It lands in `/content/`.

---

## Cell 1 — clone the repo and apply the Ed25519 patch

```python
%cd /content
!rm -rf publicly-detectable-watermark          # safe to re-run this cell
!git clone --depth 1 https://github.com/jfairoze/publicly-detectable-watermark.git
%cd publicly-detectable-watermark
!git apply /content/fairoze-ed25519.patch && echo "patch applied OK"
```

> The patch swaps the BLS signature for Ed25519 (so `p=` is a stock key), fixes
> the SHAKE256 mask, and updates `generate.py` for current transformers:
> `load_in_4bit` kwarg -> `BitsAndBytesConfig`; `torch_dtype` -> `dtype`; and the
> KV cache (whose old tuple format the sampling loop rewinds to checkpoints) is
> kept **on** but snapshotted with `copy.deepcopy` at each retry point, since
> modern `DynamicCache` mutates in place. It touches `crypto.py`, `detect.py`,
> `generate.py`, `test_crypto.py` only, and stays GPL-3.0 — the patch is a
> description of changes, kept out of the main repo.

## Cell 2 — install dependencies

```python
!pip -q install bitstring reedsolo accelerate sentencepiece
# torch + transformers are already on Colab. bplib / petlib / bls-lib are NOT
# needed. Add "bitsandbytes" only if you use --load-in-4bit below.
import transformers; print("transformers", transformers.__version__)
```

## Cell 3 — sanity-check the patched crypto (no model, ~40s)

```python
!python -m unittest -v \
  test_crypto.TestCrypto.test_bls_openssl \
  test_crypto.TestCrypto.test_bls_rsc_combination_with_hashing_openssl \
  test_crypto.TestCrypto.test_reedsolo_error_correction
```

Expect `OK`. If this fails, stop — the model won't fix it.

## Cell 4a — smoke test: does the model load and generate at all? (~1 min)

```python
MODEL = "Qwen/Qwen2.5-3B"   # base, ~6 GB fp16 — fits a T4. Downloads once (~6 GB).

!python generate.py --model "$MODEL" --gen-type plain --num-tokens 40 \
  --prompt "Pickleball is a paddle sport that"
print(open("wat.txt").read())
```

If this prints ~40 tokens of text, the environment is good. If it errors, paste
the traceback — that's an environment problem, separate from the watermark.

## Cell 4b — generate one watermarked passage

```python
PROMPT = ("Write a long, free-flowing essay about pickleball — its origins, its "
          "culture, why people love it, and how the rules work in practice.")

!python generate.py \
  --prompt "$PROMPT" \
  --model "$MODEL" \
  --gen-type asymmetric \
  --sample-type multinomial \
  --sk sk.pem --pk pk.der --seed 1

print("\n--- generated text (wat.txt) ---")
txt = open("wat.txt").read()
print(txt)
print(f"\n[{len(txt)} characters]")
```

Notes:
- Runs until one full message+signature pair is embedded (~4000-5000 chars).
  The patched cache makes each token ~5x faster than the first version — expect
  roughly **10-20 min** on a T4 for the 3B model.
- **Keep the prompt open-ended.** A tightly-worded prompt ("foot placement behind
  the baseline, both feet on the ground, ...") pins the model's next-token
  distribution and starves the watermark of the sampling freedom it needs. Broad
  and discursive works better.
- **If it fails with `already at max_planted_errors`** (the model ran out of
  entropy 3+ times): step up to a bigger base model —
  ```
  !pip -q install bitsandbytes
  ```
  then set `MODEL = "Qwen/Qwen2.5-7B"` and add `--load-in-4bit` to the command.
  Bigger base models have flatter distributions and plant fewer errors.
- **Do NOT change `--max-planted-errors`, `--bit-size`, `--signature-segment-length`
  or `--message-length`** without telling me — the verifier's profile
  (`tools/fairoze_profile.py`) is pinned to the defaults (2 / 2 / 16 / 8) and
  both sides must match exactly.
- `sk.pem` = the Ed25519 **private** key. `pk.der` = the **public** key for the
  DNS `p=` tag.

## Cell 5 — detect it with the patched `detect.py`

```python
!python detect.py wat.txt --pk pk.der --gen-type asymmetric
```

Expect `True`. That means: the patched Fairoze stack embedded a real signature
and recovered + verified it.

## Cell 6 — the public key and the DNS record

```python
import base64
pk_b64 = base64.b64encode(open("pk.der","rb").read()).decode()
print("p= value (base64 SPKI Ed25519):")
print(pk_b64)
print()
print("DNS TXT record to publish at 3._watermark-text.demo.terryzink.com :")
print(f'v=1; a=fairoze-1; p={pk_b64}; c=sign; nb=<unix-now>; na=ongoing')
```

## Cell 7 — download what you need

```python
from google.colab import files
files.download("wat.txt")     # the watermarked sample
files.download("pk.der")      # public key -> DNS
files.download("sk.pem")      # PRIVATE key -> keep safe, needed for Step 8
```

---

## Back on your laptop — the cross-check

```
~/.venvs/fairoze/bin/python tools/fairoze.py --verify --input wat.txt --pubkey pk.der
```

Expect `fairoze-1  --  VALID`. If Colab's `detect.py` said `True` and this says
`VALID`, the two independent implementations agree on a real model-generated
sample — that's the Step 7 gate.

Then note:
- the actual character length of `wat.txt` (updates `MIN_WATERMARK_CHARS` if it
  differs much from ~4360)
- how many "planted errors" the generator reported (in Colab's `logging.log`)
- how long generation took

Those numbers feed Step 8 (batch of 10) and the `fairoze-1` profile.
