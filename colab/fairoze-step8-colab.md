# Step 8 — batch 9 more `fairoze-1` samples

Step 7 confirmed the stack: Qwen2.5-3B, `--seed 1`, ~4 min, 0 planted errors,
4360 canonical chars, `detect.py` + `tools/fairoze.py` both verify.

Now generate 9 more with the **same key** (so one DNS record covers all of them),
then build 2 robustness-demo samples locally.

---

## Cell 8-setup — clone + patch + deps

Colab sessions don't persist. Re-upload **`fairoze-ed25519.patch`** to `/content`
(sidebar → folder icon → upload), then:

```python
%cd /content
!rm -rf publicly-detectable-watermark
!git clone --depth 1 -q https://github.com/jfairoze/publicly-detectable-watermark.git
%cd publicly-detectable-watermark
!git apply /content/fairoze-ed25519.patch && echo "patch applied OK"
!pip -q install bitstring reedsolo accelerate sentencepiece
!python -c "src=open('generate.py').read(); assert 'bplib' not in src; print('generate.py is patched')"
```

The last line must print `generate.py is patched`. If it raises, the patch
didn't apply — check the upload.

## Cell 8a — restore the Step 7 key

Upload **`sk.pem`** and **`pk.der`** (the two you downloaded in Step 7) into
`publicly-detectable-watermark/` — sidebar → folder icon → drag them in. Do this
*after* the setup cell (its `rm -rf` wipes the folder). Then:

```python
import os
os.chdir("/content/publicly-detectable-watermark")
assert os.path.exists("sk.pem") and os.path.exists("pk.der"), "upload sk.pem and pk.der here first"
print("key present -- generate.py will reuse it for every sample")
```

`generate.py` reuses the key when both files exist, so every sample verifies
against the same `p=`.

## Cell 8b — the batch loop (resumable)

```python
import subprocess, os

MODEL = "Qwen/Qwen2.5-3B"
PROMPTS = {
    2:  "Write a long, free-flowing essay about the history and culture of coffee.",
    3:  "Write a discursive piece on why so many cities grew up along rivers.",
    4:  "Write an essay about the appeal of long-distance hiking and what draws people to it.",
    5:  "Write a wandering essay about how board games evolved over the centuries.",
    6:  "Write an essay about the strange economics of the second-hand book market.",
    7:  "Write a reflective essay on what makes a good public library.",
    8:  "Write an essay about the rise of amateur astronomy as a hobby.",
    9:  "Write a long piece about bread baking at home and why people find it satisfying.",
    10: "Write an essay on the social history of the bicycle.",
}

os.makedirs("out", exist_ok=True)
for n, prompt in PROMPTS.items():
    dst = f"out/sample-{n:02d}.txt"
    if os.path.exists(dst):
        print(f"sample-{n:02d}: already done, skipping")
        continue
    print(f"\n=== sample-{n:02d} ===  {prompt[:60]}...")
    r = subprocess.run(
        ["python", "generate.py", "--prompt", prompt, "--model", MODEL,
         "--gen-type", "asymmetric", "--sample-type", "multinomial",
         "--sk", "sk.pem", "--pk", "pk.der", "--seed", str(n)],
        capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-2000:]); print(r.stderr[-2000:])
        print(f"sample-{n:02d} FAILED -- fix and re-run this cell (finished ones are skipped)")
        break
    os.replace("wat.txt", dst)
    txt = open(dst).read()
    det = subprocess.run(["python", "detect.py", dst, "--pk", "pk.der"],
                         capture_output=True, text=True).stdout.strip()
    print(f"sample-{n:02d}: {len(txt)} chars, detect.py -> {det}")

print("\ndone:", sorted(os.listdir("out")))
```

Each sample is ~4 min → the whole cell is ~35–40 min. If Colab disconnects,
just re-run the cell — it skips the samples already in `out/`.

## Cell 8c — download

```python
import shutil
shutil.make_archive("fairoze-1-samples", "zip", "out")
from google.colab import files
files.download("fairoze-1-samples.zip")
```

---

## Back on your laptop

```bash
cd "…/GitHub"
mkdir -p samples/fairoze-1
unzip -o ~/Downloads/fairoze-1-samples.zip -d samples/fairoze-1/

# the public key, as the base64 p= value (fairoze-1.pub is what the repo commits)
base64 -i ~/Downloads/pk.der | tr -d '\n' > samples/fairoze-1/fairoze-1.pub

# verify all 10
for f in samples/fairoze-1/sample-*.txt; do
  printf "%s: " "$f"
  ~/.venvs/fairoze/bin/python tools/fairoze.py --verify --input "$f" \
    --pubkey samples/fairoze-1/fairoze-1.pub | head -1
done
```

Every one should print `fairoze-1  --  VALID`.

## The two robustness-demo samples

Nothing to write — there's a script for it. From the repo root:

```bash
~/.venvs/fairoze/bin/python tools/fairoze_demo_edits.py
```

It reads `samples/fairoze-1/sample-01.txt` and writes two edited copies:

| file | edit | expected |
|---|---|---|
| `sample-01-edited-tail.txt` | one character in the **last** segment | **VALID** — Reed-Solomon absorbs it |
| `sample-01-edited-early.txt` | one character near the **start** | **NOT VERIFIED** — the chained hash cascades (D4) |

The script prints the verdict of each and exits non-zero if either is wrong.
These two files illustrate, on a real sample, that `fairoze-1` tolerates edits
only at the very end.

Then confirm:

```bash
~/.venvs/fairoze/bin/python tools/fairoze.py --verify \
  --input samples/fairoze-1/sample-01-edited-tail.txt \
  --pubkey samples/fairoze-1/fairoze-1.pub          # -> VALID

~/.venvs/fairoze/bin/python tools/fairoze.py --verify \
  --input samples/fairoze-1/sample-01-edited-early.txt \
  --pubkey samples/fairoze-1/fairoze-1.pub          # -> NOT VERIFIED
```

---

## Then

- `samples/fairoze-1/README.md` documents the set (prompts, model, seeds, the
  key, the DNS record)
- Step 9: publish a TXT record at `3._watermark-text.demo.terryzink.com`:
  `v=1; a=fairoze-1; p=<contents of fairoze-1.pub>; c=sign; nb=<unix now>; na=ongoing`
