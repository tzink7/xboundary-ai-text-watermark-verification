# Generating `synthid-1` sample text on Colab

`synthid-1` (Google DeepMind's SynthID-Text) is a *symmetric, statistical*
watermark -- here as the contrast case against `fairoze-1` / `tzsataitw-*`.
Generation is cheap (a small per-token overhead, no rejection sampling).

**You probably don't need this file.** `tools/synthid_smoke.py --build` runs
fine on a laptop -- CPU (~2-3 hrs for a full batch) or Apple MPS (~20-40 min).
`synthid.py` monkeypatches the SynthID sampling table onto the CPU generator
(`make_device_independent()`), so a mark embedded on *any* device verifies on a
CPU laptop / Cloud Run. Colab is only worth it if you want a bigger model
(Qwen2.5-3B rather than 0.5B) for nicer prose, done in ~15 min on a T4.

If you do use Colab: it runs the **same `tools/synthid_smoke.py --build`** this
repo ships -- clone, install, generate + calibrate + package on the GPU, then
download the finished `samples/synthid-1/` folder. No parameter duplication.

---

## Before you start

- Colab runtime: **GPU** (Runtime -> Change runtime type -> T4 is enough).
- Have your **`synthid-1.keys.json`** ready to upload -- the file with
  `{"keys": [ ... 24 ints ... ]}`. This is the watermark secret; it never goes
  in the repo.

## Cell 1 -- clone + install

```python
!git clone --depth 1 -q https://github.com/tzink7/xboundary-ai-text-watermark-verification.git
%cd xboundary-ai-text-watermark-verification
!pip -q install -r tools/requirements-synthid.txt
```

## Cell 2 -- upload the keys

Sidebar -> folder icon -> upload `synthid-1.keys.json` into `/content`. Then:

```python
import json, os
keys = json.load(open("/content/synthid-1.keys.json"))["keys"]
assert all(isinstance(k, int) for k in keys) and len(keys) >= 20
print(f"{len(keys)} keys loaded")
```

## Cell 3 -- sanity check (30 sec)

Confirms the watermark signal survives CUDA generation before you commit to the
full run.

```python
!python tools/synthid_smoke.py --smoke --device cuda --dtype float16 --pairs 3 \
    --model Qwen/Qwen2.5-3B-Instruct \
    --keys /content/synthid-1.keys.json --out /content/smoke
```

Look for `separation +0.0x` with `mean plain` near `0.5000`. Anything above
`+0.05` is a clean signal; if it is near zero, stop -- something is wrong with
the keys or the transformers version.

## Cell 4 -- the build (~15 min on a T4)

```python
!python tools/synthid_smoke.py --build --device cuda --dtype float16 \
    --model Qwen/Qwen2.5-3B-Instruct \
    --samples 10 --controls 40 --num-tokens 650 --fpr 0.02 \
    --keys /content/synthid-1.keys.json
```

`--dtype float16` matters: Qwen2.5-3B at the fp32 default is ~12 GB and OOMs a
16 GB T4 mid-run (which writes nothing). fp16 is ~6 GB and still watermarks fine
-- the device-independence patch handles the table, not the dtype. If it still
OOMs, drop to `Qwen/Qwen2.5-1.5B-Instruct`.

This generates `samples/synthid-1/sample-01..10.txt` (watermarked) and
`controls/ctrl-000..039.txt` (unwatermarked), calibrates the detection
threshold on the controls, writes `synthid-1.config.json` + `samples.json`, and
prints a table. **Read the last lines** -- it must say `demo samples cleared:
10/10`. If not, raise `--num-tokens` and re-run (resumable; `--force` redoes all).
If the run dies or you see a CUDA OOM, nothing is written -- fix and rerun.

Adjust `--samples` / `--controls` to taste. 3 samples + 22 controls is a
perfectly good demo and runs in ~5 min; 10 + 40 gives a fuller picker and a
tighter threshold.

Then confirm the files are actually there before moving on:

```python
!ls samples/synthid-1/ && ls samples/synthid-1/controls/ | wc -l
```

## Cell 5 -- download

```python
import shutil
shutil.make_archive("synthid-1-samples", "zip", "samples/synthid-1")
from google.colab import files
files.download("synthid-1-samples.zip")
```

---

## Back on your laptop

```bash
cd "…/GitHub"
rm -rf samples/synthid-1
mkdir -p samples/synthid-1
unzip -o ~/Downloads/synthid-1-samples.zip -d samples/synthid-1/

# spot-check: every sample should verify, a fairoze sample should not
for f in samples/synthid-1/sample-*.txt; do
  printf "%s: " "$f"
  ~/.venvs/fairoze/bin/python tools/synthid.py --verify --input "$f" \
    --config samples/synthid-1/synthid-1.config.json \
    --keys ~/Documents/synthid-keys/synthid-1.keys.json | head -1
done
~/.venvs/fairoze/bin/python tools/synthid.py --verify \
  --input samples/fairoze-1/sample-02.txt \
  --config samples/synthid-1/synthid-1.config.json \
  --keys ~/Documents/synthid-keys/synthid-1.keys.json | head -1   # -> NOT DETECTED
```

`synthid-1.config.json` carries the calibrated threshold and the tokenizer /
vocab_size / param set -- it is committable (no keys). The keys stay in Secret
Manager for the demo, exactly like the fairoze private key and the tzsataitw
signing keys.

## Then

- Decide whether to commit `samples/synthid-1/controls/` (reproducible
  calibration, ~40 small files) or gitignore it.
- Publish `4._watermark-text.demo.terryzink.com` -- `v=1; a=synthid-1; c=sign;
  nb=<unix>; na=ongoing`, **no `p=`** (symmetric). Log the p=-required tension in
  `implementation-open-questions.md`.
- Wire `synthid-1` into the demo (sample picker + a verify path that shows the
  score / threshold and states that only the key holder can run it).
