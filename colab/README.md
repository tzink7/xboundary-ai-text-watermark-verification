# colab/ — running the Fairoze generator for `fairoze-1`

The `fairoze-1` verifier (`tools/fairoze.py`) is pure CPU and lives in this repo.
*Generating* a `fairoze-1` watermark needs an open-weight LLM with token-level
sampling control — that runs in Google Colab on a GPU.

| file | what |
|---|---|
| `fairoze-ed25519.patch` | unified diff against `github.com/jfairoze/publicly-detectable-watermark` — swaps its BLS signature for Ed25519 (so `p=` is a stock SPKI) and fixes the SHAKE256 mask. `git apply` it to a fresh clone. |
| `step6-fairoze-ed25519-patch.md` | what the patch changes and how it was verified on CPU (done — repo `test_crypto.py` passes, wire-compatible with `tools/fairoze.py`) |
| `fairoze-step7-colab.md` | copy-paste Colab walkthrough: clone → patch → generate one real sample → detect it → cross-check locally. **Step 7 passed 2026-09-03** (Qwen2.5-3B, ~4 min, 0 planted errors, 4360 chars). |
| `fairoze-step8-colab.md` | batch 9 more samples with the same key, + 2 local robustness-demo samples |

The patched Fairoze files themselves are **GPL-3.0** (derivative of the upstream
repo). Only the *patch* is kept here; the modified files live in Colab / a
scratch checkout, never vendored into this repo.

Start with `fairoze-step7-colab.md`.
