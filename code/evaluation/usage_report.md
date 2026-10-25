# Usage report: final full-dataset run

## Final run that produced `output.csv`

Command: `python3 code/main.py` (default mode). Runtime is about 1 second on a laptop CPU.

| Provider | Model | Model calls | Input tokens | Output tokens | Total tokens | Cost (USD) |
|---|---|---|---|---|---|---|
| none | none (deterministic pipeline) | 0 | 0 | 0 | 0 | $0.00 |
| **Overall** | | **0** | **0** | **0** | **0** | **$0.00** |

| Per-request figure | Value |
|---|---|
| Requests processed | 518 |
| Average tokens per request | 0 |
| Estimated cost per request | $0.00 |

The final run makes **no model calls**. Every decision (identity resolution, state reconstruction, policy application, step ordering) is computed in Python from the files in `dataset/`. This was a deliberate choice: the problem is mostly exact matching and rule application, where an LLM adds cost and nondeterminism without improving accuracy. The token counter in `code/usage.py` still runs on every execution and writes `code/cache/last_run_usage.json`.

## Where models were used

### 1. Multimodal extraction of the 15 PDFs and screenshots (one-off, cached)

The 11 PNG screenshots were read with Claude vision. The 4 PDFs were converted with `pdftotext` and the result was checked by the model. The structured records are committed in `code/extracted/*.json` and reviewed by hand. The pipeline reads only this cache, so the extraction cost is paid once, not per run. `code/extract_media.py --force` reproduces it through the Anthropic API.

The figures below are estimates. The extraction ran inside the development session, so exact token counts weren't recorded. They use about 1,600 × 1,200 px per screenshot ≈ 2,600 input tokens, plus about 300 output tokens per file.

| Provider | Model | Calls | Input tokens (est.) | Output tokens (est.) | Total (est.) | Cost at $3 / $15 per Mtok (est.) |
|---|---|---|---|---|---|---|
| Anthropic | Claude (vision), screenshots | 11 | ~29,000 | ~3,300 | ~32,300 | ~$0.14 |
| Anthropic | Claude, PDF text review | 4 | ~4,000 | ~1,200 | ~5,200 | ~$0.03 |
| **Overall (one-off)** | | **15** | **~33,000** | **~4,500** | **~37,500** | **~$0.17** |

Spread over the 518 requests, that's about 72 tokens and $0.0003 per request, one time.

### 2. Optional LLM intent classifier (off by default)

`python3 code/main.py --llm` with `ANTHROPIC_API_KEY` set sends each distinct `request_text` to `claude-haiku-4-5` once, caches the answer, and falls back to the rule-based classifier on any error. The rule-based classifier agrees with all 32 sample labels and flags exactly the 10 evaluation requests that state a non-deletion purpose (access, export, correction, opt-out, login help, e-mail change), so the final submission doesn't use the LLM path.

If it is enabled, the estimate is: 518 calls × (about 170 input + 2 output tokens) ≈ 89,000 tokens ≈ $0.09 at $1 / $5 per Mtok, or about 172 tokens and $0.00017 per request. Calls and tokens are then recorded per model in `code/cache/last_run_usage.json`.
