"""Multimodal extraction for PDFs and screenshots -> code/extracted/<name>.json

The 15 PDF/PNG evidence files are converted once into structured records (resource_id, system,
record_type and the identifiers/flags visible on the page). The committed cache in
code/extracted/ was produced with Claude vision (screenshots) and pdftotext (PDFs) and then
reviewed by hand; the main pipeline only reads the cache, so runs are deterministic and free.

To regenerate the cache with a model (needs `pip install anthropic` and ANTHROPIC_API_KEY):
    python3 code/extract_media.py --force
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(HERE, "extracted")
sys.path.insert(0, HERE)
from usage import Usage  # noqa: E402

PROMPT = """You are reading an internal business artifact from an online shop (an admin-console
screenshot or a PDF). Extract every data record that has a resource id such as account_123,
search_45, support_6, analytics_7, export_8, data_flow_9, backup_10, audit_record_11,
tombstone_12, marketing_13 or object_14. Return JSON: {"records": [ {"resource_id": ...,
"system": ..., "record_type": one of USER_PROFILE, SEARCH_INDEX_ENTRY, SUPPORT_MESSAGE,
SUPPORT_ATTACHMENT, ANALYTICS_PROFILE, USER_EXPORT, MARKETING_PROFILE, DATA_FLOW, BACKUP_ARCHIVE,
SECURITY_AUDIT_LOG, ACCOUNT_TOMBSTONE, plus any visible identifiers (full_name, email, phone,
customer_reference/user_id/subject_reference, subject_selector) and flags (enabled,
restore_allowed, download_available). Use null for identifiers that are shown as removed.
Mark rows that are only mentioned in passing with "context_only": true. Output JSON only."""


def pdf_text(path):
    try:
        return subprocess.run(["pdftotext", "-layout", path, "-"], capture_output=True, text=True, check=True).stdout
    except Exception:
        try:
            import pdfplumber
            with pdfplumber.open(path) as pdf:
                return "\n".join(p.extract_text() or "" for p in pdf.pages)
        except Exception:
            return ""


def extract(path, usage, model):
    import anthropic
    client = anthropic.Anthropic()
    if path.lower().endswith(".pdf"):
        content = [{"type": "text", "text": PROMPT + "\n\nDocument text:\n" + pdf_text(path)}]
    else:
        data = base64.standard_b64encode(open(path, "rb").read()).decode()
        content = [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}},
                   {"type": "text", "text": PROMPT}]
    msg = client.messages.create(model=model, max_tokens=2000, messages=[{"role": "user", "content": content}])
    usage.record(model, msg.usage.input_tokens, msg.usage.output_tokens)
    text = msg.content[0].text
    return json.loads(text[text.index("{"): text.rindex("}") + 1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--model", default=os.environ.get("VISION_MODEL", "claude-sonnet-4-5"))
    args = ap.parse_args()
    usage = Usage()
    manifest = list(csv.DictReader(open(os.path.join(ROOT, "dataset", "evidence_files.csv"))))
    for m in manifest:
        path = os.path.join(ROOT, "dataset", m["file_path"])
        if not path.lower().endswith((".pdf", ".png", ".jpg")):
            continue
        out = os.path.join(OUT, os.path.splitext(os.path.basename(path))[0] + ".json")
        if os.path.exists(out) and not args.force:
            continue
        data = extract(path, usage, args.model)
        data["source"] = f"{args.model} extraction"
        json.dump(data, open(out, "w"), indent=1)
        print("extracted", out)
    print(json.dumps(usage.summary(n_requests=0), indent=1))


if __name__ == "__main__":
    main()
