"""Ablation study + confidence calibration on the 32 labelled samples.

    python3 code/evaluation/ablation.py

1. Ablation: switches each technique off in turn and re-scores the samples, showing what each one
   contributes. Also reports how many of the 518 evaluation answers change when it is removed.
2. Calibration: groups the sample cases by the agent's own confidence level and reports the exact-case
   accuracy per level, to check that "high" really means more reliable than "low".
"""
from __future__ import annotations

import csv
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.dirname(HERE)
ROOT = os.path.dirname(CODE)
sys.path.insert(0, CODE)


from main import run  # noqa: E402


DATA = os.path.join(ROOT, "dataset")
SAMPLES = os.path.join(DATA, "sample_deletion_requests.csv")
GOLD = os.path.join(DATA, "sample_output.csv")
FULL = os.path.join(DATA, "deletion_requests.csv")

VARIANTS = [
    ("Full agent", {}, True),
    ("- identity history (old e-mails/phones/hashes)", {}, False),
    ("- worker-run linking (identifier-free records)", {"worker_linking": False}, True),
    ("- status/result compatibility", {"status_compat": False}, True),
    ("- evidence co-occurrence", {"evidence_cooccurrence": False}, True),
    ("- policy-action chain timing", {"policy_chain": False}, True),
    ("- proof-aware refinement pass", {"proof_refinement": False}, True),
    ("- replica drift (primary only)", {"replica_drift": False}, True),
    ("- snapshot absence proof", {"snapshot_absence": False}, True),
    ("- catalog contradiction check", {"catalog_check": False}, True),
]


def load_rows(path):
    return {r["case_id"]: (r["deletion_status"], r["steps_json"]) for r in csv.DictReader(open(path, encoding="utf-8"))}


def main():
    import importlib.util
    spec = importlib.util.spec_from_file_location("evalmain", os.path.join(HERE, "main.py"))
    ev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ev)
    tmp = tempfile.mkdtemp()
    gold = ev.load(GOLD)
    base_full = None
    lines = ["| Variant | Status acc. | Step F1 | Exact cases | Eval answers changed (status / steps) |",
             "|---|---|---|---|---|"]
    for name, feats, hist in VARIANTS:
        sp, fp = os.path.join(tmp, "s.csv"), os.path.join(tmp, "f.csv")
        run(SAMPLES, sp, DATA, features=feats, history=hist)
        res, _ = ev.score(ev.load(sp), gold)
        run(FULL, fp, DATA, features=feats, history=hist)
        full = load_rows(fp)
        if base_full is None:
            base_full = full
            delta = "-"
        else:
            st = sum(full[c][0] != base_full[c][0] for c in base_full)
            stp = sum(full[c][1] != base_full[c][1] for c in base_full)
            delta = f"{st} / {stp}"
        lines.append(f"| {name} | {res['status_accuracy']:.1%} | {res['step_f1']:.3f} | "
                     f"{round(res['exact_case_accuracy'] * res['cases'])}/{res['cases']} | {delta} |")
    print("\n".join(lines))

    # Confidence calibration on the samples
    sp = os.path.join(tmp, "s.csv")
    run(SAMPLES, sp, DATA)
    trail = {c["case_id"]: c for c in run.trail}
    pred = ev.load(sp)
    by = {}
    for cid, (gs, gsteps) in gold.items():
        lvl = trail[cid]["confidence"]["level"]
        ok = pred[cid][0] == gs and [ev.tup(s) for s in pred[cid][1]] == [ev.tup(s) for s in gsteps]
        by.setdefault(lvl, []).append(ok)
    print("\n| Confidence | Sample cases | Exact-case accuracy |\n|---|---|---|")
    for lvl in ("high", "medium", "low"):
        v = by.get(lvl, [])
        print(f"| {lvl} | {len(v)} | {(sum(v) / len(v)) if v else 0:.0%} |")


if __name__ == "__main__":
    main()
