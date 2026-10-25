"""Evaluate predictions against labelled cases.

    python3 code/evaluation/main.py                      # runs the agent on the 32 samples and scores it
    python3 code/evaluation/main.py --pred X.csv --gold Y.csv
    python3 code/evaluation/main.py --custom             # also run the custom evaluation cases

Metrics
* case status accuracy           - deletion_status exact match
* exact case accuracy            - whole steps_json array identical
* step precision / recall / F1   - steps compared as (phase, system_id, resource_id, operation, state, evidence_id)
* field accuracy                 - per field, over aligned steps (aligned by phase+resource+operation)
* sequence accuracy              - cases whose step order equals gold order (on the common steps)
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.dirname(HERE)
ROOT = os.path.dirname(CODE)
sys.path.insert(0, CODE)

FIELDS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def load(path):
    return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(open(path, encoding="utf-8"))}


def tup(s):
    return tuple(s[f] for f in FIELDS)


def score(pred, gold, verbose=False):
    n = len(gold)
    status_ok = exact_ok = seq_ok = 0
    tp = fp = fn = 0
    field_hits = {f: 0 for f in FIELDS}
    aligned = 0
    failures = []
    for cid, (gs, gsteps) in sorted(gold.items(), key=lambda x: int(x[0].split("_")[1])):
        ps, psteps = pred.get(cid, ("MISSING", []))
        status_ok += ps == gs
        G = [tup(s) for s in gsteps]
        Pp = [tup(s) for s in psteps]
        exact_ok += G == Pp
        gset, pset = set(G), set(Pp)
        tp += len(gset & pset)
        fp += len(pset - gset)
        fn += len(gset - pset)
        common = [x for x in Pp if x in gset]
        seq_ok += common == [x for x in G if x in pset]
        gk = {(s[0], s[2], s[3]): s for s in G}
        for s in Pp:
            k = (s[0], s[2], s[3])
            if k in gk:
                aligned += 1
                for i, f in enumerate(FIELDS):
                    field_hits[f] += s[i] == gk[k][i]
        if ps != gs or G != Pp:
            failures.append((cid, gs, ps, sorted(gset - pset), sorted(pset - gset)))
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    out = {
        "cases": n,
        "status_accuracy": status_ok / n,
        "exact_case_accuracy": exact_ok / n,
        "step_precision": prec, "step_recall": rec, "step_f1": f1,
        "sequence_accuracy": seq_ok / n,
        "field_accuracy": {f: (field_hits[f] / aligned if aligned else 0) for f in FIELDS},
        "aligned_steps": aligned,
    }
    if verbose:
        for cid, gs, ps, miss, extra in failures:
            print(f"{cid}: gold={gs} pred={ps}")
            for m in miss:
                print("   missing", m)
            for e in extra:
                print("   extra  ", e)
    return out, failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred")
    ap.add_argument("--gold", default=os.path.join(ROOT, "dataset", "sample_output.csv"))
    ap.add_argument("--requests", default=os.path.join(ROOT, "dataset", "sample_deletion_requests.csv"))
    ap.add_argument("--custom", action="store_true")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    pred_path = args.pred
    if not pred_path:
        from main import run
        os.makedirs(os.path.join(CODE, "cache"), exist_ok=True)
        pred_path = os.path.join(tempfile.gettempdir(), "sample_pred.csv")
        run(args.requests, pred_path, os.path.join(ROOT, "dataset"))
    res, _ = score(load(pred_path), load(args.gold), verbose=args.v)
    print(json.dumps(res, indent=1))
    if args.custom:
        from custom_cases import run_custom
        run_custom()


if __name__ == "__main__":
    main()
