"""Ghost Data Still Exists - deletion audit agent.

Usage (from the repository root):
    python3 code/main.py                     # audits dataset/deletion_requests.csv -> output.csv
    python3 code/main.py --requests dataset/sample_deletion_requests.csv --out sample_pred.csv
    python3 code/main.py --llm               # also use an LLM for request-intent classification
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from evidence_parser import load_all  # noqa: E402
from identity import IdentityIndex  # noqa: E402
from engine import Engine, build_steps  # noqa: E402
from request_classifier import RequestClassifier  # noqa: E402
from usage import Usage  # noqa: E402


def read_requests(path):
    return list(csv.DictReader(open(path, encoding="utf-8")))


def case_num(cid):
    return int(cid.split("_")[1])


def confidence(status, detail, n_resources):
    """Grade how much the answer rests on inference rather than direct evidence."""
    reasons = []
    level = "high"
    for d in detail:
        att = d.get("attribution") or {}
        method = att.get("method")
        if method == "tie-break":
            reasons.append(f"{d['resource_id']}: attributed by deterministic tie-break between {att.get('tied_with')} requests")
            level = "low"
        elif method == "deduced-after-tie-break":
            reasons.append(f"{d['resource_id']}: deduced by elimination against a record that was itself placed by tie-break")
            level = "low"
        elif method == "proof-refinement":
            reasons.append(f"{d['resource_id']}: attribution chosen in the proof-refinement pass")
            level = "medium" if level == "high" else level
        elif method == "deduced" and att.get("window_candidates", 1) > 1:
            reasons.append(f"{d['resource_id']}: no identifiers; deduced from {att['window_candidates']} candidate requests"
                           f" via {', '.join(att.get('filters') or ['one-per-kind elimination'])}")
            level = "medium" if level == "high" else level
        if d["evidence_kind"].startswith("activity"):
            reasons.append(f"{d['resource_id']}: state taken from an activity status check (no evidence file)")
            level = "medium" if level == "high" else level
        if status == "COMPLETE" and not d["evidence_id"]:
            reasons.append(f"{d['resource_id']}: compliant state not read back in any evidence file")
            level = "low"
        if any(s.startswith("catalog:") for s in d.get("linked_by", [])):
            reasons.append(f"{d['resource_id']}: linked only through a data-catalog claim")
            level = "medium" if level == "high" else level
    if n_resources == 0:
        reasons.append("no record attributable to the subject was found")
        level = "low"
    return {"level": level, "reasons": reasons}


def run(requests_path, out_path, dataset_dir, use_llm=False, explain=False, features=None, history=True,
        trail_path=None):
    t0 = time.time()
    usage = Usage()
    obs, captured = load_all(dataset_dir, os.path.join(HERE, "extracted"))
    IdentityIndex.use_history = history
    ident = IdentityIndex(dataset_dir)
    engine = Engine(dataset_dir, obs, captured, ident)
    if features:
        engine.features.update(features)
    clf = RequestClassifier(use_llm=use_llm, cache_path=os.path.join(HERE, "cache", "intent_cache.json"), usage=usage)

    target = read_requests(requests_path)
    # Every known request competes for the shared deletion-worker activity stream.
    universe = {}
    for p in (os.path.join(dataset_dir, "deletion_requests.csv"), os.path.join(dataset_dir, "sample_deletion_requests.csv")):
        if os.path.exists(p):
            for q in read_requests(p):
                universe[(p, q["case_id"])] = q
    for q in target:
        universe[(requests_path, q["case_id"])] = q
    # Unique key per request (sample and evaluation case ids overlap).
    keyed = []
    for (p, cid), q in universe.items():
        qq = dict(q)
        qq["case_id"] = f"{os.path.basename(p)}::{cid}"
        keyed.append(qq)
    uid_of, deletion = {}, {}
    for q in keyed:
        uid, _ = ident.resolve_email(q["email"])
        uid_of[q["case_id"]] = uid
        deletion[q["case_id"]] = clf.is_deletion(q["request_text"])
    worker = engine.assign_worker_resources([q for q in keyed if deletion[q["case_id"]]], uid_of)
    if not engine.features["worker_linking"]:
        worker = defaultdict(set)

    # Provisional audit of every request, then the account-proof refinement pass.
    by_key = {q["case_id"]: q for q in keyed}
    statuses = {}
    for k, q in by_key.items():
        if deletion[k] and uid_of[k]:
            statuses[k] = engine.audit_case(q, uid_of[k], worker.get(k, set()))[0]
    if engine.features["proof_refinement"]:
        engine.refine_accounts(by_key, worker, statuses, uid_of)

    files = {r["file_id"]: r for r in csv.DictReader(open(os.path.join(dataset_dir, "evidence_files.csv"), encoding="utf-8"))}
    rows, explanations, trail = [], {}, []
    tag = os.path.basename(requests_path)
    for q in sorted(target, key=lambda q: case_num(q["case_id"])):
        key = f"{tag}::{q['case_id']}"
        uid, via = ident.resolve_email(q["email"])
        subject = {"request_email": q["email"], "user_id": uid,
                   "matched_via": None if uid is None else (f"historical email ({via})" if via else "current email"),
                   "identifiers_searched": len(ident.identifiers(uid)) if uid else 0}
        if not deletion[key] or uid_of[key] is None:
            rows.append((q["case_id"], "NOT_APPLICABLE", "[]"))
            trail.append({"case_id": q["case_id"], "deletion_status": "NOT_APPLICABLE", "subject": subject,
                          "audit_at": q["audit_at"], "workflow_claim": q["reported_status"],
                          "intent": "non-deletion purpose stated in request_text" if not deletion[key] else "subject not found",
                          "confidence": {"level": "high", "reasons": []}, "resources": [], "steps": []})
            continue
        status, f, r, v, res = engine.audit_case(q, uid_of[key], worker.get(key, set()))
        steps = build_steps(status, f, r, v)
        rows.append((q["case_id"], status, json.dumps(steps, ensure_ascii=False)))
        detail = engine.last_detail
        for d in detail:
            if d["evidence_id"] in files:
                d["evidence_file"] = files[d["evidence_id"]]["file_path"]
                d["evidence_captured_at"] = files[d["evidence_id"]]["captured_at"]
        trail.append({"case_id": q["case_id"], "deletion_status": status, "subject": subject,
                      "audit_at": q["audit_at"], "workflow_claim": q["reported_status"],
                      "confidence": confidence(status, detail, len(res)),
                      "resources": sorted(detail, key=lambda d: (d["system_id"], d["resource_id"])),
                      "steps": steps})
        if explain:
            explanations[q["case_id"]] = {rid: {"category": x.category, "sources": sorted(x.sources)} for rid, x in res.items()}
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        for row in rows:
            w.writerow(row)
    if trail_path:
        json.dump({"generated_from": os.path.basename(requests_path), "features": engine.features,
                   "cases": trail}, open(trail_path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    usage.write(os.path.join(HERE, "cache", "last_run_usage.json"), n_requests=len(target), seconds=time.time() - t0)
    run.trail = trail
    return rows, explanations


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", default=os.path.join(ROOT, "dataset", "deletion_requests.csv"))
    ap.add_argument("--out", default=os.path.join(ROOT, "output.csv"))
    ap.add_argument("--dataset", default=os.path.join(ROOT, "dataset"))
    ap.add_argument("--llm", action="store_true", help="use an LLM (ANTHROPIC_API_KEY) for intent classification")
    ap.add_argument("--trail", default=os.path.join(ROOT, "audit_trail.json"),
                    help="where to write the per-case evidence trail ('' to skip)")
    args = ap.parse_args()
    os.makedirs(os.path.join(HERE, "cache"), exist_ok=True)
    rows, _ = run(args.requests, args.out, args.dataset, use_llm=args.llm, trail_path=args.trail or None)
    from collections import Counter
    print(f"wrote {len(rows)} rows to {args.out}: {dict(Counter(r[1] for r in rows))}")
    if args.trail:
        conf = Counter(c["confidence"]["level"] for c in run.trail)
        print(f"wrote evidence trail to {args.trail}: confidence {dict(conf)}")


if __name__ == "__main__":
    main()
