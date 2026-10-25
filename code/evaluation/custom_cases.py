"""Custom evaluation cases (written by the team, not part of the supplied labels).

Each case perturbs a real request and states the behaviour the agent must show. They are
property tests: the expected answer follows from the challenge rules, not from hidden labels.

    python3 code/evaluation/custom_cases.py
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

DATASET = os.path.join(ROOT, "dataset")
FIELDS = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]


def requests(path):
    return {r["case_id"]: r for r in csv.DictReader(open(path, encoding="utf-8"))}


def audit(rows):
    """Run the agent on custom request rows; returns {case_id: (status, steps)}."""
    tmp = tempfile.mkdtemp()
    req = os.path.join(tmp, "custom_requests.csv")
    out = os.path.join(tmp, "custom_output.csv")
    with open(req, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r[k] for k in FIELDS})
    run(req, out, DATASET)
    return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"]))
            for r in csv.DictReader(open(out, encoding="utf-8"))}


def captured():
    return {r["file_id"]: r["captured_at"] for r in csv.DictReader(open(os.path.join(DATASET, "evidence_files.csv")))}


def run_custom():
    samples = requests(os.path.join(DATASET, "sample_deletion_requests.csv"))
    main = requests(os.path.join(DATASET, "deletion_requests.csv"))
    cap = captured()
    results = []

    # C1 - historical identifier: the same request filed with the user's previous e-mail must be
    #      resolved to the same subject and produce the same audit.
    base = dict(samples["case_12"])          # user_12 changed minjun.kim90@ -> minjun.kim@
    old = dict(base, case_id="case_901", email="minjun.kim90@gmail.com")
    # C2 - upper-case / formatting variant of the e-mail must resolve identically.
    upper = dict(base, case_id="case_902", email=base["email"].upper())
    # C3 - time cutoff: move audit_at before the 2026-10-01 handover snapshot. The handover
    #      (evidence_03) must not be cited and nothing captured after audit_at may be cited.
    early = dict(samples["case_11"], case_id="case_903", audit_at="2026-09-20T12:00:00Z")
    # C4 - non-deletion intent in another wording -> NOT_APPLICABLE with [].
    na = dict(samples["case_21"], case_id="case_904",
              request_text="Could you send me a copy of everything you store about me? Please don't delete anything.")
    # C5 - look-alike decoy: g.silva76.jr@gmail.com (search_1874) must never be attributed to
    #      g.silva76@gmail.com.
    decoy = dict(main["case_35"], case_id="case_905")
    # C6 - catalog claim contradicted by the record itself: marketing_001 is linked to Kwame Mensah
    #      by the data catalog, but the record shows a different person; it must not be reported.
    catalog = dict(main["case_63"], case_id="case_906")
    reference = dict(base, case_id="case_900")

    out = audit([reference, old, upper, early, na, decoy, catalog])

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    check("C1 historical e-mail resolves to the same subject",
          out["case_901"] == out["case_900"], f"status={out['case_901'][0]}")
    check("C2 upper-case e-mail resolves identically",
          out["case_902"] == out["case_900"], f"status={out['case_902'][0]}")
    cited = {s["evidence_id"] for s in out["case_903"][1] if s["evidence_id"].startswith("evidence_")}
    late = [e for e in cited if cap[e] > early["audit_at"]]
    check("C3 nothing captured after audit_at is cited", not late and "evidence_03" not in cited,
          f"status={out['case_903'][0]} cited={sorted(cited)}")
    check("C4 non-deletion request is NOT_APPLICABLE with []",
          out["case_904"] == ("NOT_APPLICABLE", []), f"got={out['case_904'][0]}")
    rids = {s["resource_id"] for s in out["case_905"][1]}
    check("C5 look-alike search document is not attributed", "search_1874" not in rids and "search_428" in rids,
          f"resources={sorted(rids)}")
    rids6 = {s["resource_id"] for s in out["case_906"][1]}
    check("C6 contradicted catalog link is rejected", "marketing_001" not in rids6, f"resources={sorted(rids6)}")

    print("\nCustom evaluation cases")
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}  {detail}")
    print(f"  {sum(ok for _, ok, _ in results)}/{len(results)} passed")
    return results


if __name__ == "__main__":
    run_custom()
