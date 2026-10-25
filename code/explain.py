"""Explain one audit decision from audit_trail.json (written by code/main.py).

    python3 code/explain.py case_49
    python3 code/explain.py --low          # list the low-confidence cases and why
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIL = os.path.join(ROOT, "audit_trail.json")


def show(c):
    s = c["subject"]
    print(f"\n{c['case_id']}  ->  {c['deletion_status']}   (workflow claimed {c.get('workflow_claim', '-')}, "
          f"audit_at {c.get('audit_at', '-')})")
    print(f"  subject   {s['request_email']} -> {s['user_id']} via {s['matched_via']}, "
          f"{s['identifiers_searched']} identifiers searched")
    conf = c["confidence"]
    print(f"  confidence {conf['level'].upper()}")
    for r in conf["reasons"]:
        print(f"     - {r}")
    if c.get("intent"):
        print(f"  intent    {c['intent']}")
    for d in c["resources"]:
        st = d.get("state_at_audit") or {}
        flags = ", ".join(f"{k}={v}" for k, v in st.items() if v is not None) or "not read back"
        rule = d["rule"]
        print(f"\n  {d['system_id']}/{d['resource_id']}  [{d['data_category']}]  rule {rule.get('rule_id')} "
              f"{rule.get('required_action')}")
        print(f"     linked by   {', '.join(d['linked_by'])}  (attribution: {d['attribution'].get('method')})")
        print(f"     state       {flags}")
        ev = d["evidence_id"] or "-"
        if d.get("evidence_file"):
            ev += f"  {d['evidence_file']}  captured {d['evidence_captured_at']}"
        print(f"     evidence    {ev}")
        print(f"     decision    {d['decision']}")
    if c["steps"]:
        print("\n  steps")
        for st in c["steps"]:
            print(f"    {st['step_no']:>2}. {st['phase']:<12} {st['operation']:<26} {st['system_id']}/{st['resource_id']}"
                  f"  {st['evidence_id']}")


def main():
    if not os.path.exists(TRAIL):
        sys.exit("audit_trail.json not found - run python3 code/main.py first")
    cases = {c["case_id"]: c for c in json.load(open(TRAIL, encoding="utf-8"))["cases"]}
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    if args[0] == "--low":
        for c in cases.values():
            if c["confidence"]["level"] == "low":
                print(f"{c['case_id']:<9} {c['deletion_status']:<11} " + "; ".join(c["confidence"]["reasons"]))
        return
    for cid in args:
        if cid not in cases:
            print(f"{cid}: not in audit_trail.json")
            continue
        show(cases[cid])


if __name__ == "__main__":
    main()
