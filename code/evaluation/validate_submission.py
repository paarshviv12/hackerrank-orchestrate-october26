"""Pre-submission diagnostics for output.csv, code.zip contents and secrets.

    python3 code/evaluation/validate_submission.py

Checks every rule in the README / problem_statement / AGENTS.md submission checklist and
prints PASS / FAIL lines. Exit code 1 if anything fails.
"""
from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DATA = os.path.join(ROOT, "dataset")

PHASE_OPS = {
    "FINDING": ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"],
    "REMEDIATION": ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"],
    "VERIFICATION": ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                     "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"],
}
STATE = {"REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT", "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
         "REPORT_RESTORE_RISK": "ACTIVE", "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
         "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
         "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
         "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
         "VERIFY_RESTORE_BLOCKED": "BLOCKED"}
KEYS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}

results = []


def check(name, problems):
    problems = list(problems)
    results.append((name, not problems))
    print(f"[{'PASS' if not problems else 'FAIL'}] {name}" + (f"  ({len(problems)} problems)" if problems else ""))
    for p in problems[:8]:
        print("       ", p)


def main():
    out_path = os.path.join(ROOT, "output.csv")
    reqs = list(csv.DictReader(open(os.path.join(DATA, "deletion_requests.csv"), encoding="utf-8")))
    req = {r["case_id"]: r for r in reqs}
    cap = {r["file_id"]: r["captured_at"] for r in csv.DictReader(open(os.path.join(DATA, "evidence_files.csv")))}
    acts = {r["activity_id"]: r["event_time"] for r in csv.DictReader(open(os.path.join(DATA, "system_activity.csv")))}
    audits = {r["audit_id"]: r["event_time"] for r in csv.DictReader(open(os.path.join(DATA, "user_audit_log.csv")))}

    with open(out_path, newline="", encoding="utf-8") as fh:
        raw = list(csv.reader(fh))
    check("exact header case_id,deletion_status,steps_json",
          [] if raw and raw[0] == ["case_id", "deletion_status", "steps_json"] else [f"header={raw[0] if raw else None}"])
    rows = [dict(zip(raw[0], r)) for r in raw[1:]]
    ids = [r["case_id"] for r in rows]
    check("518 rows, one per request, no duplicates",
          ([f"rows={len(rows)}"] if len(rows) != 518 else []) +
          [f"missing {c}" for c in sorted(set(req) - set(ids))] +
          [f"unexpected {c}" for c in sorted(set(ids) - set(req))] +
          (["duplicates"] if len(ids) != len(set(ids)) else []))
    check("rows sorted by case_id (same order as deletion_requests.csv)",
          [] if ids == [r["case_id"] for r in reqs] else ["order differs"])
    check("deletion_status values", [f"{r['case_id']}={r['deletion_status']}" for r in rows
                                      if r["deletion_status"] not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")])

    bad_json, bad_keys, bad_num, bad_phase, bad_op, bad_state, bad_sort = [], [], [], [], [], [], []
    bad_na, bad_complete, bad_incomplete, bad_ev, late_ev = [], [], [], [], []
    for r in rows:
        cid, st = r["case_id"], r["deletion_status"]
        try:
            steps = json.loads(r["steps_json"])
            assert isinstance(steps, list)
        except Exception:
            bad_json.append(cid)
            continue
        if st == "NOT_APPLICABLE":
            if steps:
                bad_na.append(cid)
            continue
        if [s.get("step_no") for s in steps] != list(range(1, len(steps) + 1)):
            bad_num.append(cid)
        order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        phases = [s.get("phase") for s in steps]
        if any(p not in order for p in phases) or phases != sorted(phases, key=lambda p: order.get(p, 9)):
            bad_phase.append(cid)
        for s in steps:
            if set(s) != KEYS:
                bad_keys.append(cid)
            if s.get("operation") not in PHASE_OPS.get(s.get("phase"), []):
                bad_op.append(f"{cid}:{s.get('phase')}/{s.get('operation')}")
            elif STATE[s["operation"]] != s.get("state"):
                bad_state.append(f"{cid}:{s['operation']}->{s.get('state')}")
        for ph, opl in PHASE_OPS.items():
            seq = [(opl.index(s["operation"]), s["system_id"], s["resource_id"]) for s in steps
                   if s["phase"] == ph and s["operation"] in opl]
            if seq != sorted(seq):
                bad_sort.append(f"{cid}:{ph}")
        if st == "COMPLETE":
            if not steps or any(s["phase"] != "VERIFICATION" or not s["evidence_id"] for s in steps):
                bad_complete.append(cid)
        if st == "INCOMPLETE":
            if not any(s["phase"] == "FINDING" for s in steps) or \
                    any(s["evidence_id"] for s in steps if s["phase"] != "FINDING") or \
                    any(not s["evidence_id"] for s in steps if s["phase"] == "FINDING"):
                bad_incomplete.append(cid)
        audit_at = req[cid]["audit_at"]
        for s in steps:
            e = s["evidence_id"]
            if not e:
                continue
            t = cap.get(e) or acts.get(e) or audits.get(e)
            if t is None:
                bad_ev.append(f"{cid}:{e}")
            elif t > audit_at:
                late_ev.append(f"{cid}:{e} captured {t} > audit {audit_at}")
    check("every steps_json is a JSON array", bad_json)
    check("each step has exactly the 7 required fields", sorted(set(bad_keys)))
    check("step numbers consecutive from 1", bad_num)
    check("phase order FINDING -> REMEDIATION -> VERIFICATION", bad_phase)
    check("operations valid for their phase", bad_op)
    check("state matches operation", bad_state)
    check("within phase: operation order, then system_id, then resource_id", bad_sort)
    check("NOT_APPLICABLE rows use []", bad_na)
    check("COMPLETE rows: only verification steps, each citing evidence", bad_complete)
    check("INCOMPLETE rows: findings cite evidence, remediation/verification use \"\"", bad_incomplete)
    check("cited evidence ids exist (file_id / activity_id / audit_id)", bad_ev)
    check("no cited evidence captured after the case's audit_at", late_ev)

    # Deliverables and hygiene
    need = ["README.md", "code/main.py", "code/evaluation/evaluation_report.md", "code/evaluation/usage_report.md", "log.txt"]
    check("required deliverable files exist", [p for p in need if not os.path.exists(os.path.join(ROOT, p))])
    log = open(os.path.join(ROOT, "log.txt"), encoding="utf-8").read() if os.path.exists(os.path.join(ROOT, "log.txt")) else ""
    check("log.txt has SESSION START and populated tool=/model= lines",
          ([] if "SESSION START" in log else ["no SESSION START"]) +
          [l for l in log.splitlines() if re.match(r"^(tool|model)=\s*(<.*>|unknown)?\s*$", l)])
    secret_re = re.compile(r"(sk-ant-[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,})")
    hits = []
    for base in ["README.md", "log.txt", "code"]:
        p = os.path.join(ROOT, base)
        files = [p] if os.path.isfile(p) else [os.path.join(d, f) for d, _, fs in os.walk(p) for f in fs]
        for f in files:
            try:
                if secret_re.search(open(f, encoding="utf-8", errors="ignore").read()):
                    hits.append(os.path.relpath(f, ROOT))
            except OSError:
                pass
    check("no API keys / tokens in README, log.txt or code/", hits)
    try:
        ign = subprocess.run(["git", "check-ignore", ".env", ".venv"], cwd=ROOT, capture_output=True, text=True).stdout.split()
        check(".env and .venv are git-ignored", [p for p in (".env", ".venv") if p not in ign])
        tracked = subprocess.run(["git", "ls-files", ".env"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        check(".env is not tracked by git", [".env is tracked"] if tracked else [])
    except FileNotFoundError:
        print("[SKIP] git not available")
    zip_path = os.path.join(ROOT, "code.zip")
    if os.path.exists(zip_path):
        import zipfile
        names = zipfile.ZipFile(zip_path).namelist()
        probs = [n for n in names if n.startswith("dataset/") or "__pycache__" in n or ".venv" in n
                 or n.endswith((".zip", ".tar", ".gz", ".tgz", ".7z", ".rar")) or n.endswith(".env")]
        probs += [f"missing {p}" for p in ("README.md", "code/main.py", "code/evaluation/evaluation_report.md",
                                          "code/evaluation/usage_report.md") if p not in names]
        check("code.zip contents (no dataset/venv/caches/nested archives; reports included)", probs)
    else:
        print("[SKIP] code.zip not built yet")

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
