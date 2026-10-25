"""Evidence parsing: turns every supplied evidence file into normalized observations.

An Observation is one statement, taken from one evidence file, about the state of one
resource (account_123, search_45, ...) at one point in time. Parsers never decide
whether a case is complete; they only record what the file shows:

* exists      - True (record present), False (record absent / 404 / NOT_FOUND), None
* pii         - True (direct identifiers still on the record), False (no identifiers), None
* active      - for data flows and backups: True (enabled / restorable), False, None
* links       - identifiers that connect the record to a person (emails, phones,
                hashes, user ids, names, lookup keys)
* category    - data category hint (USER_PROFILE, SUPPORT_ATTACHMENT, ...), if known
"""
from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Iterable

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
RID_RE = re.compile(
    r"\b(account|search|support|analytics|export|data_flow|backup|audit_record|tombstone|"
    r"legal_hold|marketing|object|cache|email_delivery)_\d+\b"
)

PREFIX_SYSTEM = [
    ("audit_record_", "security_service"),
    ("data_flow_", "integration_service"),
    ("email_delivery_", "email_delivery_service"),
    ("legal_hold_", "legal_service"),
    ("tombstone_", "identity_service"),
    ("account_", "account_service"),
    ("search_", "search_service"),
    ("support_", "support_platform"),
    ("analytics_", "analytics_platform"),
    ("export_", "export_service"),
    ("backup_", "backup_service"),
    ("marketing_", "marketing_platform"),
    ("object_", "object_storage"),
    ("cache_", "cache_service"),
]

DEFAULT_CATEGORY = {
    "account_service": "USER_PROFILE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "support_platform": "SUPPORT_MESSAGE",
    "analytics_platform": "ANALYTICS_PROFILE",
    "export_service": "USER_EXPORT",
    "integration_service": "DATA_FLOW",
    "backup_service": "BACKUP_ARCHIVE",
    "security_service": "SECURITY_AUDIT_LOG",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "legal_service": "LEGAL_HOLD_RECORD",
    "marketing_platform": "MARKETING_PROFILE",
    "object_storage": "SUPPORT_ATTACHMENT",
    "cache_service": "CACHE_ENTRY",
    "email_delivery_service": "EMAIL_DELIVERY_LOG",
}


FULL_STORE_SYSTEMS = ("account_service", "search_service", "support_platform", "analytics_platform",
                      "export_service", "integration_service", "backup_service", "security_service",
                      "identity_service", "legal_service")


def system_for(rid: str) -> str | None:
    for prefix, system in PREFIX_SYSTEM:
        if rid.startswith(prefix):
            return system
    return None


def norm(v) -> str | None:
    """Normalize an identifier value for matching (case/format-insensitive)."""
    if v is None:
        return None
    s = str(v).strip()
    if not s or s.lower() in ("null", "none", "-", "n/a"):
        return None
    if "@" in s:
        return s.lower()
    digits = re.sub(r"[^\d+]", "", s)
    if s.startswith("+") and len(digits) >= 8:
        return "tel:" + digits.lstrip("+")
    return s.lower()


def is_null(v) -> bool:
    return norm(v) is None


@dataclass
class Observation:
    file_id: str
    ts: str
    system: str
    rid: str
    exists: bool | None = None
    pii: bool | None = None
    active: bool | None = None
    category: str | None = None
    links: set = field(default_factory=set)
    note: str = ""
    weak: bool = False  # e.g. a heartbeat/log hint rather than an authoritative read


IDENT_KEYS = (
    "email", "phone", "email_hash", "full_name", "name", "display_name",
    "requester_email", "requester_name", "requester_phone", "owner_email", "owner_phone",
    "customer_email", "uploaded_by",
)
REF_KEYS = (
    "customer_reference", "subject_reference", "user_id", "lookup_value", "subject_selector",
    "lookup_key", "match_key", "subject_key", "subject_ref", "scan_key", "owner_key",
    "correlation_key", "matched_value", "query",
)


def collect_links(d: dict) -> set:
    out = set()
    for k in IDENT_KEYS + REF_KEYS:
        if k in d and not isinstance(d[k], (dict, list)):
            n = norm(d[k])
            if n and not RID_RE.fullmatch(n):
                out.add(n)
    for k in ("message_text", "message_excerpt"):
        if isinstance(d.get(k), str):
            for e in EMAIL_RE.findall(d[k]):
                out.add(e.lower())
    return out


def has_direct_pii(d: dict) -> bool:
    for k in IDENT_KEYS:
        if k in d and not isinstance(d[k], (dict, list)) and not is_null(d[k]):
            return True
    txt = d.get("message_text") or ""
    if isinstance(txt, str) and EMAIL_RE.search(txt):
        return True
    return False


def truthy(v):
    if v is None:
        return None
    s = str(v).strip().strip('"').lower()
    if s in ("1", "true", "yes", "enabled", "allowed"):
        return True
    if s in ("0", "false", "no", "disabled", "blocked"):
        return False
    return None


# ---------------------------------------------------------------------------
# Generic record interpretation (used for JSON, SQL rows and structured logs)
# ---------------------------------------------------------------------------

RESULT_MAP = {
    # result -> (exists, pii, active)
    "FOUND": (True, None, None),
    "PRESENT": (True, None, None),
    "NOT_FOUND": (False, None, None),
    "ABSENT": (False, None, None),
    "DELETED": (False, None, None),
    "IDENTIFIABLE": (True, True, None),
    "EXPOSED": (True, True, None),
    "REDACTED": (True, False, None),
    "ANONYMIZED": (True, False, None),
    "ACTIVE": (True, None, True),
    "ENABLED": (True, None, True),
    "DISABLED": (True, None, False),
    "BLOCKED": (True, None, False),
    "RETAINED": (True, None, None),
}


def record_observation(file_id, ts, d: dict, system=None, category=None, note="") -> Observation | None:
    rid = d.get("resource_id")
    if not rid or not isinstance(rid, str):
        return None
    system = d.get("system") or system or system_for(rid)
    if system is None:
        return None
    ob = Observation(file_id=file_id, ts=ts, system=system, rid=rid, note=note)
    ob.category = d.get("record_type") or category
    ob.links = collect_links(d)
    result = d.get("result")
    if isinstance(result, str) and result.upper() in RESULT_MAP:
        ob.exists, ob.pii, ob.active = RESULT_MAP[result.upper()]
        return ob
    # A plain record row: it exists.
    ob.exists = True
    ob.pii = has_direct_pii(d)
    if "enabled" in d:
        ob.active = truthy(d["enabled"])
    if "restore_allowed" in d:
        ob.active = truthy(d["restore_allowed"])
    status = str(d.get("account_status") or "").upper()
    if status == "DELETED" and system == "account_service":
        ob.exists = False
    if d.get("download_available") is not None and system == "export_service":
        avail = truthy(d.get("download_available"))
        if avail is False:
            ob.note += " download_unavailable"
    if system == "support_platform" and (d.get("storage_class") == "ticket_attachment" or d.get("file_name")):
        ob.category = ob.category or "SUPPORT_ATTACHMENT"
    return ob


# ---------------------------------------------------------------------------
# Format-specific parsers
# ---------------------------------------------------------------------------

def parse_json(file_id, captured_at, path) -> list[Observation]:
    data = json.load(open(path, encoding="utf-8"))
    out: list[Observation] = []
    if "service_exports" in data:  # service_resource_export_*.json
        for system, groups in data["service_exports"].items():
            for group, items in groups.items():
                for it in items:
                    ts = it.get("observed_at") or captured_at
                    if system == "account_service":
                        prof = it.get("profile")
                        ob = Observation(file_id, ts, system, it["resource_id"])
                        if prof is None or it.get("status_code") == 404:
                            ob.exists = False
                        else:
                            ob.exists = True
                            ob.pii = has_direct_pii(prof)
                            ob.links = collect_links(prof)
                        out.append(ob)
                    elif system == "search_service":
                        docs = (it.get("hits") or {}).get("documents") or []
                        ob = Observation(file_id, ts, system, it["resource_id"])
                        ob.links = {norm(it.get("query"))} - {None}
                        if docs:
                            ob.exists = True
                            for doc in docs:
                                ob.links |= collect_links(doc)
                            ob.pii = any(has_direct_pii(doc) for doc in docs)
                        else:
                            ob.exists = False
                        out.append(ob)
                    else:
                        ob = record_observation(file_id, ts, it, system=system)
                        if ob:
                            out.append(ob)
        return out
    if "snapshots" in data:  # customer_data_snapshot_bundle_*.json
        for snap in data["snapshots"]:
            ts = snap.get("captured_at") or captured_at
            coll = snap.get("collection")
            store = snap.get("data_store")
            if coll in ("customer_profiles",):
                out.append(Observation(file_id, ts, store, "__scope__", note="scope"))
            for rec in snap.get("records", []):
                if coll == "operational_record_history":
                    ob = record_observation(file_id, rec.get("recorded_at") or ts, rec)
                else:
                    flat = dict(rec)
                    if isinstance(rec.get("document"), dict):
                        flat.update({k: v for k, v in rec["document"].items()})
                    cat = None
                    if coll == "ticket_attachments":
                        cat = "SUPPORT_ATTACHMENT"
                    elif coll == "support_conversations":
                        cat = "SUPPORT_MESSAGE"
                    elif coll == "deleted_customer_references":
                        cat = "ACCOUNT_TOMBSTONE"
                    elif coll == "retained_order_records":
                        cat = "LEGAL_HOLD_RECORD"
                    ob = record_observation(file_id, ts, flat, system=None, category=cat)
                    if ob and coll == "deleted_customer_references":
                        ob.exists = True
                        ob.pii = has_direct_pii(flat)
                if ob:
                    out.append(ob)
        return out
    if isinstance(data.get("records"), list):
        ts0 = data.get("captured_at") or data.get("exported_at") or captured_at
        for rec in data["records"]:
            ob = record_observation(file_id, rec.get("recorded_at") or ts0, rec)
            if ob:
                out.append(ob)
    return out


def parse_sql(file_id, captured_at, path) -> list[Observation]:
    con = sqlite3.connect(":memory:")
    con.executescript(open(path, encoding="utf-8").read())
    cur = con.cursor()
    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    out: list[Observation] = []
    scope = set()
    if "snapshot_scope" in tables:
        scope = {r[0] for r in cur.execute("SELECT origin_system FROM snapshot_scope")}
    for t in tables:
        if t == "snapshot_scope":
            continue
        if t.startswith("customer_profiles"):
            scope.add("account_service")
        cols = [c[1] for c in cur.execute(f'PRAGMA table_info("{t}")')]
        for row in cur.execute(f'SELECT * FROM "{t}"'):
            d = dict(zip(cols, row))
            note = f"table={t}"
            if "record_json" in d:
                rec = json.loads(d["record_json"])
                # a customer_data_* table is a full copy of the customer data store
                scope.update(FULL_STORE_SYSTEMS)
                if isinstance(rec.get("document"), dict):
                    rec.update(rec["document"])
                cat = {"ticket_attachments": "SUPPORT_ATTACHMENT",
                       "support_conversations": "SUPPORT_MESSAGE",
                       "deleted_customer_references": "ACCOUNT_TOMBSTONE",
                       "retained_order_records": "LEGAL_HOLD_RECORD"}.get(d.get("collection_name"))
                ob = record_observation(file_id, captured_at, rec, system=d.get("origin_system"), category=cat, note=note)
                if ob and d.get("collection_name") == "deleted_customer_references":
                    ob.exists, ob.pii = True, has_direct_pii(rec)
            else:
                if t.startswith("search_documents") and d.get("source_resource_id"):
                    d = dict(d)
                    d["source"] = d.pop("source_resource_id")
                ob = record_observation(file_id, captured_at, d, note=note)
                if ob and "account_status" in d and str(d["account_status"]).upper() in ("DELETION_PENDING", "ACTIVE"):
                    ob.exists = True
                if ob and t.startswith("search_documents"):
                    ob.note += f" source={d.get('source')}"
            if ob:
                out.append(ob)
    con.close()
    # Remember which systems a full inventory covered (absence of a row is evidence).
    for s in scope:
        out.append(Observation(file_id, captured_at, s, "__scope__", note="scope"))
    return out


KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def parse_kv(text: str) -> dict:
    d = {}
    for k, v in KV_RE.findall(text):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1].replace('\\"', '"')
        d[k] = v
    return d


TRACE_KEYS = ("trace_id", "requestId")


def parse_log_line(line: str) -> dict | None:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    m = re.match(r"(\d{4}-\d\d-\d\dT[\d:]+Z)\s+(.*)", line)
    if not m:
        return None
    ts, rest = m.groups()
    d: dict = {"_ts": ts}
    if rest.startswith("{"):
        try:
            d.update(json.loads(rest))
        except json.JSONDecodeError:
            pass
        return d
    # bracket style: [INFO] [service] [trace] event: k="v"
    mb = re.match(r"\[(\w+)\]\s+\[([\w-]+)\]\s+\[([\w-]+)\]\s+(\w+):\s*(.*)", rest)
    if mb:
        d.update(level=mb.group(1), service=mb.group(2), trace_id=mb.group(3), event=mb.group(4))
        d.update(parse_kv(mb.group(5)))
        return d
    # pipe style: | LEVEL | service | trace | event | kv
    if rest.startswith("|"):
        parts = [p.strip() for p in rest.strip("|").split("|")]
        if len(parts) >= 5:
            d.update(level=parts[0], service=parts[1], trace_id=parts[2], event=parts[3])
            d.update(parse_kv("|".join(parts[4:])))
            return d
    # syslog style: <12>1 node service trace - - kv
    ms = re.match(r"<\d+>\d+\s+\S+\s+(\S+)\s+(\S+)\s+-\s+-\s+(.*)", rest)
    if ms:
        d.update(service=ms.group(1), trace_id=ms.group(2))
        d.update(parse_kv(ms.group(3)))
        return d
    kv = parse_kv(rest)
    d.update(kv)
    if "message" in kv and "=" in kv["message"]:
        d.update(parse_kv(kv["message"]))
    return d


def log_event_observation(file_id, d: dict, links: set) -> Observation | None:
    rid = d.get("resource_id")
    if not rid:
        return None
    ev = d.get("event", "")
    system = d.get("system") or system_for(rid)
    if system is None:
        return None
    ts = d["_ts"]
    ob = Observation(file_id, ts, system, rid, note=f"event={ev}")
    ob.links = set(links) | collect_links(d)
    if ev == "record_lookup" or "record_type" in d:
        res = str(d.get("result", "")).upper()
        if res in RESULT_MAP:
            ob.exists, ob.pii, ob.active = RESULT_MAP[res]
        ob.category = d.get("record_type")
        return ob
    if ev in ("profile_lookup_completed",):
        rows = d.get("rows")
        status = str(d.get("http_status", ""))
        ob.exists = not (status == "404" or rows == "0")
        if ob.exists:
            ob.pii = has_direct_pii(d) if any(k in d for k in ("email", "phone")) else None
        return ob
    if ev == "index_query_completed":
        res = str(d.get("result", "")).lower()
        ob.exists = res in ("hit", "found") or str(d.get("total_hits", "0")) not in ("0", "")
        if res in ("miss", "no_hit", "none", "not_found"):
            ob.exists = False
        return ob
    if ev in ("analytics_profile_read_completed", "analytics_profile_read"):
        ob.exists = True
        if "direct_identifiers" in d:
            ob.pii = str(d["direct_identifiers"]) not in ("0", "")
        else:
            ob.pii = has_direct_pii(d)
        return ob
    if ev in ("analytics_identity_scan", "message_pii_scan", "attachment_pii_scan"):
        ob.exists, ob.pii = True, True
        if ev == "attachment_pii_scan":
            ob.category = "SUPPORT_ATTACHMENT"
        return ob
    if ev == "contact_lookup_completed":
        ob.exists = str(d.get("rows", "1")) != "0"
        ob.pii = True
        if "email_opt_in" in d:
            ob.category = "MARKETING_PROFILE"
        return ob
    if ev in ("support_ticket_read_completed", "message_read"):
        ob.exists = True
        ob.pii = has_direct_pii(d) or bool(EMAIL_RE.search(d.get("message_text", "") or ""))
        return ob
    if ev in ("contact_query_completed",):
        ob.exists = str(d.get("rows", "1")) != "0"
        ob.pii = True if ob.exists else None
        return ob
    if ev == "deletion_marker_check":
        ob.exists = truthy(d.get("marker_found")) is not True
        ob.pii = True if ob.exists else None
        return ob
    if ev in ("connector_config_read_completed", "connector_heartbeat", "connector_config_loaded"):
        ob.exists = True
        en = truthy(d.get("enabled"))
        if en is None and "scheduler_registered" in d:
            en = truthy(d.get("scheduler_registered"))
        ob.active = en
        return ob
    if ev in ("restore_policy_read_completed",):
        ob.exists = truthy(d.get("archive_present")) is not False
        ob.active = truthy(d.get("restore_allowed"))
        return ob
    if ev == "restore_candidate_evaluated":
        ob.exists = True
        elig = truthy(d.get("eligible"))
        block = truthy(d.get("deletion_block"))
        ob.active = bool(elig) and not bool(block)
        return ob
    if ev == "restore_authorization_completed":
        ob.exists = True
        dec = str(d.get("decision", "")).lower()
        ob.active = dec in ("allow", "allowed", "approved", "permit", "permitted")
        return ob
    if ev in ("export_metadata_read_completed", "export_download_check_completed"):
        av = truthy(d.get("available"))
        ob.exists = True
        ob.pii = has_direct_pii(d) if "owner_email" in d else None
        if av is False:
            ob.note += " download_unavailable"
        return ob
    if ev in ("retained_order_loaded",):
        ob.exists = True
        ob.category = "LEGAL_HOLD_RECORD"
        return ob
    if ev == "audit_record_read_completed":
        ob.exists = str(d.get("rows", "1")) != "0"
        return ob
    if ev in ("cache_lookup",):
        return None
    if ev.endswith("_started"):
        return None
    if "decision" in d and "policy" in d:
        ob.exists = True
        ob.active = str(d["decision"]).lower() in ("allow", "allowed", "approved")
        return ob
    return None


def parse_log(file_id, captured_at, path) -> list[Observation]:
    lines = [parse_log_line(l) for l in open(path, encoding="utf-8")]
    lines = [d for d in lines if d]
    # Link "started" events (which carry lookup keys) to completed events via trace id.
    trace_links: dict = {}
    for d in lines:
        tr = next((d[k] for k in TRACE_KEYS if k in d), None)
        if not tr:
            continue
        keys = set()
        for k in ("lookup_key", "match_key", "subject_key", "subject_ref", "scan_key", "owner_key"):
            n = norm(d.get(k))
            if n and not RID_RE.fullmatch(n):
                keys.add(n)
        if keys:
            trace_links.setdefault(tr, set()).update(keys)
    out = []
    for d in lines:
        tr = next((d[k] for k in TRACE_KEYS if k in d), None)
        ob = log_event_observation(file_id, d, trace_links.get(tr, set()) if tr else set())
        if ob:
            out.append(ob)
    return out


def parse_txt(file_id, captured_at, path) -> list[Observation]:
    out = []
    for line in open(path, encoding="utf-8"):
        if not line.startswith("-") or "|" not in line:
            continue
        parts = [p.strip() for p in line.lstrip("- ").split("|")]
        if len(parts) < 6:
            continue
        ts, system, rid, rtype, result, ref = parts[:6]
        d = {"resource_id": rid, "system": system, "record_type": rtype, "result": result, "subject_reference": ref}
        ob = record_observation(file_id, ts, d)
        if ob:
            out.append(ob)
    return out


def parse_extracted(file_id, captured_at, path, extracted_dir) -> list[Observation]:
    """PDFs and images: read the cached structured extraction (see extract_media.py)."""
    base = os.path.splitext(os.path.basename(path))[0]
    cache = os.path.join(extracted_dir, base + ".json")
    if not os.path.exists(cache):
        return []
    data = json.load(open(cache, encoding="utf-8"))
    out = []
    for rec in data.get("records", []):
        ob = record_observation(file_id, rec.get("observed_at") or captured_at, rec, category=rec.get("record_type"))
        if ob:
            out.append(ob)
    return out


def load_manifest(dataset_dir) -> list[dict]:
    return list(csv.DictReader(open(os.path.join(dataset_dir, "evidence_files.csv"), encoding="utf-8")))


def load_all(dataset_dir: str, extracted_dir: str) -> tuple[list[Observation], dict]:
    manifest = load_manifest(dataset_dir)
    obs: list[Observation] = []
    captured = {}
    for m in manifest:
        fid, rel, cap = m["file_id"], m["file_path"], m["captured_at"]
        captured[fid] = cap
        path = os.path.join(dataset_dir, rel)
        ext = os.path.splitext(path)[1].lower()
        if ext == ".json":
            obs += parse_json(fid, cap, path)
        elif ext == ".sql":
            obs += parse_sql(fid, cap, path)
        elif ext == ".log":
            obs += parse_log(fid, cap, path)
        elif ext == ".txt":
            obs += parse_txt(fid, cap, path)
        elif ext in (".pdf", ".png", ".jpg", ".jpeg"):
            obs += parse_extracted(fid, cap, path, extracted_dir)
    return obs, captured
