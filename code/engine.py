"""Deletion-audit engine: links resources to a case, reconstructs their state at audit_at,
applies deletion_rules.csv and emits ordered FINDING / REMEDIATION / VERIFICATION steps."""
from __future__ import annotations

import csv
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from evidence_parser import Observation, norm, system_for, DEFAULT_CATEGORY, EMAIL_RE, USER_RE
from identity import IdentityIndex


def T(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# Treatment required by deletion_rules.csv, keyed by data category.
def load_rules(dataset_dir):
    rules = {}
    for r in csv.DictReader(open(os.path.join(dataset_dir, "deletion_rules.csv"), encoding="utf-8")):
        rules[r["data_category"]] = (r["rule_id"], r["required_action"], r["condition"])
    return rules


FINDING_ORDER = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"]
REMEDIATION_ORDER = ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"]
VERIFICATION_ORDER = ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                      "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]
STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

# Systems where "no row in a full snapshot" proves the required end state (record absent).
ABSENCE_PROVABLE = {"account_service", "search_service", "export_service"}

WORKER_TYPES = {"DELETE_RECORD", "ANONYMIZE_RECORD", "REDACT_RECORD", "CHECK_DATA_FLOW", "DISABLE_DATA_FLOW",
                "BLOCK_RESTORE", "CHECK_RESTORE_ACCESS", "RETAIN_RECORD"}
WINDOW_BEFORE = timedelta(hours=1.5)
WINDOW_AFTER = timedelta(hours=2.2)


@dataclass
class Resource:
    rid: str
    system: str
    category: str = ""
    sources: set = field(default_factory=set)  # how it was linked
    obs: list = field(default_factory=list)    # observations usable at audit_at
    activity: list = field(default_factory=list)


class Engine:
    def __init__(self, dataset_dir: str, observations: list[Observation], captured: dict, identity: IdentityIndex):
        self.dataset_dir = dataset_dir
        self.obs = observations
        self.captured = captured
        self.ident = identity
        self.rules = load_rules(dataset_dir)
        self.activity = list(csv.DictReader(open(os.path.join(dataset_dir, "system_activity.csv"), encoding="utf-8")))
        self.by_rid: dict[str, list[Observation]] = defaultdict(list)
        self.scopes: dict[str, set] = defaultdict(set)  # file_id -> systems fully inventoried
        for o in observations:
            if o.rid == "__scope__":
                self.scopes[o.file_id].add(o.system)
            else:
                self.by_rid[o.rid].append(o)
        self.files_with_primary = {o.file_id for o in observations if "primary" in o.note}
        self.rids_in_file: dict[str, set] = defaultdict(set)
        for o in observations:
            self.rids_in_file[o.file_id].add(o.rid)
        self.act_by_rid: dict[str, list[dict]] = defaultdict(list)
        for a in self.activity:
            self.act_by_rid[a["resource_id"]].append(a)
            m = re.search(r"downstream resource (\w+)", a["details"])
            if m:
                self.act_by_rid[m.group(1)].append(a)
        self.catalog = self._catalog_links()
        self.owner_cache: dict[str, set] = {}
        # Feature switches (all on for the submission; switched off one at a time for the ablation study).
        self.features = {
            "worker_linking": True,      # link identifier-free records through the deletion-worker run
            "status_compat": True,       # primary-profile result must match the workflow claim
            "evidence_cooccurrence": True,  # prefer the request whose snapshot contains the record
            "policy_chain": True,        # policy actions of one request form a ~7 min chain
            "proof_refinement": True,    # second pass: COMPLETE requests need read-back proof
            "replica_drift": True,       # OR across primary + replica rows of a snapshot
            "snapshot_absence": True,    # a missing row in the request's own full snapshot proves absence
            "catalog_check": True,       # reject data-catalog links the record itself contradicts
        }
        self.resolution: dict[str, dict] = {}  # how each worker resource was attributed

    # ------------------------------------------------------------------ linking
    def _catalog_links(self):
        """Data-catalog activity: 'Data catalog linked X (...) to email and user_N.'"""
        out = []
        for a in self.activity:
            if a["event_type"] != "LINK_RESOURCE_IDENTITY":
                continue
            ids = {e.lower() for e in EMAIL_RE.findall(a["details"])} | set(USER_RE.findall(a["details"]))
            out.append((a, ids))
        return out

    def owners_of(self, rid: str, before: str | None = None) -> set:
        """Users whose identifiers appear on any observation of the resource."""
        owners = set()
        for o in self.by_rid.get(rid, []):
            if before and self.captured[o.file_id] > before:
                continue
            for l in o.links:
                owners |= self.ident.owners(l)
        return owners

    def assign_worker_resources(self, cases: list[dict], uid_of: dict) -> dict[str, set]:
        """Assign deletion-worker activity to cases. The worker run for a request happens around
        its reported_at, but several requests can share that time. Resolution order:
        1. identifiers on the resource's own evidence point at the case's subject;
        2. hard compatibility: the primary-profile submission result matches the workflow claim
           (COMPLETE~SUCCESS, PARTIALLY_COMPLETE~PARTIAL, NOT_STARTED~FAILED);
        3. the resource appears in evidence captured during that case's lifetime;
        4. one resource per system per case (one primary profile, one analytics profile, ...);
        5. deterministic tie-break."""
        cand: dict[str, set] = defaultdict(set)
        acts = [a for a in self.activity if a["source_system"] == "deletion_worker" and a["event_type"] in WORKER_TYPES]
        for q in cases:
            rep = T(q["reported_at"])
            for a in acts:
                t = T(a["event_time"])
                if rep - WINDOW_BEFORE <= t <= rep + WINDOW_AFTER:
                    cand[a["resource_id"]].add(q["case_id"])
        by_case = {q["case_id"]: q for q in cases}
        assigned: dict[str, set] = defaultdict(set)
        self.ambiguous: dict[str, set] = {}
        files_of = {cid: {f for f, c in self.captured.items() if q["requested_at"] <= c <= q["audit_at"]}
                    for cid, q in by_case.items()}
        # files captured in the 24h before audit_at: the snapshot an auditor would read for the case
        primary_of = {cid: {f for f, c in self.captured.items()
                            if T(q["audit_at"]) - timedelta(hours=24) <= T(c) <= T(q["audit_at"])}
                      for cid, q in by_case.items()}
        compat = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}

        def prefix(rid):
            return rid.rsplit("_", 1)[0]

        unresolved = {}
        for rid, cs in cand.items():
            owners = self.owners_of(rid)
            if owners:
                hit = {c for c in cs if uid_of.get(c) in owners}
                for c in hit:
                    assigned[c].add(rid)
                self.resolution[rid] = {"method": "identifiers", "window_candidates": len(cs)}
                continue  # linked to someone else -> not ours
            pool = set(cs)
            self.resolution[rid] = {"method": "deduced", "window_candidates": len(cs), "filters": []}
            if rid.startswith("account_") and self.features["status_compat"]:
                subs = [a for a in self.act_by_rid[rid] if "primary profile" in a["details"]]
                if subs:
                    res_ = subs[0]["reported_result"]
                    ok = {c for c in pool if compat.get(by_case[c]["reported_status"]) == res_}
                    if ok and ok != pool:
                        self.resolution[rid]["filters"].append("status_compat")
                    if ok:
                        pool = ok
            seen = {o.file_id for o in self.by_rid.get(rid, [])}
            if seen and self.features["evidence_cooccurrence"]:
                inf = {c for c in pool if files_of[c] & seen}
                if inf:
                    pool = inf
                prim = {c for c in pool if primary_of[c] & seen}
                if prim:
                    pool = prim
                if len(pool) < len(cs):
                    self.resolution[rid]["filters"].append("evidence_cooccurrence")
            unresolved[rid] = pool
            self.ambiguous[rid] = set(pool)

        def taken(c, rid):
            return any(prefix(r) == prefix(rid) for r in assigned[c])

        def policy_time(rid):
            for a in self.act_by_rid[rid]:
                if a["source_system"] == "deletion_worker" and a["details"].startswith("Policy action completed"):
                    return T(a["event_time"])
            return None

        def chain_residual(c, rid):
            """Policy actions of one request run as a chain roughly 7 minutes apart (+/-30 s).
            Distance (s) of this action from the chain formed by the case's linked actions."""
            t = policy_time(rid)
            if t is None:
                return None
            best = None
            for r2 in assigned[c]:
                t2 = policy_time(r2)
                if t2 is None:
                    continue
                d = abs((t2 - t).total_seconds())
                k = round(d / 420)
                res_ = min(abs(d - (420 * k + j)) for j in (-30, -1, 0, 29, 30, -31, 31, 59, -59, -60, 60))
                best = res_ if best is None else min(best, res_)
            return best

        changed = True
        while changed and unresolved:
            changed = False
            for rid, cs in sorted(unresolved.items()):
                free = {c for c in cs if not taken(c, rid)}
                if not free:
                    del unresolved[rid]  # every candidate already has a record of this kind
                    changed = True
                    continue
                if free != cs:
                    unresolved[rid] = cs = free
                    changed = True
                if len(cs) > 1 and self.features["policy_chain"]:
                    scored = {c: chain_residual(c, rid) for c in cs}
                    fits = {c for c, s in scored.items() if s is not None and s <= 3}
                    if len(fits) == 1:
                        unresolved[rid] = cs = fits
                        self.resolution[rid]["filters"].append("policy_chain")
                        changed = True
                if len(cs) == 1:
                    assigned[next(iter(cs))].add(rid)
                    del unresolved[rid]
                    changed = True
            if not changed and unresolved:
                # deterministic tie-break on the most constrained resource
                rid, cs = sorted(unresolved.items(), key=lambda x: (len(x[1]), x[0]))[0]
                ts = min(T(a["event_time"]) for a in self.act_by_rid[rid])
                pool = {c for c in cs if not taken(c, rid)}
                if pool:
                    best = sorted(pool, key=lambda c: (abs((T(by_case[c]["reported_at"]) - ts).total_seconds()), c))[0]
                    assigned[best].add(rid)
                    self.resolution[rid].update(method="tie-break", tied_with=len(pool))
                del unresolved[rid]
                changed = True
        # A record "deduced" by elimination is only as certain as the competitors it was eliminated
        # against: if a same-kind record in its candidate pool was placed by tie-break, flag it.
        owner_of = {r: c for c, rs in assigned.items() for r in rs}
        for rid, info in self.resolution.items():
            if info.get("method") != "deduced" or rid not in self.ambiguous:
                continue
            for c in self.ambiguous[rid]:
                if any(prefix(r2) == prefix(rid) and self.resolution.get(r2, {}).get("method") == "tie-break"
                       for r2 in assigned.get(c, set())):
                    info["method"] = "deduced-after-tie-break"
                    break
        return assigned

    def refine_accounts(self, keyed: dict, assigned: dict, statuses: dict, uid_of: dict) -> set:
        """Second pass: a request whose remaining records are all compliant can only be proven
        COMPLETE if its primary profile was read back in its audit snapshot. When an ambiguous
        (identifier-less) primary profile could belong to two requests, give the profile that was
        read back to the request that needs it as proof. Returns the case ids that changed."""
        changed = set()
        acct = {c: next((r for r in rs if r.startswith("account_")), None) for c, rs in assigned.items()}
        for c, status in statuses.items():
            if status != "COMPLETE" or c not in keyed:
                continue
            q = keyed[c]
            mine = acct.get(c)
            if mine and any(self.captured[o.file_id] >= q["requested_at"] and self.captured[o.file_id] <= q["audit_at"]
                            for o in self.by_rid.get(mine, [])):
                continue  # already proven by an explicit read
            if mine and mine not in self.ambiguous:
                continue
            for other_rid, cands in self.ambiguous.items():
                if not other_rid.startswith("account_") or c not in cands:
                    continue
                reads = [o for o in self.by_rid.get(other_rid, [])
                         if q["requested_at"] <= self.captured[o.file_id] <= q["audit_at"] and o.exists is False]
                if not reads:
                    continue
                owner = next((o for o, r in acct.items() if r == other_rid), None)
                if owner == c:
                    continue
                if owner is not None and (mine is None or owner not in self.ambiguous.get(mine, set())):
                    continue
                if owner is not None and statuses.get(owner) == "COMPLETE":
                    continue
                # swap
                if owner is not None:
                    assigned[owner].discard(other_rid)
                    if mine:
                        assigned[owner].add(mine)
                    acct[owner] = mine
                    changed.add(owner)
                if mine:
                    assigned[c].discard(mine)
                assigned[c].add(other_rid)
                self.resolution.setdefault(other_rid, {})["method"] = "proof-refinement"
                if mine:
                    self.resolution.setdefault(mine, {})["method"] = "proof-refinement"
                acct[c] = other_rid
                changed.add(c)
                break
        # Ambiguous compliant records (e.g. an anonymized analytics profile whose policy action
        # succeeded) carry no identifiers; prefer the candidate request that is otherwise complete
        # and lacks that kind of record, since a completed run is what produced the compliant copy.
        def kind(r):
            return r.rsplit("_", 1)[0]
        for rid, cands in sorted(self.ambiguous.items()):
            if rid.startswith("account_") or len(cands) < 2:
                continue
            owner = next((c for c in cands if rid in assigned.get(c, set())), None)
            if owner is None or statuses.get(owner) != "INCOMPLETE":
                continue
            ok = any(a["details"].startswith("Policy action completed") for a in self.act_by_rid[rid])
            if not ok:
                continue
            alt = sorted(c for c in cands if c != owner and statuses.get(c) == "COMPLETE"
                         and not any(kind(r) == kind(rid) for r in assigned.get(c, set())))
            if len(alt) == 1:
                assigned[owner].discard(rid)
                assigned[alt[0]].add(rid)
                self.resolution.setdefault(rid, {})["method"] = "proof-refinement"
                changed |= {owner, alt[0]}
        # Conversely, an ambiguous record that was never read back cannot be proven for a COMPLETE
        # request; if an incomplete candidate exists, it is the more plausible owner.
        for rid, cands in sorted(self.ambiguous.items()):
            if rid.startswith("account_") or len(cands) < 2:
                continue
            owner = next((c for c in cands if rid in assigned.get(c, set())), None)
            if owner is None or statuses.get(owner) != "COMPLETE" or owner not in keyed:
                continue
            q = keyed[owner]
            if any(q["requested_at"] <= self.captured[o.file_id] <= q["audit_at"] for o in self.by_rid.get(rid, [])):
                continue
            alt = sorted(c for c in cands if c != owner and statuses.get(c) == "INCOMPLETE"
                         and not any(kind(r) == kind(rid) for r in assigned.get(c, set())))
            if alt:
                assigned[owner].discard(rid)
                assigned[alt[0]].add(rid)
                self.resolution.setdefault(rid, {})["method"] = "proof-refinement"
                changed |= {owner, alt[0]}
        return changed

    # ------------------------------------------------------------- per case
    def candidate_resources(self, q: dict, uid: str, worker: set) -> dict[str, Resource]:
        audit, req = q["audit_at"], q["requested_at"]
        U = self.ident.identifiers(uid)
        res: dict[str, Resource] = {}

        def add(rid, src):
            sysid = system_for(rid)
            if sysid is None:
                return
            r = res.setdefault(rid, Resource(rid, sysid))
            r.sources.add(src)

        # (a) evidence that carries the subject's identifiers, captured during the request lifetime
        for o in self.obs:
            if o.rid == "__scope__":
                continue
            cap = self.captured[o.file_id]
            if cap > audit or cap < req:
                continue
            if o.links & U:
                add(o.rid, "evidence")
        # (b) data-catalog links (claims; rejected if the record's own content names someone else)
        for a, ids in self.catalog:
            if a["event_time"] > audit or a["event_time"] < req:
                continue
            if ids & U:
                rid = a["resource_id"]
                others = self.owners_of(rid, before=audit) - {uid}
                content_links = {l for o in self.by_rid.get(rid, []) for l in o.links
                                 if "@" in l or l.startswith(("tel:", "user_")) or len(l) == 64}
                if self.features["catalog_check"] and content_links and not (content_links & U) and (content_links - {None}):
                    # the record itself identifies a different person -> catalog claim is wrong
                    continue
                if others and uid not in self.owners_of(rid, before=audit) and content_links:
                    continue
                add(rid, "catalog:" + a["activity_id"])
        # (c) worker activity assigned to this case
        for rid in worker:
            add(rid, "worker")
        # (e) retained records (security audit / legal hold) referencing the subject that are only
        #     visible in evidence captured after audit_at: kept aside, used only for post-remediation
        #     verification of an INCOMPLETE case (never cited, never changing the decision).
        self._later_retained = set()
        for o in self.obs:
            if o.rid == "__scope__" or o.rid in res:
                continue
            if o.system in ("security_service", "legal_service") and o.links & {uid} and self.captured[o.file_id] > audit:
                self._later_retained.add(o.rid)
        # (d) recreation paths touching linked resources (sync / restore repopulated a resource)
        for rid in list(res):
            for a in self.act_by_rid.get(rid, []):
                if a["event_time"] > audit:
                    continue
                if a["event_type"] in ("SYNC_RECORD", "RESTORE_BACKUP") and a["resource_id"] != rid:
                    src = a["resource_id"]
                    if src.startswith(("data_flow_", "backup_")):
                        add(src, "recreates:" + rid)
        return res

    def observations_at(self, rid: str, q: dict) -> list[Observation]:
        audit = q["audit_at"]
        return sorted([o for o in self.by_rid.get(rid, []) if self.captured[o.file_id] <= audit and o.ts <= audit],
                      key=lambda o: (self.captured[o.file_id], o.ts))

    def category_of(self, r: Resource, obs: list[Observation]) -> str:
        cats = [o.category for o in obs if o.category]
        if cats:
            return cats[-1]
        if r.system == "support_platform":
            for a in self.act_by_rid.get(r.rid, []):
                if a["event_type"] == "DELETE_RECORD":
                    return "SUPPORT_ATTACHMENT"
        return DEFAULT_CATEGORY.get(r.system, "")

    # ------------------------------------------------------------- state
    def state_at(self, r: Resource, q: dict):
        """Return (exists, pii, active, evidence_id, category) for the resource at audit_at."""
        audit, req = q["audit_at"], q["requested_at"]
        obs = self.observations_at(r.rid, q)
        latest_file, agg = None, None
        if obs:
            last_cap = self.captured[obs[-1].file_id]
            # all observations from the most recent capture (several files can share a capture time;
            # several rows - e.g. primary + replica tables - can describe the same resource)
            cur = [o for o in obs if self.captured[o.file_id] == last_cap]
            if not self.features["replica_drift"]:
                # ablation: trust only the primary table of a snapshot that has one
                prim = [o for o in cur if "replica" not in o.note]
                if prim:
                    cur = prim
                elif any(f in self.files_with_primary for f in {o.file_id for o in cur}):
                    cur = [Observation(cur[0].file_id, cur[0].ts, cur[0].system, cur[0].rid, exists=False)]
            latest_file = sorted({o.file_id for o in cur}, key=lambda f: int(f.split("_")[1]))[-1]
            exists = any(o.exists for o in cur) if any(o.exists is not None for o in cur) else None
            pii = True if any(o.pii for o in cur) else (False if any(o.pii is False for o in cur) else None)
            active = True if any(o.active for o in cur) else (False if any(o.active is False for o in cur) else None)
            agg = (exists, pii, active, latest_file, last_cap)
        # Full inventory snapshots: a missing row means the record is absent. This is weaker than an
        # explicit read, so it is used only when no explicit observation exists in the request lifetime.
        explicit = agg is not None and agg[4] >= req
        if not explicit and r.system in ABSENCE_PROVABLE and self.features["snapshot_absence"]:
            case_files = getattr(self, "_case_files", set())
            best = None
            for fid, systems in self.scopes.items():
                cap = self.captured[fid]
                if r.system in systems and req <= cap <= audit and r.rid not in self.rids_in_file[fid]:
                    in_case = fid in case_files
                    has_rows = any(x.startswith(r.rid.rsplit("_", 1)[0] + "_") for x in self.rids_in_file[fid])
                    # an inventory only proves absence for the requests it was captured for
                    if not in_case and not (has_rows and r.system == "account_service"):
                        continue
                    rank = (in_case, has_rows, cap)
                    if best is None or rank > best[0]:
                        best = (rank, fid, cap)
            if best:
                agg = (False, None, None, best[1], best[2])
        category = self.category_of(r, obs)
        if agg is None:
            # fall back to explicit status checks recorded in the activity stream
            for a in sorted(self.act_by_rid.get(r.rid, []), key=lambda a: a["event_time"]):
                if a["event_time"] > audit or a["event_time"] < req:
                    continue
                if a["event_type"] == "CHECK_DATA_FLOW" and "remains enabled" in a["details"]:
                    agg = (True, None, True, a["activity_id"], a["event_time"])
                if a["event_type"] == "CHECK_RESTORE_ACCESS" and "can still be restored" in a["details"]:
                    agg = (True, None, True, a["activity_id"], a["event_time"])
        if agg is None:
            return None, None, None, "", category
        return agg[0], agg[1], agg[2], agg[3], category

    def required_action(self, category: str, r: Resource) -> str:
        if r.system == "integration_service" or category == "DATA_FLOW":
            return "FLOW"
        if r.system == "backup_service" or category == "BACKUP_ARCHIVE":
            return "BACKUP"
        rule = self.rules.get(category)
        return rule[1] if rule else "DELETE"

    def worker_category(self, r: Resource, q: dict) -> str | None:
        """The deletion worker's attempted treatment reveals the record's policy category."""
        for a in self.act_by_rid.get(r.rid, []):
            if a["source_system"] != "deletion_worker":
                continue
            et = a["event_type"]
            if r.system == "support_platform":
                return "SUPPORT_ATTACHMENT" if et == "DELETE_RECORD" else "SUPPORT_MESSAGE"
            if r.system == "analytics_platform" and et == "DELETE_RECORD":
                return "MARKETING_PROFILE"
        return None

    def audit_case(self, q: dict, uid: str, worker: set):
        res = self.candidate_resources(q, uid, worker)
        self._case_files = {o.file_id for rid in res for o in self.observations_at(rid, q)
                            if self.captured[o.file_id] >= q["requested_at"]}
        findings, remediation, verification = [], [], []
        self.last_detail = []
        for rid, r in res.items():
            exists, pii, active, ev, category = self.state_at(r, q)
            n_find = len(findings)
            obs_cats = [o.category for o in self.observations_at(rid, q) if o.category]
            if not obs_cats:
                wc = self.worker_category(r, q)
                if wc:
                    category = wc
            r.category = category
            action = self.required_action(category, r)
            # Drop evidence-only resources that were never observed during the request lifetime.
            sysid = r.system
            if action == "FLOW":
                if active:
                    findings.append(("REPORT_ACTIVE_DATA_FLOW", sysid, rid, ev))
                    remediation.append(("DISABLE_DATA_FLOW", sysid, rid))
                verification.append(("VERIFY_DATA_FLOW_DISABLED", sysid, rid, "" if active else ev))
            elif action == "BACKUP":
                if active:
                    findings.append(("REPORT_RESTORE_RISK", sysid, rid, ev))
                    remediation.append(("BLOCK_RESTORE", sysid, rid))
                verification.append(("VERIFY_RESTORE_BLOCKED", sysid, rid, "" if active else ev))
            elif action == "RETAIN":
                verification.append(("VERIFY_RECORD_PRESENT", sysid, rid, ev if exists else ""))
            elif action == "DELETE":
                if exists:
                    findings.append(("REPORT_REMAINING_RECORD", sysid, rid, ev))
                    remediation.append(("DELETE_RECORD", sysid, rid))
                verification.append(("VERIFY_RECORD_ABSENT", sysid, rid, "" if exists else ev))
            elif action == "REDACT":
                if exists and pii:
                    findings.append(("REPORT_EXPOSED_PII", sysid, rid, ev))
                    remediation.append(("REDACT_RECORD", sysid, rid))
                    verification.append(("VERIFY_RECORD_REDACTED", sysid, rid, ""))
                elif exists is False:
                    verification.append(("VERIFY_RECORD_ABSENT", sysid, rid, ev))
                else:
                    verification.append(("VERIFY_RECORD_REDACTED", sysid, rid, ev))
            elif action == "ANONYMIZE":
                if exists and pii:
                    findings.append(("REPORT_EXPOSED_PII", sysid, rid, ev))
                    remediation.append(("ANONYMIZE_RECORD", sysid, rid))
                    verification.append(("VERIFY_RECORD_ANONYMIZED", sysid, rid, ""))
                elif exists is False:
                    verification.append(("VERIFY_RECORD_ABSENT", sysid, rid, ev))
                else:
                    verification.append(("VERIFY_RECORD_ANONYMIZED", sysid, rid, ev))
            rule = self.rules.get(category)
            self.last_detail.append({
                "resource_id": rid, "system_id": sysid, "data_category": category,
                "rule": ({"rule_id": rule[0], "required_action": rule[1], "condition": rule[2]} if rule and action not in ("FLOW", "BACKUP")
                         else {"rule_id": self.rules["BACKUP_ARCHIVE"][0], "required_action": "RETAIN + BLOCK_RESTORE"} if action == "BACKUP"
                         else {"rule_id": "completion-criterion", "required_action": "DISABLE (no active sync may recreate data)"}),
                "linked_by": sorted(r.sources),
                "attribution": self.resolution.get(rid, {"method": "identifiers" if "evidence" in r.sources else "catalog"}) if "worker" in r.sources else {"method": "identifiers" if "evidence" in r.sources else sorted(r.sources)[0]},
                "state_at_audit": {"exists": exists, "direct_identifiers_present": pii, "active": active},
                "evidence_id": ev,
                "evidence_kind": ("activity (status check claim)" if ev.startswith("activity_") else "file" if ev else "none - not read back"),
                "decision": findings[-1][0] if len(findings) > n_find else "COMPLIANT",
            })
        status = "INCOMPLETE" if findings else "COMPLETE"
        if status == "INCOMPLETE":
            for rid in sorted(self._later_retained):
                verification.append(("VERIFY_RECORD_PRESENT", system_for(rid), rid, ""))
                self.last_detail.append({"resource_id": rid, "system_id": system_for(rid), "data_category": "SECURITY_AUDIT_LOG",
                                         "rule": {"rule_id": "rule_12", "required_action": "RETAIN"},
                                         "linked_by": ["subject_reference in evidence captured after audit_at"],
                                         "attribution": {"method": "identifiers"}, "state_at_audit": None,
                                         "evidence_id": "", "evidence_kind": "none - post-remediation check only",
                                         "decision": "COMPLIANT"})
        return status, findings, remediation, verification, res


def build_steps(status, findings, remediation, verification):
    def key(order):
        return lambda x: (order.index(x[0]), x[1], x[2])
    steps = []
    if status == "INCOMPLETE":
        for op, s, rid, ev in sorted(findings, key=key(FINDING_ORDER)):
            steps.append(("FINDING", s, rid, op, ev))
        for op, s, rid in sorted(remediation, key=key(REMEDIATION_ORDER)):
            steps.append(("REMEDIATION", s, rid, op, ""))
        for op, s, rid, ev in sorted(verification, key=key(VERIFICATION_ORDER)):
            steps.append(("VERIFICATION", s, rid, op, ""))
    else:
        for op, s, rid, ev in sorted(verification, key=key(VERIFICATION_ORDER)):
            steps.append(("VERIFICATION", s, rid, op, ev))
    return [{"step_no": i + 1, "phase": ph, "system_id": s, "resource_id": rid, "operation": op,
             "state": STATE[op], "evidence_id": ev} for i, (ph, s, rid, op, ev) in enumerate(steps)]
