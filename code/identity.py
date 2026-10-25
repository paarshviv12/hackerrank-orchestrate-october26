"""Identity resolution: current + historical identifiers for each user."""
from __future__ import annotations

import csv
import os

from evidence_parser import norm


class IdentityIndex:
    use_history = True  # switched off only in the ablation study

    def __init__(self, dataset_dir: str):
        self.users: dict[str, dict] = {}
        self.history: dict[str, list[dict]] = {}
        self.by_ident: dict[str, set] = {}
        for r in csv.DictReader(open(os.path.join(dataset_dir, "user_identities.csv"), encoding="utf-8")):
            self.users[r["user_id"]] = r
        for r in csv.DictReader(open(os.path.join(dataset_dir, "user_audit_log.csv"), encoding="utf-8")):
            self.history.setdefault(r["user_id"], []).append(r)
        for uid in self.users:
            for ident in self.identifiers(uid):
                self.by_ident.setdefault(ident, set()).add(uid)

    def identifiers(self, uid: str, include_name: bool = True) -> set:
        """All normalized identifiers that may point at this user (current + historical)."""
        u = self.users.get(uid, {})
        vals = {uid, u.get("email"), u.get("phone"), u.get("email_hash")}
        if include_name:
            vals.add(u.get("name"))
        for h in (self.history.get(uid, []) if self.use_history else []):
            vals.add(h["old_value"])
            vals.add(h["new_value"])
        return {n for n in (norm(v) for v in vals) if n}

    def audit_ids(self, uid: str) -> list[str]:
        return [h["audit_id"] for h in self.history.get(uid, [])]

    def resolve_email(self, email: str) -> tuple[str | None, str | None]:
        """Return (user_id, audit_id) for a current or historical email address."""
        e = norm(email)
        for uid, u in self.users.items():
            if norm(u["email"]) == e:
                return uid, None
        for uid, hist in (self.history.items() if self.use_history else []):
            for h in hist:
                if h["field_name"] == "email" and norm(h["old_value"]) == e:
                    return uid, h["audit_id"]
        return None, None

    def owners(self, ident: str) -> set:
        return self.by_ident.get(ident, set())
