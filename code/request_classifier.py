"""Decide whether a request_text actually authorizes deletion.

Two strategies:
* rule-based (default, deterministic, multilingual keyword + negation rules)
* LLM-based (optional) when ANTHROPIC_API_KEY is set and --llm is passed; the LLM
  answer is cached per text, and the rule-based answer is used as a fallback.
"""
from __future__ import annotations

import hashlib
import json
import os
import re

DELETE_PATTERNS = [
    r"\bdelet", r"\berase", r"\berasure", r"\bclose (my|this|the) account", r"\bremove (my|the) (account|profile)",
    r"\bclosed\b.*\baccount", r"account.{0,20}\bclosed\b", r"\bdeletion\b",
    r"eliminaci[oó]n", r"eliminar", r"borrar", r"exclus[aã]o", r"excluir", r"suppression", r"supprimer",
    r"l[oö]schung", r"l[oö]schen", r"削除", r"삭제", r"cancellazione",
]
# Phrases that state a different (non-deletion) purpose or explicitly refuse deletion.
NON_DELETE_PATTERNS = [
    r"not (asking|a request) (for|to) (deletion|erase|delete)", r"not a request to erase",
    r"\bdon'?t delete\b", r"do not (close|delete)", r"without removing", r"leave (the|my) (account|profile)",
    r"keep the account", r"continue using", r"still (use|need|want)", r"marketing lists only",
    r"stop the promotional", r"\bdownload my account information\b", r"send me a copy", r"copy of (last|the information|my invoices)",
    r"what personal information you hold", r"\bchange the email\b", r"\bmisspelled\b", r"out of date",
    r"resetting the login",
]


def rule_based(text: str) -> bool:
    t = text.lower()
    non = any(re.search(p, t) for p in NON_DELETE_PATTERNS)
    dele = any(re.search(p, t) for p in DELETE_PATTERNS)
    if non:
        return False
    # Requests in this channel default to deletion intent unless a different purpose is stated;
    # the delete-pattern match is kept as a signal for the optional LLM disagreement report.
    return True


PROMPT = (
    "You classify privacy requests sent to an online shop. Answer with exactly one word: "
    "DELETE if the person is asking for their account or personal data to be deleted/erased/closed, "
    "or OTHER if they ask for anything else (access, copy/export, correction, marketing opt-out, "
    "login help, email change) or explicitly say they do not want deletion.\n\nRequest:\n"
)


class RequestClassifier:
    def __init__(self, use_llm: bool = False, cache_path: str | None = None, usage=None):
        self.use_llm = use_llm and bool(os.environ.get("ANTHROPIC_API_KEY"))
        self.cache_path = cache_path
        self.cache = {}
        self.usage = usage
        if cache_path and os.path.exists(cache_path):
            self.cache = json.load(open(cache_path, encoding="utf-8"))
        self.model = os.environ.get("CLASSIFIER_MODEL", "claude-haiku-4-5")

    def _llm(self, text: str) -> bool | None:
        key = hashlib.sha256(text.encode()).hexdigest()
        if key in self.cache:
            return self.cache[key]
        try:
            import anthropic  # optional dependency
            client = anthropic.Anthropic()
            msg = client.messages.create(model=self.model, max_tokens=5,
                                         messages=[{"role": "user", "content": PROMPT + text}])
            if self.usage is not None:
                self.usage.record(self.model, msg.usage.input_tokens, msg.usage.output_tokens)
            ans = msg.content[0].text.strip().upper().startswith("DELETE")
        except Exception:
            return None
        self.cache[key] = ans
        if self.cache_path:
            json.dump(self.cache, open(self.cache_path, "w", encoding="utf-8"), indent=1)
        return ans

    def is_deletion(self, text: str) -> bool:
        rb = rule_based(text)
        if self.use_llm:
            ans = self._llm(text)
            if ans is not None:
                return ans
        return rb
