"""Token / cost accounting for model calls made during a run."""
from __future__ import annotations

import json
from collections import defaultdict

# USD per million tokens (input, output). Update if pricing changes.
PRICES = {
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-sonnet-4-5": (3.00, 15.00),
}


class Usage:
    def __init__(self):
        self.calls = defaultdict(lambda: {"calls": 0, "input_tokens": 0, "output_tokens": 0})

    def record(self, model, inp, out):
        c = self.calls[model]
        c["calls"] += 1
        c["input_tokens"] += inp
        c["output_tokens"] += out

    def summary(self, n_requests):
        models = {}
        tot = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
        for m, c in self.calls.items():
            pi, po = PRICES.get(m, (0.0, 0.0))
            cost = c["input_tokens"] / 1e6 * pi + c["output_tokens"] / 1e6 * po
            models[m] = dict(c, cost_usd=round(cost, 6))
            for k in ("calls", "input_tokens", "output_tokens"):
                tot[k] += c[k]
            tot["cost_usd"] += cost
        tot["total_tokens"] = tot["input_tokens"] + tot["output_tokens"]
        tot["avg_tokens_per_request"] = tot["total_tokens"] / n_requests if n_requests else 0
        tot["cost_per_request_usd"] = tot["cost_usd"] / n_requests if n_requests else 0
        return {"models": models, "overall": tot, "requests": n_requests}

    def write(self, path, n_requests, seconds):
        s = self.summary(n_requests)
        s["runtime_seconds"] = round(seconds, 2)
        json.dump(s, open(path, "w"), indent=1)
