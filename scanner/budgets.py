"""Per-module scan request budgets."""

from __future__ import annotations

import dataclasses
import threading
import time
from typing import Dict, Optional


@dataclasses.dataclass
class ModuleBudget:
    label: str
    max_requests: int = 0
    deadline: float = 0.0
    requests: int = 0
    exhausted: bool = False

    def allow_request(self, now: Optional[float] = None) -> bool:
        if self.exhausted:
            return False
        current = time.monotonic() if now is None else now
        if self.deadline > 0 and current > self.deadline:
            self.exhausted = True
            return False
        if self.max_requests > 0 and self.requests >= self.max_requests:
            self.exhausted = True
            return False
        self.requests += 1
        return True


class RequestBudgetManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._budgets: Dict[str, ModuleBudget] = {}

    def start(self, label: str, *, max_requests: int = 0, timeout_seconds: float = 0.0) -> ModuleBudget:
        deadline = time.monotonic() + timeout_seconds if timeout_seconds > 0 else 0.0
        budget = ModuleBudget(label=label, max_requests=max(0, int(max_requests)), deadline=deadline)
        with self._lock:
            self._budgets[label] = budget
        return budget

    def end(self, label: str) -> None:
        with self._lock:
            self._budgets.pop(label, None)

    def allow_request(self, label: str) -> bool:
        if not label:
            return True
        with self._lock:
            budget = self._budgets.get(label)
            if budget is None:
                return True
            return budget.allow_request()

    def snapshot(self) -> Dict[str, Dict[str, object]]:
        with self._lock:
            return {
                label: {
                    "max_requests": budget.max_requests,
                    "requests": budget.requests,
                    "exhausted": budget.exhausted,
                }
                for label, budget in self._budgets.items()
            }


__all__ = ["ModuleBudget", "RequestBudgetManager"]
