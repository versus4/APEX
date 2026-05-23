"""Shared scan context object."""

from __future__ import annotations

import dataclasses
from typing import Any, Callable

from .budgets import RequestBudgetManager
from .models import ScanConfig


@dataclasses.dataclass
class ScanContext:
    config: ScanConfig
    client: Any
    budgets: RequestBudgetManager
    join_url: Callable[[str, str], str]
    category_for_option: Callable[[str], str]


__all__ = ["ScanContext"]
