"""Finding normalization helpers for report output."""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, Iterable, Optional

from .models import Finding


def coerce_finding_item(
    label: str,
    raw_item: Any,
    default_severity: str,
    severity_order: Dict[str, int],
    category: str = "misc",
) -> Optional[Finding]:
    if isinstance(raw_item, Finding):
        severity = raw_item.severity if raw_item.severity in severity_order else default_severity
        finding_category = raw_item.category
        if not finding_category or finding_category == "misc":
            finding_category = category
        return dataclasses.replace(
            raw_item,
            module=(raw_item.module or label),
            severity=severity,
            category=finding_category,
        )
    if not isinstance(raw_item, (list, tuple)) or len(raw_item) < 1:
        return None
    detail = str(raw_item[0] or "").strip()
    payload = str(raw_item[1] or "").strip() if len(raw_item) > 1 else ""
    severity = (
        str(raw_item[2]).upper()
        if len(raw_item) > 2 and str(raw_item[2]).upper() in severity_order
        else default_severity
    )
    if not detail:
        return None
    return Finding(module=label, detail=detail, payload=payload, severity=severity, category=category)


def summarize_findings(findings: Iterable[Any], severity_order: Iterable[str]) -> Dict[str, Any]:
    counts = {severity: 0 for severity in severity_order}
    confirmed = 0
    for item in findings:
        try:
            _, detail, _, severity = item
        except Exception:
            continue
        if severity in counts:
            counts[severity] += 1
        if "[CONFIRMED]" in str(detail):
            confirmed += 1
    return {"counts": counts, "confirmed": confirmed, "total": sum(counts.values())}


__all__ = ["coerce_finding_item", "summarize_findings"]
