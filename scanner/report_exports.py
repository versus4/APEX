"""SARIF and Markdown export helpers for Apex reports."""

from __future__ import annotations

import datetime
import json
import os
import re
from typing import Any, Callable, Dict, List, Sequence

from .models import Finding


def _write_text_atomic(filepath: str, text: str) -> None:
    parent = os.path.dirname(filepath)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = filepath + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, filepath)
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        raise


def _write_json_atomic(filepath: str, payload: Any) -> None:
    parent = os.path.dirname(filepath)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = filepath + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, filepath)
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        raise


def write_sarif_report(
    filepath: str,
    *,
    findings: Sequence[Finding],
    tool_name: str,
    target: str,
    remediation: Dict[str, str],
    redact_obj: Callable[[Any], Any],
    redact_text: Callable[[Any], Any],
    finding_stable_id: Callable[..., str],
) -> None:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    level_map = {"ZERO": "error", "CRIT": "error", "HIGH": "error", "MED": "warning", "LOW": "note", "INFO": "note"}
    for finding in findings:
        fid = finding.id or finding_stable_id(*finding.as_tuple())
        rule_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", finding.module).strip("-") or "scanner-finding"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding.module,
            "shortDescription": {"text": finding.module},
            "fullDescription": {"text": redact_text(remediation.get(finding.module, finding.module))},
            "properties": {"category": finding.category},
        })
        uri = finding.url or target or "target"
        results.append({
            "ruleId": rule_id,
            "level": level_map.get(finding.severity, "warning"),
            "message": {"text": redact_text(finding.detail)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {"scannerFindingId": fid},
            "properties": redact_obj({
                "severity": finding.severity,
                "payload": finding.payload,
                "confidence_score": finding.confidence_score,
                "evidence_level": finding.evidence_level,
            }),
        })
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "informationUri": "https://example.invalid/apex", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    _write_json_atomic(filepath, sarif)


def write_markdown_report(
    filepath: str,
    *,
    findings: Sequence[Finding],
    target: str,
    remediation: Dict[str, str],
    redact_text: Callable[[Any], Any],
    finding_stable_id: Callable[..., str],
    confidence_label: Callable[[int], str],
) -> None:
    order = ["ZERO", "CRIT", "HIGH", "MED", "LOW", "INFO"]
    lines = [
        "# Scanner Report",
        "",
        "- Target: `%s`" % (target or ""),
        "- Generated: `%s`" % datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "- Findings: `%d`" % len(findings),
        "",
        "## Summary",
        "",
    ]
    for sev in order:
        count = sum(1 for f in findings if f.severity == sev)
        if count:
            lines.append("- %s: %d" % (sev, count))
    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("No reportable findings.")
    for sev in order:
        for finding in [x for x in findings if x.severity == sev]:
            lines.extend([
                "### %s - %s" % (finding.severity, redact_text(finding.module)),
                "",
                "- ID: `%s`" % (finding.id or finding_stable_id(*finding.as_tuple())),
                "- Confidence: `%s` (`%s`)" % (confidence_label(finding.confidence_score), finding.confidence_score),
                "- Evidence: `%s`" % finding.evidence_level,
                "",
                redact_text(finding.detail.replace("[CONFIRMED] ", "")),
                "",
            ])
            if finding.payload:
                lines.extend(["Payload/evidence:", "", "```text", str(redact_text(finding.payload))[:2000], "```", ""])
            rem = remediation.get(finding.module)
            if rem:
                lines.extend(["Remediation: " + redact_text(rem), ""])
    _write_text_atomic(filepath, "\n".join(lines).rstrip() + "\n")


__all__ = ["write_markdown_report", "write_sarif_report"]
