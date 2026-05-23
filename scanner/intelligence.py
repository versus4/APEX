"""Scanner intelligence helpers.

This module keeps recommendation, memory, replay, and report-enrichment logic
out of the main scanner runtime.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import urllib.parse
from typing import Any, Callable, Dict, Iterable, List, Sequence, Set, Tuple

from .models import Finding


NON_VULN_MEMORY_MODULES = {"adaptive recommendations", "scanner self debug", "target playbooks"}


def target_memory_key(target: str = "") -> str:
    parsed = urllib.parse.urlparse(target or "")
    host = (parsed.netloc or target or "").lower().strip()
    return hashlib.sha256(host.encode("utf-8", "ignore")).hexdigest()[:16]


def load_scan_memory(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {"schema_version": "1.0", "targets": {}}
    with open(path, encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        data = {"schema_version": "1.0", "targets": {}}
    data.setdefault("targets", {})
    return data


def current_finding_ids(findings: Sequence[Finding], fallback_id: Callable[[Tuple[str, str, str, str]], str]) -> Set[str]:
    ids: Set[str] = set()
    for finding in findings:
        if finding.module.strip().lower() in NON_VULN_MEMORY_MODULES:
            continue
        ids.add(finding.id or fallback_id(finding.as_tuple()))
    return ids


def compute_memory_delta(
    *,
    enabled: bool,
    memory: Dict[str, Any],
    memory_file: str,
    target: str,
    current_ids: Set[str],
) -> Dict[str, Any]:
    if not enabled:
        return {"enabled": False}
    key = target_memory_key(target)
    prev = (memory.get("targets", {}) or {}).get(key, {})
    prev_ids = set(prev.get("finding_ids", []) or [])
    return {
        "enabled": True,
        "memory_file": memory_file,
        "target_key": key,
        "previous_count": len(prev_ids),
        "current_count": len(current_ids),
        "new": sorted(current_ids - prev_ids),
        "resolved": sorted(prev_ids - current_ids),
        "unchanged": sorted(current_ids & prev_ids),
        "previous_scan_at": prev.get("last_scan_at", ""),
    }


def save_scan_memory(
    *,
    path: str,
    memory: Dict[str, Any],
    target: str,
    finding_ids: Set[str],
    tech: Any,
    quality: Dict[str, Any],
    redact_obj: Callable[[Any], Any],
) -> None:
    key = target_memory_key(target)
    memory.setdefault("schema_version", "1.0")
    targets = memory.setdefault("targets", {})
    targets[key] = {
        "target": target,
        "last_scan_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "finding_ids": sorted(finding_ids),
        "tech": tech,
        "quality": quality,
    }
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(redact_obj(memory), fh, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        raise


def finding_timeline(entry: Dict[str, Any], severity_order: Dict[str, int]) -> List[Dict[str, str]]:
    sev = str(entry.get("severity", entry.get("sev", "INFO")))
    level = str(entry.get("evidence_level", "possible"))
    timeline = [
        {"stage": "discovery", "status": "done", "detail": "module %s produced the signal" % entry.get("module", "")},
        {"stage": "proof", "status": level, "detail": "evidence=%s confidence=%s" % (level, entry.get("confidence_score", ""))},
    ]
    if entry.get("confirmed"):
        timeline.append({"stage": "confirmation", "status": "done", "detail": "scanner observed a confirmed proof marker"})
    else:
        timeline.append({"stage": "confirmation", "status": "needed", "detail": "manual or replay confirmation recommended"})
    if severity_order.get(sev, 0) >= severity_order.get("HIGH", 3):
        timeline.append({"stage": "impact", "status": "priority", "detail": "high-impact finding; validate business impact and patch window"})
    timeline.append({"stage": "retest", "status": "ready", "detail": "rerun --retest or replay exported request evidence after fixing"})
    return timeline


_IMPORTANT_ROUTE_RE = re.compile(
    r"(?i)/(?:admin|login|logout|signin|signup|register|account|profile|settings|billing|"
    r"checkout|payment|invoice|oauth|saml|oidc|token|reset|password|invite|users?|roles?|"
    r"graphql|api|internal|debug|actuator|metrics|upload|files?)\b"
)

_FLOW_PATTERNS: Sequence[Tuple[str, str, str]] = (
    ("auth", r"(?i)(login|signin|logout|session|jwt|cookie|token)", "Compare anonymous/user/admin sessions and test logout/session invalidation."),
    ("password reset", r"(?i)(reset|forgot|password)", "Check token entropy, host header use, one-time use, and expiry."),
    ("billing", r"(?i)(billing|checkout|payment|invoice|coupon|cart)", "Test price tampering, replay, coupon reuse, and race windows."),
    ("admin/RBAC", r"(?i)(admin|role|permission|rbac|tenant|org)", "Run role matrix checks with at least two privilege levels."),
    ("file upload", r"(?i)(upload|file|avatar|media|import)", "Test content-type validation, storage path, and parser sandboxing."),
    ("API", r"(?i)(api|graphql|swagger|openapi|jsonrpc)", "Fuzz schema/params and verify object-level authorization."),
)


def route_importance(text: str) -> Dict[str, Any]:
    urls = re.findall(r"https?://[^\s\"'<>]+|/[A-Za-z0-9_./?=&%:-]+", text or "")
    score = 0
    matched: List[str] = []
    for url in urls[:20]:
        if _IMPORTANT_ROUTE_RE.search(url):
            matched.append(url[:180])
            score += 15
        if re.search(r"(?i)(admin|billing|oauth|saml|token|password|reset|role|tenant|graphql)", url):
            score += 10
    score = min(score, 100)
    return {"score": score, "matched_routes": matched[:8], "label": "critical" if score >= 50 else "important" if score >= 20 else "normal"}


def proof_badges(entry: Dict[str, Any]) -> List[str]:
    text = " ".join(str(entry.get(k, "")) for k in ("detail", "payload")).lower()
    badges: List[str] = []
    level = str(entry.get("evidence_level", "")).lower()
    if entry.get("confirmed"):
        badges.append("confirmed")
    if level:
        badges.append(level)
    if "http " in text or "status=" in text or "code=" in text:
        badges.append("status-signal")
    if "header" in text:
        badges.append("header-signal")
    if "body" in text or "title=" in text or "match" in text:
        badges.append("body-match")
    if "timing" in text or "delay" in text or "elapsed" in text:
        badges.append("timing")
    if "differ" in text or "anonymous" in text or "authenticated" in text:
        badges.append("differential")
    if entry.get("evidence") or entry.get("evidence_attachment"):
        badges.append("replayable")
    if entry.get("speculative"):
        badges.append("needs-review")
    out: List[str] = []
    for badge in badges:
        if badge and badge not in out:
            out.append(badge)
    return out[:8]


def false_positive_notes(entry: Dict[str, Any]) -> Dict[str, Any]:
    module = str(entry.get("module", "")).lower()
    detail = str(entry.get("detail", "")).lower()
    reasons: List[str] = []
    confirm: List[str] = []
    if entry.get("speculative") or str(entry.get("evidence_level", "")) in {"possible", "informational"}:
        reasons.append("evidence is heuristic or passive, so the signal may be environmental noise")
    if "version" in detail or "fingerprint" in module:
        reasons.append("version fingerprints can be hidden, backported, or vendor-patched")
        confirm.append("verify the exact product/version from an authenticated admin source or package manifest")
    if "cors" in module:
        reasons.append("CORS impact depends on credentialed requests and sensitive readable responses")
        confirm.append("replay with a hostile Origin and a real authenticated session")
    if "redirect" in module:
        reasons.append("some redirects are intentionally external allowlist entries")
        confirm.append("check whether arbitrary attacker domains are accepted, not only trusted domains")
    if "sqli" in module or "timing" in detail:
        reasons.append("timing and error probes can be affected by backend load or generic errors")
        confirm.append("repeat with paired true/false payloads and stable baselines")
    if "secret" in module or "secret" in detail or "token" in detail:
        reasons.append("detected tokens may be examples, public keys, or already revoked")
        confirm.append("identify owner/scope offline and rotate if it is a live credential")
    if not reasons:
        reasons.append("low likelihood if evidence is confirmed, but still verify scope and business impact")
    if not confirm:
        confirm.append("replay the captured request, compare against a clean baseline, and verify expected impact")
    return {"why_might_be_false_positive": reasons[:3], "manual_confirmation": confirm[:3]}


def finding_priority(entry: Dict[str, Any], severity_order: Dict[str, int]) -> Dict[str, Any]:
    sev = str(entry.get("severity", "INFO")).upper()
    base = severity_order.get(sev, 0) * 18
    conf = int(entry.get("confidence_score", 0) or 0) * 3
    evidence_bonus = {"confirmed": 18, "probable": 10, "possible": 3, "informational": 0}.get(str(entry.get("evidence_level", "")).lower(), 0)
    text = " ".join(str(entry.get(k, "")) for k in ("detail", "payload"))
    route = route_importance(text)
    exploit_bonus = 0
    if re.search(r"(?i)(rce|command|sqli|ssrf|auth|token|password|admin|takeover|secret|private key)", text):
        exploit_bonus += 15
    if entry.get("confirmed"):
        exploit_bonus += 8
    score = min(100, base + conf + evidence_bonus + route["score"] // 2 + exploit_bonus)
    severity_cap = {"INFO": 25, "LOW": 49, "MED": 74, "HIGH": 92, "CRIT": 100, "ZERO": 100}.get(sev, 70)
    if entry.get("confirmed") and sev == "HIGH":
        severity_cap = 100
    score = min(score, severity_cap)
    return {
        "score": score,
        "rank": "urgent" if score >= 85 else "high" if score >= 65 else "medium" if score >= 35 else "low",
        "drivers": {
            "severity": sev,
            "confidence_score": int(entry.get("confidence_score", 0) or 0),
            "evidence_level": entry.get("evidence_level", ""),
            "route_importance": route,
        },
    }


def enrich_finding_entry(entry: Dict[str, Any], severity_order: Dict[str, int]) -> Dict[str, Any]:
    enriched = dict(entry)
    text = " ".join(str(entry.get(k, "")) for k in ("detail", "payload"))
    enriched["proof_badges"] = proof_badges(entry)
    enriched["false_positive_analysis"] = false_positive_notes(entry)
    enriched["route_importance"] = route_importance(text)
    enriched["fix_priority"] = finding_priority(entry, severity_order)
    return enriched


def business_flow_hints(findings_summary: Iterable[Tuple[str, str, str, str]], endpoints: Iterable[str]) -> List[Dict[str, str]]:
    text = " ".join(" ".join(map(str, item)) for item in findings_summary) + " " + " ".join(endpoints)
    out: List[Dict[str, str]] = []
    for flow, pattern, next_step in _FLOW_PATTERNS:
        if re.search(pattern, text):
            out.append({"flow": flow, "why": "matched routes/findings for %s" % flow, "next_step": next_step})
    return out[:10]


def target_profile(
    *,
    target: str,
    detected_stack: str,
    tech_inventory: Any,
    endpoints: Iterable[str],
    findings_summary: Iterable[Tuple[str, str, str, str]],
) -> Dict[str, Any]:
    endpoint_list = list(endpoints or [])
    text = " ".join(endpoint_list).lower() + " " + " ".join(map(str, tech_inventory or [])).lower() + " " + " ".join(" ".join(map(str, f)) for f in findings_summary).lower()
    tags: List[str] = []
    if "graphql" in text:
        tags.append("graphql-api")
    if "swagger" in text or "openapi" in text or "/api/" in text:
        tags.append("rest-api")
    if any(x in text for x in ("wordpress", "wp-json", "wp-admin")):
        tags.append("wordpress")
    if any(x in text for x in ("next", "_next", "nuxt", "react", "vue")):
        tags.append("spa")
    if any(x in text for x in ("actuator", "jenkins", "grafana", "prometheus", "kubernetes", "docker")):
        tags.append("devops-console")
    if any(x in text for x in ("login", "account", "billing", "admin", "dashboard")):
        tags.append("stateful-app")
    if not tags:
        tags.append("generic-web")
    important = route_importance(" ".join(endpoint_list))
    return {
        "target": target,
        "detected_stack": detected_stack or "unknown",
        "tags": tags[:8],
        "important_route_count": len(important.get("matched_routes", [])),
        "important_routes": important.get("matched_routes", []),
        "recommended_profile": "full" if any(t in tags for t in ("stateful-app", "devops-console")) else "normal",
    }


def executive_summary(
    *,
    findings: Sequence[Dict[str, Any]],
    posture: Dict[str, Any],
    target_profile_data: Dict[str, Any],
    self_debug: Sequence[Dict[str, str]],
) -> Dict[str, Any]:
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    top = sorted(findings, key=lambda f: int((f.get("fix_priority") or {}).get("score", 0)), reverse=True)[:5]
    main_risk = "No reportable findings at the current thresholds."
    if top:
        main_risk = "Primary risk area: %s (%s)." % (top[0].get("module", "unknown"), top[0].get("severity", "INFO"))
    grade = posture.get("grade", "") if posture else ""
    if grade:
        main_risk += " Posture grade %s." % grade
    return {
        "headline": main_risk,
        "target_type": ", ".join(target_profile_data.get("tags", []) or ["generic-web"]),
        "severity_counts": sev_counts,
        "top_priorities": [
            {
                "id": f.get("id", ""),
                "module": f.get("module", ""),
                "severity": f.get("severity", ""),
                "priority": (f.get("fix_priority") or {}).get("rank", ""),
                "score": (f.get("fix_priority") or {}).get("score", 0),
            }
            for f in top
        ],
        "coverage_warning": self_debug[0]["detail"] if self_debug else "",
    }


def next_best_actions(
    *,
    adaptive_recs: Sequence[Dict[str, str]],
    self_debug: Sequence[Dict[str, str]],
    business_flows: Sequence[Dict[str, str]],
    findings: Sequence[Dict[str, Any]],
) -> List[Dict[str, str]]:
    actions: List[Dict[str, str]] = []
    for f in sorted(findings, key=lambda item: int((item.get("fix_priority") or {}).get("score", 0)), reverse=True)[:3]:
        actions.append({
            "type": "fix",
            "title": "Fix priority: " + str(f.get("module", "")),
            "why": "priority=%s score=%s" % ((f.get("fix_priority") or {}).get("rank", ""), (f.get("fix_priority") or {}).get("score", 0)),
            "command_hint": "",
        })
    for flow in business_flows[:3]:
        actions.append({"type": "manual-test", "title": "Test " + flow["flow"], "why": flow["why"], "command_hint": flow["next_step"]})
    for rec in adaptive_recs[:4]:
        actions.append({"type": "scan", "title": "Run " + rec.get("option", ""), "why": rec.get("reason", ""), "command_hint": rec.get("command_hint", "")})
    for gap in self_debug[:3]:
        actions.append({"type": "coverage", "title": "Improve " + gap.get("kind", ""), "why": gap.get("detail", ""), "command_hint": gap.get("fix", "")})
    seen: Set[str] = set()
    deduped: List[Dict[str, str]] = []
    for action in actions:
        key = action["type"] + action["title"]
        if key not in seen:
            seen.add(key)
            deduped.append(action)
    return deduped[:12]


def build_replay_pack(
    *,
    findings: Sequence[Finding],
    evidence_for: Callable[[Finding], Dict[str, Any]],
    redact_text: Callable[[str], str],
    severity_order: Dict[str, int],
) -> List[Dict[str, Any]]:
    pack: List[Dict[str, Any]] = []
    for finding in findings:
        m, d, p, s = finding.as_tuple()
        ev = evidence_for(finding) or {}
        req = ev.get("request", {}) if isinstance(ev, dict) else {}
        url = req.get("url") or (p if str(p).startswith("http") else "")
        method = req.get("method") or "GET"
        curl = "curl -i -X %s %s" % (method, json.dumps(url)) if url else ""
        pack.append({
            "id": finding.id,
            "module": m,
            "severity": s,
            "detail": redact_text(d.replace("[CONFIRMED] ", "")),
            "url": redact_text(url),
            "method": method,
            "curl": redact_text(curl),
            "timeline": finding_timeline(finding.as_json(), severity_order),
        })
    return pack


def adaptive_recommendations(
    *,
    findings_summary: Iterable[Tuple[str, str, str, str]],
    tech_inventory: Any,
    auth_profile_file: str,
    http_evidence_enabled: bool,
) -> List[Dict[str, str]]:
    text = " ".join(" ".join(map(str, item)) for item in findings_summary).lower()
    tech = " ".join(map(str, tech_inventory or [])).lower()
    recs: List[Dict[str, str]] = []

    def add(option: str, reason: str, command_hint: str = "") -> None:
        key = option.lower()
        if not any(r["option"].lower() == key for r in recs):
            recs.append({"option": option, "reason": reason, "command_hint": command_hint or ("--" + option.replace("_", "-"))})

    if "graphql" in text or "graphql" in tech:
        add("graphql_oracle", "GraphQL surface detected; run schema-aware mutation/auth checks")
    if "jwt" in text or "bearer" in text:
        add("jwtconf", "JWT/token material detected; test alg confusion, weak secrets, and audience drift")
    if any(x in tech for x in ("wordpress", "wp-")):
        add("wordpress", "WordPress fingerprint detected; run WordPress surface and plugin checks")
    if any(x in tech for x in ("spring", "java", "tomcat")):
        add("actuator_deep", "Java/Spring-like stack detected; run actuator and Java exposure checks")
    if any(x in tech for x in ("next", "nuxt", "react", "vue")):
        add("domheadless", "SPA/client framework detected; run browser/headless DOM checks")
    if "openapi" in text or "swagger" in text:
        add("openapifuzz", "OpenAPI/Swagger detected; fuzz declared API params")
    if not auth_profile_file:
        add("authprofile", "Auth profile missing; role/tenant comparison would improve authz coverage", "--auth-profile profiles.json --authprofile")
    if not http_evidence_enabled:
        add("http_evidence", "Replayable proof capture is disabled", "--http-evidence --replay-pack replay_pack.json")
    return recs[:12]


def self_debug_gaps(
    *,
    quality: Dict[str, Any],
    auth_profile_file: str,
    js_render: bool,
    proxy_report: Dict[str, Any],
    http_evidence_enabled: bool,
) -> List[Dict[str, str]]:
    gaps: List[Dict[str, str]] = []
    cov = quality.get("coverage", {}) or {}

    def add(kind: str, detail: str, fix: str) -> None:
        gaps.append({"kind": kind, "detail": detail, "fix": fix})

    if not auth_profile_file:
        add("auth", "no auth profile loaded, so RBAC/BOLA coverage is limited", "provide --auth-profile with anon/user/admin or tenant profiles")
    if not js_render:
        add("browser", "headless JS rendering is off", "rerun with --js-render for SPA routes and DOM evidence")
    if int(cov.get("forms_seen", 0) or 0) == 0:
        add("forms", "no HTML forms were discovered", "increase --crawl-pages/depth or import HAR traffic")
    if int(quality.get("failed_modules", 0) or 0) or int(quality.get("timed_out_modules", 0) or 0):
        add("module health", "some modules failed or timed out", "review module_health_audit and raise --timeout/--module-timeout")
    if proxy_report.get("configured") and int(proxy_report.get("total_successes", 0) or 0) == 0 and int(proxy_report.get("total_failures", 0) or 0) > 0:
        add("proxy", "configured proxies had no healthy candidates", "clean proxies folder or run direct with --no-proxy")
    if not http_evidence_enabled:
        add("evidence", "HTTP evidence capture is off", "use --http-evidence for replayable request/response proof")
    return gaps


def target_playbook_recommendations(
    *,
    findings_summary: Iterable[Tuple[str, str, str, str]],
    detected_stack: str,
    inferred_stack: str,
    playbooks: Dict[Tuple[str, str], Dict[str, Any]],
) -> List[Dict[str, Any]]:
    stack = detected_stack if detected_stack != "unknown" else inferred_stack
    recs: List[Dict[str, Any]] = []
    for mod, _det, _pay, sev in findings_summary:
        pb = next((p for st in (stack, detected_stack, "generic") if (p := playbooks.get((mod, st)))), None)
        if pb:
            recs.append({"module": mod, "severity": sev, "stack": stack, "root_cause": pb.get("root_cause", ""), "fix_steps": pb.get("fix_steps", [])[:5]})
    if not recs and stack != "unknown":
        recs.append({"module": "stack", "severity": "INFO", "stack": stack, "root_cause": "target stack inferred", "fix_steps": ["run stack-specific modules", "review framework security baseline"]})
    return recs[:20]
