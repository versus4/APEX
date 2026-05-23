import ast
import collections
import re
from typing import Any, Callable, Dict, Iterable, List, Tuple


def help_topic_lines(topic: str) -> List[str]:
    topics: Dict[str, List[str]] = {
        "core": [
            "Core scan:",
            "  python Scanner.py https://target --profile fast --no-prompt",
            "  --all --only MODS --exclude MODS --scan-category NAME --workers N --timeout SECS",
            "  --scanner-parity enables the competitive bundle",
        ],
        "reports": [
            "Reports:",
            "  --json report.json --html-report report.html --sarif-report report.sarif",
            "  --markdown-report report.md --http-evidence --replay-pack replay.json",
            "  --baseline old.json --only-new --compare old.json --retest old.json",
        ],
        "auth": [
            "Auth/session:",
            "  --cookie 'a=b' --header 'Authorization: Bearer ...'",
            "  --auth-profile profiles.json --authprofile --session-jar",
            "  --auto-login-detect --login-user USER --login-pass PASS",
        ],
        "advanced": [
            "Advanced:",
            "  --payload-safety passive|normal|active|intrusive --authorized",
            "  --js-render --oob-host HOST --fuzzer --nuclei-lite --source-scan --sbom-scan",
            "  Maintenance: --doctor --audit-scanner --audit-dead-code --module-self-test",
        ],
    }
    return topics.get(topic, ["Help topics: core, reports, auth, advanced"])


def audit_cves_in_source(path: str) -> Tuple[int, List[Tuple[str, str]]]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            source = fh.read()
    except OSError as ex:
        return 2, [("error", "  [audit-cves] could not read source: " + str(ex))]

    scan_source = re.sub(r"def _audit_cves_in_source[\s\S]*?\ndef main\(", "\ndef main(", source, count=1)
    cve_re = re.compile(r"CVE[-_ ](20\d{2})[-_ ](\d{3,7})", re.I)
    normalized = sorted({"CVE-%s-%s" % (m.group(1), m.group(2)) for m in cve_re.finditer(scan_source)})
    _cve = lambda year, num: "CVE-%s-%s" % (year, num)
    known_rejected = {
        _cve("2014", "8191"): "Rejected by CNA; do not use as AngularJS sandbox-bypass mapping",
        _cve("2022", "23529"): "Rejected jsonwebtoken advisory; use a non-CVE hardening tag instead",
        _cve("2025", "2825"): "Rejected/withdrawn CrushFTP identifier; use " + _cve("2025", "31161"),
    }
    product_mismatch_hints = {
        _cve("2024", "4956"): ("grafana", _cve("2024", "4956") + " is Sonatype Nexus Repository 3, not Grafana"),
        _cve("2024", "52301"): ("method override", _cve("2024", "52301") + " is Laravel environment manipulation, not method override"),
        _cve("2025", "20198"): ("asa", _cve("2025", "20198") + " is IOS XE CLI/local privilege escalation, not ASA/FTD SSL-VPN"),
        _cve("2025", "25012"): ("prototype pollution", _cve("2025", "25012") + " is Kibana open redirect, not prototype pollution RCE"),
    }

    issues: List[str] = []
    for cve in normalized:
        if cve in known_rejected:
            issues.append("%s: %s" % (cve, known_rejected[cve]))

    for line_no, line in enumerate(scan_source.splitlines(), 1):
        low = line.lower()
        for cve, (needle, msg) in product_mismatch_hints.items():
            if cve.lower() in low and needle in low:
                issues.append("%s:%d: %s" % (cve, line_no, msg))

    weird = sorted(set(re.findall(r"CVE-\d{4}-[A-Za-z0-9_-]*[A-Za-z_][A-Za-z0-9_-]*", scan_source)))
    for token in weird:
        issues.append("%s: nonstandard CVE-looking token; use an internal tag without CVE- prefix" % token)

    rows: List[Tuple[str, str]] = [
        ("info", "  [audit-cves] source: " + path),
        ("warn", "  [audit-cves] normalized CVEs: %d" % len(normalized)),
    ]
    if not issues:
        rows.append(("ok", "  [audit-cves] no known rejected IDs or local mismatch hints found"))
        return 0, rows
    rows.append(("warn_bold", "  [audit-cves] issues found: %d" % len(issues)))
    rows.extend(("warn", "    - " + item) for item in issues)
    return 1, rows


def audit_issue_category(issue: str) -> str:
    if issue.startswith("import "):
        return "imports"
    if "_SCAN_REGISTRY" in issue or issue.startswith("scan category"):
        return "registry"
    if "duplicate" in issue or "defined " in issue or "overridden" in issue:
        return "duplicates"
    return "all"


def format_dead_code_audit(result: Dict[str, Any], fallback_source: str) -> List[Tuple[str, str]]:
    candidates = result.get("candidates", [])
    dynamic_kept = result.get("dynamic_kept", [])
    rows: List[Tuple[str, str]] = [
        ("info", "  [audit-dead-code] source: " + str(result.get("source", fallback_source))),
        ("warn", "  [audit-dead-code] defs=%s registry=%s candidates=%s dynamic-kept=%s" % (
            result.get("top_level_defs", 0),
            result.get("registry_functions", 0),
            len(candidates),
            len(dynamic_kept),
        )),
    ]
    rows.extend(("warn", "    ? line %(line)s %(name)s (%(lines)s lines, refs=%(refs)s)" % item) for item in candidates[:80])
    if len(candidates) > 80:
        rows.append(("dim", "    ... %d more candidate(s)" % (len(candidates) - 80)))
    if dynamic_kept:
        rows.append(("dim", "  [audit-dead-code] skipped %d dynamic/string-referenced symbol(s)" % len(dynamic_kept)))
    return rows


def audit_scanner_source(
    path: str,
    audit_category: str,
    registry: Iterable[Tuple[str, str, Callable]],
    scan_categories: Dict[str, Iterable[str]],
    category_for_option: Callable[[str], str],
) -> Tuple[int, List[Tuple[str, str]]]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            source = fh.read()
    except OSError as ex:
        return 2, [("error", "  [audit-scanner] could not read source: " + str(ex))]

    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as ex:
        return 2, [("error", "  [audit-scanner] syntax error: " + str(ex))]

    issues: List[str] = []
    def_lines: Dict[str, List[int]] = collections.defaultdict(list)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            def_lines[node.name].append(node.lineno)
    for name, lines in sorted(def_lines.items()):
        if len(lines) > 1:
            impact = "scan implementation is overridden" if name.startswith("scan_") else "function is overridden"
            issues.append("%s defined %d times at lines %s (%s)" % (
                name, len(lines), ", ".join(str(n) for n in lines), impact
            ))

    used_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    imported_names: Dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names[alias.asname or alias.name.split(".", 1)[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    imported_names[alias.asname or alias.name] = node.lineno
    for name, line in sorted(imported_names.items(), key=lambda item: item[1]):
        if name not in used_names and not name.startswith("_"):
            issues.append("import '%s' at line %d appears unused" % (name, line))

    for node in tree.body:
        value_node = None
        target_names: List[str] = []
        if isinstance(node, ast.Assign):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            target_names = [node.target.id] if isinstance(node.target, ast.Name) else []
            value_node = node.value
        if not target_names or not isinstance(value_node, ast.Dict):
            continue
        dict_name = target_names[0]
        if dict_name not in {"_SCAN_SEVERITY", "_REMEDIATION", "_SCAN_PROFILES"}:
            continue
        seen_keys: Dict[str, int] = {}
        for key_node in value_node.keys:
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                key = key_node.value.strip().lower()
                if key in seen_keys:
                    issues.append("%s has duplicate key '%s' at lines %d and %d (later value wins)" % (
                        dict_name, key, seen_keys[key], getattr(key_node, "lineno", node.lineno)
                    ))
                else:
                    seen_keys[key] = getattr(key_node, "lineno", node.lineno)

    run_all_match = re.search(r"def run_all\([\s\S]*?\n\s*def _run_self_benchmark", source)
    if run_all_match:
        labels = collections.defaultdict(list)
        for m in re.finditer(r'\(\s*"([^"]+)"\s*,\s*lambda:', run_all_match.group(0)):
            labels[m.group(1).strip().lower()].append(source[:run_all_match.start() + m.start()].count("\n") + 1)
        for label, lines in sorted(labels.items()):
            if len(lines) > 1:
                issues.append("run_all schedules label '%s' %d times at lines %s (summary dedupe may merge findings)" % (
                    label, len(lines), ", ".join(str(n) for n in lines)
                ))

    registry_list = list(registry or [])
    opt_lines: Dict[str, int] = {}
    label_seen: Dict[str, int] = {}
    for idx, entry in enumerate(registry_list):
        try:
            opt, label, fn = entry
        except Exception:
            continue
        opt_key = str(opt).strip().lower()
        label_key = str(label).strip().lower()
        if opt_key in opt_lines:
            issues.append("_SCAN_REGISTRY duplicate option '%s' at entries %d and %d" % (opt_key, opt_lines[opt_key], idx))
        else:
            opt_lines[opt_key] = idx
        if label_key in label_seen:
            issues.append("_SCAN_REGISTRY duplicate label '%s' at entries %d and %d" % (label_key, label_seen[label_key], idx))
        else:
            label_seen[label_key] = idx
        fn_name = getattr(fn, "__name__", "")
        if fn_name and fn_name in def_lines and len(def_lines[fn_name]) > 1:
            issues.append("_SCAN_REGISTRY option '%s' points to overridden function '%s' (definitions at %s)" % (
                opt_key, fn_name, ", ".join(str(n) for n in def_lines[fn_name])
            ))
        if category_for_option(opt_key) == "misc":
            issues.append("_SCAN_REGISTRY option '%s' is uncategorized" % opt_key)

    known_options = {opt for opt, _, _ in registry_list}
    for category, options in sorted(scan_categories.items()):
        for opt in sorted(options):
            if opt not in known_options:
                issues.append("scan category '%s' references unknown option '%s'" % (category, opt))

    if audit_category != "all":
        issues = [issue for issue in issues if audit_issue_category(issue) == audit_category]

    rows: List[Tuple[str, str]] = [("info", "  [audit-scanner] source: " + path)]
    if not issues:
        rows.append(("ok", "  [audit-scanner] no duplicate definitions, duplicate keys, or registry shadows found"))
        return 0, rows
    rows.append(("warn_bold", "  [audit-scanner] warnings found: %d" % len(issues)))
    rows.extend(("warn", "    - " + item) for item in issues[:80])
    if len(issues) > 80:
        rows.append(("warn", "    ... %d more" % (len(issues) - 80)))
    return 1, rows


def validate_plugin_scan_metadata(opt: str, label: str, fn: Any, existing: Iterable[str]) -> List[str]:
    issues: List[str] = []
    existing_set = set(existing)
    if not re.match(r"^[a-z][a-z0-9_]{1,48}$", opt):
        issues.append("option must match ^[a-z][a-z0-9_]{1,48}$")
    if opt in existing_set:
        issues.append("option duplicates an existing scan")
    if not label or len(label) > 80:
        issues.append("label must be 1-80 characters")
    if not callable(fn):
        issues.append("func is not callable")
    return issues
