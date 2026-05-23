"""Local source, dependency, and SBOM analysis helpers for Apex."""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
import fnmatch
from typing import Any, Dict, Iterable, List, Sequence, Tuple

ScanFindings = List[Tuple[str, str]]

_SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    "node_modules", "vendor", "dist", "build", "target", ".venv", "venv",
    ".idea", ".vscode", ".tox", "coverage", ".next", ".nuxt",
    "output",
}

_SOURCE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".hpp", ".rs", ".swift", ".kt", ".kts",
    ".scala", ".sh", ".ps1", ".yml", ".yaml", ".json", ".toml", ".env",
    ".ini", ".properties", ".conf", ".config", ".xml", ".html", ".vue",
}

_MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock",
    "poetry.lock", "composer.json", "composer.lock", "pom.xml",
    "build.gradle", "build.gradle.kts", "go.mod", "go.sum", "Gemfile",
    "Gemfile.lock", "Cargo.toml", "Cargo.lock", "Dockerfile",
    "docker-compose.yml", "docker-compose.yaml", "bom.json", "sbom.json",
}

_SECRET_PATTERNS: Sequence[Tuple[str, str, re.Pattern[str]]] = (
    ("AWS access key", "HIGH", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS temporary access key", "HIGH", re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("GitHub token", "HIGH", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("Slack token", "HIGH", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("Stripe secret key", "HIGH", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("Google API key", "MED", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b")),
    ("SendGrid API key", "HIGH", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b")),
    ("JWT-like token", "MED", re.compile(r"\beyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Private key block", "CRIT", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Database URL with credentials", "HIGH", re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s/@]+:[^@\s]+@[^)\s\"']+", re.I)),
    ("Generic assigned secret", "MED", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"\n]{12,}['\"]")),
)

_DANGEROUS_PATTERNS: Sequence[Tuple[str, str, re.Pattern[str]]] = (
    ("Python eval/exec usage", "MED", re.compile(r"\b(?:eval|exec)\s*\(")),
    ("Python shell=True subprocess", "HIGH", re.compile(r"subprocess\.[A-Za-z_]+\([^)\n]*shell\s*=\s*True", re.S)),
    ("Python pickle loads", "MED", re.compile(r"\bpickle\.loads?\s*\(")),
    ("Unsafe YAML load", "MED", re.compile(r"\byaml\.load\s*\(")),
    ("TLS verification disabled", "MED", re.compile(r"\bverify\s*=\s*False\b")),
    ("JavaScript eval usage", "MED", re.compile(r"\beval\s*\(")),
    ("JavaScript innerHTML assignment", "MED", re.compile(r"\.innerHTML\s*=")),
    ("JavaScript document.write", "MED", re.compile(r"\bdocument\.write\s*\(")),
    ("Node child_process exec", "HIGH", re.compile(r"child_process\.(?:exec|execSync)\s*\(")),
    ("PHP command execution", "HIGH", re.compile(r"\b(?:system|shell_exec|passthru|proc_open)\s*\(")),
    ("TODO security bypass marker", "LOW", re.compile(r"(?i)\b(?:TODO|FIXME|HACK).{0,60}\b(?:auth|security|bypass|token|password)\b")),
)

_UNPINNED_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:$|[<>=~!]=?\s*[*xX]?\s*$)")


def _safe_rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except Exception:
        return path.replace("\\", "/")


def _load_apexignore(root: str) -> List[str]:
    path = os.path.join(root, ".apexignore")
    if not os.path.exists(path):
        return []
    patterns: List[str] = []
    for raw in _read_text(path, limit=200000).splitlines():
        line = raw.strip().strip("\ufeff")
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if line and not line.startswith("#"):
            patterns.append(line.replace("\\", "/"))
    return patterns


def _ignored(rel: str, patterns: Sequence[str]) -> bool:
    rel = rel.replace("\\", "/")
    name = os.path.basename(rel)
    for pat in patterns:
        clean = pat.strip("/")
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, clean) or fnmatch.fnmatch(name, pat):
            return True
        if pat.endswith("/") and (rel + "/").startswith(pat):
            return True
    return False


def _iter_files(root: str, max_files: int = 5000) -> Iterable[str]:
    seen = 0
    ignore_patterns = _load_apexignore(root)
    for current, dirs, files in os.walk(root):
        rel_current = _safe_rel(current, root)
        dirs[:] = [
            d for d in dirs
            if d not in _SKIP_DIRS and not d.startswith(".cache")
            and not _ignored((rel_current if rel_current != "." else "") + "/" + d + "/", ignore_patterns)
        ]
        for name in files:
            full = os.path.join(current, name)
            if _ignored(_safe_rel(full, root), ignore_patterns):
                continue
            seen += 1
            if seen > max_files:
                return
            yield full


def _read_text(path: str, limit: int = 600000) -> str:
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as fh:
            return fh.read(limit)
    except Exception:
        return ""


def _interesting_source(path: str) -> bool:
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    return ext in _SOURCE_EXTS or name in _MANIFEST_NAMES or name.startswith(".env")


def scan_source_tree(root: str) -> ScanFindings:
    """Find local secrets and dangerous APIs in a source tree."""
    root = os.path.abspath(root or ".")
    if not os.path.isdir(root):
        return [("source code static scan skipped", "root=%s reason=directory_not_found" % root)]
    out: ScanFindings = []
    files_scanned = 0
    for path in _iter_files(root):
        if not _interesting_source(path):
            continue
        files_scanned += 1
        rel = _safe_rel(path, root)
        text = _read_text(path)
        if not text:
            continue
        for label, severity, pattern in _SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                line = text[:match.start()].count("\n") + 1
                out.append((
                    "[CONFIRMED] %s local secret candidate" % severity,
                    "type=%s file=%s line=%d verification=manual_rotate_if_real" % (label, rel, line),
                ))
        for label, severity, pattern in _DANGEROUS_PATTERNS:
            match = pattern.search(text)
            if match:
                line = text[:match.start()].count("\n") + 1
                out.append((
                    "[CONFIRMED] %s local source risk" % severity,
                    "type=%s file=%s line=%d" % (label, rel, line),
                ))
        if len(out) >= 150:
            break
    out.insert(0, ("source code static scan completed", "root=%s files_scanned=%d findings=%d" % (root, files_scanned, len(out))))
    if len(out) == 1:
        out[0] = ("source code static scan completed", "root=%s files_scanned=%d no_high_signal_patterns_found" % (root, files_scanned))
    return out[:150]


def _load_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as fh:
            return json.load(fh)
    except Exception:
        return None


def _collect_manifest_files(root: str) -> List[str]:
    paths: List[str] = []
    for path in _iter_files(root):
        name = os.path.basename(path)
        low = name.lower()
        if name in _MANIFEST_NAMES or low.endswith(".csproj") or "cyclonedx" in low or "spdx" in low or low.startswith("sbom"):
            paths.append(path)
    return paths


def _deps_from_package_json(data: Dict[str, Any]) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        value = data.get(key)
        if isinstance(value, dict):
            for name, version in value.items():
                deps[str(name)] = str(version)
    return deps


def _parse_requirements(text: str) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip().strip("\ufeff")
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if ";" in line:
            line = line.split(";", 1)[0].strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)\s*([=<>!~].*)?$", line)
        if m:
            deps[m.group(1)] = (m.group(2) or "").strip()
    return deps


def _parse_go_mod(text: str) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("module ", "go ", "require (", ")")):
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        parts = line.split()
        if len(parts) >= 2 and "/" in parts[0]:
            deps[parts[0]] = parts[1]
    return deps


def _parse_pom(path: str) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    try:
        root = ET.parse(path).getroot()
        ns = {"m": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
        dep_nodes = root.findall(".//m:dependency", ns) if ns else root.findall(".//dependency")
        for dep in dep_nodes:
            group = dep.find("m:groupId", ns) if ns else dep.find("groupId")
            art = dep.find("m:artifactId", ns) if ns else dep.find("artifactId")
            ver = dep.find("m:version", ns) if ns else dep.find("version")
            if group is not None and art is not None and group.text and art.text:
                deps[group.text.strip() + ":" + art.text.strip()] = (ver.text or "").strip() if ver is not None else ""
    except Exception:
        pass
    return deps


def _sbom_components(data: Any) -> List[Tuple[str, str]]:
    comps: List[Tuple[str, str]] = []
    if isinstance(data, dict):
        if isinstance(data.get("components"), list):
            for item in data["components"]:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("purl") or item.get("bom-ref")
                    if name:
                        comps.append((str(name), str(item.get("version") or "")))
        packages = data.get("packages")
        if isinstance(packages, list):
            for item in packages:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("SPDXID")
                    if name:
                        comps.append((str(name), str(item.get("versionInfo") or "")))
    return comps


def _risk_hints(name: str, version: str) -> List[str]:
    low = name.lower()
    hints: List[str] = []
    if low in {"lodash", "minimist", "qs", "jquery", "log4j-core", "jackson-databind", "struts2-core"}:
        hints.append("high-profile package; verify version against current advisories")
    if any(x in low for x in ("debug", "test", "example", "demo")):
        hints.append("dependency name suggests non-production package")
    if version and any(token in version for token in ("*", "x", "latest")):
        hints.append("floating version")
    return hints


def scan_dependency_manifests(root: str) -> ScanFindings:
    """Parse local dependency manifests and SBOMs for inventory/risk hints."""
    root = os.path.abspath(root or ".")
    if not os.path.isdir(root):
        return [("local dependency inventory skipped", "root=%s reason=directory_not_found" % root)]
    manifests = _collect_manifest_files(root)
    out: ScanFindings = []
    total_deps = 0
    unpinned = 0
    sbom_components = 0
    for path in manifests[:200]:
        rel = _safe_rel(path, root)
        name = os.path.basename(path)
        deps: Dict[str, str] = {}
        if name in {"package.json", "composer.json"}:
            data = _load_json(path)
            if isinstance(data, dict):
                if name == "package.json":
                    deps = _deps_from_package_json(data)
                else:
                    deps = {str(k): str(v) for k, v in (data.get("require") or {}).items() if isinstance(data.get("require"), dict)}
        elif name in {"requirements.txt"}:
            deps = _parse_requirements(_read_text(path))
        elif name == "go.mod":
            deps = _parse_go_mod(_read_text(path))
        elif name == "pom.xml":
            deps = _parse_pom(path)
        elif name.lower().endswith(".json") or "cyclonedx" in name.lower() or "spdx" in name.lower():
            data = _load_json(path)
            comps = _sbom_components(data)
            sbom_components += len(comps)
            deps = {n: v for n, v in comps[:300]}
        else:
            text = _read_text(path, limit=200000)
            if "version" in text.lower() or "dependencies" in text.lower() or "require" in text.lower():
                out.append(("dependency manifest detected", "file=%s parser=inventory-lite" % rel))
        for dep, version in list(deps.items())[:500]:
            total_deps += 1
            if not version or _UNPINNED_RE.match("%s%s" % (dep, version)):
                unpinned += 1
                out.append(("dependency appears unpinned", "file=%s package=%s version=%s" % (rel, dep, version or "missing")))
            for hint in _risk_hints(dep, version):
                out.append(("dependency review hint", "file=%s package=%s version=%s hint=%s" % (rel, dep, version or "?", hint)))
    summary = "root=%s manifests=%d dependencies=%d sbom_components=%d unpinned=%d" % (
        root, len(manifests), total_deps, sbom_components, unpinned,
    )
    out.insert(0, ("local dependency inventory completed", summary))
    return out[:150]
