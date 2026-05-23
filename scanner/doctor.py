import datetime
import importlib.util
import json
import os
import platform
import sys
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


def _write_check(path: str) -> Tuple[bool, str]:
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".scanner_write_test")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(probe)
        return True, "writable"
    except Exception as exc:
        return False, str(exc)


def _optional_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def run_doctor(
    *,
    output_dir: str,
    proxy_files: Iterable[Tuple[str, str, str]],
    normalize_proxy_url: Callable[[str, str], Optional[str]],
    proxy_kind: Callable[[Optional[str]], str],
    scan_registry: Iterable[Tuple[str, str, Callable]],
    scan_severity: Dict[str, Any],
    load_json_file: Callable[[str, Any], Any],
    config_path: Optional[str],
    doctor_json_file: str,
    has_urllib3: bool,
    has_socks: bool,
) -> Tuple[int, List[Tuple[str, str]]]:
    rows: List[Tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        rows.append((name, ok, detail))

    add("python", sys.version_info >= (3, 9), platform.python_version())
    add("platform", True, platform.platform())
    add("working directory", os.path.isdir(os.getcwd()), os.getcwd())
    add("urllib3", has_urllib3, "available" if has_urllib3 else "missing")
    add("pysocks", has_socks, "available" if has_socks else "missing; SOCKS proxies will fail")
    add("playwright", _optional_module("playwright"), "available" if _optional_module("playwright") else "optional missing")
    add("selenium", _optional_module("selenium"), "available" if _optional_module("selenium") else "optional missing")

    for subdir in ("reports", "pocs", "logs", "evidence"):
        path = os.path.join(output_dir, subdir)
        ok, detail = _write_check(path)
        add("output/" + subdir, ok, path + " (" + detail + ")")

    proxy_counts: Dict[str, int] = {"HTTP": 0, "SOCKS4": 0, "SOCKS5": 0, "other": 0}
    seen_proxy_files: List[str] = []
    for path, label, scheme in proxy_files:
        if not os.path.exists(path):
            continue
        seen_proxy_files.append(path)
        count = 0
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    proxy = normalize_proxy_url(line, scheme)
                    if not proxy:
                        continue
                    count += 1
                    kind = proxy_kind(proxy)
                    proxy_counts[kind if kind in proxy_counts else "other"] += 1
        except Exception:
            pass
        add("proxy file " + os.path.basename(path), True, "%d valid entr%s (%s)" % (count, "y" if count == 1 else "ies", path))
    if not seen_proxy_files:
        add("proxy files", True, "none configured; direct mode is fine")

    registry_list = list(scan_registry)
    add("scan registry", bool(registry_list), "%d registered modules" % len(registry_list))
    try:
        missing_sev = [label for _, label, _ in registry_list if label.strip().lower() not in scan_severity]
        add("severity metadata", not missing_sev, "%d missing severity entr%s" % (len(missing_sev), "y" if len(missing_sev) == 1 else "ies"))
    except Exception as exc:
        add("severity metadata", False, str(exc))

    if config_path:
        ok = isinstance(load_json_file(config_path, None), (dict, list))
        add("config file", ok, config_path)

    output: List[Tuple[str, str]] = [("info_bold", "  [doctor] Scanner environment check")]
    for name, ok, detail in rows:
        tag = "OK" if ok else "WARN"
        kind = "ok_bold" if ok else "warn_bold"
        output.append((kind, "  [%s] " % tag + name.ljust(22) + detail))
    output.append(("info", "  [doctor] proxies by type: HTTP=%d SOCKS4=%d SOCKS5=%d other=%d" % (
        proxy_counts["HTTP"], proxy_counts["SOCKS4"], proxy_counts["SOCKS5"], proxy_counts["other"]
    )))

    if doctor_json_file:
        checks = [{"name": n, "ok": ok, "detail": d} for n, ok, d in rows]
        payload = {
            "schema_version": "1.0",
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "rows": checks,
            "checks": checks,
            "proxy_counts": proxy_counts,
        }
        try:
            parent = os.path.dirname(doctor_json_file)
            if parent:
                os.makedirs(parent, exist_ok=True)
            tmp = doctor_json_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
            os.replace(tmp, doctor_json_file)
            output.append(("info", "  [doctor] JSON saved to " + doctor_json_file))
        except Exception as exc:
            try:
                if os.path.exists(doctor_json_file + ".tmp"):
                    os.remove(doctor_json_file + ".tmp")
            except Exception:
                pass
            output.append(("warn", "  [doctor] JSON write failed: " + str(exc)))

    hard_fail = [name for name, ok, _ in rows if not ok and name in ("python", "working directory", "scan registry")]
    return (1 if hard_fail else 0), output
