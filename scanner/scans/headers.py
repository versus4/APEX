"""Header and browser-policy scans."""

from __future__ import annotations

import re
import urllib.parse
from typing import Iterable

from scanner.context import ScanContext
from scanner.models import ScanFindings

OPTIONS = {
    "headers", "advheaders", "cookies", "referrerpolicy", "permissionspolicy",
    "reportinghdrs", "cachecontrol", "coopeep", "docpol", "clearsitedata",
    "hstspreload", "fetchmeta",
}


DEPRECATED_HEADERS = [
    "x-webkit-csp", "x-content-security-policy", "public-key-pins",
    "public-key-pins-report-only", "expect-ct",
]


def scan_security_headers(
    ctx: ScanContext,
    base: str,
    security_headers: Iterable[str],
    deprecated_headers: Iterable[str] = DEPRECATED_HEADERS,
) -> ScanFindings:
    out: ScanFindings = []
    code, hdrs, _, _ = ctx.client.request(base, use_cache=True)
    if code == 0:
        return out
    missing = [name for name in security_headers if name not in hdrs]
    if missing:
        out.append(("missing security headers: " + ", ".join(missing), ""))
    if hdrs.get("x-powered-by"):
        out.append(("X-Powered-By information disclosure", hdrs["x-powered-by"]))
    if hdrs.get("server") and re.search(r"\d+\.\d+", hdrs["server"] or ""):
        out.append(("Server header version disclosure", hdrs["server"]))
    cors = hdrs.get("access-control-allow-origin", "")
    acac = hdrs.get("access-control-allow-credentials", "")
    if cors == "*" and (acac or "").lower() == "true":
        out.append(("CORS wildcard with credentials", "*"))
    xf = (hdrs.get("x-frame-options") or "").strip()
    csp = (hdrs.get("content-security-policy") or "").lower()
    if not xf and "frame-ancestors" not in csp:
        out.append(("clickjacking risk: no X-Frame-Options or frame-ancestors", ""))
    deprecated = [header for header in deprecated_headers if header in hdrs]
    if deprecated:
        out.append(("deprecated security headers present: " + ", ".join(deprecated), ""))
    hsts = hdrs.get("strict-transport-security", "")
    if hsts and "max-age=0" in hsts:
        out.append(("HSTS max-age=0 disables HSTS enforcement", hsts))
    acao = hdrs.get("access-control-allow-origin", "")
    if acao not in ("", "*") and acao.lower().startswith("null"):
        out.append(("CORS allows null origin (sandbox iframe bypass)", acao))
    return out


def scan_cookie_flags(ctx: ScanContext, url: str) -> ScanFindings:
    out: ScanFindings = []
    _, hdrs, _, _ = ctx.client.request(url)
    sc_raw = hdrs.get("set-cookie", "") or ""
    if not sc_raw:
        return out
    cookies = sc_raw.split("\n")
    is_https = urllib.parse.urlparse(url).scheme == "https"
    for sc in cookies:
        blob = sc.lower()
        if "httponly" not in blob:
            out.append(("session cookie missing HttpOnly flag", sc[:120]))
        if "secure" not in blob and is_https:
            out.append(("cookie missing Secure flag on HTTPS", sc[:120]))
        if "samesite" not in blob:
            out.append(("cookie missing SameSite attribute", sc[:120]))
    return out


__all__ = ["DEPRECATED_HEADERS", "OPTIONS", "scan_cookie_flags", "scan_security_headers"]
