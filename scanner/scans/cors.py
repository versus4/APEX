"""CORS scans."""

from __future__ import annotations

import urllib.parse

from scanner.context import ScanContext
from scanner.models import ScanFindings

OPTIONS = {"corsreflect", "corsfull", "corspna", "corsnull", "corswild"}


def scan_arbitrary_origin(ctx: ScanContext, base: str) -> ScanFindings:
    out: ScanFindings = []
    target_host = urllib.parse.urlparse(base).hostname or "target"
    test_origins = [
        "https://vulnscan-cors-arbitrary.invalid",
        "null",
        "https://evil-" + target_host + ".com",
    ]
    hdrs = {}
    for evil in test_origins:
        code, hdrs, _, _ = ctx.client.request(base, headers={"Origin": evil})
        if code == 0:
            continue
        acao = (hdrs.get("access-control-allow-origin") or "").strip()
        acac = (hdrs.get("access-control-allow-credentials") or "").lower() == "true"
        vary = (hdrs.get("vary") or "").lower()
        if acao in (evil, "null") and evil == "null":
            if acac:
                out.append(("CORS reflects null origin with credentials (iframe sandbox bypass)", "null"))
            else:
                out.append(("CORS reflects null origin", "null"))
        elif acao == evil:
            if acac:
                out.append(("CORS reflects arbitrary origin with credentials (account takeover risk)", evil))
            else:
                out.append(("CORS reflects arbitrary origin", evil))
        if acao and acao != "*" and "origin" not in vary:
            out.append(("CORS missing Vary: Origin header - response may be cached without origin discrimination", evil))
            break
    if (hdrs.get("access-control-allow-origin") or "").strip() == "*":
        if (hdrs.get("access-control-allow-credentials") or "").lower() == "true":
            out.append(("CORS wildcard with credentials flag", "*"))
    return out


def scan_null_origin(ctx: ScanContext, url: str) -> ScanFindings:
    out: ScanFindings = []
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    origins = [
        "null",
        "http://localhost",
        "http://127.0.0.1",
        "https://evil.com",
        "https://evil.%s" % host if host.count(".") >= 1 else "https://evilexample.com",
        "https://%s.evil.com" % host.split(".")[0],
        "file://",
    ]
    for origin in origins:
        _, hdrs, _, _ = ctx.client.request(url, headers={"Origin": origin})
        acao = hdrs.get("access-control-allow-origin", "") or hdrs.get("Access-Control-Allow-Origin", "")
        acac = hdrs.get("access-control-allow-credentials", "") or hdrs.get("Access-Control-Allow-Credentials", "")
        if not acao:
            continue
        creds = "true" in acac.lower()
        if acao == "null":
            out.append((
                "[CONFIRMED] CORS null origin accepted at %s" % url,
                "Origin: null -> ACAO: null, ACAC: %s - null origin can be sent by sandboxed iframes and local file pages"
                % acac,
                "CRIT" if creds else "HIGH",
            ))
            return out
        if (acao == origin or acao == "*") and creds:
            out.append((
                "[CONFIRMED] CORS credentials leak - %s accepted at %s" % (origin, url),
                "Origin: %s -> ACAO: %s, ACAC: true - credentialed cross-origin responses may be readable"
                % (origin, acao),
                "CRIT",
            ))
            return out
        if acao == origin and not creds and origin not in ("http://localhost", "http://127.0.0.1"):
            out.append((
                "[PROBABLE] CORS origin reflection at %s" % url,
                "Origin: %s -> ACAO: %s (ACAC: %s) - arbitrary origin reflection"
                % (origin, acao, acac or "absent"),
                "MED",
            ))
    return out


__all__ = ["OPTIONS", "scan_arbitrary_origin", "scan_null_origin"]
