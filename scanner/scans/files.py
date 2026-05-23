"""File and metadata exposure scans."""

from __future__ import annotations

from scanner.context import ScanContext
from scanner.models import ScanFindings

OPTIONS = {
    "backups", "backupfiles", "gitexposure", "envexposure", "srcmap",
    "robots", "sitemapdeep", "openapi", "manifests", "vcsm",
}


def scan_robots_disclosure(ctx: ScanContext, base: str) -> ScanFindings:
    url = ctx.join_url(base, "/robots.txt")
    code, _, body, _ = ctx.client.request(url)
    if code != 200:
        return []
    text = body.decode("utf-8", "ignore").lower()
    needles = [
        "/admin", "/backup", ".env", "/internal", "/private",
        "/.git", "/config", "/wp-admin", "/api/internal", "/secret",
    ]
    hits = sorted({needle for needle in needles if needle in text})
    if hits:
        return [("robots.txt references sensitive locations", ", ".join(hits))]
    return []


def scan_security_txt(ctx: ScanContext, base: str) -> ScanFindings:
    for path in ("/.well-known/security.txt", "/security.txt"):
        url = ctx.join_url(base, path)
        code, _, body, _ = ctx.client.request(url)
        if code == 200 and len(body) > 10:
            text = body.decode("utf-8", "ignore").lower()
            if "contact:" in text:
                return []
            return [("security.txt present but missing Contact field", path)]
    return [("no security.txt file found (no vulnerability disclosure policy)", "")]


def scan_sitemap_sensitive(ctx: ScanContext, base: str) -> ScanFindings:
    for path in ("/sitemap.xml", "/sitemap_index.xml", "/post-sitemap.xml"):
        url = ctx.join_url(base, path)
        code, _, body, _ = ctx.client.request(url)
        if code != 200:
            continue
        text = body.decode("utf-8", "ignore").lower()
        keys = ["admin", "internal", "staging", "backup", "private", "wp-admin", ".env", "debug"]
        found = sorted({key for key in keys if key in text})
        if found:
            return [("sitemap references sensitive URL patterns", ", ".join(found))]
    return []


def scan_openapi_json(ctx: ScanContext, base: str, paths) -> ScanFindings:
    out: ScanFindings = []
    for path in paths:
        url = ctx.join_url(base, path)
        code, _, body, _ = ctx.client.request(url)
        if code != 200:
            continue
        text = body[:25000].decode("utf-8", "ignore").lower()
        if '"openapi"' in text or '"swagger"' in text or "swagger 2.0" in text or "'openapi'" in text:
            out.append(("machine-readable API spec exposed", path))
    return out


__all__ = [
    "OPTIONS",
    "scan_openapi_json",
    "scan_robots_disclosure",
    "scan_security_txt",
    "scan_sitemap_sensitive",
]
