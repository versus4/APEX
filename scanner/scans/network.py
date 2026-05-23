"""Network, timing, and protocol scans."""

from __future__ import annotations

from scanner.context import ScanContext
from scanner.models import ScanFindings

OPTIONS = {
    "smuggling", "smuggling_oracle", "h2_desync", "h2c", "http2reset",
    "trailers", "race", "race_window", "racecondition", "ratelimit",
}


def scan_http_methods(ctx: ScanContext, base: str) -> ScanFindings:
    out: ScanFindings = []
    for method in ["PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT"]:
        code, hdrs, _, _ = ctx.client.request(base, method=method)
        if method == "TRACE" and code == 200:
            out.append(("TRACE method enabled (XST risk)", method))
        elif method == "PUT" and code in (200, 201, 204):
            out.append(("PUT method may be allowed", method))
        elif method == "DELETE" and code in (200, 204):
            out.append(("DELETE method may be allowed", method))
        elif method == "OPTIONS":
            allow = hdrs.get("allow", "").upper()
            if "PUT" in allow or "DELETE" in allow:
                out.append(("OPTIONS reveals dangerous methods", allow))
    return out


__all__ = ["OPTIONS", "scan_http_methods"]
