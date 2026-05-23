"""Example scanner plugin.

This file is intentionally passive. Copy it, rename the option/label/function,
and adjust the checks for your own authorized targets.
"""

from __future__ import annotations

import urllib.parse
import urllib.request


def scan_example_plugin(base: str):
    """Return a small informational finding when the target is reachable."""
    url = urllib.parse.urljoin(base.rstrip("/") + "/", "/")
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "scanner-plugin-example/1.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            server = resp.headers.get("server", "")
            return [("example plugin reached target", "status=%s server=%s" % (resp.status, server))]
    except Exception:
        return []


SCANS = [
    {
        "option": "example_plugin",
        "label": "example plugin check",
        "func": scan_example_plugin,
    }
]
