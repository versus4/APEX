"""HTTP runtime helpers shared by the scanner.

The transport itself still lives in Scanner.py because it is tightly coupled to
the existing caches and telemetry. This module holds small, testable pieces that
do not need access to scanner globals.
"""

from __future__ import annotations

import os
import urllib.parse
from typing import Callable, Dict, Optional, Tuple


ResponseTuple = Tuple[int, Dict[str, str], bytes, str]


class HttpClient:
    """Small adapter around the scanner transport.

    Scanner.py still owns the mature transport implementation. This class gives
    moved scan modules a stable client-shaped API while the transport is
    extracted gradually.
    """

    def __init__(self, request_func: Callable[..., ResponseTuple]) -> None:
        self._request = request_func

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        data: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        content_type: Optional[str] = None,
        use_cache: bool = False,
    ) -> ResponseTuple:
        return self._request(
            url,
            method=method,
            data=data,
            headers=headers,
            timeout=timeout,
            content_type=content_type,
            use_cache=use_cache,
        )


def normalize_proxy_url(raw: str, default_scheme: str = "http") -> Optional[str]:
    proxy = (raw or "").strip()
    if not proxy or proxy.startswith("#"):
        return None
    proxy = proxy.split("#", 1)[0].strip()
    if not proxy:
        return None
    if "://" not in proxy:
        proxy = default_scheme + "://" + proxy
    parsed = urllib.parse.urlparse(proxy)
    if parsed.scheme.lower() not in ("http", "https", "socks4", "socks5", "socks4h", "socks5h"):
        return None
    if not parsed.hostname or not parsed.port:
        return None
    return proxy


def default_proxy_file(root_file: str) -> str:
    try:
        return os.path.join(os.path.dirname(os.path.abspath(root_file)), "proxies.txt")
    except Exception:
        return "proxies.txt"


__all__ = ["HttpClient", "ResponseTuple", "default_proxy_file", "normalize_proxy_url"]
