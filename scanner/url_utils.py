"""URL, parameter, and evidence formatting helpers."""

from __future__ import annotations

import functools
import re
import urllib.parse
from typing import Any, Dict, List, Tuple


_SCHEME_PREFIX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", re.ASCII)


def redact_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in ("authorization", "cookie", "x-api-key", "x-auth-token"):
            out[key] = "<redacted:len=%d>" % len(value)
        else:
            out[key] = value
    return out


def body_excerpt(body: bytes, idx: int, radius: int = 80) -> str:
    start = max(0, idx - radius)
    end = min(len(body), idx + radius)
    return body[start:end].decode("utf-8", "replace")


@functools.lru_cache(maxsize=512)
def host_of(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except Exception:
        return ""


def join_url(base: str, path: str) -> str:
    if path.startswith("http"):
        return path
    return urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def inject_param(url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    found = False
    new_query = []
    for key, old_value in query:
        if key == param:
            new_query.append((key, value))
            found = True
        else:
            new_query.append((key, old_value))
    if not found:
        new_query.append((param, value))
    return urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        urllib.parse.urlencode(new_query, doseq=True),
        parsed.fragment,
    ))


def extract_url_params(url: str) -> List[str]:
    parsed = urllib.parse.urlparse(url)
    return [key for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]


def normalize_url(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if not _SCHEME_PREFIX.match(value):
        value = "https://" + value
    return value


def validate_http_url(raw: str) -> Tuple[bool, str]:
    value = normalize_url(raw)
    if not value:
        return False, "empty"
    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError:
        return False, "parse error"
    if parsed.scheme not in ("http", "https"):
        return False, "only http and https are allowed"
    host = parsed.hostname
    if not host:
        return False, "hostname required"
    hostname = host.strip(".").lower()
    if not hostname or ".." in hostname:
        return False, "invalid hostname"
    path = parsed.path if parsed.path else "/"
    return True, urllib.parse.urlunparse((
        parsed.scheme.lower(),
        parsed.netloc,
        path,
        parsed.params,
        parsed.query,
        parsed.fragment,
    ))


def build_param_url(parsed: Any, base_qs: list, param: str, value: str) -> str:
    if any(key == param for key, _ in base_qs):
        pairs = [(key, value if key == param else old_value) for key, old_value in base_qs]
    else:
        pairs = list(base_qs) + [(param, value)]
    return urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        urllib.parse.urlencode(pairs),
        parsed.fragment,
    ))


def build_multi_param_url(parsed: Any, base_qs: list, overrides: dict) -> str:
    pairs = [(key, overrides.get(key, old_value)) for key, old_value in base_qs]
    existing = {key for key, _ in base_qs}
    pairs += [(key, value) for key, value in overrides.items() if key not in existing]
    return urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        urllib.parse.urlencode(pairs),
        parsed.fragment,
    ))


__all__ = [
    "body_excerpt",
    "build_multi_param_url",
    "build_param_url",
    "extract_url_params",
    "host_of",
    "inject_param",
    "join_url",
    "normalize_url",
    "redact_sensitive_headers",
    "validate_http_url",
]
