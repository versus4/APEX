"""OOB listener address helpers."""

from __future__ import annotations

import ipaddress
import urllib.parse
from typing import Dict


def host_is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return host.endswith(".local")
    return ip.is_private or ip.is_loopback or ip.is_link_local


def target_is_local(target_url: str) -> bool:
    host = urllib.parse.urlparse(target_url).hostname or ""
    if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".local"):
        return True
    return host_is_private(host)


def describe_oob(listener_host: str, port: int, target_url: str, explicit_host: bool) -> Dict[str, object]:
    private_listener = host_is_private(listener_host)
    internet_target = bool(target_url) and not target_is_local(target_url)
    return {
        "host": listener_host,
        "port": port,
        "explicit_host": explicit_host,
        "private_listener": private_listener,
        "internet_target": internet_target,
        "internet_reachable": explicit_host or not private_listener or not internet_target,
    }


__all__ = ["describe_oob", "host_is_private", "target_is_local"]
