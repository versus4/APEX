"""Runtime configuration helpers for Scanner.py.

The main scanner still owns the mutable globals for compatibility. This module
keeps the conversion to a structured config object in one place so future scan
modules can depend on ScanConfig instead of reaching into Scanner.py.
"""

from __future__ import annotations

from typing import Any, Callable, Dict

from .models import ScanConfig


def build_scan_config(
    *,
    delay: float,
    timeout: float,
    max_body: int,
    user_agent: str,
    headers: Dict[str, str],
    tls_verify: bool,
    js_render: bool,
    module_timeout: float = 90.0,
    module_request_budget: int = 0,
) -> ScanConfig:
    return ScanConfig(
        delay=delay,
        timeout=timeout,
        module_timeout=module_timeout,
        module_request_budget=module_request_budget,
        max_body=max_body,
        user_agent=user_agent,
        headers=dict(headers),
        tls_verify=tls_verify,
        js_render=js_render,
    )


def scan_config_snapshot(
    cfg: ScanConfig,
    redact_headers: Callable[[Dict[str, str]], Dict[str, str]],
) -> Dict[str, Any]:
    return {
        "delay": cfg.delay,
        "timeout": cfg.timeout,
        "module_timeout": cfg.module_timeout,
        "module_request_budget": cfg.module_request_budget,
        "max_body": cfg.max_body,
        "user_agent": cfg.user_agent,
        "headers": redact_headers(cfg.headers),
        "tls_verify": cfg.tls_verify,
        "js_render": cfg.js_render,
        "browser_ignores_https_errors": not cfg.tls_verify,
    }


__all__ = ["build_scan_config", "scan_config_snapshot"]
