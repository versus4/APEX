"""Filesystem path helpers for Apex."""

from __future__ import annotations

import os
from typing import Optional, Set


def resolve_output_path(path: Optional[str], output_dir: str, subdir: str = "reports") -> Optional[str]:
    if not path:
        return path
    raw = os.path.expandvars(os.path.expanduser(str(path)))
    if os.path.isabs(raw) or os.path.dirname(raw):
        parent = os.path.dirname(raw)
        if parent:
            os.makedirs(parent, exist_ok=True)
        return raw
    target_dir = os.path.join(output_dir, subdir) if subdir else output_dir
    os.makedirs(target_dir, exist_ok=True)
    return os.path.join(target_dir, raw)


def repo_file(anchor_file: str, *parts: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(anchor_file)), *parts)


def default_template_path(anchor_file: str) -> str:
    path = repo_file(anchor_file, "templates")
    return path if os.path.isdir(path) else ""


def default_fuzz_wordlist_path(anchor_file: str) -> str:
    path = repo_file(anchor_file, "wordlists", "common.txt")
    return path if os.path.exists(path) else ""


def split_csv(value: Optional[str]) -> Set[str]:
    if not value:
        return set()
    return {part.strip().lower() for part in str(value).split(",") if part.strip()}


__all__ = [
    "default_fuzz_wordlist_path",
    "default_template_path",
    "repo_file",
    "resolve_output_path",
    "split_csv",
]
