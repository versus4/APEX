"""Scan category metadata.

Scan implementations still live in Scanner.py during the compatibility split.
The registry can use this metadata to reason about categories before the scan
functions are physically moved into submodules.
"""

from .categories import SCAN_CATEGORIES, category_for_option

__all__ = ["SCAN_CATEGORIES", "category_for_option"]
