"""Registry-aware dead-code audit helpers for Apex."""

from __future__ import annotations

import ast
from typing import Any, Dict, Iterable, List, Set


def audit_dead_code(source_path: str, registry_specs: Iterable[Any]) -> Dict[str, Any]:
    with open(source_path, "r", encoding="utf-8", errors="ignore") as fh:
        source = fh.read()
    tree = ast.parse(source, filename=source_path)
    registry_names: Set[str] = set()
    for item in registry_specs:
        try:
            registry_names.add(str(item[2]))
        except Exception:
            pass
    top_defs: Dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            top_defs[node.name] = node
    refs: Dict[str, int] = {name: 0 for name in top_defs}
    string_refs: Dict[str, int] = {name: 0 for name in top_defs}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in refs:
            refs[node.id] += 1
        elif isinstance(node, ast.Attribute) and node.attr in refs:
            refs[node.attr] += 1
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for name in top_defs:
                if name in node.value:
                    string_refs[name] += 1
    candidates: List[Dict[str, Any]] = []
    dynamic_kept: List[Dict[str, Any]] = []
    for name, node in sorted(top_defs.items(), key=lambda kv: getattr(kv[1], "lineno", 0)):
        lineno = int(getattr(node, "lineno", 0) or 0)
        end = int(getattr(node, "end_lineno", lineno) or lineno)
        text_refs = source.count(name)
        row = {
            "name": name,
            "line": lineno,
            "lines": max(1, end - lineno + 1),
            "refs": refs.get(name, 0),
            "text_refs": text_refs,
            "string_refs": string_refs.get(name, 0),
        }
        if name in registry_names or name == "main":
            continue
        if refs.get(name, 0) <= 1 and string_refs.get(name, 0) > 0:
            dynamic_kept.append(row)
        elif refs.get(name, 0) <= 1 and text_refs <= 1 and string_refs.get(name, 0) == 0:
            candidates.append(row)
    return {
        "source": source_path,
        "top_level_defs": len(top_defs),
        "registry_functions": len(registry_names),
        "candidates": candidates,
        "dynamic_kept": dynamic_kept,
    }


__all__ = ["audit_dead_code"]
