"""Hidden-parameter Bayesian helper wiring."""

from __future__ import annotations

from typing import Any, Callable, Dict, List


def build_hpb_probe_surfaces(surface_cls: Callable[..., Any], builders: Dict[str, Callable]) -> List[Any]:
    return [
        surface_cls("GET", builders["get"], 1.0),
        surface_cls("POST_FORM", builders["post_form"], 0.9),
        surface_cls("POST_JSON", builders["post_json"], 0.9),
        surface_cls("HEADER", builders["header"], 0.7),
        surface_cls("PATH", builders["path"], 0.6),
        surface_cls("COOKIE", builders["cookie"], 0.5),
    ]


__all__ = ["build_hpb_probe_surfaces"]
