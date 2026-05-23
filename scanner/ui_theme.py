"""Terminal UI theme constants."""

from __future__ import annotations

_UI3 = {
    "paper": "\033[38;5;230m",
    "dim": "\033[38;5;244m",
    "line": "\033[38;5;238m",
    "amber": "\033[38;5;214m",
    "moss": "\033[38;5;107m",
    "rose": "\033[38;5;203m",
    "wine": "\033[38;5;198m",
    "ice": "\033[38;5;117m",
    "steel": "\033[38;5;145m",
    "lime": "\033[38;5;149m",
    "bg": "\033[48;5;235m",
}

def build_severity_colors(color_enabled: bool, ansi: object) -> dict:
    return {
        "ZERO": "\033[1;5;97;45m" if color_enabled else "",
        "CRIT": ansi.BD + ansi.N7,
        "HIGH": ansi.N6 + ansi.BD,
        "MED": ansi.N5,
        "LOW": ansi.N3,
        "INFO": ansi.D + ansi.W,
    }

def build_impact_colors(ansi: object) -> dict:
    return {
        "RCE": ansi.N7 + ansi.BD,
        "LPE": ansi.N6,
        "ATO": ansi.N6 + ansi.BD,
        "Exfil": ansi.N5,
        "SSRF": ansi.N4 + ansi.BD,
        "DoS": ansi.N3,
        "Info Leak": ansi.N2,
        "Supply Chain": ansi.N7 + ansi.BD,
    }

__all__ = [
    "_UI3",
    "build_severity_colors",
    "build_impact_colors",
]
