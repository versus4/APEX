"""Registry grouping for scan modules."""

from __future__ import annotations

from typing import Dict, Iterable, Set

from . import ai, auth, cors, files, headers, injection, network

SCAN_CATEGORIES: Dict[str, Set[str]] = {
    "headers": headers.OPTIONS,
    "injection": injection.OPTIONS,
    "auth": auth.OPTIONS,
    "cors": cors.OPTIONS,
    "files": files.OPTIONS,
    "network": network.OPTIONS,
    "ai": ai.OPTIONS,
    "fingerprint": {
        "waf", "tech", "tls", "cvefp", "subenum", "wordpress", "laraveldebug",
        "stackcoherence", "deployage", "depcve", "ctlogs", "dnscaa", "emaildns",
        "entropy", "timing", "srvtiming", "timecov", "inventory", "inventory_cves",
        "tlsdeep", "wafdeep", "wp_plugins", "wp_users", "wp_xmlrpc",
        "laravel_env_deep", "django_debug", "actuator_deep",
    },
    "api": {
        "graphql", "gqldep", "gqlsuggest", "gqlalias", "gqlintrob", "gqlbatch",
        "gqlsub", "gqlmutate", "graphql_oracle", "jsonrpc", "openapifuzz",
        "apiver", "apiverscliff", "apiversionbypass", "odatasoap", "grpcreflect",
        "hasura", "openapi_routes", "gqlschema", "oauth_redirects", "saml_metadata",
    },
    "client": {
        "csp", "domxss", "jssecrets", "mixed", "comments", "sri", "cspscheme",
        "appcache", "srisameorigin", "webauthn", "nextjsdata", "nuxtpayload",
        "jsendpoints", "clientstorage", "trustfiles", "policydrift", "jsonp",
        "swaggerxss", "wasm", "importmap", "domheadless", "cspheadless",
        "clickheadless", "domsecrets", "swsurface", "sse", "domrecord",
        "sourcemap_recon", "sourcemap_secrets", "csp_suggestions",
    },
    "cache": {
        "cachepoison", "cachekey", "cachepoisonxfh", "cachecontrol", "cache_poison",
        "cachetimeenum", "cachedeception", "behavcache",
    },
    "ssrf": {
        "ssrf", "cloudmeta", "gopher", "gcpssrf", "azureimds", "ssrftiming",
        "urljuggle",
        "oobimap", "ooblog4jhdr",
    },
    "cloud": {
        "s3", "dkube", "redisunauth", "esunauth", "mongounauth", "k8setcd",
        "firebasedb", "firebase_deep", "supabase", "k8smanifest", "memcached",
        "prometheus", "hashicorp", "cloud_buckets", "cloud_blob_urls",
        "k8s_dashboard", "docker_registry", "observability_stack",
    },
    "exposure": {
        "listing", "secrets", "sectxt", "upload", "takeover", "srcmap",
        "deepgit", "phpinfo", "webdav", "iisshort", "defcreds", "putwrite",
        "dnszone", "ftpanon", "smtprelay", "hosthdr", "ipbypass", "pathtrav",
        "dupcookie", "pwresetpoison", "logpoison", "emailinject", "tokenfresh",
        "cookiescope", "hostheader", "xffbypass", "nuclei_lite", "fuzzer",
        "sqlmap_export", "jenkins_exposure", "grafana_exposure", "admin_finder",
        "backup_smart", "sectxt_parser", "dep_license_risk", "robots_score",
        "source_scan", "sbom_scan",
    },
    "logic": {
        "bizlogic", "massassign", "typeconf", "typejuggle", "hpp", "padoracle",
        "mine", "parammatrix", "ghostparams", "formmutate", "paymin",
        "behavauth", "behavioral_matrix", "appmodel", "causal_proof",
        "consistency", "respvariance", "pdg", "mvfusion", "timecov", "selfconsist",
        "schemafuzz", "errorling", "deadcode", "sessiondrift", "tokenflow",
        "diffbaseline", "shadowroute", "semequiv", "killchain", "atchain",
        "intoverflow", "protopollution", "frontier", "formflow", "authprofile",
        "adaptive_recs", "self_debug", "target_playbooks",
    },
    "protocol": {
        "verbs", "httpdowngrade", "ws", "wshijack", "http3down", "tecl",
        "crlfsmuggle", "trailers", "wsfuzz", "wsheadless", "http2reset",
        "methover", "methodoverride", "verbtunnel", "redirect", "mergeslas",
        "raceamp", "servicedisc", "ws_auth_cors",
    },
    "config": {
        "errors", "actuator", "offbyslash", "log4j", "depconf", "jwks",
        "samlsig", "samlweakalg", "oauthstate", "oidc", "csrf", "csrfpoc",
        "clickjack", "dangle", "dnsrebind", "redos", "ctconf", "contentneg",
        "cors_preflight_cache",
        "samlweakalg", "ssocas", "captcha", "implicitflow",
    },
    "zeroday": {
        "wpauto27956", "grafanapath", "rsssl10924", "jenkins43044", "wug6670",
        "roundcube37383", "edimax1316", "laravel52301", "sp38094", "cleo55956",
    },
    "oracle": {
        "ssti_oracle", "xxe_oracle", "pp_oracle", "session_oracle", "deception",
        "breachoracle",
    },
    "advanced": {
        "proto", "xxe", "deser", "polyglot", "secondorder", "phpwrap", "esi",
        "xslt", "taint", "sstifp", "cspgadget", "unibp", "nosqlblind", "xssi",
        "rfd", "nullbyte", "pathparam", "jslibcve", "cspt", "xxeupload",
        "sessfixation", "boolsqli", "polyupload", "jwtaudconf", "sspp",
        "wafbypass", "deserchains",
    },
    "plugins": {
        "example_plugin",
    },
}


def category_for_option(option: str, known_categories: Iterable[str] = SCAN_CATEGORIES.keys()) -> str:
    for category in known_categories:
        if option in SCAN_CATEGORIES.get(category, set()):
            return category
    return "misc"


__all__ = ["SCAN_CATEGORIES", "category_for_option"]
