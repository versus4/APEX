import unittest

from scanner.budgets import RequestBudgetManager
from scanner.config import build_scan_config, scan_config_snapshot
from scanner.context import ScanContext
from scanner.http_client import HttpClient
from scanner.http_client import normalize_proxy_url
from scanner.models import Finding
from scanner.reporting import coerce_finding_item
from scanner.reporting import summarize_findings
from scanner.scans import category_for_option
from scanner.scans.cors import scan_null_origin
from scanner.scans.files import scan_openapi_json, scan_sitemap_sensitive
from scanner.scans.headers import scan_security_headers
from scanner.scans.network import scan_http_methods
from scanner.url_utils import inject_param, validate_http_url


class ScannerModuleTests(unittest.TestCase):
    def test_validate_http_url_adds_https_and_path(self):
        self.assertEqual(validate_http_url("example.com"), (True, "https://example.com/"))

    def test_inject_param_replaces_existing_value(self):
        self.assertEqual(inject_param("https://a.test/?q=1", "q", "2"), "https://a.test/?q=2")

    def test_proxy_normalization(self):
        self.assertEqual(normalize_proxy_url("127.0.0.1:8080"), "http://127.0.0.1:8080")
        self.assertEqual(normalize_proxy_url("127.0.0.1:9050", default_scheme="socks5"), "socks5://127.0.0.1:9050")
        self.assertEqual(normalize_proxy_url("socks4://127.0.0.1:9050"), "socks4://127.0.0.1:9050")
        self.assertEqual(normalize_proxy_url("socks5://127.0.0.1:9050"), "socks5://127.0.0.1:9050")

    def test_config_snapshot_redacts_headers(self):
        cfg = build_scan_config(
            delay=0,
            timeout=5,
            max_body=1024,
            user_agent="test",
            headers={"Authorization": "secret"},
            tls_verify=True,
            js_render=False,
        )
        snap = scan_config_snapshot(cfg, lambda h: {"Authorization": "<redacted>"})
        self.assertEqual(snap["headers"]["Authorization"], "<redacted>")

    def test_reporting_coerces_tuple_and_finding(self):
        order = {"INFO": 0, "LOW": 1, "HIGH": 3}
        item = coerce_finding_item("xss", ("detail", "payload", "HIGH"), "LOW", order, "injection")
        self.assertEqual(item.severity, "HIGH")
        self.assertEqual(item.category, "injection")
        existing = coerce_finding_item("", Finding(module="", detail="d", severity="BOGUS"), "LOW", order, "headers")
        self.assertEqual(existing.severity, "LOW")
        self.assertEqual(existing.category, "headers")

    def test_budget_exhausts_after_limit(self):
        manager = RequestBudgetManager()
        manager.start("xss", max_requests=1)
        self.assertTrue(manager.allow_request("xss"))
        self.assertFalse(manager.allow_request("xss"))
        manager.end("xss")
        self.assertTrue(manager.allow_request("xss"))

    def test_scan_category_metadata(self):
        self.assertEqual(category_for_option("xss"), "injection")
        self.assertEqual(category_for_option("unknown-option"), "misc")

    def test_http_client_adapter_and_moved_header_scan(self):
        def fake_request(url, **kwargs):
            return 200, {"server": "nginx/1.2", "x-powered-by": "php"}, b"", url

        client = HttpClient(fake_request)
        ctx = ScanContext(
            config=build_scan_config(
                delay=0,
                timeout=5,
                max_body=1024,
                user_agent="test",
                headers={},
                tls_verify=True,
                js_render=False,
            ),
            client=client,
            budgets=RequestBudgetManager(),
            join_url=lambda base, path: base.rstrip("/") + "/" + path.lstrip("/"),
            category_for_option=category_for_option,
        )
        findings = scan_security_headers(ctx, "https://example.test", ["x-frame-options"])
        self.assertTrue(any("missing security headers" in item[0] for item in findings))
        self.assertTrue(any("Server header version disclosure" in item[0] for item in findings))

    def test_moved_file_network_and_cors_scans(self):
        def fake_request(url, **kwargs):
            if url.endswith("/sitemap.xml"):
                return 200, {}, b"<url><loc>/admin</loc></url>", url
            if url.endswith("/openapi.json"):
                return 200, {}, b'{"openapi":"3.0.0"}', url
            if kwargs.get("method") == "OPTIONS":
                return 204, {"allow": "GET, PUT, DELETE"}, b"", url
            if (kwargs.get("headers") or {}).get("Origin") == "null":
                return 200, {"access-control-allow-origin": "null"}, b"", url
            return 404, {}, b"", url

        ctx = ScanContext(
            config=build_scan_config(
                delay=0,
                timeout=5,
                max_body=1024,
                user_agent="test",
                headers={},
                tls_verify=True,
                js_render=False,
            ),
            client=HttpClient(fake_request),
            budgets=RequestBudgetManager(),
            join_url=lambda base, path: base.rstrip("/") + "/" + path.lstrip("/"),
            category_for_option=category_for_option,
        )
        self.assertTrue(scan_sitemap_sensitive(ctx, "https://example.test"))
        self.assertTrue(scan_openapi_json(ctx, "https://example.test", ["/openapi.json"]))
        self.assertTrue(scan_http_methods(ctx, "https://example.test"))
        self.assertTrue(scan_null_origin(ctx, "https://example.test"))

    def test_summarize_findings(self):
        summary = summarize_findings(
            [("m", "[CONFIRMED] detail", "", "HIGH"), ("m", "info", "", "INFO")],
            ["HIGH", "INFO"],
        )
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["confirmed"], 1)


if __name__ == "__main__":
    unittest.main()
