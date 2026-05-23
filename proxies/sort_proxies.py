#!/usr/bin/env python3
"""Check a proxy list and rewrite it with live entries only."""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import socks  # type: ignore
    HAS_SOCKS = True
except Exception:
    socks = None
    HAS_SOCKS = False


Progress = Tuple[str, bool, float, str]
PROXY_FOLDER_FILES = {
    "http": ("http.txt", "http"),
    "socks4": ("socks4.txt", "socks4"),
    "socks5": ("socks5.txt", "socks5"),
}


def normalize_proxy(raw: str, default_scheme: str = "http") -> Optional[str]:
    item = (raw or "").strip().strip("\ufeff")
    if not item or item.startswith("#"):
        return None
    item = item.split("#", 1)[0].strip()
    if not item:
        return None
    if "://" not in item:
        item = default_scheme + "://" + item
    parsed = urllib.parse.urlparse(item)
    if parsed.scheme not in ("http", "https", "socks4", "socks5", "socks4h", "socks5h"):
        return None
    if not parsed.hostname or not parsed.port:
        return None
    return item


def load_proxies(path: str, default_scheme: str, dedupe: bool) -> List[str]:
    seen = set()
    out: List[str] = []
    with open(path, encoding="utf-8-sig", errors="ignore") as fh:
        for line in fh:
            proxy = normalize_proxy(line, default_scheme)
            if not proxy:
                continue
            key = proxy.lower()
            if dedupe and key in seen:
                continue
            seen.add(key)
            out.append(proxy)
    return out

def proxy_kind(proxy: str) -> str:
    scheme = urllib.parse.urlparse(proxy).scheme.lower()
    if scheme in ("socks4", "socks4h"):
        return "socks4"
    if scheme in ("socks5", "socks5h"):
        return "socks5"
    return "http"

def proxy_label(proxy: str) -> str:
    return proxy_kind(proxy).upper()

def proxy_folder_paths(folder: str) -> List[Tuple[str, str]]:
    paths = [
        (os.path.join(folder, filename), scheme)
        for _, (filename, scheme) in PROXY_FOLDER_FILES.items()
    ]
    known = {os.path.abspath(path).lower() for path, _ in paths}
    if os.path.isdir(folder):
        for name in sorted(os.listdir(folder)):
            path = os.path.join(folder, name)
            if not name.lower().endswith(".txt") or not os.path.isfile(path):
                continue
            if os.path.abspath(path).lower() in known:
                continue
            lname = name.lower()
            if "socks5" in lname:
                scheme = "socks5"
            elif "socks4" in lname:
                scheme = "socks4"
            else:
                scheme = "http"
            paths.append((path, scheme))
    return paths

def load_proxy_sources(path: str, default_scheme: str, dedupe: bool) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    sources: List[Tuple[str, str]] = []
    if not os.path.exists(path) and os.path.basename(os.path.normpath(path)).lower() == "proxies":
        os.makedirs(path, exist_ok=True)
    if os.path.isdir(path):
        for file_path, scheme in proxy_folder_paths(path):
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            if not os.path.exists(file_path):
                open(file_path, "a", encoding="utf-8").close()
            sources.append((file_path, scheme))
    else:
        sources.append((path, default_scheme))
    rows: List[Tuple[str, str]] = []
    seen = set()
    for file_path, scheme in sources:
        if not os.path.exists(file_path):
            continue
        for proxy in load_proxies(file_path, scheme, False):
            key = proxy.lower()
            if dedupe and key in seen:
                continue
            seen.add(key)
            rows.append((file_path, proxy))
    return sources, rows


def tcp_check(proxy: str, timeout: float) -> Tuple[bool, str]:
    parsed = urllib.parse.urlparse(proxy)
    host = parsed.hostname
    port = parsed.port
    if not host or not port:
        return False, "invalid"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "tcp-open"
    except OSError as exc:
        return False, type(exc).__name__

def socks_check(proxy: str, check_url: str, timeout: float) -> Tuple[bool, str]:
    if not HAS_SOCKS or socks is None:
        ok, reason = tcp_check(proxy, timeout)
        return ok, reason + " (SOCKS port only; PySocks missing)"
    parsed_proxy = urllib.parse.urlparse(proxy)
    parsed_target = urllib.parse.urlparse(check_url)
    proxy_host = parsed_proxy.hostname
    proxy_port = parsed_proxy.port
    target_host = parsed_target.hostname
    if not proxy_host or not proxy_port or not target_host:
        return False, "invalid"
    target_port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)
    proxy_type = socks.SOCKS5 if parsed_proxy.scheme.startswith("socks5") else socks.SOCKS4
    sock = socks.socksocket()
    sock.set_proxy(
        proxy_type,
        proxy_host,
        proxy_port,
        username=urllib.parse.unquote(parsed_proxy.username or "") or None,
        password=urllib.parse.unquote(parsed_proxy.password or "") or None,
    )
    sock.settimeout(timeout)
    try:
        sock.connect((target_host, target_port))
        if parsed_target.scheme == "http":
            path = urllib.parse.urlunparse(("", "", parsed_target.path or "/", parsed_target.params, parsed_target.query, ""))
            req = "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: proxy-cleaner/1.0\r\n\r\n" % (path, target_host)
            sock.sendall(req.encode("ascii", "ignore"))
            data = sock.recv(64)
            if data.startswith(b"HTTP/"):
                parts = data.split(None, 2)
                code = parts[1].decode("ascii", "ignore") if len(parts) > 1 else "?"
                return True, "SOCKS HTTP " + code
        return True, "SOCKS connect"
    except Exception as exc:
        return False, type(exc).__name__
    finally:
        try:
            sock.close()
        except Exception:
            pass


def http_check(proxy: str, check_url: str, timeout: float) -> Tuple[bool, str]:
    parsed = urllib.parse.urlparse(proxy)
    if parsed.scheme.startswith("socks"):
        return socks_check(proxy, check_url, timeout)
    handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(check_url, headers={"User-Agent": "proxy-cleaner/1.0"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            code = resp.getcode() or 0
            if 200 <= code < 500:
                return True, "HTTP %d" % code
            return False, "HTTP %d" % code
    except urllib.error.HTTPError as exc:
        return 200 <= exc.code < 500, "HTTP %d" % exc.code
    except Exception as exc:
        return False, type(exc).__name__


def check_one(proxy: str, check_url: str, timeout: float) -> Progress:
    start = time.perf_counter()
    ok, reason = http_check(proxy, check_url, timeout)
    return proxy, ok, time.perf_counter() - start, reason


def render_progress(done: int, total: int, alive: int, started: float) -> None:
    if total <= 0:
        return
    width = 28
    filled = int(width * done / total)
    bar = "#" * filled + "." * (width - filled)
    pct = int(100 * done / total)
    elapsed = time.perf_counter() - started
    sys.stdout.write("\rCHECK |%s| %3d%% %d/%d alive:%d %.1fs" % (bar, pct, done, total, alive, elapsed))
    sys.stdout.flush()


def write_output(path: str, rows: Iterable[Tuple[str, float]], dry_run: bool) -> None:
    lines = [proxy for proxy, _ in rows]
    if dry_run:
        print("\n[dry-run] would write %d alive proxy/proxies to %s" % (len(lines), path))
        return
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            for proxy in lines:
                fh.write(proxy + "\n")
        os.replace(tmp, path)
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        raise

def write_outputs(sources: List[Tuple[str, str]], rows: Iterable[Tuple[str, str, float]], dry_run: bool) -> None:
    by_path: Dict[str, List[Tuple[str, float]]] = {path: [] for path, _ in sources}
    for source_path, proxy, elapsed in rows:
        by_path.setdefault(source_path, []).append((proxy, elapsed))
    for path, items in sorted(by_path.items()):
        write_output(path, items, dry_run)


def main() -> int:
    ap = argparse.ArgumentParser(description="Remove offline proxies from a proxy list or typed proxy folder.")
    ap.add_argument("file", nargs="?", default="proxies", help="Proxy file or folder to clean (default: proxies)")
    ap.add_argument("--check-url", default="https://httpbin.org/ip", help="URL used to verify HTTP proxies")
    ap.add_argument("--timeout", type=float, default=6.0, help="Per-proxy timeout in seconds")
    ap.add_argument("--workers", type=int, default=80, help="Concurrent checks")
    ap.add_argument("--max-runtime", type=float, default=180.0, help="Stop after N seconds and keep completed alive proxies")
    ap.add_argument("--scheme", choices=["http", "https", "socks4", "socks5"], default="http", help="Default scheme for host:port lines when checking one file")
    ap.add_argument("--dedupe", action="store_true", help="Deduplicate the input before checking")
    ap.add_argument("--sort-speed", action="store_true", help="Write alive proxies sorted by fastest response")
    ap.add_argument("--progress", action="store_true", help="Show a progress bar")
    ap.add_argument("--dry-run", action="store_true", help="Do not rewrite the file")
    ap.add_argument("--allow-partial", action="store_true", help="Rewrite even if --max-runtime stops before all proxies are checked")
    args = ap.parse_args()

    input_path = os.path.expandvars(os.path.expanduser(args.file))
    if input_path == "proxies" and not os.path.exists(input_path):
        input_path = os.path.dirname(os.path.abspath(__file__))
    sources, proxy_rows = load_proxy_sources(input_path, args.scheme, args.dedupe)
    if not proxy_rows:
        print("no valid proxies found in %s" % input_path)
        return 1

    total = len(proxy_rows)
    alive: List[Tuple[str, str, float]] = []
    done = 0
    started = time.perf_counter()
    deadline = started + max(1.0, args.max_runtime)
    workers = max(1, min(500, int(args.workers or 1)))
    timeout = max(0.5, float(args.timeout or 0.5))
    lock = threading.Lock()

    if args.progress:
        render_progress(0, total, 0, started)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(check_one, proxy, args.check_url, timeout): (source_path, proxy) for source_path, proxy in proxy_rows}
        while future_map:
            remaining_timeout = max(0.0, deadline - time.perf_counter())
            if remaining_timeout <= 0:
                for fut in future_map:
                    fut.cancel()
                break
            done_set, _ = concurrent.futures.wait(
                future_map,
                timeout=min(0.25, remaining_timeout),
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for fut in done_set:
                source_path, _submitted_proxy = future_map.pop(fut, ("", ""))
                try:
                    proxy, ok, elapsed, reason = fut.result()
                except Exception as exc:
                    source_path, proxy, ok, elapsed, reason = "", "", False, 0.0, type(exc).__name__
                with lock:
                    done += 1
                    if ok and proxy:
                        alive.append((source_path, proxy, elapsed))
                    if args.progress:
                        render_progress(done, total, len(alive), started)
                    elif ok:
                        print("alive --%-6s-- %-40s %.2fs" % (proxy_label(proxy), proxy, elapsed))

    if args.progress:
        render_progress(done, total, len(alive), started)
        print()
    incomplete = done < total
    if args.sort_speed:
        alive.sort(key=lambda row: row[2])
    if incomplete and not args.allow_partial:
        print("\n[max-runtime] not rewriting %s because %d proxy/proxies were unchecked; use --allow-partial to keep only completed alive checks" % (input_path, total - done))
    else:
        write_outputs(sources, alive, args.dry_run)
    dead_checked = max(0, done - len(alive))
    print("checked=%d alive=%d dead_checked=%d" % (done, len(alive), dead_checked))
    if incomplete:
        print("stopped after max runtime; unchecked=%d" % (total - done))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
