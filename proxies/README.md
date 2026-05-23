# Proxy Folder

Apex can load HTTP, HTTPS, SOCKS4, and SOCKS5 proxies from this folder. Proxy files are local working data and are ignored by Git by default.

## Typed Proxy Files

Use these files:

- `http.txt` for HTTP/HTTPS proxies.
- `socks4.txt` for SOCKS4 proxies.
- `socks5.txt` for SOCKS5 proxies.

Plain `host:port` entries inherit the file type. For example, this line in `socks5.txt`:

```text
127.0.0.1:1080
```

is treated as:

```text
socks5://127.0.0.1:1080
```

You can also include schemes explicitly:

```text
http://127.0.0.1:8080
socks4://127.0.0.1:9050
socks5://user:pass@127.0.0.1:1080
```

Lines starting with `#` are comments. Inline comments after a proxy are also supported:

```text
127.0.0.1:8080 # local burp
```

## Extra Proxy Files

You can add your own `.txt` files. Names containing `socks4` or `socks5` inherit that type; other `.txt` files default to HTTP.

## Cleaning Proxy Lists

Preview without rewriting:

```powershell
python proxies\sort_proxies.py proxies --dry-run --max-runtime 30
```

Check and rewrite all typed proxy files with live entries only:

```powershell
python proxies\sort_proxies.py proxies --dedupe --sort-speed --progress
```

Check a single file:

```powershell
python proxies\sort_proxies.py proxies\socks5.txt --scheme socks5 --dedupe --progress
```

If a run stops because of `--max-runtime`, the cleaner will not rewrite files unless `--allow-partial` is set.

## Scanner Usage

Use proxies automatically from the folder:

```powershell
python Scanner.py https://example.com --test-proxies --no-prompt
```

Disable proxies for a scan:

```powershell
python Scanner.py https://example.com --no-proxy --no-prompt
```

Require proxies and fail closed if none are healthy:

```powershell
python Scanner.py https://example.com --proxy-required --test-proxies --no-prompt
```

## Release Hygiene

Do not commit real proxy lists. The repository `.gitignore` excludes `proxies/*.txt`; keep only this README and the cleaner script in public releases.
