# Scanner Plugins

Apex can load small Python plugins from this folder. Plugins are useful for organization-specific checks, temporary customer rules, or experiments that should not live in the main scanner registry yet.

Files whose names start with `_` are ignored.

## Plugin Shape

Each plugin can expose either a `SCANS` list or a simple `scan(base)` function.

Recommended `SCANS` format:

```python
def scan_example(base: str):
    return [("example plugin reached target", "url=" + base)]

SCANS = [
    {
        "option": "example_plugin",
        "label": "example plugin check",
        "func": scan_example,
        "severity": "INFO",
        "category": "plugins",
    }
]
```

Plugin scan functions receive the target base URL and should return a list of `(detail, payload)` tuples. Keep payload values concise and avoid storing secrets unless they are redacted.

## Running Plugins

List loaded plugins:

```powershell
python Scanner.py --list-plugins
python Scanner.py --list-plugins-json
```

Run one plugin:

```powershell
python Scanner.py https://example.com --plugin-scan example_plugin --no-prompt
```

Load plugins from a different directory:

```powershell
python Scanner.py https://example.com --plugins C:\path\to\plugins --plugin-scan example_plugin --no-prompt
```

## Safety Notes

- Only run active/write-style plugin behavior on systems you are authorized to test.
- Prefer read-only checks by default.
- Give each plugin a stable `option` name so users can run it with `--plugin-scan`.
- Return clear evidence strings. Users should be able to understand why a plugin produced a finding.
- Do not hardcode customer secrets, cookies, API keys, or private target names into plugins that will be committed.
