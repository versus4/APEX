# Output Folder

Apex writes generated assessment artifacts here so the project root stays clean.

This folder is intentionally ignored by Git except for this README. Reports can contain target URLs, headers, cookies, tokens, evidence snippets, proxy diagnostics, and other sensitive assessment data.

## Default Subfolders

- `reports/` - JSON, HTML, SARIF, Markdown, HAR, doctor JSON, replay packs, and `latest_summary.json`.
- `evidence/` - detached evidence attachments when `--evidence-dir` or report evidence features are enabled.
- `logs/` - text logs, profiling output, and OOB listener logs.
- `pocs/` - generated proof-of-concept files such as CSRF PoCs.
- `state/` - resume files, module timing cache, scan memory, and other reusable scanner state.

The scanner creates these folders automatically when needed.

## Common Examples

```powershell
python Scanner.py https://example.com --json scan.json --html-report scan.html --no-prompt
python Scanner.py https://example.com --http-evidence --har-export evidence.har --no-prompt
python Scanner.py https://example.com --resume myscan.json --only headers --no-prompt
python Scanner.py --doctor --doctor-json doctor.json --no-prompt
```

## Release Hygiene

Before publishing the repository, remove generated files under `output/`. Keep only this README unless you intentionally want to ship sample reports.
