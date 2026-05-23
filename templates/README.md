# Scanner Templates

Apex includes a lightweight Nuclei-style template runner called `--nuclei-lite`. Put JSON or YAML templates in this folder, then run the scanner with `--nuclei-lite`.

When `--nuclei-lite` is enabled and no `--templates` path is supplied, Apex loads this folder automatically.

## Run Templates

```powershell
python Scanner.py https://example.com --nuclei-lite --templates templates --html-report template_scan.html --no-prompt
```

Run one template file:

```powershell
python Scanner.py https://example.com --nuclei-lite --templates templates\exposure-basics.json --no-prompt
```

## Supported Fields

The lightweight runner supports a practical subset of Nuclei-style fields:

- `id`
- `info.name`
- `info.severity`
- `paths`
- `path`
- `status`
- `statuses`
- `words`
- `regex`
- `matchers`
- `extractors`
- `stop_at_first_match`

Supported matchers include simple `status`, `words`, and `regex` checks against body, headers, or all response text.

## Minimal JSON Template

```json
{
  "id": "example-health-check",
  "info": {
    "name": "Example Health Check",
    "severity": "INFO"
  },
  "paths": ["/health", "/status"],
  "status": [200],
  "words": ["ok"]
}
```

## Included Starter Packs

- `exposure-basics.json` - common exposed files and metadata.
- `api-exposures.json` - API docs, GraphQL, OAuth, and OpenAPI metadata.
- `cloud-devops.json` - DevOps consoles and runtime endpoints.
- `framework-fingerprints.json` - framework debug and metadata paths.
- `panel-fingerprints.json` - common admin/panel fingerprints.

## Template Tips

- Keep templates read-only unless you have explicit authorization for active behavior.
- Use clear IDs and names; these show up in reports.
- Prefer `status` plus `words` or `regex` to reduce false positives.
- Avoid storing customer-specific URLs, tokens, or internal hostnames in templates that will be committed.
