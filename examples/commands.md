# Apex Command Examples

These examples assume authorized testing. Replace `https://example.com` with a target you own or have permission to assess.

## Basic Scans

Quick targeted scan:

```powershell
python Scanner.py https://example.com --only headers,tech,sectxt --json quick.json --html-report quick.html --no-prompt
```

Broad scan:

```powershell
python Scanner.py https://example.com --all --json full.json --html-report full.html --no-prompt
```

Competitive scanner preset:

```powershell
python Scanner.py https://example.com --scanner-parity --no-prompt
```

## Module Selection

Run only a few modules:

```powershell
python Scanner.py https://example.com --only headers,corsfull,tech --no-prompt
```

Exclude noisy modules:

```powershell
python Scanner.py https://example.com --all --exclude fuzzer,subdomains --no-prompt
```

List scan modules:

```powershell
python Scanner.py --list-scans
python Scanner.py --list-scans-json
```

## Reports

Write multiple report formats:

```powershell
python Scanner.py https://example.com --only headers --json scan.json --html-report scan.html --sarif scan.sarif --markdown-report scan.md --no-prompt
```

Capture replayable HTTP evidence:

```powershell
python Scanner.py https://example.com --http-evidence --har-export evidence.har --replay-pack replay_pack.json --json scan.json --no-prompt
```

Export the resolved runtime configuration:

```powershell
python Scanner.py https://example.com --export-config resolved_config.json --no-prompt
```

## Resume, Baselines, And Replay

Resume a scan:

```powershell
python Scanner.py https://example.com --all --resume customer_a.json --no-prompt
```

Compare a new scan to an older JSON report:

```powershell
python Scanner.py https://example.com --json current.json --compare output\reports\old.json --no-prompt
```

Keep only findings not present in a previous baseline:

```powershell
python Scanner.py https://example.com --all --baseline previous.json --only-new --json new_findings.json --no-prompt
```

## Templates And Fuzzing

Run starter templates:

```powershell
python Scanner.py https://example.com --nuclei-lite --templates templates --html-report recon.html --no-prompt
```

Run templates and the built-in fuzzer:

```powershell
python Scanner.py https://example.com --nuclei-lite --fuzzer --fuzz-recursion --html-report recon.html --no-prompt
```

## Local Source And SBOM Review

Scan local source for secrets and risky APIs:

```powershell
python Scanner.py --source-scan --source-dir . --json source_review.json --no-prompt
```

Parse local dependency manifests and SBOM files:

```powershell
python Scanner.py --sbom-scan --source-dir . --json dependency_review.json --no-prompt
```

Run both:

```powershell
python Scanner.py --source-scan --sbom-scan --source-dir . --json local_review.json --no-prompt
```

## Proxies

Clean proxy files:

```powershell
python proxies\sort_proxies.py proxies --dedupe --sort-speed --progress
```

Preview proxy cleaning without rewriting:

```powershell
python proxies\sort_proxies.py proxies --dry-run --max-runtime 30
```

Scan without proxies:

```powershell
python Scanner.py https://example.com --no-proxy --no-prompt
```

Require healthy proxies:

```powershell
python Scanner.py https://example.com --proxy-required --test-proxies --no-prompt
```

## Doctor And Maintenance

Check the local environment:

```powershell
python Scanner.py --doctor --doctor-json doctor.json --no-prompt
```

Run scanner registry checks:

```powershell
python Scanner.py --audit-scanner --no-proxy --no-prompt
python Scanner.py --module-self-test --no-proxy --no-prompt
```

Run Python tests:

```powershell
python -m unittest discover -s tests -v
```
