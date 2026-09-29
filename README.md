# CyberRecon Pro

Passive-first reconnaissance toolkit for assets you own or are authorized to assess.

## Quick start

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
python -m cyberrecon init
python -m cyberrecon scan example.com --output json
```

Use `--output csv`, `--output html` or `--output pdf` for the other report formats. API keys can
be set with environment variables such as `CR_VIRUSTOTAL_API_KEY` or with
`python -m cyberrecon config-set api_keys.virustotal YOUR_KEY`.

Providers may use a YAML key list for rotation, or a comma-separated
`CR_<PROVIDER>_API_KEYS` environment variable:

```yaml
api_keys:
  virustotal:
    - first-key
    - second-key
```

Targets are assigned deterministically to a key slot. If a provider returns
401, 403 or 429/rate-limit errors, the next configured key is attempted. Only
non-secret rotation metadata is stored in reports.

For documentation or CI ingestion, use Markdown or SARIF output:

```powershell
python -m cyberrecon scan example.com --output md
python -m cyberrecon scan example.com --output sarif
python -m cyberrecon scan example.com --output pdf
```

SARIF 2.1.0 contains risk indicators, HTTP security findings and scan errors
with the target attached as a location.

Create a focused operator report from an existing JSON scan without changing
the source report or its full-scan risk score:

```powershell
python -m cyberrecon filter reports/example.com_scan.json --min-severity high --output html
python -m cyberrecon filter reports/example.com_scan.json --min-severity critical --output pdf
```

The filtered report records the threshold and included/excluded counts.

CI quality gates can fail the command after writing its report:

```powershell
python -m cyberrecon scan example.com --output sarif --fail-on high
python -m cyberrecon compare reports/old.json reports/new.json --fail-on-change
```

The process exits with code `1` when the selected policy is violated and `2`
when a policy option is invalid.

## Continuous integration

`.github/workflows/ci.yml` runs the test suite on Python 3.10 through 3.13 for
pushes and pull requests targeting `main`. It also compiles the source and
builds both wheel and source distributions.

`.github/workflows/security.yml` runs CodeQL, `pip-audit`, and pull-request
dependency review. Dependabot is configured to keep Python and GitHub Actions
dependencies current.

Each scan records a unique `run_id`, total runtime, per-stage duration and stage
status in `telemetry`. These fields are included in JSON, Markdown, SARIF and
HTML output for monitoring and troubleshooting.

Review stored scan trends with:

```powershell
python -m cyberrecon history --target example.com --limit 20
```

The history table shows risk score/severity, runtime, baseline changes and
module errors without opening each report manually.

Run a non-invasive preflight check before deployment or scanning:

```powershell
python -m cyberrecon doctor
python -m cyberrecon doctor --output json --strict
python -m cyberrecon doctor --live-apis --api-target example.com
```

The doctor checks runtime dependencies, configuration, output/cache paths,
optional API-key availability, active allowlisting and report inventory.
`--live-apis` is opt-in and performs bounded read-only provider requests; it
reports only status/attempt metadata and never prints keys or response bodies.

For continuous passive monitoring, use `watch`; each run gets a unique report
name and is compared with the previous iteration:

```powershell
python -m cyberrecon watch example.com --iterations 3 --interval 300 --output html
```

Use `--fail-on-change` or `--fail-on high` to stop the watch with a non-zero
exit code when the monitoring policy is violated.

Run a focused scan when only a few intelligence sources need refreshing:

```powershell
python -m cyberrecon scan example.com --only dns,tls,technology --output html
python -m cyberrecon scan example.com --skip external_intelligence --output json
```

Available passive modules are `dns`, `whois`, `subdomains`,
`ip_intelligence`, `technology`, `tls` and `external_intelligence`. Active
modules use names such as `active.ports` and still require active authorization.
The risk assessment always runs as the final stage.

## Baseline comparison

Keep a previous JSON report and compare future scans against it. The comparison
tracks DNS, subdomains, technologies, security findings, open ports, TLS expiry
and risk-score changes:

```powershell
python -m cyberrecon scan example.com --output json
python -m cyberrecon scan example.com --output html --baseline reports/example.com_scan.json
python -m cyberrecon compare reports/older.json reports/newer.json --output html
python -m cyberrecon reports
```

Baseline scans are written as `*_scan_with_baseline.*` so the previous report is
not overwritten. Comparison reports are self-contained HTML dashboards or
machine-readable JSON/CSV files.

Use `reports` to see the exact JSON filenames before running `compare`; this is
especially useful when several scans of the same target are stored together.

## Active checks

Active mode is disabled by default. To enable it, edit `config.yaml`:

```yaml
active:
  enabled: true
  allowed_targets:
    - example.com
```

Then run:

```powershell
python -m cyberrecon scan example.com --mode full --confirm-active
```

The active layer contains bounded DNS wordlist resolution and a configurable
port list. It does not perform exploitation, credential testing, or banner
grabbing. Only use it with written authorization.

## Architecture

- `config.py`: validated, deep-merged YAML configuration with atomic writes
- `modules/passive`: DNS, WHOIS, CT logs, IP intelligence, HTTP fingerprinting, favicon fingerprinting and public web metadata
- DNS reports include DNSSEC evidence, CAA issuers and mail-domain SPF/DMARC posture analysis
- `modules/passive`: TLS certificate inspection and HTTP security-header posture analysis
- `integrations.py`: optional read-only VirusTotal, URLScan, SecurityTrails, Shodan and Censys lookups
- `utils/http.py`: shared retry, rate-limit and TTL-cache policy for HTTP intelligence modules
- `modules/active.py`: guarded wordlist DNS resolution and bounded TCP probes
- `diffing.py`: validated baseline loading and report change detection
- `reporting.py`: JSON, CSV, PDF, Markdown, SARIF and self-contained HTML reports with highlighted findings
- `risk.py`: conservative heuristic indicators, not a vulnerability score
- `tests/`: offline unit tests with network calls mocked or avoided
