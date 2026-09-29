# CyberRecon Pro

Passive-first reconnaissance toolkit for assets you own or are authorized to assess.

## Quick start

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
python -m cyberrecon init
python -m cyberrecon scan example.com --output json
```

Use `--output csv` or `--output html` for the other report formats. API keys can
be set with environment variables such as `CR_VIRUSTOTAL_API_KEY` or with
`python -m cyberrecon config-set api_keys.virustotal YOUR_KEY`.

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
- `modules/passive`: DNS, WHOIS, CT logs, IP intelligence and HTTP fingerprinting
- `modules/passive`: TLS certificate inspection and HTTP security-header posture analysis
- `integrations.py`: optional read-only VirusTotal, URLScan, SecurityTrails, Shodan and Censys lookups
- `modules/active.py`: guarded wordlist DNS resolution and bounded TCP probes
- `diffing.py`: validated baseline loading and report change detection
- `reporting.py`: JSON, CSV and self-contained HTML reports with highlighted findings
- `risk.py`: conservative heuristic indicators, not a vulnerability score
- `tests/`: offline unit tests with network calls mocked or avoided
