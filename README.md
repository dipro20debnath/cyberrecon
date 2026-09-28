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
- `integrations.py`: optional read-only VirusTotal, URLScan, SecurityTrails, Shodan and Censys lookups
- `modules/active.py`: guarded wordlist DNS resolution and bounded TCP probes
- `reporting.py`: JSON, CSV and self-contained HTML reports
- `risk.py`: conservative heuristic indicators, not a vulnerability score
- `tests/`: offline unit tests with network calls mocked or avoided
