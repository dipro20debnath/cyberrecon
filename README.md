# CyberRecon Pro

[![CI](https://github.com/dipro20debnath/cyberrecon/actions/workflows/ci.yml/badge.svg)](https://github.com/dipro20debnath/cyberrecon/actions/workflows/ci.yml)
[![Security](https://github.com/dipro20debnath/cyberrecon/actions/workflows/security.yml/badge.svg)](https://github.com/dipro20debnath/cyberrecon/actions/workflows/security.yml)

CyberRecon Pro is a passive-first reconnaissance and security-posture toolkit for domains and IP addresses that you own or are explicitly authorized to assess.

It collects public intelligence, highlights important findings, tracks changes over time, and produces reports that work for both people and CI pipelines.

> Use this tool only on assets you own or have written permission to test. Active checks are guarded and do not perform exploitation, credential attacks, or banner grabbing.

## What can it do?

- Discover DNS, WHOIS, certificate, subdomain, technology, TLS, and HTTP-security information.
- Query optional read-only intelligence providers such as VirusTotal, URLScan, Shodan, Censys, IPinfo, and SecurityTrails.
- Run guarded active checks: bounded TCP port checks, DNS wordlist discovery, zone-transfer posture checks, and optional screenshots.
- Show live scan progress and record per-module timing and errors.
- Produce JSON, CSV, HTML, PDF, Markdown, and SARIF reports.
- Compare scans, highlight changes, filter findings by severity, monitor targets, and enforce CI quality gates.

## Complete setup and first scan

Follow the steps below from start to finish. You need Python 3.10-3.13, Git, and an internet connection for installation and public-data lookups.

### 1. Download the repository

#### Windows PowerShell

```powershell
git clone https://github.com/dipro20debnath/cyberrecon.git
Set-Location cyberrecon
```

#### Linux

```bash
git clone https://github.com/dipro20debnath/cyberrecon.git
cd cyberrecon
```

#### macOS

```bash
git clone https://github.com/dipro20debnath/cyberrecon.git
cd cyberrecon
```

If you already downloaded the repository, open a terminal in its folder and skip this step.

### Windows PowerShell

Run these commands from the repository directory:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m cyberrecon init
.\.venv\Scripts\python.exe -m cyberrecon doctor
# Optional: activate the environment so the remaining examples can use `python`.
.\.venv\Scripts\Activate.ps1
```

Run a first passive scan. No API key is required for the core passive modules:

```powershell
.\.venv\Scripts\python.exe -m cyberrecon scan example.com --mode passive --output html
```

Open the generated file in `reports/`.

### Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m cyberrecon init
python -m cyberrecon doctor
```

### macOS

Install Python and Git with [Homebrew](https://brew.sh/) if they are not already installed:

```bash
brew install python git
```

Then create the environment and install CyberRecon Pro:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m cyberrecon init
python -m cyberrecon doctor
```

### 2. Run the first passive scan

Passive scanning is the recommended starting point. It does not require API keys:

```bash
python -m cyberrecon scan example.com --mode passive --output html
```

The tool displays live progress and saves the report inside `reports/`. Replace `example.com` with a domain or IP address you own or are authorized to assess.

## Recommended user workflow

1. Run `doctor` to check the local installation.
2. Run a passive scan and review the HTML report.
3. Add optional API keys if you need provider enrichment.
4. Save a JSON scan as a baseline for future comparisons.
5. Use `watch` for recurring monitoring and `history` for trends.
6. Enable active checks only after configuring an authorized target allowlist.

This workflow keeps the default experience safe, repeatable, and easy to automate.

### 3. Open and understand the report

The HTML report is designed for people. JSON and SARIF are better for automation. Available formats are `json`, `csv`, `html`, `pdf`, `md`, `markdown`, and `sarif`.

```bash
python -m cyberrecon scan example.com --output json
python -m cyberrecon scan example.com --output pdf
python -m cyberrecon scan example.com --output sarif
```

List the exact report filenames before using them in another command:

```bash
python -m cyberrecon reports
```

## The main commands

| Command | Purpose |
| --- | --- |
| `scan` | Run one reconnaissance scan and save a report. |
| `watch` | Repeat scans and compare each run with the previous one. |
| `compare` | Compare two JSON reports. |
| `filter` | Create a focused report containing findings at or above a severity. |
| `reports` | List available JSON reports and their exact filenames. |
| `history` | Show risk, runtime, change, and error trends. |
| `doctor` | Check dependencies, configuration, wordlists, reports, and optional API readiness. |
| `config-show` | Show effective configuration with secrets redacted. |
| `config-set` | Update a configuration value. |
| `init` | Create or repair the configuration, directories, and default wordlists. |

Every command has built-in help:

```powershell
.\.venv\Scripts\python.exe -m cyberrecon --help
.\.venv\Scripts\python.exe -m cyberrecon scan --help
```

## Scanning options

### Select modules

Run only the modules you need:

```powershell
python -m cyberrecon scan example.com `
  --only dns,tls,technology `
  --output html
```

Skip an optional module:

```powershell
python -m cyberrecon scan example.com `
  --skip external_intelligence `
  --output json
```

Available passive modules are:

`dns`, `whois`, `subdomains`, `ip_intelligence`, `technology`, `tls`, and `external_intelligence`.

### Report formats

Use `--output` with one of these formats:

`json`, `csv`, `html`, `pdf`, `md`, `markdown`, or `sarif`.

Examples:

```powershell
python -m cyberrecon scan example.com --output json
python -m cyberrecon scan example.com --output pdf
python -m cyberrecon scan example.com --output md
python -m cyberrecon scan example.com --output sarif
```

SARIF reports contain risk indicators, HTTP security findings, and scan errors in a format supported by many CI and code-scanning tools.

## Optional API integrations

API keys are optional. Core passive scanning works without them. Prefer environment variables so secrets do not end up in `config.yaml` or Git history.

| Provider | Environment variable | Key page |
| --- | --- | --- |
| VirusTotal | `CR_VIRUSTOTAL_API_KEY` | [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) |
| URLScan | `CR_URLSCAN_API_KEY` | [URLScan API guide](https://docs.urlscan.io/guides/quickstart) |
| SecurityTrails | `CR_SECURITYTRAILS_API_KEY` | [SecurityTrails credentials](https://securitytrails.com/app/account/credentials) |
| Shodan | `CR_SHODAN_API_KEY` | [Shodan API requirements](https://developer.shodan.io/api/requirements) |
| Censys | `CR_CENSYS_API_KEY` | [Censys API setup](https://docs.censys.com/reference/get-started) |
| IPinfo | `CR_IPINFO_API_KEY` | [IPinfo token page](https://ipinfo.io/account/token) |

For a temporary PowerShell session:

```powershell
$env:CR_VIRUSTOTAL_API_KEY = "YOUR_KEY"
$env:CR_URLSCAN_API_KEY = "YOUR_KEY"
$env:CR_SHODAN_API_KEY = "YOUR_KEY"
$env:CR_CENSYS_API_KEY = "YOUR_KEY"
$env:CR_IPINFO_API_KEY = "YOUR_KEY"
```

For Linux and macOS shells:

```bash
export CR_VIRUSTOTAL_API_KEY="YOUR_KEY"
export CR_URLSCAN_API_KEY="YOUR_KEY"
export CR_SHODAN_API_KEY="YOUR_KEY"
export CR_CENSYS_API_KEY="YOUR_KEY"
export CR_IPINFO_API_KEY="YOUR_KEY"
```

Validate configured providers without printing keys or response bodies:

```powershell
python -m cyberrecon doctor --live-apis --api-target your-authorized-domain.com
```

Domain targets validate domain-oriented providers. Shodan and Censys require an authorized IP target:

```powershell
python -m cyberrecon doctor --live-apis --api-target YOUR_AUTHORIZED_IP
```

Multiple keys can be rotated with a comma-separated variable:

```powershell
$env:CR_VIRUSTOTAL_API_KEYS = "FIRST_KEY,SECOND_KEY"
```

The tool retries transient requests, respects the configured rate limit, and records only non-secret key-slot metadata in reports. Never commit real keys.

## Baselines, comparisons, and monitoring

Save a baseline JSON report, then compare a later scan against it:

```powershell
python -m cyberrecon scan example.com --output json
python -m cyberrecon scan example.com `
  --baseline reports/example.com_scan.json `
  --output html
python -m cyberrecon reports
python -m cyberrecon compare reports/older.json reports/newer.json --output html
```

Create a focused report without changing the original scan or its full risk score:

```powershell
python -m cyberrecon filter reports/example.com_scan.json `
  --min-severity high `
  --output html
```

Run repeated passive monitoring:

```powershell
python -m cyberrecon watch example.com `
  --iterations 3 `
  --interval 300 `
  --output html
```

Review stored trends:

```powershell
python -m cyberrecon history --target example.com --limit 20
```

## CI quality gates

Reports can be written before a command exits with a policy failure:

```powershell
python -m cyberrecon scan example.com --output sarif --fail-on high
python -m cyberrecon compare reports/old.json reports/new.json --fail-on-change
python -m cyberrecon watch example.com --iterations 3 --fail-on-change
```

The process exits with code `1` when a selected policy is violated and `2` when a policy option is invalid.

The repository CI workflow tests Python 3.10-3.13 on Ubuntu and Windows. The security workflow runs CodeQL, dependency auditing, and pull-request dependency review.

## Active checks

Active checks require an enabled configuration, an explicit allowlist, and the `--confirm-active` flag. New configurations use active mode disabled by default. Before using it, configure an explicit allowlist for a target you own or are authorized to assess:

```yaml
active:
  enabled: true
  allowed_targets:
    - your-authorized-domain.com
  allow_private_targets: false
```

Then confirm authorization at runtime:

```powershell
python -m cyberrecon scan your-authorized-domain.com `
  --mode full `
  --confirm-active `
  --output html
```

Active checks are bounded and limited to:

- Configured TCP ports
- DNS wordlist resolution
- DNS zone-transfer posture checks
- Optional Playwright screenshots

They do not exploit vulnerabilities, test credentials, brute-force accounts, or grab service banners.

## Troubleshooting

### PowerShell cannot find Python

Run the command from the repository directory and use the correct virtual-environment path:

```powershell
.\.venv\Scripts\python.exe -m cyberrecon --help
```

If your virtual environment is one directory above the repository, use `..\.venv\Scripts\python.exe` instead.

### `compare` says a report is missing

List the exact filenames first:

```powershell
python -m cyberrecon reports
```

Then pass two existing JSON report paths to `compare`.

### Shodan/Censys show `skipped`

This is expected when the validation target is a domain. Run `doctor --live-apis` with an authorized IP target for those providers.

### API warnings

Warnings are not necessarily code errors. They may mean that a provider key is not configured, the target type is unsupported, the provider plan does not allow the endpoint, or the request quota was reached.

## Project layout

```text
cyberrecon/
|-- modules/passive/       Passive intelligence modules
|-- modules/active.py      Guarded active checks
|-- data/                  Bundled default assets for clean installs
|-- integrations.py        Optional external providers
|-- scanner.py             Scan orchestration and progress
|-- reporting.py           JSON/CSV/HTML/PDF/Markdown/SARIF reports
|-- diffing.py             Baseline and change detection
|-- policy.py              CI quality gates
`-- doctor.py              Readiness diagnostics
tests/                     Offline regression tests
wordlists/                 Local active-scan wordlists
```

## Development

Install development dependencies and run the test suite:

```powershell
python -m pip install -r requirements.txt
python -m pytest
python -m compileall -q cyberrecon tests
```

The tests are designed to run offline; external provider requests are mocked or avoided.
