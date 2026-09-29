"""Command-line interface for CyberRecon Pro."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from time import sleep

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeRemainingColumn
from rich.table import Table

from cyberrecon.config import Config, ConfigError, config
from cyberrecon.diffing import ComparisonError, compare_reports, discover_json_reports, load_json_report
from cyberrecon.doctor import diagnostics_summary, run_diagnostics
from cyberrecon.history import HistoryError, collect_history
from cyberrecon.policy import PolicyError, evaluate_gate, validate_fail_level
from cyberrecon.reporting import ReportError, filter_findings, validate_min_severity, write_report
from cyberrecon.scanner import ReconScanner, ScanError
from cyberrecon.utils.validators import safe_filename


app = typer.Typer(
    name="cyberrecon",
    help="CyberRecon Pro - modular reconnaissance toolkit",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
SUPPORTED_OUTPUTS = {"json", "csv", "html", "pdf", "md", "markdown", "sarif"}


def print_banner() -> None:
    console.print(Panel("CYBERRECON PRO\nPassive-first reconnaissance toolkit", title="CyberRecon", border_style="blue"))


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    config_file: str = typer.Option("config.yaml", "--config", "-c", help="Configuration file path"),
) -> None:
    global config
    try:
        config = Config(config_file)
    except ConfigError as exc:
        raise typer.BadParameter(str(exc), param_hint="--config") from exc
    if verbose:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        console.print(f"Config: {config.config_path}")


def _execute_scan(target: str, mode: str, confirm_active: bool, only: str = "", skip: str = "") -> dict:
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Preparing scan", total=1)

        def update_progress(completed: int, total: int, label: str) -> None:
            progress.update(task_id, total=total, completed=completed, description=label)

        return ReconScanner(config).scan(
            target,
            mode=mode,
            confirm_active=confirm_active,
            progress_callback=update_progress,
            only=only or None,
            skip=skip or None,
        )


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain name or IP address"),
    mode: str = typer.Option("passive", "--mode", "-m", help="passive, active or full"),
    output: str = typer.Option("json", "--output", "-o", help="json, csv, html, pdf, md/markdown or sarif"),
    confirm_active: bool = typer.Option(False, "--confirm-active", help="Confirm you are authorized for active checks"),
    baseline: str = typer.Option("", "--baseline", help="Previous JSON report to compare against"),
    only: str = typer.Option("", "--only", help="Comma-separated modules to run, for example dns,tls"),
    skip: str = typer.Option("", "--skip", help="Comma-separated modules to skip"),
    fail_on: str = typer.Option("", "--fail-on", help="Exit 1 when risk reaches low, medium, high or critical"),
) -> None:
    """Run a reconnaissance scan and save a report."""

    print_banner()
    if output.lower().lstrip(".") not in SUPPORTED_OUTPUTS:
        console.print("[red]Scan failed:[/red] Output format must be json, csv, html, pdf, md/markdown or sarif")
        raise typer.Exit(code=2)
    try:
        results = _execute_scan(target, mode, confirm_active, only, skip)
        suffix = "scan"
        if baseline.strip():
            baseline_path = Path(baseline).expanduser()
            previous = load_json_report(baseline_path)
            comparison = compare_reports(previous, results)
            comparison["baseline"]["source"] = str(baseline_path)
            results["comparison"] = comparison["comparison"]
            results["baseline"] = comparison["baseline"]
            results["current"] = comparison["current"]
            suffix = "scan_with_baseline"
        path = write_report(results, config.output_dir, target, output, suffix=suffix)
    except (ScanError, ReportError, ComparisonError, PolicyError, ConfigError, PermissionError, OSError) as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title="Scan summary")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Target", str(results.get("target")))
    table.add_row("Mode", str(results.get("mode")))
    table.add_row("Modules", str(len(results.get("modules", {}))))
    table.add_row("Errors", str(len(results.get("errors", []))))
    if isinstance(results.get("comparison"), dict):
        summary = results["comparison"].get("summary", {})
        table.add_row("Baseline changes", f"+{summary.get('added', 0)} / -{summary.get('removed', 0)}")
    table.add_row("Report", str(path))
    console.print(table)
    try:
        gate_reasons = evaluate_gate(results, fail_on=fail_on)
    except PolicyError as exc:
        console.print(f"[red]Policy failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    if gate_reasons:
        console.print("[red]Quality gate failed:[/red] " + "; ".join(gate_reasons))
        raise typer.Exit(code=1)


@app.command()
def watch(
    target: str = typer.Argument(..., help="Domain name or IP address"),
    interval: int = typer.Option(3600, "--interval", help="Seconds between scans"),
    iterations: int = typer.Option(1, "--iterations", "-n", help="Number of scans to run (1-1000)"),
    mode: str = typer.Option("passive", "--mode", "-m", help="passive, active or full"),
    output: str = typer.Option("json", "--output", "-o", help="json, csv, html, pdf, md/markdown or sarif"),
    confirm_active: bool = typer.Option(False, "--confirm-active", help="Confirm you are authorized for active checks"),
    baseline: str = typer.Option("", "--baseline", help="Initial JSON report for the first comparison"),
    only: str = typer.Option("", "--only", help="Comma-separated modules to run"),
    skip: str = typer.Option("", "--skip", help="Comma-separated modules to skip"),
    fail_on: str = typer.Option("", "--fail-on", help="Exit 1 when risk reaches this severity"),
    fail_on_change: bool = typer.Option(False, "--fail-on-change", help="Exit 1 when any comparison change is detected"),
) -> None:
    """Repeat passive scans and persist timestamp-independent, unique reports."""

    print_banner()
    if output.lower().lstrip(".") not in SUPPORTED_OUTPUTS:
        console.print("[red]Watch failed:[/red] Output format must be json, csv, html, pdf, md/markdown or sarif")
        raise typer.Exit(code=2)
    if interval < 0:
        console.print("[red]Watch failed:[/red] Interval cannot be negative")
        raise typer.Exit(code=2)
    if iterations < 1 or iterations > 1000:
        console.print("[red]Watch failed:[/red] Iterations must be between 1 and 1000")
        raise typer.Exit(code=2)
    try:
        if fail_on:
            validate_fail_level(fail_on)
        previous = load_json_report(Path(baseline).expanduser()) if baseline.strip() else None
    except (ComparisonError, PolicyError, OSError) as exc:
        console.print(f"[red]Watch failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    failed = False
    for iteration in range(1, iterations + 1):
        try:
            results = _execute_scan(target, mode, confirm_active, only, skip)
            if previous:
                comparison = compare_reports(previous, results)
                if baseline.strip() and iteration == 1:
                    comparison["baseline"]["source"] = str(Path(baseline).expanduser())
                results["comparison"] = comparison["comparison"]
                results["baseline"] = comparison["baseline"]
                results["current"] = comparison["current"]
            suffix = f"watch_{str(results.get('run_id', iteration))[:12]}"
            path = write_report(results, config.output_dir, target, output, suffix=suffix)
        except (ScanError, ReportError, ComparisonError, ConfigError, PermissionError, OSError) as exc:
            console.print(f"[red]Watch failed:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        summary = results.get("comparison", {}).get("summary", {}) if isinstance(results.get("comparison"), dict) else {}
        console.print(
            f"Iteration {iteration}/{iterations}: run={results.get('run_id', '-')} "
            f"risk={results.get('risk', {}).get('score', 'unknown') if isinstance(results.get('risk'), dict) else 'unknown'} "
            f"changes=+{summary.get('added', 0)} / -{summary.get('removed', 0)} report={path}"
        )
        try:
            gate_reasons = evaluate_gate(results, fail_on=fail_on, fail_on_change=fail_on_change)
        except PolicyError as exc:
            console.print(f"[red]Policy failed:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        if gate_reasons:
            console.print("[red]Quality gate failed:[/red] " + "; ".join(gate_reasons))
            failed = True
            break
        previous = results
        if iteration < iterations and interval:
            sleep(interval)

    if failed:
        raise typer.Exit(code=1)


@app.command()
def compare(
    baseline: str = typer.Argument(..., help="Previous JSON report path"),
    current: str = typer.Argument(..., help="Current JSON report path"),
    output: str = typer.Option("html", "--output", "-o", help="json, csv, html, pdf, md/markdown or sarif"),
    fail_on: str = typer.Option("", "--fail-on", help="Exit 1 when current risk reaches this severity"),
    fail_on_change: bool = typer.Option(False, "--fail-on-change", help="Exit 1 when any baseline change is detected"),
) -> None:
    """Compare two JSON reports for the same target."""

    print_banner()
    if output.lower().lstrip(".") not in SUPPORTED_OUTPUTS:
        console.print("[red]Comparison failed:[/red] Output format must be json, csv, html, pdf, md/markdown or sarif")
        raise typer.Exit(code=2)
    baseline_path = Path(baseline).expanduser()
    current_path = Path(current).expanduser()
    try:
        comparison = compare_reports(load_json_report(baseline_path), load_json_report(current_path))
        comparison["baseline"]["source"] = str(baseline_path)
        comparison["current"]["source"] = str(current_path)
        target_label = f"{safe_filename(current_path.stem)}_vs_{safe_filename(baseline_path.stem)}"
        path = write_report(comparison, config.output_dir, target_label, output, suffix="comparison")
    except (ComparisonError, ReportError, PolicyError, ConfigError, PermissionError, OSError) as exc:
        console.print(f"[red]Comparison failed:[/red] {exc}")
        if "not found" in str(exc).lower():
            available = discover_json_reports(config.output_dir)
            if available:
                console.print(f"[yellow]Available JSON reports in {config.output_dir}:[/yellow]")
                for report_path in available[:10]:
                    console.print(f"  {report_path}")
                console.print("[yellow]Use `python -m cyberrecon reports` to list report details.[/yellow]")
        raise typer.Exit(code=2) from exc

    changes = comparison["comparison"]
    summary = changes["summary"]
    table = Table(title="Baseline comparison")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Target", str(comparison.get("target")))
    table.add_row("Added", str(summary.get("added", 0)))
    table.add_row("Removed", str(summary.get("removed", 0)))
    table.add_row("Risk delta", str(changes.get("risk", {}).get("delta", "unknown")))
    table.add_row("Report", str(path))
    console.print(table)
    try:
        gate_reasons = evaluate_gate(comparison, fail_on=fail_on, fail_on_change=fail_on_change)
    except PolicyError as exc:
        console.print(f"[red]Policy failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    if gate_reasons:
        console.print("[red]Quality gate failed:[/red] " + "; ".join(gate_reasons))
        raise typer.Exit(code=1)


@app.command(name="filter")
def filter_report(
    report: str = typer.Argument(..., help="Source JSON scan report"),
    output: str = typer.Option("html", "--output", "-o", help="json, csv, html, pdf, md/markdown or sarif"),
    min_severity: str = typer.Option("medium", "--min-severity", help="Include info, low, medium, high or critical findings and above"),
) -> None:
    """Create a focused report view without changing the source scan or risk score."""

    print_banner()
    if output.lower().lstrip(".") not in SUPPORTED_OUTPUTS:
        console.print("[red]Filter failed:[/red] Output format must be json, csv, html, pdf, md/markdown or sarif")
        raise typer.Exit(code=2)
    try:
        level = validate_min_severity(min_severity)
        source_path = Path(report).expanduser()
        source = load_json_report(source_path)
        filtered = filter_findings(source, level)
        target = str(filtered.get("target", source_path.stem))
        path = write_report(filtered, config.output_dir, target, output, suffix=f"filtered_{level}")
    except (ComparisonError, ReportError, ConfigError, PermissionError, OSError) as exc:
        console.print(f"[red]Filter failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    metadata = filtered.get("finding_filter", {}) if isinstance(filtered.get("finding_filter"), dict) else {}
    table = Table(title="Filtered report")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Source", str(source_path))
    table.add_row("Threshold", str(metadata.get("minimum_severity", level)))
    table.add_row("Included", str(metadata.get("included_findings", 0)))
    table.add_row("Excluded", str(metadata.get("excluded_findings", 0)))
    table.add_row("Report", str(path))
    console.print(table)


@app.command(name="reports")
def reports() -> None:
    """List JSON reports available for baseline comparison."""

    paths = discover_json_reports(config.output_dir)
    if not paths:
        console.print(f"[yellow]No JSON reports found in {config.output_dir}[/yellow]")
        console.print("Run `python -m cyberrecon scan <target> --output json` first.")
        return

    table = Table(title=f"Available reports: {config.output_dir}")
    table.add_column("File", style="cyan")
    table.add_column("Target", style="green")
    table.add_column("Mode")
    table.add_column("Completed")
    table.add_column("Size")
    for path in paths:
        try:
            payload = load_json_report(path)
            size = f"{path.stat().st_size / 1024:.1f} KB"
            table.add_row(
                path.name,
                str(payload.get("target", "unknown")),
                str(payload.get("mode", "unknown")),
                str(payload.get("completed_at", "-")),
                size,
            )
        except (ComparisonError, OSError):
            table.add_row(path.name, "invalid report", "-", "-", "-")
    console.print(table)


@app.command()
def history(
    target: str = typer.Option("", "--target", "-t", help="Filter history to one domain or IP"),
    limit: int = typer.Option(20, "--limit", "-n", help="Maximum reports to show (1-500)"),
) -> None:
    """Show risk and runtime trends from stored JSON reports."""

    try:
        records = collect_history(config.output_dir, target=target, limit=limit)
    except HistoryError as exc:
        console.print(f"[red]History failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    if not records:
        scope = f" for {target}" if target else ""
        console.print(f"[yellow]No valid JSON scan history found{scope} in {config.output_dir}[/yellow]")
        return

    table = Table(title=f"Scan history: {config.output_dir}")
    table.add_column("File", style="cyan")
    table.add_column("Target", style="green")
    table.add_column("Completed")
    table.add_column("Risk")
    table.add_column("Duration")
    table.add_column("Changes")
    table.add_column("Errors")
    for record in records:
        duration = record["duration_ms"]
        duration_text = "-" if duration in (None, "unknown", "") else f"{duration} ms"
        table.add_row(
            record["path"].name,
            str(record["target"]),
            str(record["completed_at"]),
            f"{record['risk_score']} ({record['risk_severity']})",
            duration_text,
            str(record["changes"]),
            str(record["errors"]),
        )
    console.print(table)


@app.command()
def doctor(
    output: str = typer.Option("table", "--output", "-o", help="table or json"),
    strict: bool = typer.Option(False, "--strict", help="Treat warnings as failures"),
    live_apis: bool = typer.Option(False, "--live-apis", help="Make bounded read-only requests to configured API providers"),
    api_target: str = typer.Option("example.com", "--api-target", help="Domain or IP to use with --live-apis"),
) -> None:
    """Check runtime, configuration and optional live API readiness."""

    output = output.lower().strip()
    if output not in {"table", "json"}:
        console.print("[red]Doctor failed:[/red] Output must be table or json")
        raise typer.Exit(code=2)
    checks = run_diagnostics(config, live_apis=live_apis, api_target=api_target)
    summary = diagnostics_summary(checks)
    if output == "json":
        console.print(json.dumps({"checks": checks, "summary": summary}, indent=2, ensure_ascii=False))
    else:
        table = Table(title="CyberRecon preflight diagnostics")
        table.add_column("Status")
        table.add_column("Check", style="cyan")
        table.add_column("Details", style="green")
        for item in checks:
            status = item["status"]
            color = {"ok": "green", "warn": "yellow", "fail": "red"}.get(status, "white")
            table.add_row(f"[{color}]{status.upper()}[/{color}]", item["name"], item["details"])
        table.add_row("", "Summary", f"OK={summary['ok']} WARN={summary['warn']} FAIL={summary['fail']}")
        console.print(table)
    if summary["fail"] or (strict and summary["warn"]):
        raise typer.Exit(code=1)


@app.command(name="config-show")
def config_show() -> None:
    """Show the effective configuration with secrets redacted."""

    console.print(json.dumps(config.redacted(), indent=2, ensure_ascii=False))


@app.command(name="config-set")
def config_set(
    key: str = typer.Argument(..., help="Dotted config key, for example settings.timeout"),
    value: str = typer.Argument(..., help="Value; YAML scalar syntax is accepted"),
) -> None:
    """Set a configuration value."""

    try:
        config.set(key, value)
    except ConfigError as exc:
        console.print(f"[red]Config update failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    console.print(f"Updated {key}")


@app.command()
def init() -> None:
    """Create or repair config and required directories."""

    config.save()
    config.output_dir.mkdir(parents=True, exist_ok=True)
    for relative in ("wordlists", "tests"):
        (config.config_path.parent / relative).mkdir(parents=True, exist_ok=True)
    console.print(f"Initialized configuration at {config.config_path}")
    console.print(f"Reports directory: {config.output_dir}")


if __name__ == "__main__":
    app()
