"""Command-line interface for CyberRecon Pro."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeRemainingColumn
from rich.table import Table

from cyberrecon.config import Config, ConfigError, config
from cyberrecon.diffing import ComparisonError, compare_reports, discover_json_reports, load_json_report
from cyberrecon.policy import PolicyError, evaluate_gate
from cyberrecon.reporting import ReportError, write_report
from cyberrecon.scanner import ReconScanner, ScanError
from cyberrecon.utils.validators import safe_filename


app = typer.Typer(
    name="cyberrecon",
    help="CyberRecon Pro - modular reconnaissance toolkit",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
SUPPORTED_OUTPUTS = {"json", "csv", "html", "md", "markdown", "sarif"}


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


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain name or IP address"),
    mode: str = typer.Option("passive", "--mode", "-m", help="passive, active or full"),
    output: str = typer.Option("json", "--output", "-o", help="json, csv, html, md/markdown or sarif"),
    confirm_active: bool = typer.Option(False, "--confirm-active", help="Confirm you are authorized for active checks"),
    baseline: str = typer.Option("", "--baseline", help="Previous JSON report to compare against"),
    only: str = typer.Option("", "--only", help="Comma-separated modules to run, for example dns,tls"),
    skip: str = typer.Option("", "--skip", help="Comma-separated modules to skip"),
    fail_on: str = typer.Option("", "--fail-on", help="Exit 1 when risk reaches low, medium, high or critical"),
) -> None:
    """Run a reconnaissance scan and save a report."""

    print_banner()
    if output.lower().lstrip(".") not in SUPPORTED_OUTPUTS:
        console.print("[red]Scan failed:[/red] Output format must be json, csv, html, md/markdown or sarif")
        raise typer.Exit(code=2)
    try:
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

            results = ReconScanner(config).scan(
                target,
                mode=mode,
                confirm_active=confirm_active,
                progress_callback=update_progress,
                only=only or None,
                skip=skip or None,
            )
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
def compare(
    baseline: str = typer.Argument(..., help="Previous JSON report path"),
    current: str = typer.Argument(..., help="Current JSON report path"),
    output: str = typer.Option("html", "--output", "-o", help="json, csv, html, md/markdown or sarif"),
    fail_on: str = typer.Option("", "--fail-on", help="Exit 1 when current risk reaches this severity"),
    fail_on_change: bool = typer.Option(False, "--fail-on-change", help="Exit 1 when any baseline change is detected"),
) -> None:
    """Compare two JSON reports for the same target."""

    print_banner()
    if output.lower().lstrip(".") not in SUPPORTED_OUTPUTS:
        console.print("[red]Comparison failed:[/red] Output format must be json, csv, html, md/markdown or sarif")
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
