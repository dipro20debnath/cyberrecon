"""Command-line interface for CyberRecon Pro."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cyberrecon.config import Config, ConfigError, config
from cyberrecon.reporting import ReportError, write_report
from cyberrecon.scanner import ReconScanner, ScanError


app = typer.Typer(
    name="cyberrecon",
    help="CyberRecon Pro - modular reconnaissance toolkit",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


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
    output: str = typer.Option("json", "--output", "-o", help="json, csv or html"),
    confirm_active: bool = typer.Option(False, "--confirm-active", help="Confirm you are authorized for active checks"),
) -> None:
    """Run a reconnaissance scan and save a report."""

    print_banner()
    if output.lower().lstrip(".") not in {"json", "csv", "html"}:
        console.print("[red]Scan failed:[/red] Output format must be json, csv or html")
        raise typer.Exit(code=2)
    try:
        results = ReconScanner(config).scan(target, mode=mode, confirm_active=confirm_active)
        path = write_report(results, config.output_dir, target, output)
    except (ScanError, ReportError, ConfigError, PermissionError, OSError) as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title="Scan summary")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Target", str(results.get("target")))
    table.add_row("Mode", str(results.get("mode")))
    table.add_row("Modules", str(len(results.get("modules", {}))))
    table.add_row("Errors", str(len(results.get("errors", []))))
    table.add_row("Report", str(path))
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
