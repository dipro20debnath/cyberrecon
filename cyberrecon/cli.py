"""
CyberRecon Pro - Main CLI Interface
"""
import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from pathlib import Path

# এই line ঠিক করো - Config class import করো
from cyberrecon.config import Config, config

app = typer.Typer(
    name="cyberrecon",
    help="🔍 CyberRecon Pro - Advanced Reconnaissance Tool",
    add_completion=False
)
console = Console()

def print_banner():
    """Print logo banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║      🔍 CYBERRECON PRO - Advanced Reconnaissance        ║
    ║                                                          ║
    ║   Domain • Subdomain • IP • Technology Intelligence     ║
    ╚══════════════════════════════════════════════════════════╝
    """
    console.print(Panel(
        Text(banner, style="cyan"),
        title="[bold green]Welcome[/bold green]",
        border_style="blue"
    ))

@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    config_file: str = typer.Option("config.yaml", "--config", "-c", help="Config file path")
):
    """CyberRecon Pro - Complete reconnaissance solution"""
    global config
    config = Config(config_file)
    
    if verbose:
        console.print("[yellow]Verbose mode enabled[/yellow]")

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain or IP address"),
    mode: str = typer.Option("passive", "--mode", "-m", help="Scan mode: passive, active, full"),
    output: str = typer.Option("json", "--output", "-o", help="Output format: json, csv, html"),
    threads: int = typer.Option(50, "--threads", "-t", help="Number of threads")
):
    """
    🎯 Start reconnaissance scan on a target
    """
    print_banner()
    
    console.print(f"\n[bold blue]Target:[/bold blue] {target}")
    console.print(f"[bold blue]Mode:[/bold blue] {mode}")
    console.print(f"[bold blue]Output:[/bold blue] {output}")
    console.print(f"[bold blue]Threads:[/bold blue] {threads}\n")
    
    console.print("[yellow]⚠️  Scanner module will be implemented in upcoming days![/yellow]")

@app.command(name="config-show")
def config_show():
    """
    ⚙️  Show current configuration
    """
    table = Table(title="Current Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Config File", str(config.config_path))
    table.add_row("Threads", str(config.threads))
    table.add_row("Timeout", f"{config.timeout}s")
    table.add_row("Output Directory", str(config.output_dir))
    table.add_row("VirusTotal API", "✅ Set" if config.get_api_key('virustotal') else "❌ Not Set")
    table.add_row("Shodan API", "✅ Set" if config.get_api_key('shodan') else "❌ Not Set")
    
    console.print(table)

@app.command(name="config-set")
def config_set(
    key: str = typer.Argument(..., help="Config key (e.g., api_keys.virustotal)"),
    value: str = typer.Argument(..., help="Config value")
):
    """
    📝 Set configuration value
    """
    config.set(key, value)
    console.print(f"[green]✅ Set {key} = {value}[/green]")

@app.command()
def init():
    """
    🚀 Initialize CyberRecon Pro (create config, download wordlists)
    """
    print_banner()
    
    console.print("\n[bold yellow]Initializing CyberRecon Pro...[/bold yellow]\n")
    
    # Create config file
    if not Path("config.yaml").exists():
        # ফাঁকা create করো, পরবর্তীতে default ব্যবহার হবে
        console.print("[green]✅ Config file will be created on first use[/green]")
    else:
        console.print("[yellow]⚠️  Config file already exists[/yellow]")
    
    # Create directories
    Path("reports").mkdir(exist_ok=True)
    Path("wordlists").mkdir(exist_ok=True)
    Path("tests").mkdir(exist_ok=True)
    
    console.print("[green]✅ Directories created[/green]")
    console.print("\n[bold cyan]Next steps:[/bold cyan]")
    console.print("1. Edit config.yaml and add your API keys")
    console.print("2. Run: python -m cyberrecon scan example.com")
    
    # Download basic wordlist
    import urllib.request
    wordlist_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt"
    
    try:
        console.print("\n[yellow]📥 Downloading subdomain wordlist...[/yellow]")
        urllib.request.urlretrieve(wordlist_url, "wordlists/subdomains.txt")
        console.print("[green]✅ Wordlist downloaded: wordlists/subdomains.txt[/green]")
    except Exception as e:
        console.print(f"[red]❌ Failed to download wordlist: {e}[/red]")

if __name__ == "__main__":
    app()
