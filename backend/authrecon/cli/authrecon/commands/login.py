"""Login command."""
import click
from rich.console import Console
from rich.panel import Panel

from authrecon.config import set_api_key, set_api_url, get_api_url

console = Console()


@click.command()
@click.option("--api-url", help="API URL (default: http://localhost:8001/api/v1)")
def login(api_url):
    """Configure AuthRecon CLI with your API key.

    Get your API key from the web UI at Settings > Profile > API Keys.
    """
    # Set API URL if provided
    if api_url:
        set_api_url(api_url)

    current_url = get_api_url()

    console.print("\n[bold cyan]AuthRecon CLI Login[/bold cyan]\n")
    console.print(f"API URL: [yellow]{current_url}[/yellow]")
    console.print("\n[dim]Get your API key from: Settings > Profile > API Keys[/dim]\n")

    # Prompt for API key
    api_key = click.prompt(
        "Enter your API key",
        type=str,
        hide_input=True,
    )

    if not api_key.startswith("ak_live_"):
        console.print("[red]Error:[/red] Invalid API key format. Must start with 'ak_live_'")
        raise click.Abort()

    # Save API key
    set_api_key(api_key)

    console.print(
        Panel(
            "[green]✓[/green] Successfully logged in!\n\n"
            "Try: [cyan]authrecon runs list[/cyan]",
            title="Success",
            border_style="green",
        )
    )
