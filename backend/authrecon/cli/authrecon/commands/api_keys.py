"""API keys commands."""
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from authrecon.api import AuthReconAPI, AuthReconAPIError

console = Console()


@click.group(name="api-keys")
def api_keys():
    """Manage API keys."""
    pass


@api_keys.command("list")
def list_keys():
    """List your API keys."""
    try:
        api = AuthReconAPI()
        keys = api.list_api_keys()

        if not keys:
            console.print("[yellow]No API keys found[/yellow]")
            return

        table = Table(title="API Keys", box=box.ROUNDED)
        table.add_column("Name", style="cyan")
        table.add_column("Prefix", style="white")
        table.add_column("Status", style="green")
        table.add_column("Created", style="dim")
        table.add_column("Last Used", style="dim")

        for key in keys:
            status = "[red]Revoked[/red]" if key.get("is_revoked") else "[green]Active[/green]"
            last_used = key.get("last_used_at", "Never")[:19] if key.get("last_used_at") else "Never"

            table.add_row(
                key.get("name", ""),
                key.get("prefix", ""),
                status,
                key.get("created_at", "")[:19],
                last_used,
            )

        console.print(table)

    except AuthReconAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort()


@api_keys.command("create")
@click.option("--name", required=True, help="Key name (e.g., 'CI/CD Pipeline')")
@click.option("--expires-days", type=int, help="Expiration in days (default: never)")
def create_key(name, expires_days):
    """Create a new API key.

    WARNING: The key will only be shown once!
    """
    try:
        api = AuthReconAPI()
        key = api.create_api_key(name, expires_days)

        console.print(
            Panel(
                f"[bold yellow]⚠ SAVE THIS KEY NOW - IT WILL NEVER BE SHOWN AGAIN![/bold yellow]\n\n"
                f"[cyan]{key['key']}[/cyan]\n\n"
                f"Name: {key['name']}\n"
                f"Prefix: {key['prefix']}\n"
                f"Expires: {key.get('expires_at', 'Never')[:19] if key.get('expires_at') else 'Never'}",
                title="API Key Created",
                border_style="yellow",
            )
        )

    except AuthReconAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort()


@api_keys.command("revoke")
@click.argument("key_id")
@click.confirmation_option(prompt="Are you sure you want to revoke this key?")
def revoke_key(key_id):
    """Revoke an API key."""
    try:
        api = AuthReconAPI()
        api.revoke_api_key(key_id)

        console.print(f"[green]✓[/green] API key revoked: [cyan]{key_id[:8]}[/cyan]")

    except AuthReconAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort()
