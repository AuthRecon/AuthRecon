"""Runs commands."""
import click
from rich.console import Console
from rich.table import Table
from rich import box

from authrecon.api import AuthReconAPI, AuthReconAPIError

console = Console()


@click.group()
def runs():
    """Manage authentication reconnaissance runs."""
    pass


@runs.command("list")
def list_runs():
    """List all runs."""
    try:
        api = AuthReconAPI()
        runs_list = api.list_runs()

        if not runs_list:
            console.print("[yellow]No runs found[/yellow]")
            return

        table = Table(title="AuthRecon Runs", box=box.ROUNDED)
        table.add_column("ID", style="cyan")
        table.add_column("Target", style="white")
        table.add_column("Status", style="green")
        table.add_column("Created", style="dim")

        for run in runs_list:
            table.add_row(
                run.get("id", "")[:8],
                run.get("target_url", ""),
                run.get("status", ""),
                run.get("created_at", "")[:19],
            )

        console.print(table)

    except AuthReconAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort()


@runs.command("show")
@click.argument("run_id")
def show_run(run_id):
    """Show run details."""
    try:
        api = AuthReconAPI()
        run = api.get_run(run_id)

        console.print(f"\n[bold cyan]Run {run['id'][:8]}[/bold cyan]\n")
        console.print(f"  Target:  {run.get('target_url', '')}")
        console.print(f"  Status:  {run.get('status', '')}")
        console.print(f"  Created: {run.get('created_at', '')}")
        console.print(f"  Updated: {run.get('updated_at', '')}")

        if run.get("error_message"):
            console.print(f"\n  [red]Error:[/red] {run['error_message']}")

    except AuthReconAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort()


@runs.command("create")
@click.option("--target", required=True, help="Target URL")
@click.option("--username", required=True, help="Username")
@click.option("--password", required=True, help="Password", hide_input=True, prompt=True)
@click.option("--credential-id", help="Credential ID (optional)")
def create_run(target, username, password, credential_id):
    """Create a new run."""
    try:
        api = AuthReconAPI()
        run = api.create_run(target, username, password, credential_id)

        console.print(f"\n[green]✓[/green] Run created: [cyan]{run['id'][:8]}[/cyan]")
        console.print(f"  Status: {run.get('status', '')}")
        console.print(f"\nView details: [cyan]authrecon runs show {run['id']}[/cyan]")

    except AuthReconAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort()
