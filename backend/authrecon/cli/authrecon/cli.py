"""Main CLI entry point."""
import click

from authrecon.commands import login, runs, api_keys


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """AuthRecon CLI - Manage authentication reconnaissance from the command line."""
    pass


# Register commands
cli.add_command(login.login)
cli.add_command(runs.runs)
cli.add_command(api_keys.api_keys)


if __name__ == "__main__":
    cli()
