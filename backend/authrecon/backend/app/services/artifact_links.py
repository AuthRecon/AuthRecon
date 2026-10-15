from urllib.parse import quote


def build_placeholder_url(run_id: str, file_name: str) -> str:
    """Build a presigned-style URL for artifact downloads."""
    safe_name = quote(file_name)
    return f"https://artifacts.example/{run_id}/{safe_name}"
