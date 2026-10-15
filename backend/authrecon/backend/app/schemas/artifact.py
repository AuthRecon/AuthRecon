from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class ArtifactType(str, Enum):
    screenshot = "screenshot"
    side_file = "side_file"
    har = "har"
    html = "html"
    sitemap = "sitemap"
    log = "log"
    scanner_import = "scanner_import"  # Burp / curl / Postman / ZAP files


class Artifact(BaseModel):
    id: str
    run_id: str
    name: str
    description: str | None = None
    type: ArtifactType
    size_bytes: int
    created_at: datetime
    download_url: str | None = None
    is_encrypted: bool = False
    role_slug: str | None = None
    role_label: str | None = None
