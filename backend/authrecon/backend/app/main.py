import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.core.config import APP_VERSION, get_settings
from app.api import runs, ai, scan_exports, health, artifacts, ai_assist, playbooks, auth, credentials, api_keys, vnc_portal

_DEBUG = os.getenv("AUTHRECON_DEBUG", "false").lower() == "true"


def _register_artifact_hooks() -> None:
    from app.services.artifact_crypto import register_model_hooks

    register_model_hooks()


def create_app() -> FastAPI:
    _register_artifact_hooks()
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=APP_VERSION,
        docs_url="/docs" if _DEBUG else None,
        redoc_url="/redoc" if _DEBUG else None,
        openapi_url="/openapi.json" if _DEBUG else None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-Portal-Token"],
        expose_headers=["Content-Length", "Content-Type"],
    )

    # noVNC static files — served at /novnc/ and proxied through the portal
    # at /apps/authrecon/novnc/ for authenticated browser-based VNC sessions.
    app.mount("/novnc", StaticFiles(directory="/opt/novnc"), name="novnc")

    # Internal VNC session info endpoint — called only by the portal WS proxy
    app.include_router(vnc_portal.router, tags=["vnc-internal"])

    app.include_router(health.router, prefix="/health", tags=["health"])
    app.include_router(auth.router, prefix=settings.api_v1_prefix)
    app.include_router(credentials.router, prefix=settings.api_v1_prefix)
    app.include_router(api_keys.router, prefix=settings.api_v1_prefix)
    # users router removed - user management now in Portal
    app.include_router(
        runs.router,
        prefix=settings.api_v1_prefix + "/runs",
        tags=["runs"]
    )
    app.include_router(
        artifacts.router,
        prefix=settings.api_v1_prefix + "/runs",
        tags=["artifacts"]
    )
    app.include_router(
        ai_assist.router,
        prefix=settings.api_v1_prefix + "/runs",
        tags=["ai-assist"]
    )
    app.include_router(
        playbooks.router,
        prefix=settings.api_v1_prefix + "/playbooks",
        tags=["playbooks"]
    )
    app.include_router(ai.router, prefix=settings.api_v1_prefix)
    app.include_router(scan_exports.router, prefix=settings.api_v1_prefix)
    return app


app = create_app()
