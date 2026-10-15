"""
HTTP Basic Authentication Scenario
Browser-based basic auth with WWW-Authenticate header.
"""
import base64
import secrets
from fastapi import APIRouter, Request, Response, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse

from ...main import verify_credentials, telemetry

router = APIRouter()


def parse_basic_auth(authorization: str) -> tuple[str, str]:
    """Parse HTTP Basic Auth header."""
    if not authorization.startswith("Basic "):
        raise ValueError("Invalid authorization header")

    encoded = authorization[6:]  # Remove "Basic " prefix
    decoded = base64.b64decode(encoded).decode("utf-8")
    username, password = decoded.split(":", 1)
    return username, password


@router.get("/basic-auth", response_class=HTMLResponse)
async def basic_auth_page(request: Request, response: Response):
    """
    HTTP Basic Authentication endpoint.
    Returns 401 with WWW-Authenticate header if not authenticated.
    """
    authorization = request.headers.get("Authorization")

    # Capture request telemetry
    request_data = {
        "method": request.method,
        "path": str(request.url.path),
        "headers": dict(request.headers),
        "ip": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown"),
    }

    if not authorization:
        # No credentials provided - send challenge
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers["WWW-Authenticate"] = 'Basic realm="LoginLab Basic Auth Test"'

        telemetry.record(
            scenario="basic-auth",
            request_data=request_data,
            response_data={
                "status": 401,
                "headers": {"WWW-Authenticate": 'Basic realm="LoginLab Basic Auth Test"'},
            },
            detection_hints={
                "auth_type": "http_basic",
                "challenge_sent": True,
                "realm": "LoginLab Basic Auth Test",
            },
            success=False,
            run_id=request.headers.get("X-AuthRecon-Run-ID"),
        )

        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Basic Auth Required - LoginLab</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {
                    font-family: system-ui, -apple-system, sans-serif;
                    max-width: 600px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #f5f5f5;
                }
                .card {
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                h1 { color: #333; margin-top: 0; }
                code {
                    background: #f0f0f0;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-size: 0.9em;
                }
                .hint {
                    background: #e3f2fd;
                    padding: 15px;
                    border-left: 4px solid #2196f3;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>🔒 Basic Authentication Required</h1>
                <p>This page requires HTTP Basic Authentication.</p>
                <p>Your browser should prompt you for credentials.</p>

                <div class="hint">
                    <strong>Test Credentials:</strong><br>
                    Username: <code>testuser@loginlab.local</code><br>
                    Password: <code>TestPass123!</code>
                </div>

                <div class="hint" style="background: #f3e5f5; border-color: #9c27b0;">
                    <strong>Detection Hints:</strong><br>
                    • HTTP 401 status<br>
                    • WWW-Authenticate: Basic realm="..."<br>
                    • Requires Authorization header<br>
                    • Auth type: <code>http_basic</code>
                </div>
            </div>
        </body>
        </html>
        """

    # Parse and verify credentials
    try:
        username, password = parse_basic_auth(authorization)
        user = verify_credentials(username, password)

        if not user:
            # Invalid credentials
            response.status_code = status.HTTP_401_UNAUTHORIZED
            response.headers["WWW-Authenticate"] = 'Basic realm="LoginLab Basic Auth Test"'

            telemetry.record(
                scenario="basic-auth",
                request_data={**request_data, "username": username},
                response_data={
                    "status": 401,
                    "headers": {"WWW-Authenticate": 'Basic realm="LoginLab Basic Auth Test"'},
                },
                detection_hints={
                    "auth_type": "http_basic",
                    "credentials_invalid": True,
                },
                success=False,
                run_id=request.headers.get("X-AuthRecon-Run-ID"),
            )

            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authentication Failed - LoginLab</title>
                <style>
                    body { font-family: system-ui; max-width: 600px; margin: 50px auto; padding: 20px; }
                    .error { background: #ffebee; color: #c62828; padding: 15px; border-radius: 4px; }
                </style>
            </head>
            <body>
                <div class="error">
                    <h2>❌ Authentication Failed</h2>
                    <p>Invalid username or password. Please try again.</p>
                </div>
            </body>
            </html>
            """

        # Success!
        telemetry.record(
            scenario="basic-auth",
            request_data={**request_data, "username": username},
            response_data={
                "status": 200,
                "user": user,
            },
            detection_hints={
                "auth_type": "http_basic",
                "auth_successful": True,
                "user_role": user["role"],
            },
            success=True,
            run_id=request.headers.get("X-AuthRecon-Run-ID"),
        )

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authenticated - LoginLab</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta data-auth-success="true" data-auth-type="basic" data-user-role="{user['role']}">
            <style>
                body {{
                    font-family: system-ui, -apple-system, sans-serif;
                    max-width: 600px;
                    margin: 50px auto;
                    padding: 20px;
                    background: #f5f5f5;
                }}
                .card {{
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .success {{
                    background: #e8f5e9;
                    color: #2e7d32;
                    padding: 15px;
                    border-radius: 4px;
                    border-left: 4px solid #4caf50;
                }}
                .user-info {{
                    background: #f5f5f5;
                    padding: 15px;
                    border-radius: 4px;
                    margin-top: 20px;
                }}
                h1 {{ color: #333; margin-top: 0; }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="success">
                    <h1>✅ Authentication Successful</h1>
                    <p>You have been authenticated using HTTP Basic Authentication.</p>
                </div>

                <div class="user-info">
                    <strong>User Information:</strong><br>
                    Name: {user['display_name']}<br>
                    Username: {username}<br>
                    Role: {user['role']}<br>
                </div>

                <div class="user-info" style="background: #e3f2fd;">
                    <strong>Detection Summary:</strong><br>
                    Auth Type: <code>http_basic</code><br>
                    Expected Confidence: <code>100%</code><br>
                    Status: <code>Authenticated</code>
                </div>
            </div>

            <script>
                console.log('[LoginLab] Basic auth success:', {{
                    scenario: 'basic-auth',
                    user: '{username}',
                    role: '{user['role']}',
                    timestamp: new Date().toISOString()
                }});
            </script>
        </body>
        </html>
        """

    except Exception as e:
        # Malformed authorization header
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers["WWW-Authenticate"] = 'Basic realm="LoginLab Basic Auth Test"'

        telemetry.record(
            scenario="basic-auth",
            request_data=request_data,
            response_data={
                "status": 401,
                "error": str(e),
            },
            detection_hints={
                "auth_type": "http_basic",
                "auth_malformed": True,
            },
            success=False,
            run_id=request.headers.get("X-AuthRecon-Run-ID"),
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
            headers={"WWW-Authenticate": 'Basic realm="LoginLab Basic Auth Test"'},
        )
