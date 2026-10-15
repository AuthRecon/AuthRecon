"""API client for AuthRecon."""
from typing import Optional, Dict, Any, List

import requests

from authrecon.config import get_api_key, get_api_url


class AuthReconAPIError(Exception):
    """API error."""
    pass


class AuthReconAPI:
    """Client for AuthRecon API."""

    def __init__(self, api_key: Optional[str] = None, api_url: Optional[str] = None):
        self.api_key = api_key or get_api_key()
        self.api_url = api_url or get_api_url()

        if not self.api_key:
            raise AuthReconAPIError(
                "No API key found. Run 'authrecon login' first."
            )

    def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Make API request."""
        url = f"{self.api_url}{path}"
        headers = {"X-API-Key": self.api_key}

        try:
            response = requests.request(
                method, url, headers=headers, json=json, params=params, timeout=30
            )
            response.raise_for_status()
            return response.json() if response.content else None
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise AuthReconAPIError(
                    "Authentication failed. Your API key may be invalid or revoked."
                )
            raise AuthReconAPIError(f"API error: {e.response.text}")
        except requests.exceptions.RequestException as e:
            raise AuthReconAPIError(f"Request failed: {str(e)}")

    # Runs
    def list_runs(self) -> List[Dict[str, Any]]:
        """List all runs."""
        return self._request("GET", "/runs")

    def get_run(self, run_id: str) -> Dict[str, Any]:
        """Get run details."""
        return self._request("GET", f"/runs/{run_id}")

    def create_run(
        self, target_url: str, username: str, password: str, credential_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new run."""
        return self._request(
            "POST",
            "/runs",
            json={
                "target_url": target_url,
                "username": username,
                "password": password,
                "credential_id": credential_id,
            },
        )

    # API Keys
    def list_api_keys(self) -> List[Dict[str, Any]]:
        """List API keys."""
        return self._request("GET", "/api-keys")

    def create_api_key(self, name: str, expires_days: Optional[int] = None) -> Dict[str, Any]:
        """Create a new API key."""
        return self._request(
            "POST", "/api-keys", json={"name": name, "expires_days": expires_days}
        )

    def revoke_api_key(self, key_id: str) -> Dict[str, Any]:
        """Revoke an API key."""
        return self._request("DELETE", f"/api-keys/{key_id}")
