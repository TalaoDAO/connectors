import os
import requests
from typing import Optional, Dict, Any

class AgntcyRestError(RuntimeError):
    pass

def _agntcy_rest_base_url(config: Optional[dict] = None) -> str:
    """
    REST base URL for Identity Service.

    Recommended:
      - Hosted: https://api.agent-identity.outshift.com
      - Self-host: http://localhost:4000 (as in OpenAPI)
    """
    # Prefer Flask config, then env, then fallback
    if config and config.get("AGNTCY_IDENTITY_REST_BASE_URL"):
        return str(config["AGNTCY_IDENTITY_REST_BASE_URL"]).rstrip("/")
    return os.environ.get("AGNTCY_IDENTITY_REST_BASE_URL", "https://api.agent-identity.outshift.com").rstrip("/")

def _agntcy_headers(api_key: str, access_token: Optional[str] = None) -> Dict[str, str]:
    # OpenAPI: ApiKey header name is x-id-api-key; Bearer token is optional :contentReference[oaicite:1]{index=1}
    h = {
        "Content-Type": "application/json",
        "x-id-api-key": api_key,
    }
    if access_token:
        h["Authorization"] = f"Bearer {access_token}"
    return h

def agntcy_create_app_rest(
    *,
    api_key: str,
    app_name: str,
    app_type: str,
    description: str = "",
    access_token: Optional[str] = None,
    config: Optional[dict] = None,
) -> Dict[str, Any]:
    """
    POST /v1alpha1/apps
    app_type examples: APP_TYPE_AGENT_A2A, APP_TYPE_MCP_SERVER, ...
    """
    base = _agntcy_rest_base_url(config)
    headers = _agntcy_headers(api_key, access_token)

    payload = {
        "name": app_name,
        "description": description,
        "type": app_type,
    }
    r = requests.post(f"{base}/v1alpha1/apps", headers=headers, json=payload, timeout=30)
    if not r.ok:
        raise AgntcyRestError(f"CreateApp failed: {r.status_code} {r.text}")
    return r.json()

def agntcy_issue_a2a_badge_rest(
    *,
    api_key: str,
    app_id: str,
    well_known_url: str,
    access_token: Optional[str] = None,
    config: Optional[dict] = None,
) -> Dict[str, Any]:
    """
    POST /v1alpha1/apps/{appId}/badges
    Uses IssueBadgeRequest with a2a.wellKnownUrl :contentReference[oaicite:2]{index=2}
    """
    base = _agntcy_rest_base_url(config)
    headers = _agntcy_headers(api_key, access_token)

    payload = {
        "appId": app_id,      # optional in schema but OK :contentReference[oaicite:3]{index=3}
        "a2a": {"wellKnownUrl": well_known_url},
    }
    r = requests.post(f"{base}/v1alpha1/apps/{app_id}/badges", headers=headers, json=payload, timeout=30)
    if not r.ok:
        raise AgntcyRestError(f"IssueBadge failed: {r.status_code} {r.text}")
    return r.json()

def agntcy_create_agent_and_badge_rest(
    *,
    api_key: str,
    agent_name: str,
    well_known_url: str,
    agent_description: str = "",
    access_token: Optional[str] = None,
    config: Optional[dict] = None,
) -> Dict[str, Any]:
    """
    Two-call flow:
      1) Create agent App (APP_TYPE_AGENT_A2A)
      2) Issue A2A badge for that App
    """
    app = agntcy_create_app_rest(
        api_key=api_key,
        app_name=agent_name,
        description=agent_description,
        app_type="APP_TYPE_AGENT_A2A",
        access_token=access_token,
        config=config,
    )
    app_id = app.get("id")
    if not app_id:
        raise AgntcyRestError(f"CreateApp response missing id: {app}")

    badge = agntcy_issue_a2a_badge_rest(
        api_key=api_key,
        app_id=app_id,
        well_known_url=well_known_url,
        access_token=access_token,
        config=config,
    )

    return {"app": app, "badge": badge, "app_id": app_id}


def agntcy_verify_badge_rest(
    *,
    org_api_key: str,
    badge_jose: str,
    access_token: Optional[str] = None,
    config: Optional[dict] = None,
) -> Dict[str, Any]:
    """
    POST /v1alpha1/badges/verify with VerifyBadgeRequest { badge: <string> } :contentReference[oaicite:4]{index=4}
    Returns VerificationResult. :contentReference[oaicite:5]{index=5}
    """
    base = _agntcy_rest_base_url(config)
    headers = _agntcy_headers(org_api_key, access_token)

    payload = {"badge": badge_jose}
    r = requests.post(f"{base}/v1alpha1/badges/verify", headers=headers, json=payload, timeout=30)
    if not r.ok:
        raise AgntcyRestError(f"VerifyBadge failed: {r.status_code} {r.text}")
    return r.json()


