import os
import logging
from typing import Optional

try:
    from identityservice.sdk import IdentityServiceSdk as Sdk
except Exception:
    Sdk = None


def agntcy_enabled() -> bool:
    return bool(os.getenv("AGNTCY_API_URL")) and bool(os.getenv("AGNTCY_AGENTIC_SERVICE_API_KEY"))


def issue_agent_badge(agent_manifest_url: str) -> Optional[str]:
    """
    Returns the JOSE / compact JWS badge as a string (what you store + return),
    or None if not enabled / failed.

    IMPORTANT:
    - Use the *Agentic Service API key* to issue (not the dashboard/org key). :contentReference[oaicite:5]{index=5}
    """
    if not agntcy_enabled() or not Sdk:
        logging.warning("AGNTCY not enabled or SDK missing (pip install identity-service-sdk)")
        return None

    api_key = os.getenv("AGNTCY_AGENTIC_SERVICE_API_KEY")
    api_url = os.getenv("AGNTCY_API_URL")

    sdk = Sdk(api_key=api_key, base_url=api_url)
    try:
        # docs: issue_badge("{AGENTIC_SERVICE_URL}") :contentReference[oaicite:6]{index=6}
        badge = sdk.issue_badge(agent_manifest_url)

        # Some SDK versions return a dict. Normalize to string.
        if isinstance(badge, dict):
            # common keys you might see (keep it flexible)
            badge = badge.get("badge") or badge.get("jose") or badge.get("token")

        return badge if isinstance(badge, str) and badge.strip() else None

    except Exception as e:
        logging.exception("AGNTCY issue_badge failed: %s", str(e))
        return None
