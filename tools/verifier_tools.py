import io
import json
import base64
import uuid
from typing import Any, Dict, List, Optional
import logging
import qrcode
from routes.verifier import oidc4vp

tools_dev = []
tools_guest = []

tools_agent = [
    {
        "name": "start_user_verification",
        "description": "Create a user wallet request as a QR code image or link.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "description": "User scope to verify. Profile is first name, last name and birth date.",
                    "enum": ["email", "over18", "profile", "wallet_identifier"],
                    "default": "email"
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional caller-provided user session id."
                }
            },
            "required": ["scope"]
        }
    },
    {
        "name": "poll_user_verification",
        "description": "Poll current verification status for a user verification; returns user wallet data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string"
                }
            },
            "required": ["session_id"]
        }
    }
]

def _qr_png_b64(text: str) -> Optional[str]:
        """Return base64 PNG of QR for 'text'; None if qrcode not available."""
        img = qrcode.make(text)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()


def _ok_content(blocks: List[Dict[str, Any]], structured: Optional[Dict[str, Any]] = None, is_error: bool = False) -> Dict[str, Any]:
    out: Dict[str, Any] = {"content": blocks}
    if structured is not None:
        out["structuredContent"] = structured
    if is_error:
        out["isError"] = True
    return out


# --------- Tool implementations ---------
def call_start_user_verification(arguments: Dict[str, Any], verifier_api_key: Optional[str], config: dict) -> Dict[str, Any]:
    pull_status_base = config["PULL_STATUS_BASE"]
    public_base_url = config["PUBLIC_BASE_URL"]
    red = config["REDIS"]
    mode = config["MODE"]

    scope = arguments.get("scope")
    
    verifier_id_for_scope = {
        "wallet_identifier": "0000",
        "email": "0001",
        "over18": "0002",
        "profile": "0003"
    }
    verifier_id = verifier_id_for_scope.get(scope, "custom")
    
    print(scope, verifier_id)
    
    # optional session_id
    session_id = arguments.get("session_id") or str(uuid.uuid4())
        
    data = oidc4vp.oidc4vp_qrcode(verifier_id, session_id, scope, red, mode)
    
    link = data.get("url")
    session_id = data.get("session_id", session_id)

    # Build structured flow info
    flow = {
        "session_id": session_id,
        "oidc4vp_request": link,
    }

    blocks: List[Dict[str, Any]] = []
    b64 = _qr_png_b64(link) if link else None
    if b64:
        blocks.append({"type": "image", "data": b64, "mimeType": "image/png"})
    # Always include a text hint
    text_hint = f"Scan the QR code (if shown) or open wallet link:\n{link}" if link else "No deeplink URL returned."
    blocks.append({"type": "text", "text": text_hint})
    return _ok_content(blocks, structured=flow)


def call_poll_user_verification(arguments: Dict[str, Any], verifier_api_key: Optional[str], config: dict) -> Dict[str, Any]:
    red = config["REDIS"]
    session_id = arguments.get("session_id")
    if not session_id:
        return _ok_content(
            [{"type": "text", "text": "session_id is required"}],
            structured={"error": "invalid_arguments", "missing": ["session_id"]},
            is_error=True
        )
    
    payload = oidc4vp.wallet_pull_status(session_id, red)
    print("payload = ", payload)
    status = payload.get("status", "pending")

    # current oidc4vp: claims merged at the top level (exclude status/session_id)
    claims = {k: v for k, v in payload.items() if k not in ("status", "session_id")}

    structured = {"status": status, "session_id": session_id, **claims}

    # Human-friendly text block (special hint for wallet_identifier scope)
    text_blocks = []
    scope = claims.get("scope")
    if scope == "wallet_identifier" and claims.get("wallet_identifier"):
        text_blocks.append({
            "type": "text",
            "text": f'Wallet identifier: {claims.get("wallet_identifier")}'
        })
    # Always include the full JSON as text for debugging/visibility
    text_blocks.append({"type": "text", "text": json.dumps(structured, ensure_ascii=False)})

    return _ok_content(text_blocks, structured=structured)
