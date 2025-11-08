import io
import json
import base64
import uuid
from typing import Any, Dict, List, Optional
import logging
import qrcode
from routes.verifier import oidc4vp


tools_agent = [
    {
        "name": "get_supported_user_verification_scopes",
        "description": "Return supported scopes, the claims each scope returns, and available verifier profiles.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "start_user_verification",
        "description": "Create a wallet request as a QR code image or deeplink.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "description": "Scope to verify."
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional caller-provided session id."
                }
            },
            "required": ["scope"]
        }
    },
    {
        "name": "poll_user_verification",
        "description": "Poll current status for a session; returns structured status and redacted wallet_data.",
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

    verifier_id = arguments.get("scope")
    
    # scope is now unique by verifier_id
    scope_for_demo = {
        "0000": "wallet_identifier",
        "0001": "email",
        "0002": "over18",
        "0003": "profile"
    }
    scope = scope_for_demo.get(verifier_id, "custom")
    
    # optional session_id
    session_id = arguments.get("session_id") or str(uuid.uuid4())
        
    data = oidc4vp.oidc4vp_qrcode(verifier_id, session_id, scope, red, mode)
    
    deeplink = data.get("url")
    sess = data.get("session_id", session_id)

    # Build structured flow info
    flow = {
        "session_id": sess,
        "deeplink_url": deeplink,
        "pull_url": f"{pull_status_base.rstrip('/')}/{sess}",
        "public_base_url": public_base_url
    }

    blocks: List[Dict[str, Any]] = []
    b64 = _qr_png_b64(deeplink) if deeplink else None
    if b64:
        blocks.append({"type": "image", "data": b64, "mimeType": "image/png"})
    # Always include a text hint
    text_hint = f"Scan the QR code (if shown) or open wallet link:\n{deeplink}" if deeplink else "No deeplink URL returned."
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
