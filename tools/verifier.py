import io
import json
import base64
import uuid
from typing import Any, Dict, List, Optional
import logging
import requests
import qrcode


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
def call_start_wallet_verification(arguments: Dict[str, Any], verifier_api_key: Optional[str], config: dict) -> Dict[str, Any]:
    verifier_api_start = config["VERIFIER_API_START"]
    pull_status_base = config["PULL_STATUS_BASE"]
    public_base_url = config["PUBLIC_BASE_URL"]

    verifier_id = arguments.get("verifier_id")
    
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
        
    payload = {"verifier_id": verifier_id, "session_id": session_id, "scope": scope}
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-API-KEY": verifier_api_key
    }
    try:
        r = requests.post(verifier_api_start, json=payload, headers=headers, timeout=30)
    except Exception as e:
        return _ok_content(
            [{"type": "text", "text": f"Network error calling oidc4vp API : {e}"}],
            structured={"error": "network_error", "detail": str(e)},
            is_error=True
        )
    if r.status_code >= 400:
        txt = r.text
        try:
            err = r.json()
        except Exception:
            err = {"status": r.status_code, "body": txt}
        return _ok_content(
            [{"type": "text", "text": f"Verifier API error {r.status_code}"}],
            structured={"error": "upstream_error", "upstream": err},
            is_error=True
        )

    data = r.json()
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

def call_poll_wallet_verification(arguments: Dict[str, Any], verifier_api_key: Optional[str], config: dict) -> Dict[str, Any]:
    pull_status_base = config["PULL_STATUS_BASE"]
    session_id = arguments.get("session_id")
    if not session_id:
        return _ok_content(
            [{"type": "text", "text": "session_id is required"}],
            structured={"error": "invalid_arguments", "missing": ["session_id"]},
            is_error=True
        )
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-API-KEY": verifier_api_key
    }
    try:
        r = requests.get(f"{pull_status_base.rstrip('/')}/{session_id}", headers=headers, timeout=20)
        payload = r.json()
    except Exception as e:
        return _ok_content(
            [{"type": "text", "text": f"Network error polling status: {e}"}],
            structured={"error": "network_error", "detail": str(e)},
            is_error=True
        )

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

def call_revoke_wallet_flow(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    session_id = arguments.get("session_id")
    if not session_id:
        return _ok_content(
            [{"type": "text", "text": "session_id is required"}],
            structured={"error": "invalid_arguments", "missing": ["session_id"]},
            is_error=True
        )
    red = config["REDIS"]
    red.delete(session_id)
    structured = {"ok": True, "session_id": session_id}
    return _ok_content([{"type": "text", "text": "Flow revoked (TTL cleanup handled server-side)."}], structured=structured)

