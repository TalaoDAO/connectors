import io
import json
import base64
import uuid
from typing import Any, Dict, List, Optional
import logging
import qrcode
from routes.verifier import oidc4vp
from utils import message

tools_dev = []
tools_guest = []
tools_agent = [
    {
        "name": "start_user_verification",
        "description": (
            "Start a user verification by email invitation. "
            "The agent MUST first ask the user for their email address. "
            "An email is sent with a special link that opens the user's identity "
            "wallet and starts the verification process (no QR code is used)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "description": (
                        "What should be verified in the user's wallet. "
                        "'profile' is first name, last name and birth date; "
                        "'over18' is a proof that the user is older than 18; "
                        "'wallet_identifier' is a stable identifier of the wallet."
                    ),
                    "enum": ["over18", "profile", "wallet_identifier"],
                    "default": "profile"
                },
                "user_email": {
                    "type": "string",
                    "description": (
                        "Email address of the user. The verification invitation "
                        "will be sent to this email, and the link in that email "
                        "will open the user's identity wallet to start verification."
                    )
                }
            },
            "required": ["scope", "user_email"]
        }
    },
    {
        "name": "poll_user_verification",
        "description": (
            "Poll the current verification status for a given user_email. "
            "Use this after the user has received the email invitation and "
            "completed (or is completing) the verification in their wallet. "
            "Returns the verification status and any verified wallet data."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_email": {
                    "type": "string",
                    "description": "The user_email associated with the verification session."
                }
            },
            "required": ["user_email"]
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
def call_start_user_verification(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    red = config["REDIS"]
    mode = config["MODE"]

    scope = arguments.get("scope")
    
    verifier_id_for_scope = {
        "wallet_identifier": "0000",
        "over18": "0002",
        "profile": "0003"
    }
    verifier_id = verifier_id_for_scope.get(scope, "custom")
    
    # optional user_id
    user_email = arguments.get("user_email")
        
    data = oidc4vp.oidc4vp_qrcode(verifier_id, user_email, scope, red, mode)
    if not data:
        return _ok_content(
            [{"type": "text", "text": "Server error"}],
            is_error=True,
        )
    openid_vc_uri = data.get('url')
    verif_id = data.get("verif_id")
    email_page_link = mode.server + "verification_email/" + verif_id
    
    # Sed email
    success = message.messageHTML(
        subject="Your verification link",
        to=arguments.get("user_email"),
        HTML_key="verification_en",  # register it in HTML_templates
        format_dict={
            "openid_vc_uri": openid_vc_uri,
            "email_page_link": email_page_link
        },
        mode=mode
    )
    
    # Build structured flow info
    flow = {
        "user_email": user_email,
        "email_sent": success
    }
    
    blocks: List[Dict[str, Any]] = []
    
    #b64 = _qr_png_b64(link) if link else None
    #if b64:
    #    blocks.append({"type": "image", "data": b64, "mimeType": "image/png"})
    
    text_hint = f"An email has been sent to you.  Clic on the link in your to open your wallet and present your credential." if success else "No email sent."
    blocks.append({"type": "text", "text": text_hint})
    return _ok_content(blocks, structured=flow)


def call_poll_user_verification(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    red = config["REDIS"]
    user_email = arguments.get("user_email")
    
    payload = oidc4vp.wallet_pull_status(user_email, red)
    status = payload.get("status", "pending")

    # current oidc4vp: claims merged at the top level (exclude status/user_id)
    claims = {k: v for k, v in payload.items() if k not in ("status", "user_id")}

    structured = {"status": status, "user_email": user_email, **claims}

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

    if status == "verified":
        logging.info("verification data attached to %s are deleted from REDIS", user_email)
        red.delete(user_email)
        red.delete(user_email + "_wallet_data")
        red.delete(user_email + "_status")
    return _ok_content(text_blocks, structured=structured)
