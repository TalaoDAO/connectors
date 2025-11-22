import io
import json
import base64
from typing import Any, Dict, List, Optional
import logging
import qrcode
from routes.verifier import oidc4vp
from utils import message
import requests



RESOLVER_LIST = [
    'https://unires:test@unires.talao.co/1.0/identifiers/',
    'https://dev.uniresolver.io/1.0/identifiers/',
    'https://resolver.cheqd.net/1.0/identifiers/'
] 

tools_dev = []
tools_guest = []
tools_agent = [
    {
        "name": "start_user_verification",
        "description": (
            "Start a user verification by email invitation. "
            "The agent MUST first ask the user for their email address. "
            "An email is sent with a special link that opens the user's identity "
            "wallet and starts the verification process (no QR code is used). "
            "The tool returns a verification_request_id that MUST be reused "
            "when polling the result."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "description": (
                        "What should be verified in the user's wallet. "
                        "'profile' is first name, last name and birth date; "
                        "'over18' is a proof that the user is older than 18."
                    ),
                    "enum": ["over18", "profile"],
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
            "Poll the verification result for a previously started user verification. "
            "You MUST provide the exact verification_request_id that was returned "
            "by the last call to start_user_verification. "
            "Never derive or guess this value from the email address."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "verification_request_id": {
                    "type": "string",
                    "description": (
                        "The verification_request_id returned in structuredContent "
                        "by start_user_verification."
                    )
                }
            },
            "required": ["verification_request_id"]
        }
    },
    {
        "name": "poll_agent_authentication",
        "description": (
            "Poll the current authentication status for a previously started "
            "agent-to-agent authentication. "
            "You MUST provide the exact authentication_request_id that was "
            "returned by start_agent_authentication. "
            "Never derive or guess this value from the agent DID."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "authentication_request_id": {
                    "type": "string",
                    "description": (
                        "The authentication_request_id returned in structuredContent "
                        "by start_agent_authentication."
                    )
                }
            },
            "required": ["authentication_request_id"]
        }
    },
    {
        "name": "start_agent_authentication",
        "description": (
            "Start another agent authentication. This process is very fast and does "
            "not require user interaction. Immediately after calling this tool, "
            "the Agent SHOULD call poll_agent_authentication with the returned "
            "authentication_request_id to obtain the result."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_identifier": {
                    "type": "string",
                    "description": "The DID of the other agent."
                }
            },
            "required": ["agent_identifier"]
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
    verifier_id = "0001"    
    user_email = arguments.get("user_email")
        
    data = oidc4vp.oidc4vp_qrcode(verifier_id, scope, red, mode)
    if not data:
        return _ok_content(
            [{"type": "text", "text": "Server error"}],
            is_error=True,
        )
    openid_vc_uri = data.get('url')
    url_id = data.get("url_id")
    verification_request_id = data.get("verification_request_id")
    
    email_page_link = mode.server + "verification_email/" + url_id
    
    # Send email
    success = message.messageHTML(
        subject="Your verification link",
        to=user_email,
        HTML_key="verification_en",  # register it in HTML_templates
        format_dict={
            "openid_vc_uri": openid_vc_uri,
            "email_page_link": email_page_link
        },
        mode=mode
    )
    
    # Build structured flow info
    flow = {
        #"user_email": user_email,
        "email_sent": success,
        "verification_request_id": verification_request_id 
    }
    if not success:
        flow["error_description"] = "Failed to send email to user."
    
    blocks: List[Dict[str, Any]] = []

    #b64 = _qr_png_b64(link) if link else None
    #if b64:
    #    blocks.append({"type": "image", "data": b64, "mimeType": "image/png"})
    
    text_hint = f"An email has been sent to you.  Clic on the link in your to open your wallet and present your credential." if success else "No email sent."
    blocks.append({"type": "text", "text": text_hint})
        
    if success and verification_request_id:
        blocks.append({
            "type": "text",
            "text": f"verification_request_id={verification_request_id}"
        })    
    return _ok_content(blocks, structured=flow)


def call_start_agent_authentication(target_agent, agent_identifier, config: dict) -> Dict[str, Any]:
    red = config["REDIS"]
    mode = config["MODE"]
    manager = config["MANAGER"]

    # 1. Create OIDC4VP/SIOPV2 authentication request
    data = oidc4vp.oidc4vp_agent_authentication(target_agent, agent_identifier, red, mode, manager)
    if not data:
        return _ok_content(
            [{"type": "text", "text": "Server error while creating OIDC4VP request"}],
            is_error=True,
        )

    oidc4vp_request = data.get("oidc4vp_request")

    # Default flow values; will be enriched step by step
    flow: Dict[str, Any] = {
        #"agent_identifier": agent_identifier,
        "authentication_request_id": data.get("authentication_request_id"),
        "request_sent": False,
    }

    # 2. Resolve DID Document of the targeted agent
    for res in RESOLVER_LIST:
        try:
            r = requests.get(res + target_agent, timeout=10)
            logging.info("resolver used = %s", res)
            break
        except Exception:
            pass
    did_document = r.json().get('didDocument')
    if not did_document:
        logging.exception("Failed to resolve DID Document for %s", target_agent)
        return _ok_content(
            [{"type": "text", "text": f"Failed to resolve DID Document for {target_agent}"}],
            structured=flow,
            is_error=True,
        )

    # 3. Find OIDC4VP service endpoint in DID Document
    services = did_document.get("service", []) or []
    oidc4vp_endpoint = None
    for svc in services:
        if svc.get("type") == "OIDC4VP":
            oidc4vp_endpoint = svc.get("serviceEndpoint")
            break

    if not oidc4vp_endpoint:
        return _ok_content(
            [{"type": "text", "text": "No OIDC4VP service endpoint found in DID Document."}],
            structured=flow,
            is_error=True,
        )

    #flow["oidc4vp_service_endpoint"] = oidc4vp_endpoint

    # 4. Fetch authorization_endpoint from well-known endpoint
    #    Conventionally: <serviceEndpoint>/.well-known/openid-configuration
    well_known_url = oidc4vp_endpoint.rstrip("/") + "/.well-known/openid-configuration"

    try:
        wk_resp = requests.get(well_known_url, timeout=5)
        wk_resp.raise_for_status()
        metadata = wk_resp.json()
    except Exception as e:
        logging.exception("Failed to fetch OIDC metadata from %s", well_known_url)
        return _ok_content(
            [{"type": "text", "text": f"Failed to fetch OIDC metadata from {well_known_url}: {e}"}],
            structured=flow,
            is_error=True,
        )
    authorization_endpoint = metadata.get("authorization_endpoint")
    if not authorization_endpoint:
        return _ok_content(
            [{"type": "text", "text": "authorization_endpoint not found in OIDC metadata."}],
            structured=flow,
            is_error=True,
        )

    #flow["authorization_endpoint"] = authorization_endpoint

    # 5. Send GET request to the authorization_endpoint with the OIDC4VP request URL
    #    as argument. We use 'request_uri' as a conventional parameter name.
    request = authorization_endpoint + oidc4vp_request.split("//")[1] 
    #flow["request"] = request

    try:
        auth_resp = requests.get(request, timeout=5)
        flow["authorization_http_status"] = auth_resp.status_code
        flow["authorization_response_ok"] = auth_resp.ok
        success = auth_resp.ok
    except Exception as e:
        logging.exception("Failed to call authorization_endpoint %s %s", authorization_endpoint, str(e))
        return _ok_content(
            [{"type": "text", "text": f"Failed to call agent : {target_agent}"}],
            structured=flow,
            is_error=True,
        )

    flow["request_sent"] = success

    blocks: List[Dict[str, Any]] = []
    if success:
        text_hint = "Authentication request has been sent to the other agent."
    else:
        text_hint = (
            "Authentication request could not be sent successfully "
            f"(HTTP status: {flow.get('authorization_http_status')})."
        )
        
    blocks.append({"type": "text", "text": text_hint})

    if success and authentication_request_id:
        blocks.append({
            "type": "text",
            "text": f"authentication_request_id={authentication_request_id}"
        })

    return _ok_content(blocks, structured=flow)



def call_poll_user_verification(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    red = config["REDIS"]
    verification_request_id = arguments.get("verification_request_id")
    
    payload = oidc4vp.wallet_pull_status(verification_request_id, red)
    status = payload.get("status", "pending")

    # current oidc4vp: claims merged at the top level (exclude status/user_id)
    claims = {k: v for k, v in payload.items() if k not in ("status", "id")}

    structured = {"status": status, "verification_request_id": verification_request_id, **claims}

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
        logging.info("verification data attached to %s are deleted from REDIS", verification_request_id)
        red.delete(verification_request_id + "_status")
        red.delete(verification_request_id + "_wallet_data")
    return _ok_content(text_blocks, structured=structured)


def call_poll_agent_authentication(arguments, config: dict) -> Dict[str, Any]:
    red = config["REDIS"]
    
    authentication_request_id = arguments.get("authentication_request_id")
    payload = oidc4vp.wallet_pull_status(authentication_request_id, red)
    status = payload.get("status", "pending")
    structured = {"status": status}

    text_blocks = []
    if status == "verified":
        text = f"Agent has status {status}."
    elif status == "denied":
        text = f"Agent authentication was denied."
    elif status == "pending":
        text = f"Authentication is still pending."
    else:  # e.g. "not_found"
        text = f"Authentication status: {status}."

    text_blocks.append({"type": "text", "text": text})
    text_blocks.append({"type": "text", "text": json.dumps(structured, ensure_ascii=False)})

    if status == "verified":
        logging.info("verification data are deleted from REDIS %s", authentication_request_id)
        red.delete(authentication_request_id + "_status")

    return _ok_content(text_blocks, structured=structured)