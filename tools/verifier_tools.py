import io
import json
import base64
from typing import Any, Dict, List, Optional
import logging
import qrcode
from routes import verifier
from utils import message
import requests

RESOLVER_LIST = [
    'https://unires:test@unires.talao.co/1.0/identifiers/',
    'https://dev.uniresolver.io/1.0/identifiers/',
    'https://resolver.cheqd.net/1.0/identifiers/'
]

tools_dev: List[Dict[str, Any]] = []
tools_guest: List[Dict[str, Any]] = []

tools_agent: List[Dict[str, Any]] = [
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
            "by start_user_verification. Never derive or guess this value from "
            "the email address."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "verification_request_id": {
                    "type": "string",
                    "description": (
                        "The verification_request_id returned in structuredContent "
                        "by start_user_verification. It is not the user email."
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
                        "by start_agent_authentication. It is not the agent identifier."
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
    },
]


def _ok_content(
    blocks: List[Dict[str, Any]],
    structured: Optional[Dict[str, Any]] = None,
    is_error: bool = False,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"content": blocks}
    if structured is not None:
        out["structuredContent"] = structured
    if is_error:
        out["isError"] = True
    return out


# --------- Tool implementations ---------
def call_start_user_verification(arguments: Dict[str, Any], agent_identifier, config: dict) -> Dict[str, Any]:
    """
    Start an email-based OIDC4VP verification and send the user a mail.
    Returns a human message plus structuredContent with verification_request_id.
    """
    red = config["REDIS"]
    mode = config["MODE"]
    manager = config["MANAGER"]

    scope = arguments.get("scope")
    user_email = arguments.get("user_email")

    # Create OIDC4VP request & internal verification_request_id
    data = verifier.user_verification(agent_identifier, scope, red, mode, manager)
    if not data:
        return _ok_content(
            [{"type": "text", "text": "Server error while preparing verification."}],
            is_error=True,
        )

    openid_vc_uri = data.get("url")
    url_id = data.get("url_id")  # internal reference used by email page
    verification_request_id = data.get("verification_request_id")
    email_page_link = mode.server + "verification_email/" + url_id

    # Send email
    success = message.messageHTML(
        subject="Your verification link",
        to=user_email,
        HTML_key="verification_en",  # HTML template
        format_dict={
            "openid_vc_uri": openid_vc_uri,
            "email_page_link": email_page_link,
        },
        mode=mode,
    )

    # Structured info (for the LLM / tools, not for user UI)
    flow: Dict[str, Any] = {
        "scope": scope,
        "user_email": user_email,
        "email_sent": success,
        "verification_request_id": verification_request_id,
    }

    blocks: List[Dict[str, Any]] = []
    if success:
        text_hint = (
            f"An email has been sent to {user_email}. Open it to start the verification "
            f"in the identity wallet. The verification_request_id is '{verification_request_id}'"
        )
    else:
        text_hint = (
            "The verification email could not be sent. Please check your email "
            "address or try again later."
        )

    blocks.append({"type": "text", "text": text_hint})
    # No technical IDs in text
    return _ok_content(blocks, structured=flow)


def call_start_agent_authentication(
    target_agent: str, agent_identifier: str, config: dict
) -> Dict[str, Any]:
    """
    Start an agent-to-agent OIDC4VP authentication by:
    - Creating an OIDC4VP auth request
    - Resolving the target agent DID to find its OIDC4VP service endpoint
    - Fetching its OIDC metadata to find authorization_endpoint
    - Sending the OIDC4VP request to that authorization_endpoint
    Returns a human message and structuredContent with authentication_request_id.
    """
    red = config["REDIS"]
    mode = config["MODE"]
    manager = config["MANAGER"]
    myenv = config["MYENV"]

    # Create OIDC4VP/SIOPV2 request for agent authentication
    data = verifier.agent_authentication(
        target_agent, agent_identifier, red, mode, manager
    )
    if not data:
        return _ok_content(
            [{"type": "text", "text": "Server error while creating authentication request."}],
            is_error=True,
        )

    oidc4vp_request = data.get("oidc4vp_request")
    authentication_request_id = data.get("authentication_request_id")

    # Base flow info stored as structuredContent
    flow: Dict[str, Any] = {
        "target_agent": target_agent,
        "authentication_request_id": authentication_request_id,
        "request_sent": False,
    }
    if myenv != "local":
        # 2. Resolve DID Document of the targeted agent to get the agent endpoint
        for res in RESOLVER_LIST:
            try:
                r = requests.get(res + target_agent, timeout=10)
                logging.info("resolver used = %s", res)
                break
            except Exception:
                pass
        try:
            did_doc = r.json().get('didDocument')
        except Exception:
            did_doc = None
        if not did_doc:
            logging.exception("Failed to resolve DID Document for %s", target_agent)
            return _ok_content(
                [{"type": "text", "text": f"Failed to resolve DID Document for {target_agent}"}],
                structured=flow,
                is_error=True,
            )

        # Find service of type OIDC4VP
        services = did_doc.get("service", [])
        oidc4vp_endpoint = None
        for s in services:
            stype = s.get("type")
            if isinstance(stype, list):
                if "OIDC4VP" in stype:
                    oidc4vp_endpoint = s.get("serviceEndpoint")
                    break
            elif stype == "OIDC4VP":
                oidc4vp_endpoint = s.get("serviceEndpoint")
                break
        
        if not oidc4vp_endpoint:
            return _ok_content(
                [{"type": "text", "text": "No OIDC4VP service endpoint found in the agent's DID Document."}],
                structured=flow,
                is_error=True,
            )
    else: # for testing
        oidc4vp_endpoint = mode.server + target_agent 

    # 2. Fetch authorization_endpoint from well-known endpoint
    try:
        well_known_url = oidc4vp_endpoint.rstrip("/") + "/.well-known/openid-configuration"
    except Exception:
        logging.info("serviceEndpoint is an array")
        well_known_url = oidc4vp_endpoint[0].rstrip("/") + "/.well-known/openid-configuration"        
    
    try:
        wk_resp = requests.get(well_known_url, timeout=5)
        wk_resp.raise_for_status()
        metadata = wk_resp.json()
    except Exception:
        logging.exception("Failed to fetch OIDC metadata from %s", well_known_url)
        return _ok_content(
            [
                {
                    "type": "text",
                    "text": "Failed to contact the other agent's authentication service.",
                }
            ],
            structured=flow,
            is_error=True,
        )

    authorization_endpoint = metadata.get("authorization_endpoint")
    if not authorization_endpoint:
        return _ok_content(
            [{"type": "text", "text": "authorization_endpoint not found in the other agent's OIDC metadata."}],
            structured=flow,
            is_error=True,
        )

    # 3. Call the authorization_endpoint with the OIDC4VP request URL
    #    We reuse the request URI part after the scheme to keep it simple.
    request_url = authorization_endpoint + oidc4vp_request.split("//", 1)[1]

    try:
        auth_resp = requests.get(request_url, timeout=10)
        success = auth_resp.ok
    except Exception as e:
        logging.exception("Failed to call authorization_endpoint %s: %s", authorization_endpoint, str(e))
        return _ok_content(
            [{"type": "text", "text": f"Failed to send authentication request to the other agent: {target_agent}."}],
            structured=flow,
            is_error=True,
        )

    flow["request_sent"] = success

    blocks: List[Dict[str, Any]] = []
    if success:
        text_hint = f"Authentication request has been sent to the other agent. The 'authentication_request_id' is {authentication_request_id}"
    else:
        text_hint = f"Authentication request could not be sent successfully to: {target_agent}."

    blocks.append({"type": "text", "text": text_hint})
    # No technical IDs in text; authentication_request_id is only in structuredContent
    return _ok_content(blocks, structured=flow)


def call_poll_user_verification(arguments: Dict[str, Any], agent_identifier, config: dict) -> Dict[str, Any]:
    """
    Poll the verification result given a verification_request_id.
    Returns user-friendly text and structuredContent with status + claims.
    """
    red = config["REDIS"]
    verification_request_id = arguments.get("verification_request_id")

    payload = verifier.wallet_pull_status(verification_request_id, red)
    status = payload.get("status", "pending")
    # fallback
    if status == "not_found":
        fallback_id = agent_identifier + "_last_user_verification"
        payload = verifier.wallet_pull_status(fallback_id, red)
        status = payload.get("status", "pending")

    # claims are all non-technical keys
    claims = {k: v for k, v in payload.items() if k not in ("status", "id", "user_verification_id", "scope")}
    scope = payload.get("scope")
    structured = {
        "status": status,
        "verification_request_id": verification_request_id,
        **claims,
    }
    text_blocks: List[Dict[str, Any]] = []

    # Human messages depending on scope / status
    if status == "pending":
        text = (
            "User verification is still pending. Please open the email and "
            "approve the request in the identity wallet."
        )
    elif status == "verified":
        if scope == "over18":
            text = "User age has been verified as over 18."
        elif scope == "profile":
            text = "The user identity profile has been verified from his wallet. User data received: " + json.dumps(claims)
        elif scope == "wallet_identifier" and claims.get("wallet_identifier"):
            text = f"The user wallet identifier has been verified: {claims.get('wallet_identifier')}."
        else:
            text = "User verification has completed successfully."
    elif status == "denied":
        text = "User verification was denied."
    else:  # not_found or other
        text = "I could not retrieve user verification result. We may need to restart the process."

    text_blocks.append({"type": "text", "text": text})
    return _ok_content(text_blocks, structured=structured)


def call_poll_agent_authentication(arguments: Dict[str, Any], agent_identifier, config: dict) -> Dict[str, Any]:
    """
    Poll the status of an agent-to-agent authentication given authentication_request_id.
    """
    red = config["REDIS"]
    authentication_request_id = arguments.get("authentication_request_id")

    payload = verifier.wallet_pull_status(authentication_request_id, red)
    status = payload.get("status", "pending")
    # fallback
    if status == "not_found":
        fallback_id = agent_identifier + "_last_agent_authentication"
        payload = verifier.wallet_pull_status(fallback_id, red)
        status = payload.get("status", "pending")

    structured = {"status": status, "authentication_request_id": authentication_request_id}

    text_blocks: List[Dict[str, Any]] = []
    if status == "verified":
        text = "The other Agent is successfully authenticated."
    elif status == "denied":
        text = "The other Agent authentication failed."
    elif status == "pending":
        text = "The other Agent authentication is still pending."
    else:  # not_found or other
        text = "I could not retrieve the agent authentication result."

    text_blocks.append({"type": "text", "text": text})

    return _ok_content(text_blocks, structured=structured)
