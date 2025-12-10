
import json
from typing import Any, Dict, List, Optional
from db_model import Wallet
import logging
from routes import wallet
from db_model import Wallet, Attestation, db
import requests
import base64
from urllib.parse import unquote
import time                       # <-- ADD
from datetime import datetime      # <-- ADD
import linked_vp
from utils import message

RESOLVER_LIST = [
    "https://unires:test@unires.talao.co/1.0/identifiers/",
    "https://dev.uniresolver.io/1.0/identifiers/",
    "https://resolver.cheqd.net/1.0/identifiers/",
]


tools_agent_receive_credentials = [
    {
        "name": "accept_credential_offer",
        "description": (
            "Accept an OIDC4VCI credential offer on behalf of this Agent and return "
            "the issued credential. The issued object is typically a Verifiable "
            "Credential (VC), which can then be stored in the Agent's wallet or "
            "published for later presentation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "credential_offer": {
                    "type": "string",
                    "description": (
                        "An OIDC4VCI credential offer, or a credential_offer_uri as "
                        "provided by an external issuer."
                    )
                }
            },
            "required": ["credential_offer"]
        }
    }
]
tools_agent_sign = [
    {
        "name": "sign_text_message",
        "description": (
            "Sign a text message using this Agent's DID and private keys."
            "Return the base64-encoded signature bytes. Use this tool to prove you are the admin of your DID and private keys."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "The text message to sign."
                }
            },
            "required": ["message"]
        }
    },
    {
        "name": "sign_json_payload",
        "description": (
            "Sign a json payload using this Agent's DID and private keys."
            "Return a JWS in Compact Serialization"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload": {
                    "type": "string",
                    "description": "The payload as a json."
                }
            },
            "required": ["payload"]
        }
    }
]

    
tools_agent_others = [
    {
        "name": "resolve_agent_identifier",
        "description": (
            "Resolve an Agent identifier (DID) and summarize its DID Document. "
            "Useful to understand another Agent's public keys, services and Linked VPs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_identifier": {
                    "type": "string",
                    "description": "The DID of the Agent to resolve (e.g. did:web:wallet4agent.com:xyz)."
                }
            },
            "required": ["agent_identifier"]
        }
    },
    {
        "name": "get_this_agent_data",
        "description": (
            "Retrieve a high-level overview of this Agent's identity and its attached wallet configuration. "
            "The Agent is identified by its DID. The wallet is a secure component attached "
            "to the Agent that stores verifiable credentials on its behalf. "
            "This tool returns metadata such as the Agent's DID, the ecosystem profile, the wallet endpoint URL, "
            "the number of stored attestations, and whether a human is always kept in the loop."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_attestations_of_this_wallet",
        "description": (
            "List all attestations (verifiable credentials) stored in the wallet that is "
            "attached to this Agent. The Agent is identified by its DID, while the wallet "
            "serves as the secure storage and credential manager. Use this tool to inspect "
            "what credentials the Agent currently holds."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_attestations_of_another_agent",
        "description": (
            "Resolve another Agent's DID and retrieve its published attestations. "
            "The DID identifies the Agent itself. The returned attestations are "
            "verifiable credentials or linked verifiable presentations that the "
            "Agent has chosen to expose publicly (for example AgentCards, proofs "
            "of authorization, capability statements, or certificates)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_identifier": {
                    "type": "string",
                    "description": (
                        "The DID of the Agent whose published attestations should be "
                        "listed (for example: did:web:wallet4agent.com:demo:abc...)."
                    ),
                }
            },
            "required": ["agent_identifier"]
        }
    },
    {
        "name": "describe_wallet4agent",
        "description": (
            "Explain what the Wallet4Agent MCP server and its wallet do. Use this "
            "tool when you need to understand the concepts of 'wallet', 'Agent', and "
            "'digital/verifiable credentials' in this ecosystem before calling "
            "other tools."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "help_wallet4agent",
        "description": (
            "Explain to a human developer how to install and use the Wallet4Agent MCP "
            "server with their own agent. Describe at a high level:\n"
            "- How to install and run the Wallet4Agent MCP server.\n"
            "- How to configure and use the manifest.json so the agent can discover the MCP server.\n"
            "- How to connect as a guest, and how to obtain a developer personal access token (PAT).\n"
            "- How to create a new Agent identifier (DID) and an attached wallet for that Agent, "
            "including how the DID document is published and where the wallet endpoint lives.\n"
            "- How to configure the agent to use that DID and wallet (including storing the PAT safely).\n"
            "- Basic security best practices for protecting keys, PATs, and the wallet endpoint.\n\n"
            "Use this tool whenever a developer asks how to get started with Wallet4Agent, how to "
            "create a DID or wallet for an Agent, or how to wire the Agent and wallet together."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
]

tools_agent_publish_unpublish = [
    {
        "name": "publish_attestation",
        "description": (
            "Publish one of this Agent's stored attestations as a Linked Verifiable "
            "Presentation in the DID Document. The attestation itself is already "
            "stored in the wallet; this tool only exposes it via a Linked VP "
            "service. Supports both did:web and did:cheqd identifiers."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "attestation_id": {
                    "type": "integer",
                    "description": (
                        "The local Attestation ID (from get_attestations_of_this_wallet "
                        "structuredContent.id) to publish."
                    )
                }
            },
            "required": ["attestation_id"]
        }
    },
    {
        "name": "unpublish_attestation",
        "description": (
            "Unpublish one of this Agent's previously published attestations: "
            "it removes the Linked Verifiable Presentation from the DID Document "
            "and from the wallet's linked_vp registry, but keeps the credential "
            "stored locally. Supports both did:web and did:cheqd identifiers."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "attestation_id": {
                    "type": "integer",
                    "description": (
                        "The local Attestation ID (from get_attestations_of_this_wallet "
                        "structuredContent.id) to unpublish."
                    )
                }
            },
            "required": ["attestation_id"]
        }
    }
]

tools_agent = (
    tools_agent_receive_credentials
    + tools_agent_sign
    + tools_agent_publish_unpublish
    + tools_agent_others
)

def _ok_content(blocks: List[Dict[str, Any]], structured: Optional[Dict[str, Any]] = None, is_error: bool = False) -> Dict[str, Any]:
    out: Dict[str, Any] = {"content": blocks}
    if structured is not None:
        out["structuredContent"] = structured
    if is_error:
        out["isError"] = True
    return out


def admin_message(wallet, message_text, mode):
    if wallet.always_human_in_the_loop and wallet.notification_email:
        to = wallet.notification_email
        subject = f"Agent: {wallet.did}"
        message.message(subject, to, message_text, mode)
        

def _decode_sd_jwt_local(sd_jwt_token: str) -> Optional[Dict[str, Any]]:
    """
    Decode a locally stored SD-JWT or SD-JWT+KB (the compact form you keep
    in Attestation.vc when vc_format is 'dc+sd-jwt' or 'vc+sd-jwt').

    This reuses _extract_sd_jwt_payload_from_data_uri by wrapping the token
    into a synthetic data: URI, so we get exactly the same behavior and
    return structure as when parsing SD-JWTs from Linked VPs.

    Returns a dict shaped like:
      {
        "vc": {...},
        "vc_jwt": "<issuer VC-JWT>",
        "vc_valid": True/False,
        "vc_validity_status": "valid" | "expired" | "not_yet_valid" | "invalid_date_format",
        "vc_validity_reasons": [...],
        "credentialSubject": {...}  # if present
      }
    or None if the token cannot be parsed.
    """
    if not isinstance(sd_jwt_token, str):
        return None

    token = sd_jwt_token.strip()
    if not token:
        return None

    # Reuse the existing parser logic by constructing a synthetic data: URI
    synthetic_data_uri = f"data:application/dc+sd-jwt,{token}"
    return _extract_sd_jwt_payload_from_data_uri(synthetic_data_uri)


def _summarize_local_attestation(att: Attestation) -> Dict[str, Any]:
    """
    Turn an Attestation SQL row into a structured dict, trying to decode the VC
    when possible (SD-JWT, JWT VC etc.).
    """
    item: Dict[str, Any] = {
        "id": att.id,
        "wallet_did": att.wallet_did,
        "service_id": att.service_id,
        "name": att.name,
        "description": att.description,
        "issuer": att.issuer,
        "vc_format": att.vc_format,
        "vct": att.vct,
        "published": bool(att.published),
        "created_at": att.created_at.isoformat() if att.created_at else None,
        "exp": att.exp.isoformat() if att.exp else None,
    }

    raw_vc = (att.vc or "").strip()
    if not raw_vc:
        return item

    fmt = (att.vc_format or "").lower()

    # ---- SD-JWT formats (dc+sd-jwt / vc+sd-jwt) ----
    if fmt in ["dc+sd-jwt", "vc+sd-jwt"]:
        decoded = _decode_sd_jwt_local(raw_vc)
        if decoded:
            item["decoded"] = decoded
            item["credentialSubject"] = decoded.get("credentialSubject")

    # ---- JWT-VC formats (jwt_vc_json / jwt_vc_json-ld) ----
    elif fmt in ["jwt_vc_json", "jwt_vc_json-ld"]:
        # raw_vc is a JWT, possibly followed by disclosures (for sd-jwt style).
        jwt_token = raw_vc.split("~", 1)[0]
        try:
            payload_full = _decode_jwt_payload_full(jwt_token)
        except Exception:
            payload_full = None
        if isinstance(payload_full, dict):
            vc_data = payload_full.get("vc", payload_full)
            if isinstance(vc_data, dict):
                item["decoded"] = {
                    "vc": vc_data,
                    "vc_jwt": jwt_token,
                }
                if isinstance(vc_data.get("credentialSubject"), dict):
                    item["credentialSubject"] = vc_data["credentialSubject"]

    # ---- ldp_vc or plain JSON VC ----
    else:
        try:
            maybe_json = json.loads(raw_vc)
            if isinstance(maybe_json, dict):
                item["decoded"] = {"vc": maybe_json}
                if isinstance(maybe_json.get("credentialSubject"), dict):
                    item["credentialSubject"] = maybe_json["credentialSubject"]
        except Exception:
            # not JSON, leave as is
            pass

    return item


def _parse_iso8601_to_timestamp(value: str) -> Optional[float]:
    """
    Parse an ISO8601 datetime string into a UNIX timestamp (seconds since epoch).
    Handles nanosecond precision by truncating to 6 fractional digits (microseconds).
    Returns None if parsing still fails.
    """
    try:
        original = value

        # Normalize trailing 'Z' to '+00:00' so datetime.fromisoformat can handle it
        tz_suffix = ""
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        # Split off timezone offset if present (+HH:MM or -HH:MM)
        # e.g. "2025-04-05T16:12:06.056491516+00:00"
        tz_pos = max(value.rfind("+"), value.rfind("-"))
        if tz_pos > value.find("T"):
            datetime_part = value[:tz_pos]
            tz_suffix = value[tz_pos:]
        else:
            datetime_part = value

        # Truncate fractional seconds to at most 6 digits
        if "." in datetime_part:
            date_part, frac_part = datetime_part.split(".", 1)
            # frac_part might still contain something like "056491516"
            # (only digits) so just cut to 6 digits
            digits = "".join(ch for ch in frac_part if ch.isdigit())
            digits = digits[:6]  # microseconds precision
            datetime_part = f"{date_part}.{digits}"
        # Rebuild full string for fromisoformat
        norm = datetime_part + tz_suffix

        dt = datetime.fromisoformat(norm)
        return dt.timestamp()
    except Exception:
        logging.exception("Failed to parse ISO8601 datetime %s", value)
        return None


def _extract_vc_from_jwt_vp(jwt_vp: str) -> Optional[Dict[str, Any]]:
    """
    From a VP in compact JWT format, extract the embedded VC
    and compute a simple date-based validity for that VC.

    Returns a dict that can be merged into an attestation, e.g.:
      {
        "vc": { ... VC JSON ... },
        "credentialSubject": { ... },
        "vc_valid": True/False,
        "vc_validity_status": "valid" | "expired" | "not_yet_valid" | "invalid_date_format",
        "vc_validity_reasons": [ ...optional text reasons... ]
      }
    """
    # 1. Decode VP payload (full, no claim stripping)
    vp_payload = _decode_jwt_payload_full(jwt_vp)
    if not isinstance(vp_payload, dict):
        logging.warning("VP-JWT payload is not a JSON object")
        return None

    vp_obj = vp_payload.get("vp") or {}
    if not isinstance(vp_obj, dict):
        logging.warning("VP-JWT has no 'vp' object")
        return None

    vcs = vp_obj.get("verifiableCredential") or []
    if not vcs or not isinstance(vcs, list):
        logging.warning("VP-JWT 'vp.verifiableCredential' is missing or not a list")
        return None

    vc_jwt = vcs[0]
    if not isinstance(vc_jwt, str):
        logging.warning("First verifiableCredential in VP is not a string JWT")
        return None

    # 2. Decode VC payload
    vc_payload_full = _decode_jwt_payload_full(vc_jwt)
    if not isinstance(vc_payload_full, dict):
        logging.warning("VC-JWT payload is not a JSON object")
        return None

    # VC data itself is usually under "vc"
    vc_data = vc_payload_full.get("vc", vc_payload_full)
    if not isinstance(vc_data, dict):
        logging.warning("VC data is not a JSON object")
        return None

    # 3. Date-based validity check
    now_ts = time.time()
    status = "valid"
    reasons: List[str] = []

    # Check VC-JWT level nbf / exp
    nbf = vc_payload_full.get("nbf")
    exp = vc_payload_full.get("exp")

    if isinstance(nbf, (int, float)) and now_ts < nbf:
        status = "not_yet_valid"
        reasons.append(f"VC not yet valid (nbf={nbf}, now={int(now_ts)})")

    if isinstance(exp, (int, float)) and now_ts > exp:
        status = "expired"
        reasons.append(f"VC expired (exp={exp}, now={int(now_ts)})")

    # Check VC-level validFrom / expirationDate (ISO8601)
    valid_from_str = vc_data.get("validFrom") or vc_data.get("issuanceDate")
    expiration_str = vc_data.get("expirationDate")

    if valid_from_str:
        ts = _parse_iso8601_to_timestamp(valid_from_str)
        if ts is None:
            if status == "valid":
                status = "invalid_date_format"
            reasons.append(f"Cannot parse validFrom/issuanceDate: {valid_from_str}")
        elif now_ts < ts and status == "valid":
            status = "not_yet_valid"
            reasons.append(f"VC not yet valid (validFrom={valid_from_str})")

    if expiration_str:
        ts = _parse_iso8601_to_timestamp(expiration_str)
        if ts is None:
            if status == "valid":
                status = "invalid_date_format"
            reasons.append(f"Cannot parse expirationDate: {expiration_str}")
        elif now_ts > ts and status == "valid":
            status = "expired"
            reasons.append(f"VC expired (expirationDate={expiration_str})")

    # 4. Build result to merge into attestation
    result: Dict[str, Any] = {
        "vc": vc_data,
        "vc_jwt": vc_jwt,  
        "vc_valid": (status == "valid"),
        "vc_validity_status": status,
    }
    if reasons:
        result["vc_validity_reasons"] = reasons

    credential_subject = vc_data.get("credentialSubject")
    if isinstance(credential_subject, dict):
        # Expose credentialSubject at top level too (often what you want to see)
        result["credentialSubject"] = credential_subject

    return result

# for admin and agent
def call_get_attestations_of_this_wallet(
    wallet_did: str,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """
    List all attestations stored for THIS Agent's wallet.

    - Looks up Attestation rows by wallet_did
    - For each one, tries to decode the underlying VC / SD-JWT
    - Returns both human-readable text blocks and a structured JSON payload
      suitable for an Agent.
    """

    logging.info("Listing attestations for wallet %s", wallet_did)

    attestations = (
        Attestation.query
        .filter_by(wallet_did=wallet_did)
        .order_by(Attestation.created_at.desc())
        .all()
    )

    items: List[Dict[str, Any]] = []
    for att in attestations:
        try:
            items.append(_summarize_local_attestation(att))
        except Exception as e:
            logging.exception("Failed to summarize attestation %s", att.id)
            # Fallback: minimal info
            items.append({
                "id": att.id,
                "wallet_did": att.wallet_did,
                "service_id": att.service_id,
                "name": att.name,
                "description": att.description,
                "vc_format": att.vc_format,
                "published": bool(att.published),
                "error": f"summary_error: {e}",
            })

    # Build a short human-readable text summary for MCP UI
    if not items:
        text = (
            "This Agent's wallet does not contain any stored attestations yet. "
            "You may ask a human or an external issuer to send new credential offers "
            "that the Agent can accept."
        )
    else:
        lines = [f"Found {len(items)} attestation(s) for this Agent:"]
        for att in items[:10]:  # don't flood the UI
            line = f"- #{att.get('id')} — {att.get('name') or 'Unnamed attestation'}"
            if att.get("issuer"):
                line += f" | issuer: {att['issuer']}"
            if att.get("vc_format"):
                line += f" | format: {att['vc_format']}"
            if att.get("published"):
                line += " | published"
            lines.append(line)
        if len(items) > 10:
            lines.append(f"... and {len(items) - 10} more.")
        text = "\n".join(lines)

    structured = {
        "wallet_did": wallet_did,
        "attestations": items,
    }

    return _ok_content(
        [{"type": "text", "text": text}],
        structured=structured,
    )


def _parse_data_uri(data_uri: str) -> (Optional[str], Optional[str]):
    """
    Parse a data: URI into (media_type, data_string).
    Example: data:application/dc+sd-jwt,eyJhbGciOi...
    """
    if not isinstance(data_uri, str) or not data_uri.startswith("data:"):
        return None, None

    # Strip "data:"
    body = data_uri[5:]
    # Split media type and data
    if "," not in body:
        return None, None
    media_type, data_part = body.split(",", 1)
    if not media_type:
        media_type = "text/plain;charset=US-ASCII"

    # Data might be URL-encoded
    data_str = unquote(data_part)
    return media_type, data_str


def _decode_jwt_payload_full(jwt_token: str) -> Optional[Dict[str, Any]]:
    """
    Decode a JWT payload without removing any claims.
    Used when we need access to exp/nbf or other meta fields.
    """
    try:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload_json = json.loads(payload_bytes.decode("utf-8"))
        return payload_json
    except Exception:
        logging.exception("Failed to decode JWT payload (full)")
        return None

"""
def _decode_jwt_payload(jwt_token: str) -> Optional[Dict[str, Any]]:
    try:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        # add padding if needed
        padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload_json = json.loads(payload_bytes.decode("utf-8"))
        for claim in ["vct", "iat", "exp", "cnf", "_sd", "_sd_alg", "iss", "status"]:
            payload_json.pop(claim, None)
        return payload_json
    except Exception:
        logging.exception("Failed to decode JWT payload")
        return None
"""

def _extract_sd_jwt_payload_from_data_uri(data_uri: str) -> Optional[Dict[str, Any]]:
    """
    From a data: URI that contains an SD-JWT or SD-JWT+KB, extract the embedded
    VC-JWT and compute the same date-based validity as _extract_vc_from_jwt_vp.

    The returned dict has the same shape as _extract_vc_from_jwt_vp, so callers
    (like call_get_attestations_of_another_agent) see a consistent structure:
      {
        "vc": { ... },
        "vc_jwt": "<issuer VC-JWT>",
        "vc_valid": True/False,
        "vc_validity_status": "...",
        "vc_validity_reasons": [...],
        "credentialSubject": { ... }  # if present
      }
    """
    media_type, data_str = _parse_data_uri(data_uri)
    if media_type is None or data_str is None:
        return None

    lowered = media_type.lower()
    # Only handle SD-JWT / JWT-like media types
    if "sd-jwt" not in lowered and "jwt" not in lowered:
        return None

    # SD-JWT(+KB): first segment before "~" is the issuer-signed JWT
    parts = data_str.split("~", 1)
    if not parts or not parts[0]:
        return None

    issuer_jwt = parts[0]

    # Decode the issuer VC-JWT with all claims preserved
    vc_payload_full = _decode_jwt_payload_full(issuer_jwt)
    if not isinstance(vc_payload_full, dict):
        logging.warning("SD-JWT issuer JWT payload is not a JSON object")
        return None

    # VC data itself is usually under "vc"; fall back to full payload if absent
    vc_data = vc_payload_full.get("vc", vc_payload_full)
    if not isinstance(vc_data, dict):
        logging.warning("SD-JWT VC data is not a JSON object")
        return None

    # --- Date-based validity checks (same logic as _extract_vc_from_jwt_vp) ---
    now_ts = time.time()
    status = "valid"
    reasons: List[str] = []

    # Check VC-JWT level nbf / exp
    nbf = vc_payload_full.get("nbf")
    exp = vc_payload_full.get("exp")

    if isinstance(nbf, (int, float)) and now_ts < nbf:
        status = "not_yet_valid"
        reasons.append(f"VC not yet valid (nbf={nbf}, now={int(now_ts)})")

    if isinstance(exp, (int, float)) and now_ts > exp:
        status = "expired"
        reasons.append(f"VC expired (exp={exp}, now={int(now_ts)})")

    # Check VC-level validFrom / issuanceDate / expirationDate (ISO8601)
    valid_from_str = vc_data.get("validFrom") or vc_data.get("issuanceDate")
    expiration_str = vc_data.get("expirationDate")

    if valid_from_str:
        ts = _parse_iso8601_to_timestamp(valid_from_str)
        if ts is None:
            if status == "valid":
                status = "invalid_date_format"
            reasons.append(f"Cannot parse validFrom/issuanceDate: {valid_from_str}")
        elif now_ts < ts and status == "valid":
            status = "not_yet_valid"
            reasons.append(f"VC not yet valid (validFrom={valid_from_str})")

    if expiration_str:
        ts = _parse_iso8601_to_timestamp(expiration_str)
        if ts is None:
            if status == "valid":
                status = "invalid_date_format"
            reasons.append(f"Cannot parse expirationDate: {expiration_str}")
        elif now_ts > ts and status == "valid":
            status = "expired"
            reasons.append(f"VC expired (expirationDate={expiration_str})")

    # --- Build result in the same shape as _extract_vc_from_jwt_vp ---
    result: Dict[str, Any] = {
        "vc": vc_data,
        "vc_jwt": issuer_jwt,
        "vc_valid": (status == "valid"),
        "vc_validity_status": status,
    }
    if reasons:
        result["vc_validity_reasons"] = reasons

    credential_subject = vc_data.get("credentialSubject")
    if isinstance(credential_subject, dict):
        result["credentialSubject"] = credential_subject

    return result



def call_get_attestations_of_another_agent(wallet_did: str) -> Dict[str, Any]:
    """
    List attestations (Linked VPs) of an Agent DID.

    For each LinkedVerifiablePresentation service:
      * Fetch its verifiable presentation from serviceEndpoint.
      * If it's a JSON-LD VerifiablePresentation, embed VP JSON-LD.
      * If it's an EnvelopedVerifiablePresentation with an SD-JWT VC
        (data:application/dc+sd-jwt,...), embed the decoded SD-JWT payload.
    """

    # 1. Resolve DID using Universal Resolver (Talao -> fallback to public)
    resolver_urls = [
        f"https://unires:test@unires.talao.co/1.0/identifiers/{wallet_did}",
        f"https://dev.uniresolver.io/1.0/identifiers/{wallet_did}",
    ]
    did_doc = None
    last_exception = None

    for url in resolver_urls:
        try:
            logging.info("Resolving DID %s via %s", wallet_did, url)
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            payload = r.json()
            logging.info("DID Resolution response: %s", payload)
            did_doc = payload.get("didDocument") or {}
            break
        except Exception as e:
            logging.exception("Failed to resolve DID via %s", url)
            last_exception = e

    if did_doc is None:
        logging.warning("Failed to resolve DID %s via all resolvers", wallet_did)
        text = f"Could not resolve DID {wallet_did} using Universal Resolver."
        structured = {
            "attestations": [],
            "error": "cannot_access_universal_resolver",
            "details": str(last_exception) if last_exception else None,
        }
        return _ok_content([{"type": "text", "text": text}], structured=structured)

    # 2. Extract LinkedVerifiablePresentation services as "attestations"
    services: List[Dict[str, Any]] = did_doc.get("service", []) or []

    wallet_attestations: List[Dict[str, Any]] = []

    for svc in services:
        svc_type = svc.get("type", "")
        # type can be string or list
        if isinstance(svc_type, list):
            is_linked_vp = "LinkedVerifiablePresentation" in svc_type
        else:
            is_linked_vp = svc_type == "LinkedVerifiablePresentation"

        if not is_linked_vp:
            continue

        service_endpoint = svc.get("serviceEndpoint")
        attestation: Dict[str, Any] = {
            "attestation_id": svc.get("id"),
            #"name": svc.get("label") or "Linked Verifiable Presentation",
            #"description": "LinkedVerifiablePresentation service discovered in DID Document",
            #"service_endpoint": service_endpoint,
            #"validity": "active",  # assumption; revocation could be checked in a registry
        }

        # 2.a Fetch VP from serviceEndpoint (if HTTP(S))
        vp_json: Optional[Dict[str, Any]] = None
        vp_jwt: Optional[str] = None

        if isinstance(service_endpoint, str):
            if service_endpoint.startswith("data:"):
                # Endpoint itself is a data: URI; handled later by SD-JWT extractor
                vp_json = None
            else:
                try:
                    logging.info("Fetching VP from serviceEndpoint %s", service_endpoint)
                    resp = requests.get(service_endpoint, timeout=10)
                    resp.raise_for_status()
                    body = (resp.text or "").strip()
                    content_type = (resp.headers.get("Content-Type") or "").lower()

                    # Try JSON first if Content-Type suggests it
                    if "application/json" in content_type or "ld+json" in content_type:
                        try:
                            vp_json = resp.json()
                        except Exception:
                            logging.exception("Failed to parse VP JSON from %s", service_endpoint)
                            vp_json = None
                    else:
                        # Try JSON anyway if it looks like JSON
                        if body.startswith("{") or body.startswith("["):
                            try:
                                vp_json = resp.json()
                            except Exception:
                                logging.exception("Failed to parse VP JSON from %s", service_endpoint)
                                vp_json = None

                        # If not JSON, check if it looks like a compact JWT VP
                        if vp_json is None and body.count(".") == 2:
                            logging.info("ServiceEndpoint %s returned compact JWT VP", service_endpoint)
                            vp_jwt = body

                except Exception:
                    logging.exception("Failed to fetch serviceEndpoint %s", service_endpoint)

        # 2.b Decide representation based on VCDM 2.0 types / envelope

        # Case 1: JSON-LD VP / Enveloped VP JSON object
        if isinstance(vp_json, dict):
            # case: jwt_vp_json format:
            jwt_vp_candidate = vp_json.get("jwt_vp_json") or vp_json.get("vp_jwt")
            if isinstance(jwt_vp_candidate, str) and jwt_vp_candidate.count(".") == 2:
                logging.info("Detected jwt_vp_json wrapper at %s", service_endpoint)
                vc_info = _extract_vc_from_jwt_vp(jwt_vp_candidate)
                if vc_info is not None:
                    attestation.update(vc_info)
                else:
                    attestation["raw"] = vp_json
            else:
                vp_type = vp_json.get("type", [])
                if isinstance(vp_type, str):
                    vp_type_list = [vp_type]
                else:
                    vp_type_list = vp_type or []

                # EnvelopedVerifiablePresentation per VCDM 2.0
                if "EnvelopedVerifiablePresentation" in vp_type_list:
                    data_uri = vp_json.get("id")
                    payload = None
                    if isinstance(data_uri, str) and data_uri.startswith("data:"):
                        payload = _extract_sd_jwt_payload_from_data_uri(data_uri)

                    if payload is not None:
                        attestation.update(payload)
                    else:
                        attestation["envelope"] = vp_json

                # Non-enveloped VerifiablePresentation JSON-LD
                elif "VerifiablePresentation" in vp_type_list:
                    attestation["verifiable_presentation"] = vp_json

                else:
                    # Unknown type, but still JSON; keep for debugging
                    attestation["raw"] = vp_json

        # Case 2: HTTP(S) endpoint returned a compact JWT VP directly
        elif isinstance(vp_jwt, str):
            vc_info = _extract_vc_from_jwt_vp(vp_jwt)
            if vc_info is not None:
                attestation.update(vc_info)
            else:
                attestation["raw"] = vp_jwt

        # Case 3: serviceEndpoint itself is a data: URI (no JSON wrapper)
        elif isinstance(service_endpoint, str) and service_endpoint.startswith("data:"):
            payload = _extract_sd_jwt_payload_from_data_uri(service_endpoint)
            if payload is not None:
                attestation.update(payload)
            else:
                attestation["raw"] = service_endpoint

        else:
            # We couldn't fetch or parse a VP; keep meta only
            attestation["format"] = "unavailable"

        wallet_attestations.append(attestation)

    structured = {"attestations": wallet_attestations}

    # 3. Human-readable text for MCP client
    if not wallet_attestations:
        text = f"No attestations found for Agent DID {wallet_did}."
    else:
        nb_attestations = str(len(wallet_attestations))
        text = f"{nb_attestations} attestations of Agent DID {wallet_did}."
        i = 1
        for attest in wallet_attestations:
            text += "\n attestation #" + str(i) + " = " + json.dumps(attest)
            i += 1
    return _ok_content([{"type": "text", "text": text}], structured=structured)



def call_get_this_agent_data(agent_identifier) -> Dict[str, Any]:
    """
    Return a high-level overview of this Agent's identity (DID) and its attached wallet.

    The DID identifies the Agent itself.
    The wallet is a secure component attached to this Agent that stores credentials.
    """
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    attestations_list = Attestation.query.filter_by(wallet_did=agent_identifier).all()
    
    # number of published attestation:
    nb_published_attestations = 0
    for a in attestations_list:
        if a.published == 1:
            nb_published_attestations += 1
        
    structured = {
        "agent": {
            "did": agent_identifier,
        },
        "wallet": {
            "wallet_endpoint": this_wallet.url if this_wallet else None,
            "ecosystem": this_wallet.ecosystem_profile,
            "number_of_attestations": len(attestations_list),
            "number_of_published_attestations": nb_published_attestations,
            "human_in_the_loop": bool(this_wallet.always_human_in_the_loop) if this_wallet else False,
            "sign": bool(this_wallet.sign) if this_wallet else False,
            "publish_unpublish": bool(this_wallet.publish_unpublish) if this_wallet else False,
            "receive_credentials": bool(this_wallet.receive_credentials) if this_wallet else False,
        },
    }

    if this_wallet:
        text = (
            f"My DID is {agent_identifier}. "
            f"I have an attached wallet at {this_wallet.url} "
            f"with a total of {len(attestations_list)} attestations. "
            f"{'I need a human in the loop' if this_wallet.always_human_in_the_loop else 'I dont need a human'}."
            f"{'I can sign payload' if this_wallet.sign else 'I cannot sign payload'}."
            f"{'I can receive credentials' if this_wallet.receive_credentials else 'I cannot receive credentials'}."
            f"{'I can publish and unpublish attestations'  if this_wallet.publish_unpublish else 'I cannot publish or unpublish attestations'}."
        )
    else:
        text = (
            f"My DID is {agent_identifier}, but py wallet has not be found in the database."
        )

    return _ok_content([{"type": "text", "text": text}], structured=structured)


# agent tool
def call_accept_credential_offer( arguments: Dict[str, Any], agent_identifier: str, config: dict ) -> Dict[str, Any]:
    """
    MCP tool: accept an OIDC4VCI credential offer for this Agent.
    The 'credential_offer' argument may be:
    - the full 'openid-credential-offer://' URI,
    - an HTTPS URL with 'credential_offer_uri' or 'credential_offer' params,
    - or the JSON 'credential_offer' object as a string.
    We delegate the heavy lifting to wallet.build_session_config / wallet.wallet.
    """
    raw_offer = arguments.get("credential_offer")
    logging.info("accept_credential_offer called with: %r (%s)", raw_offer, type(raw_offer))

    if raw_offer is None:
        return _ok_content(
            [{"type": "text", "text": "Missing 'credential_offer' argument."}],
            is_error=True,
        )
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    if this_wallet.always_human_in_the_loop:
        return _ok_content(
            [{"type": "text", "text": "Human in the loop is needed."}],
            is_error=True,
        )
    if not this_wallet.receive_credentials:
        return _ok_content(
            [{"type": "text", "text": "Agent cannot receive credentials"}],
            is_error=True,
        )

    message_text = "Agent receives an attestation"
    admin_message(this_wallet, message_text, config["MODE"])
    
    
    # Normalize input for wallet.wallet():
    # - dict -> keep as-is
    # - string:
    #     * if it looks like JSON, try json.loads
    #     * otherwise, pass the string through (URI / URL case)
    if isinstance(raw_offer, dict):
        normalized_offer = raw_offer
    elif isinstance(raw_offer, str):
        stripped = raw_offer.strip()

        # Heuristic: only try to parse as JSON if it *looks* like JSON
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                normalized_offer = json.loads(stripped)
                logging.info("Parsed credential_offer string as JSON object.")
            except Exception:
                # Not actually valid JSON → let wallet.build_session_config do its own parsing
                logging.exception("Failed to json.loads credential_offer string; using raw string instead.")
                normalized_offer = raw_offer
        else:
            # Likely an openid-credential-offer:// or HTTPS URL.
            # build_session_config() will handle 'credential_offer_uri' / 'credential_offer'.
            normalized_offer = raw_offer
    else:
        # Unsupported type
        msg = f"Unsupported credential_offer type: {type(raw_offer)}. Expected string or object."
        logging.warning(msg)
        return _ok_content([{"type": "text", "text": msg}], is_error=True)

    mode = config["MODE"]
    manager = config["MANAGER"]

    # Delegate to the wallet OIDC4VCI client logic to receive the attestation
    try:
        session_config, attestation, text = wallet.wallet(agent_identifier, normalized_offer, mode, manager) 
    except Exception:
        msg = "Incorret credential_offer format"
        logging.warning(msg)
        return _ok_content([{"type": "text", "text": msg}], is_error=True)
    
    # store and publish if consent
    if attestation:
        if session_config["always_human_in_the_loop"]:
            structured = {
                "attestation": attestation
            }
            text = "Thank you, I have received the attestation but I cannot store this attestation without the my admin consent."
            return _ok_content([{"type": "text", "text": text}], is_error=False, structured=structured)
        else:
            result, message = wallet.store_and_publish(attestation, session_config, mode, manager, published=True)
            if result:
                message = "Thank you, the attestation has been stored and published successfully."
                return _ok_content([{"type": "text", "text": message}], is_error=False)
            else:
                message = "Sorry, I have received the attestation but I could not store it."
                return _ok_content([{"type": "text", "text": text}], is_error=False)
    else:
        return _ok_content([{"type": "text", "text": text}], is_error=True)


def call_describe_wallet4agent() -> Dict[str, Any]:
    """
    Self-description tool for the Wallet4Agent MCP server.

    Returns a human-readable explanation plus structured information about:
      - what the server is,
      - what a wallet is in this context,
      - how it relates to AI agents and digital/verifiable credentials.
    """

    text = (
        "This is the Wallet4Agent MCP server. It exposes tools for interacting with a "
        "digital wallet dedicated to AI agents.\n\n"
        "In this context, a wallet is a secure software component that stores and "
        "manages digital credentials and verifiable credentials (including W3C VCs "
        "and SD-JWT VCs) on behalf of a subject: a human, an organization, or an AI "
        "agent acting for them.\n\n"
        "The wallet can:\n"
        "- accept credentials from external issuers via protocols like OIDC4VCI,\n"
        "- store those credentials as attestations for later use,\n"
        "- present them to verifiers as verifiable presentations (including Linked "
        "Verifiable Presentations published in DID Documents), and\n"
        "- act as the identity and authorization layer for AI agents.\n\n"
        "AI agents use this wallet as their 'identity and credentials layer' so that "
        "every action or delegation can be traced back to a responsible human or "
        "organization, enabling accountability, interoperability, and compliance."
    )

    structured = {
        "server": "wallet4agent-mcp",
        "role": "agent_wallet_and_credential_orchestrator",
        "wallet_definition": {
            "short": "Secure store and orchestrator for digital and verifiable credentials.",
            "details": [
                "Stores W3C Verifiable Credentials and SD-JWT VCs.",
                "Receives credentials via OIDC4VCI and similar issuance protocols.",
                "Presents credentials as verifiable presentations to other parties.",
                "Binds credentials to humans, organizations, and AI agents via DIDs.",
            ],
        },
        "agent_context": {
            "purpose": (
                "Provide AI agents with an attached, accountable identity and "
                "a portable set of credentials for cross-ecosystem interactions."
            ),
            "key_concepts": [
                "agent wallet",
                "digital credentials",
                "verifiable credentials",
                "proof of delegation / authorization",
                "Linked Verifiable Presentation",
            ],
        },
    }

    return _ok_content(
        [{"type": "text", "text": text}],
        structured=structured,
    )


def call_help_wallet4agent() -> Dict[str, Any]:
    """
    Agent tool: serve the up-to-date 'get_started.md' documentation to a developer.

    This reads the markdown file from disk and returns it as text so the LLM
    (or MCP Inspector) can present the actual, current documentation.
    """
    try:
        with open("documentation/get_started.md", "r", encoding="utf-8") as f:
            md_text = f.read()

        text = md_text
        structured = {
            "topic": "installation_and_integration",
            "audience": "developer",
            "format": "markdown",
            "source": "get_started.md",
        }

        return _ok_content(
            [{"type": "text", "text": text}],
            structured=structured,
        )

    except Exception as e:
        # Fallback: simple error message if the file cannot be read
        fallback_text = (
            "I tried to load the developer guide 'get_started.md' from the server, "
            "but an error occurred while reading the file. "
            "Please check that get_started.md is deployed alongside the MCP server "
            f"code. (Details: {str(e)})"
        )
        return _ok_content(
            [{"type": "text", "text": fallback_text}],
            structured={"error": "cannot_read_get_started_md"},
            is_error=True,
        )
        

def call_sign_text_message(arguments: Dict[str, Any], agent_identifier: str, config: dict) -> Dict[str, Any]:
    message = arguments.get("message", "")
    if not isinstance(message, str):
        message = str(message)
    
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    if not this_wallet.sign:
        return _ok_content(
            [{"type": "text", "text": "Agent cannot sign."}],
            is_error=True,
        )
    message_text = f"Agent signs message: {message}"
    admin_message(this_wallet, message_text, config["MODE"])
        
    # Prefer injected manager
    manager = config.get("MANAGER")
    vm_id = agent_identifier + "#key-1"

    try:
        # lazily create or fetch tenant key
        key_id = manager.create_or_get_key_for_tenant(vm_id)
        sig, _ = manager.sign_message(key_id, message.encode("utf-8"))
        sig_b64 = base64.b64encode(sig).decode("ascii")

        structured = {
            "agent_did": agent_identifier,
            "message": message,
            "signature_base64": sig_b64,
        }
        text = f"Signed message for Agent {agent_identifier}. Base64 signature: {sig_b64}"
        return _ok_content([{"type": "text", "text": text}], structured=structured)

    except Exception as e:
        logging.exception("Failed to sign text message with KMS %s", str(e))
        text = f"Failed to sign message with my DID."
        return _ok_content([{"type": "text", "text": text}], is_error=True)


def call_sign_json_payload(arguments: Dict[str, Any], agent_identifier: str, config: dict) -> Dict[str, Any]:
    payload = arguments.get("payload", "")
    payload = json.loads(payload)
    
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    if not this_wallet.sign:
        return _ok_content(
            [{"type": "text", "text": "Agent cannot sign."}],
            is_error=True,
        )
        
    message_text = "Agent signs payload"
    admin_message(this_wallet, message_text, config["MODE"])

    # Prefer injected manager
    manager = config.get("MANAGER")
    vm_id = agent_identifier + "#key-1"
    
    try:
        # lazily create or fetch tenant key
        key_id = manager.create_or_get_key_for_tenant(vm_id)
        jwk, kid, alg = manager.get_public_key_jwk(key_id)
        header = {
            "typ": "JWT",
            "alg": alg,
            "kid": agent_identifier + "#key-1"
        }
        signed_json = manager.sign_jwt_with_key(key_id, header, payload)
        structured = {
            "agent_did": agent_identifier,
            "payload": payload,
            "signed_json": signed_json,
        }
        text = f"Signed payload for Agent {agent_identifier}. jws: {signed_json}"
        return _ok_content([{"type": "text", "text": text}], structured=structured)

    except Exception as e:
        logging.exception("Failed to sign text message with KMS %s", str(e))
        text = f"Failed to sign message with my DID"
        return _ok_content([{"type": "text", "text": text}], is_error=True)
    
    
def call_resolve_agent_identifier(
    arguments: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Resolve any DID and return its DID Document + a human-readable summary.
    This is especially useful for resolving other Agents (did:web, did:cheqd, ...).
    """
    target = arguments.get("agent_identifier")
    if not target:
        return _ok_content(
            [{"type": "text", "text": "Missing 'agent_identifier' argument."}],
            is_error=True,
        )

    did_document = None
    last_error = None

    for base in RESOLVER_LIST:
        try:
            resp = requests.get(base + target, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                did_document = data.get("didDocument") or data.get("did_document") or data
                if did_document:
                    break
            else:
                last_error = f"{base}: HTTP {resp.status_code}"
        except Exception as e:
            last_error = f"{base}: {str(e)}"
            continue

    if did_document is None:
        msg = f"Unable to resolve DID {target} via configured resolvers."
        if last_error:
            msg += f" Last error: {last_error}"
        return _ok_content(
            [{"type": "text", "text": msg}],
            is_error=True,
        )

    vm_list = did_document.get("verificationMethod", [])
    services = did_document.get("service", [])

    # Quick categorization of services
    linked_vp_services = [
        s for s in services if s.get("type") == "LinkedVerifiablePresentation"
    ]

    structured = {
        "did": did_document.get("id", target),
        "did_document": did_document,
        "verification_methods_count": len(vm_list),
        "services_count": len(services),
        "linked_vp_services": linked_vp_services,
    }

    text_lines = [
        f"DID resolution for {target}:",
        f"- id: {structured['did']}",
        f"- verification methods: {structured['verification_methods_count']}",
        f"- services: {structured['services_count']}",
    ]
    if linked_vp_services:
        text_lines.append(f"- Linked VP services: {len(linked_vp_services)}")
    else:
        text_lines.append("- Linked VP services: none")

    text = "\n".join(text_lines)

    return _ok_content(
        [{"type": "text", "text": text}],
        structured=structured,
    )


def call_publish_attestation(arguments: Dict[str, Any], agent_identifier: str, config: dict) -> Dict[str, Any]:
    """
    Agent tool: publish an existing Attestation as a LinkedVerifiablePresentation
    service in the Agent's DID Document.

    - Keeps the VC in the Attestation row
    - Updates wallet.linked_vp
    - Updates DID Document (service entry)
    - For did:cheqd, also updates the DID on-ledger via Universal Registrar
    """
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    if not this_wallet.publish_unpublish:
        return _ok_content(
            [{"type": "text", "text": "Agent cannot publish attestations."}],
            is_error=True,
        )
        
    message_text = "Agent publishes an attestation"
    admin_message(this_wallet, message_text, config["MODE"])
    
    attestation_id = arguments.get("attestation_id")
    if attestation_id is None:
        return _ok_content(
            [{"type": "text", "text": "Missing 'attestation_id' argument."}],
            is_error=True,
        )

    mode = config["MODE"]
    manager = config["MANAGER"]

    att = Attestation.query.filter_by(id=attestation_id, wallet_did=agent_identifier).one_or_none()
    if not att:
        msg = f"No attestation with id {attestation_id} for Agent {agent_identifier}."
        logging.warning(msg)
        return _ok_content([{"type": "text", "text": msg}], is_error=True)

    # Ensure we have a service_id; if not, create one (non-OASF case)
    service_id = att.service_id
    if not service_id:
        local_id = secrets.token_hex(16)
        service_id = f"{agent_identifier}#{local_id}"
        att.service_id = service_id

    vc = att.vc
    vc_format = att.vc_format or "dc+sd-jwt"

    result = linked_vp.publish_linked_vp(
        service_id=service_id,
        attestation=vc,
        server=mode.server,
        mode=mode,
        manager=manager,
        vc_format=vc_format,
    )

    if not result:
        msg = f"Failed to publish attestation {attestation_id} as Linked VP."
        logging.warning(msg)
        return _ok_content([{"type": "text", "text": msg}], is_error=True)

    att.published = True
    db.session.commit()

    structured = {
        "attestation_id": att.id,
        "wallet_did": att.wallet_did,
        "service_id": service_id,
        "published": True,
        "linked_vp": result,
    }
    text = (
        f"Attestation #{att.id} has been published as a Linked Verifiable "
        f"Presentation with service id {service_id}."
    )
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def call_unpublish_attestation(arguments: Dict[str, Any], agent_identifier: str, config: dict) -> Dict[str, Any]:
    """
    Agent tool: unpublish a previously published Attestation.

    - Removes the Linked VP from wallet.linked_vp
    - Removes the LinkedVerifiablePresentation service from the DID Document
    - For did:cheqd, also updates the DID on-ledger via Universal Registrar
    - Keeps the Attestation (VC) stored locally, but sets published=False
    """
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    if not this_wallet.publish_unpublish:
        return _ok_content(
            [{"type": "text", "text": "Agent cannot unpublish attestations."}],
            is_error=True,
        )
    
    message_text = "Agent unpublishes an attestation"
    admin_message(this_wallet, message_text, config["MODE"])
    
    attestation_id = arguments.get("attestation_id")
    if attestation_id is None:
        return _ok_content(
            [{"type": "text", "text": "Missing 'attestation_id' argument."}],
            is_error=True,
        )

    mode = config["MODE"]
    manager = config["MANAGER"]

    att = Attestation.query.filter_by(id=attestation_id, wallet_did=agent_identifier).one_or_none()
    if not att:
        msg = f"No attestation with id {attestation_id} for Agent {agent_identifier}."
        logging.warning(msg)
        return _ok_content([{"type": "text", "text": msg}], is_error=True)

    if not att.service_id:
        msg = (
            f"Attestation #{att.id} does not have a service_id and is not currently "
            f"published as a Linked Verifiable Presentation."
        )
        logging.info(msg)
        return _ok_content([{"type": "text", "text": msg}], is_error=True)

    service_id = att.service_id

    result = linked_vp.unpublish_linked_vp(
        service_id=service_id,
        server=mode.server,
        mode=mode,
        manager=manager,
    )

    if not result:
        msg = f"Failed to unpublish attestation {attestation_id}."
        logging.warning(msg)
        return _ok_content([{"type": "text", "text": msg}], is_error=True)

    att.published = False
    db.session.commit()

    structured = {
        "attestation_id": att.id,
        "wallet_did": att.wallet_did,
        "service_id": service_id,
        "published": False,
        "unpublished": True,
    }
    text = (
        f"Attestation #{att.id} has been unpublished and is no longer exposed "
        f"as a Linked Verifiable Presentation in the DID Document. Nobody can access to this attestation anymore."
    )
    return _ok_content([{"type": "text", "text": text}], structured=structured)
