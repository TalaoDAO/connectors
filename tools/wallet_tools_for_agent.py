
import json
from typing import Any, Dict, List, Optional
from db_model import Wallet
import logging
from routes import wallet
from db_model import Attestation
import requests
import base64
from urllib.parse import unquote
import time                       # <-- ADD
from datetime import datetime      # <-- ADD




tools_agent = [
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
    },
    {
        "name": "sign_text_message",
        "description": (
            "Sign a text message using this Agent's DID and private keys."
            "Return the base64-encoded signature bytes. Use this tool to prove you are the owner of your DID and private keys."
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
    },
    {
        "name": "get_this_wallet_data",  # get agent identity ?
        "description": (
            "Retrieve a high-level overview of this Agent's identity and its attached wallet. "
            "The Agent is identified by its DID. The wallet is a secure component attached "
            "to the Agent that stores verifiable credentials on its behalf. "
            "This tool returns metadata such as the Agent's DID, the wallet endpoint URL, "
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
    "name": "explain_how_to_install_wallet4agent",
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


def _ok_content(blocks: List[Dict[str, Any]], structured: Optional[Dict[str, Any]] = None, is_error: bool = False) -> Dict[str, Any]:
    out: Dict[str, Any] = {"content": blocks}
    if structured is not None:
        out["structuredContent"] = structured
    if is_error:
        out["isError"] = True
    return out


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

# for dev and agent
def call_get_attestations_of_this_wallet(wallet_did, config) -> Dict[str, Any]:
    # Query attestations linked to this wallet, published or not 
    attestations_list = Attestation.query.filter_by(wallet_did=wallet_did).all()
    wallet_attestations = []
    for attestation in attestations_list:
        validity = "active"
        decoded_vc = _decode_jwt_payload(attestation.vc)
        wallet_attestations.append(
            {
                "attestation_id": attestation.id,
                "attestation_content": decoded_vc,
                "name": attestation.name,
                "description": attestation.description,
                "issuer": attestation.issuer,
                "iat": attestation.created_at.isoformat() if attestation.created_at else None,
                "validity": validity,
                "is_published": attestation.published
            }
        )        
    structured = {
        "nb_of_attestations": len(wallet_attestations),
        "attestations": wallet_attestations
    }
    if not wallet_attestations:
        text = "0 attestation found"
    else:
        text = str(len(wallet_attestations)) +  " attestations found in the wallet : " + json.dumps(wallet_attestations)
    return _ok_content([{"type": "text", "text": text}], structured=structured)


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


def _decode_jwt_payload(jwt_token: str) -> Optional[Dict[str, Any]]:
    """
    Decode JWT payload (no signature verification).
    """
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



def call_get_this_wallet_data(agent_identifier) -> Dict[str, Any]:
    """
    Return a high-level overview of this Agent's identity (DID) and its attached wallet.

    The DID identifies the Agent itself.
    The wallet is a secure component attached to this Agent that stores credentials.
    """
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    attestations_list = Attestation.query.filter_by(wallet_did=agent_identifier).all()

    structured = {
        "agent": {
            "did": agent_identifier,
        },
        "wallet": {
            "endpoint": this_wallet.url if this_wallet else None,
            "number_of_attestations": len(attestations_list),
            "human_in_the_loop": bool(this_wallet.always_human_in_the_loop) if this_wallet else False,
        },
    }

    if this_wallet:
        text = (
            f"This Agent's DID is {agent_identifier}. "
            f"It has an attached wallet at {this_wallet.url} "
            f"with {len(attestations_list)} attestations. "
            f"Human in the loop: {'yes' if this_wallet.always_human_in_the_loop else 'no'}."
        )
    else:
        text = (
            f"This Agent's DID is {agent_identifier}, but no wallet record "
            "was found in the database."
        )

    return _ok_content([{"type": "text", "text": text}], structured=structured)


# agent tool
def call_accept_credential_offer(arguments: Dict[str, Any], agent_identifier, config: dict) -> Dict[str, Any]:
    credential_offer = arguments.get("credential_offer")
    if isinstance(credential_offer, str):
        credential_offer = json.loads(credential_offer)
    mode = config["MODE"]
    manager = config["MANAGER"]
    attestation, text = wallet.wallet(agent_identifier, credential_offer, mode, manager)
    if not attestation:
        return _ok_content([{"type": "text", "text": text}], is_error=True)     
    structured = {
        "attestation": attestation
    }
    text = "Attestation successfully received (not stored automatically)."
    return _ok_content([{"type": "text", "text": text}], structured=structured)



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


def call_explain_how_to_install_wallet4agent() -> Dict[str, Any]:
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

    # Prefer injected manager
    manager = config.get("MANAGER")

    try:
        # lazily create or fetch tenant key
        key_id = manager.create_or_get_key_for_tenant(agent_identifier)
        sig, _ = manager.sign_message(key_id, message.encode("utf-8"))
        sig_b64 = base64.b64encode(sig).decode("ascii")

        structured = {
            "agent_did": agent_identifier,
            "message": message,
            "signature_base64": sig_b64,
            "signing_algorithm": "ECDSA_SHA_256",
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

    # Prefer injected manager
    manager = config.get("MANAGER")
    
    try:
        # lazily create or fetch tenant key
        key_id = manager.create_or_get_key_for_tenant(agent_identifier)
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