import json
from typing import Any, Dict, List, Optional
from db_model import Wallet, db, User
import secrets
import logging
from sqlalchemy import and_
from routes import wallet
from db_model import Attestation
from utils import deterministic_jwk, oidc4vc, message
import urllib
import requests
import base64
from urllib.parse import unquote
import tenant_kms


tools_guest = [
    {
        "name": "create_agent_identifier_and_wallet",
        "description": "Generate an identifier (DID) for the Agent in the ecosystem and create a new wallet to store Agent digital credentials",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agentcard_url": {
                    "type": "string",
                    "description": "Optional AgentCard URL."
                },
                "always_human_in_the_loop": {
                    "type": "boolean",
                    "description": "Always human in the loop",
                    "default": True
                },
                "organization": {
                    "type": "string",
                    "description": "Optional company name of the Agent provider",
                },
                "owners_identity_provider": {
                    "type": "string",
                    "description": "Identity provider for owners",
                    "enum": ["google", "github", "wallet"],
                    "default": "google"
                },
                "owners_login": {
                    "type": "string",
                    "description": "One or more user login separated by a comma (Google email, Github login, personal wallet DID)"
                },
                "ecosystem": {
                    "type": "string",
                    "description": "Ecosystem profile",
                    "enum": ["EBSI V3", "DIIP V4", "DIIP V3", "ARF"],
                    "default": "DIIP V4"
                },
                "agent_framework": {
                    "type": "string",
                    "description": "Agent framework",
                    "enum": ["None", "Agntcy"],
                    "default": "None"
                }
            },
            "required": ["owners_identity_provider", "owners_login"]
        }
    }
]
tools_agent = [
    {
        "name": "accept_credential_offer",
        "description": (
            "Accept an OIDC4VCI credential offer on behalf of this AI agent and return "
            "the issued digital credential. The credential is typically a Verifiable "
            "Credential (VC), often in SD-JWT VC format, that can later be stored in "
            "the agent's wallet or presented to third parties."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "credential_offer": {
                    "type": "string",
                    "description": (
                        "OIDC4VCI credential offer or credential_offer_uri as provided "
                        "by an external issuer."
                    )
                }
            },
            "required": ["credential_offer"]
        }
    },
    {
        "name": "get_wallet_data",
        "description": (
            "Retrieve a high-level overview of this agent's wallet. The wallet is a "
            "secure software component that stores and manages digital and verifiable "
            "credentials (e.g., W3C VCs, SD-JWT VCs) for the agent and the humans or "
            "organizations it represents. This tool returns metadata such as the "
            "wallet URL, ecosystem profile, number of stored attestations, and whether "
            "a human is always kept in the loop."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_wallet_attestations",
        "description": (
            "List all attestations (verifiable credentials) currently stored in this "
            "agent's wallet. Use this to understand what has been issued about the "
            "agent (or its owner), such as AgentCards, proofs of delegation, "
            "capabilities, or organizational attributes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_agent_attestations",
        "description": (
            "Resolve another agent's DID and retrieve its published attestations."
            " These are digital credentials that the agent "
            " has chosen to expose publicly via its DID, such as "
            "AgentCards, proofs of authorization, capability statements or certificates."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_identifier": {
                    "type": "string",
                    "description": (
                        "The DID of the agent whose published attestations should be "
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
            "tool first if you need to understand the concepts of 'wallet', 'agent', "
            "and 'digital/verifiable credentials' in this ecosystem before calling "
            "other tools."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
]

tools_dev = [
    {
        "name": "get_identity_data",
        "description": "Get all information about an agent identity",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "delete_wallet",
        "description": "Delete the current wallet",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "rotate_bearer_token",
        "description": "Rotate one of the bearer tokens",
        "inputSchema": {
            "type": "object",
            "properties": {
                "role": {
                    "type": "string",
                    "description": "Choose the token to rotate",
                    "enum": ["agent", "dev"],
                    "default": "dev"
                }
            },
            "required": []
        }
    },
    {
        "name": "add_authentication_key",
        "description": "Add an authentication public key",
        "inputSchema": {
            "type": "object",
            "properties": {
                "public_key": {
                    "type": "string",
                    "description": "Public key as a JWK (JSON Web Key) encoded as a JSON string"
                }
            },
            "required": ["public_key"]
        }
    },
    {
        "name": "get_wallet_attestations",
        "description": "Get all attestations of the wallet",
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


def call_get_wallet_attestations(wallet_did, config) -> Dict[str, Any]:
    # Query attestations linked to this wallet
    attestations_list = Attestation.query.filter_by(wallet_did=wallet_did).all()
    wallet_attestations = []
    for attestation in attestations_list:
        validity = "active"
        wallet_attestations.append(
            {
                "attestation_id": attestation.id,
                "vc": attestation.vc,
                "name": attestation.name,
                "description": attestation.description,
                "issuer": attestation.issuer,
                "iat": attestation.created_at.isoformat() if attestation.created_at else None,
                "validity": validity
            }
        )        
    structured = {"attestations": wallet_attestations}
    if not wallet_attestations:
        text = "No attestation found"
    else:
        text = "All attestations of the Agent"
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
    From a data: URI that contains an SD-JWT or SD-JWT+KB, extract the
    Issuer-signed JWT payload as JSON.
    We assume format:
      - SD-JWT:    <issuer-jwt>~<disclosure>~...~
      - SD-JWT+KB: <issuer-jwt>~<disclosure>~...~<kb-jwt>
    """
    media_type, data_str = _parse_data_uri(data_uri)
    if media_type is None or data_str is None:
        return None

    # Only handle SD-JWT / VC-JWT-like media types here
    # (dc+sd-jwt is used for SD-JWT VC; vc+sd-jwt is legacy).:contentReference[oaicite:1]{index=1}
    lowered = media_type.lower()
    if "sd-jwt" not in lowered and "jwt" not in lowered:
        return None

    # If SD-JWT(+KB), first segment before the first "~" is the issuer JWT.
    issuer_jwt = data_str.split("~", 1)[0]
    payload = _decode_jwt_payload(issuer_jwt)
    return payload


def call_get_agent_attestations(wallet_did: str) -> Dict[str, Any]:
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
        vp_json = None
        if isinstance(service_endpoint, str):
            if service_endpoint.startswith("data:"):
                # Endpoint itself is a data: URI
                vp_json = None  # handled below as enveloped only
            else:
                try:
                    logging.info("Fetching VP from serviceEndpoint %s", service_endpoint)
                    resp = requests.get(service_endpoint, timeout=10)
                    resp.raise_for_status()
                    # Expect a JSON VP envelope by default
                    try:
                        vp_json = resp.json()
                    except Exception:
                        logging.exception("Failed to parse VP JSON from %s", service_endpoint)
                        vp_json = None
                except Exception:
                    logging.exception("Failed to fetch serviceEndpoint %s", service_endpoint)

        # 2.b Decide representation based on VCDM 2.0 types / envelope

        # Case 1: JSON-LD VP / Enveloped VP JSON object
        if isinstance(vp_json, dict):
            vp_type = vp_json.get("type", [])
            if isinstance(vp_type, str):
                vp_type_list = [vp_type]
            else:
                vp_type_list = vp_type or []

            # EnvelopedVerifiablePresentation per VCDM 2.0.:contentReference[oaicite:2]{index=2}
            if "EnvelopedVerifiablePresentation" in vp_type_list:
                data_uri = vp_json.get("id")
                payload = None
                if isinstance(data_uri, str) and data_uri.startswith("data:"):
                    payload = _extract_sd_jwt_payload_from_data_uri(data_uri)

                if payload is not None:
                    #attestation["format"] = "sd_jwt_vc"
                    #attestation["payload"] = payload
                    attestation.update(payload)
                else:
                    # Fallback: store the raw envelope
                    #attestation["format"] = "enveloped_vp"
                    attestation["envelope"] = vp_json

            # Non-enveloped VerifiablePresentation JSON-LD
            elif "VerifiablePresentation" in vp_type_list:
                #attestation["format"] = "vp_jsonld"
                attestation["verifiable_presentation"] = vp_json

            else:
                # Unknown type, but still JSON; keep for debugging
                #attestation["format"] = "unknown_json"
                attestation["raw"] = vp_json

        # Case 2: serviceEndpoint itself is a data: URI (no JSON wrapper)
        elif isinstance(service_endpoint, str) and service_endpoint.startswith("data:"):
            payload = _extract_sd_jwt_payload_from_data_uri(service_endpoint)
            if payload is not None:
                #attestation["format"] = "sd_jwt_vc"
                #attestation["payload"] = payload
                attestation.update(payload)
            else:
                #attestation["format"] = "unknown_data_uri"
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


# for agent
def call_get_wallet_data(agent_identifier) -> Dict[str, Any]:
    # Query attestations linked to this wallet
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    attestations_list = Attestation.query.filter_by(wallet_did=agent_identifier).all()
    structured = {
        "agent_identifier": agent_identifier,
        "wallet_url": this_wallet.url,
        "number_of_attestations": len(attestations_list),
        "ecosystem_profile": this_wallet.ecosystem_profile,
        "human_in_the_loop": this_wallet. always_human_in_the_loop
        }
    text = "Agent identifier is " + agent_identifier + " and wallet url is " + this_wallet.url
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def call_delete_wallet(wallet_did, config) -> Dict[str, Any]:
    """
    Delete a wallet and its related data from the database.

    - Removes the Wallet row identified by `wallet_did`
    - Removes all Attestations linked to this wallet
    - Returns a structured summary of what was deleted
    """

    # Look up the wallet
    this_wallet = Wallet.query.filter(Wallet.did == wallet_did).one_or_none()
    if not this_wallet:
        text = f"Wallet not found for DID: {wallet_did}"
        return _ok_content(
            [{"type": "text", "text": text}],
            is_error=True,
        )

    # Query attestations linked to this wallet
    attestations_list = Attestation.query.filter_by(wallet_did=wallet_did).all()
    number_of_attestations = len(attestations_list)

    # Capture info before deletion
    structured = {
        "wallet_did": wallet_did,
        "wallet_url": getattr(this_wallet, "url", None),
        "number_of_attestations_deleted": number_of_attestations,
        "ecosystem_profile": getattr(this_wallet, "ecosystem_profile", None),
        "human_in_the_loop": getattr(this_wallet, "always_human_in_the_loop", None),
        "deleted": True,
    }

    # First delete attestations, then wallet
    for att in attestations_list:
        db.session.delete(att)

    db.session.delete(this_wallet)
    db.session.commit()

    text = (
        f"Wallet {wallet_did} has been deleted, along with "
        f"{number_of_attestations} attestation(s)."
    )

    return _ok_content(
        [{"type": "text", "text": text}],
        structured=structured,
    )


# agent tool
def call_accept_credential_offer(arguments: Dict[str, Any], agent_identifier, config: dict) -> Dict[str, Any]:
    credential_offer = arguments.get("credential_offer")
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


# dev tool
def call_get_identity_data(agent_identifier, config) -> Dict[str, Any]:
    mode = config["MODE"]
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    structured = {
        "agent_identifier": this_wallet.did,
        "dev_bearer_token": this_wallet.dev_token,
        "agent_bearer_token": this_wallet.agent_token,
        "wallet_url": mode.server + "did/" + urllib.parse.quote(this_wallet.did, safe=""),
        "did_document": json.loads(this_wallet.did_document),
        "owners_login": this_wallet.owner_login,
        "ecosystem_profile": this_wallet.ecosystem_profile,
        "agent_framework": this_wallet.agent_framework,
        "owners_identity_provider": this_wallet.owner_identity_provider
    }
    return _ok_content([{"type": "text", "text": "All data"}], structured=structured)
    

def call_rotate_bearer_token(arguments, agent_identifier, config) -> Dict[str, Any]:
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    if arguments.get("role") == "dev":
        this_wallet.dev_token = oidc4vc.sign_mcp_bearer_token(agent_identifier, "dev")
    else:
        this_wallet.agent_token = oidc4vc.sign_mcp_bearer_token(agent_identifier, "agent")
    db.session.commit()
    text = "New token available"
    structured = {
        "agent_identifier": this_wallet.did,
        "dev_bearer_token": this_wallet.dev_token,
        "agent_bearer_token": this_wallet.agent_token,
        "wallet_url": this_wallet.url
    }
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def call_add_authentication_key(arguments, agent_identifier, config) -> Dict[str, Any]:
    # Find the wallet for this agent
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    if not this_wallet:
        return _ok_content(
            [{"type": "text", "text": "Wallet not found for this agent_identifier"}],
            is_error=True,
        )

    public_key_str = arguments.get("public_key")
    if not public_key_str:
        return _ok_content(
            [{"type": "text", "text": "Missing 'public_key' argument"}],
            is_error=True,
        )

    # Parse the JWK
    try:
        jwk = json.loads(public_key_str)
    except Exception:
        logging.exception("Invalid JWK passed to call_add_authentication_key")
        return _ok_content(
            [{"type": "text", "text": "Invalid JSON for 'public_key' (JWK)"}],
            is_error=True,
        )

    # Ensure no private part is stored, just in case
    jwk.pop("d", None)

    # Load the existing DID Document
    try:
        did_document = json.loads(this_wallet.did_document)
    except Exception:
        logging.exception("Invalid DID Document in wallet")
        return _ok_content(
            [{"type": "text", "text": "Stored DID Document is invalid JSON"}],
            is_error=True,
        )

    # Get or init verificationMethod array
    verification_methods = did_document.get("verificationMethod", [])

    # Choose an identifier for the new key
    # Prefer a provided 'kid' if present, otherwise use "key-N"
    did = this_wallet.did
    key_suffix = jwk.get("kid")
    if not key_suffix:
        key_suffix = f"key-{len(verification_methods) + 1}"

    verification_method_id = f"{did}#{key_suffix}"

    new_verification_method = {
        "id": verification_method_id,
        "type": "JsonWebKey2020",
        "controller": did,
        "publicKeyJwk": jwk,
    }

    verification_methods.append(new_verification_method)
    did_document["verificationMethod"] = verification_methods

    # Add this key as an authentication method (by reference)
    authentication = did_document.get("authentication", [])
    if verification_method_id not in authentication:
        authentication.append(verification_method_id)
    did_document["authentication"] = authentication

    # Persist the updated DID Document
    this_wallet.did_document = json.dumps(did_document)
    db.session.commit()

    text = "New authentication key added to the DID Document."
    structured = {
        "agent_identifier": this_wallet.did,
        "dev_bearer_token": this_wallet.dev_token,
        "agent_bearer_token": this_wallet.agent_token,
        "wallet_url": this_wallet.url,
        "did_document": did_document,
        "added_key_id": verification_method_id,
    }
    return _ok_content([{"type": "text", "text": text}], structured=structured)


# guest tool
def call_create_agent_identifier_and_wallet(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    mode = config["MODE"]
    manager = config["MANAGER"]
    owners_identity_provider = arguments.get("owners_identity_provider")
    owners_login = arguments.get("owners_login").split(",")
    agent_card_url = arguments.get("agentcard_url")
    agent_did = "did:web:wallet4agent.com:" + secrets.token_hex(16)
    vm = agent_did + "#key-1"
    key_id = manager.create_or_get_key_for_tenant(vm)
    jwk, kid, alg = manager.get_public_key_jwk(key_id)
    url = mode.server + "did/" + agent_did
    did_document = create_did_web_document(agent_did, jwk, url, agent_card_url=agent_card_url)
    dev_token = oidc4vc.sign_mcp_bearer_token(vm, "dev", manager)
    agent_token = oidc4vc.sign_mcp_bearer_token(vm, "agent", manager)
    wallet = Wallet(
        dev_token=dev_token,
        agent_token=agent_token,
        owner_login=json.dumps(owners_login),
        owner_identity_provider=owners_identity_provider,
        ecosystem_profile=arguments.get("ecosystem", "DIIP V4"),
        agent_framework=arguments.get("agent_framework", "None"),
        did=agent_did,
        did_document=json.dumps(did_document),
        url=url
    )
    for user_login in owners_login:
        if owners_identity_provider == "google":
            email = user_login
            login = email
            owner = User.query.filter_by(email=email).first()
        elif owners_identity_provider == "github":
            owner = User.query.filter_by(email=user_login).first()
            email = ""
            login = user_login
        elif owners_identity_provider == "wallet":
            login = user_login
            owner = User.query.filter_by(login=user_login).first()
            email = ""
        else:
            break
        if not owner:
            owner = User(
                email=email,
                login=login,
                registration="wallet_creation",
                subscription="free",
                profile_picture="default_picture.jpeg",
            )
        db.session.add(owner)  
    db.session.add(wallet)
    db.session.commit()
    text = "New agent identifier and wallet created."
    
    structured = {
        "agent_identifier": wallet.did,
        "dev_bearer_token": wallet.dev_token,
        "agent_bearer_token": wallet.agent_token,
        "wallet_url": wallet.url
    }
    # send message
    message_text = json.dumps(owners_login) + " from " + owners_identity_provider
    message.message("A new wallet for AI Agent has been created", "thierry.thevenet@talao.io", message_text, mode)
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def create_did_web_document(did, jwk_1, url, agent_card_url=False):
    document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            {
                "@id": "https://w3id.org/security#publicKeyJwk",
                "@type": "@json"
            }
        ],
        "id": did,
        "verificationMethod": [ 
            {
                "id": did + "#key-1",
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk_1
            }
        ],
        "assertionMethod" : [
            did + "#key-1",
        ],
        "service": [
            {
                "id": did + "#oidc4vp",
                "type": "OIDC4VP",
                "serviceEndpoint": url
            }  
        ]
    }
    if agent_card_url:
        document["service"].append(
            {
                "id": did + "#a2a",
                "type": "A2AService",
                "serviceEndpoint": agent_card_url
            }
        )
    return document

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
