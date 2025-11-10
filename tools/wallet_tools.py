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

tools_guest = [
    {
        "name": "create_identity",
        "description": "Generate an identifier (DID) for the Agent in the ecosystem and create a new wallet to store Agent verifiable credentials",
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
        "name": "request_attestation",
        "description": "Request the verifiable credential which is offered.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "credential_offer": {
                    "type": "string",
                    "description": "OIDC4VCI credential offer"
                }
            },
            "required": ["credential_offer"]
        }
    },
    {
        "name": "get_wallet_data",
        "description": "Get all the information about the wallet",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_wallet_attestation_list",
        "description": "List all attestations of the wallet",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [""]
        }
    },
    {
        "name": "get_agent_attestation_list",
        "description": "List all attestations of the wallet",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent identifier"
                    }
            },
            "required": ["agent_id"]
        }
    },
    {
        "name": "get_wallet_attestation",
        "description": "Get the content of an attestation of the wallet",
        "inputSchema": {
            "type": "object",
            "properties": {
                "attestation_id": {
                    "type": "string",
                    "description": "Attestation identifier.",
                }
            },
            "required": ["attestation_id"]
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
        "name": "get_attestation_list",
        "description": "List all attestations of the agent",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [""]
        }
    },
    {
        "name": "get_attestation",
        "description": "Display the content of an attestation",
        "inputSchema": {
            "type": "object",
            "properties": {
                "attestation_id": {
                    "type": "string",
                    "description": "Attestation identifier.",
                }
            },
            "required": ["attestation_id"]
        }
    },
    
]


def _ok_content(blocks: List[Dict[str, Any]], structured: Optional[Dict[str, Any]] = None, is_error: bool = False) -> Dict[str, Any]:
    out: Dict[str, Any] = {"content": blocks}
    if structured is not None:
        out["structuredContent"] = structured
    if is_error:
        out["isError"] = True
    return out

def call_get_wallet_attestation(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    # Query attestations linked to this wallet
    attestation_id = arguments.get("attestation_id")
    attestation = Attestation.query.filter_by(id=attestation_id).first()
    structured = {"attestation": attestation.vc}
    return _ok_content([{"type": "text", "text": "An attestations of the Agent"}], structured=structured)


def call_get_wallet_attestation_list(wallet_did, config) -> Dict[str, Any]:
    # Query attestations linked to this wallet
    attestations_list = Attestation.query.filter_by(wallet_did=wallet_did).all()
    wallet_attestations = []
    for attestation in attestations_list:
        validity = "active"
        wallet_attestations.append(
            {
                "attestation_id": attestation.id,
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


def call_get_agent_attestation_list(wallet_did: str, config: Dict[str, Any]) -> Dict[str, Any]:

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
            did_doc = payload.get("didDocument") or payload.get("didDocument", {})
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

        # Basic info from service; you can add more from your own conventions
        attestation = {
            "attestation_id": svc.get("id"),
            "name": svc.get("label") or "Linked Verifiable Presentation",
            "description": "LinkedVerifiablePresentation service discovered in DID Document",
            "issuer": wallet_did,
            "service_endpoint": svc.get("serviceEndpoint"),
            "iat": None,         # no issuance time in DID Doc; can be enriched later
            "validity": "active" # assumption; you could check revocation if you have a registry
        }
        wallet_attestations.append(attestation)

    structured = {"attestations": wallet_attestations}

    # 3. Human-readable text for MCP client
    if not wallet_attestations:
        text = f"No attestations found for Agent DID {wallet_did}."
    else:
        text = f"All attestations (Linked VPs) of Agent DID {wallet_did}."

    return _ok_content([{"type": "text", "text": text}], structured=structured)


# for agent
def call_get_wallet_data(wallet_did, config) -> Dict[str, Any]:
    # Query attestations linked to this wallet
    this_wallet = Wallet.query.filter(Wallet.did == wallet_did).one_or_none()
    attestations_list = Attestation.query.filter_by(wallet_did=wallet_did).all()
    structured = {
        "wallet_url": this_wallet.url,
        "number_of_attestations": len(attestations_list),
        "ecosystem_profile": this_wallet.ecosystem_profile,
        "human_in_the_loop": this_wallet. always_human_in_the_loop
        }
    text = "Wallet data"
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
def call_request_attestation(arguments: Dict[str, Any], agent_id, config: dict) -> Dict[str, Any]:
    credential_offer = arguments.get("credential_offer")
    mode = config["MODE"]
    attestation, text = wallet.wallet(agent_di, credential_offer, mode)
    if not attestation:
        return _ok_content([{"type": "text", "text": text}], is_error=True)     
    structured = {
        "attestation": attestation
    }
    text = "attestation is stored"
    return _ok_content([{"type": "text", "text": text}], structured=structured)


# dev tool
def call_get_identity_data(agent_id, config) -> Dict[str, Any]:
    mode = config["MODE"]
    this_wallet = Wallet.query.filter(Wallet.did == agent_id).one_or_none()
    structured = {
        "agent_id": this_wallet.did,
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
    

def call_rotate_bearer_token(arguments, agent_id, config) -> Dict[str, Any]:
    this_wallet = Wallet.query.filter(Wallet.did == agent_id).one_or_none()
    if arguments.get("role") == "dev":
        this_wallet.dev_token = oidc4vc.sign_mcp_bearer_token(agent_id, "dev")
    else:
        this_wallet.agent_token = oidc4vc.sign_mcp_bearer_token(agent_id, "agent")
    db.session.commit()
    text = "New token available"
    structured = {
        "agent_id": this_wallet.did,
        "dev_bearer_token": this_wallet.dev_token,
        "agent_bearer_token": this_wallet.agent_token,
        "wallet_url": this_wallet.url
    }
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def call_add_authentication_key(arguments, agent_id, config) -> Dict[str, Any]:
    # Find the wallet for this agent
    this_wallet = Wallet.query.filter(Wallet.did == agent_id).one_or_none()
    if not this_wallet:
        return _ok_content(
            [{"type": "text", "text": "Wallet not found for this agent_id"}],
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
        "agent_id": this_wallet.did,
        "dev_bearer_token": this_wallet.dev_token,
        "agent_bearer_token": this_wallet.agent_token,
        "wallet_url": this_wallet.url,
        "did_document": did_document,
        "added_key_id": verification_method_id,
    }
    return _ok_content([{"type": "text", "text": text}], structured=structured)


# guest tool
def call_create_identity(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    mode = config["MODE"]
    owners_identity_provider = arguments.get("owners_identity_provider")
    owners_login = arguments.get("owners_login").split(",")
    agent_card_url = arguments.get("agentcard_url")
    agent_did = "did:web:wallet4agent.com:" + secrets.token_hex(16)
    jwk_1 = deterministic_jwk.jwk_p256_from_passphrase(agent_did + "#key-1")
    # add alg for DID Document only
    jwk_1["alg"] = "ES256"
    jwk_1.pop("d", None)
    url = mode.server + "did/" + urllib.parse.quote(agent_did, safe="")
    url = mode.server + "did/" + agent_did
    did_document = create_did_web_document(agent_did, jwk_1, url, agent_card_url=agent_card_url)
    dev_token = oidc4vc.sign_mcp_bearer_token(agent_did, "dev")
    agent_token = oidc4vc.sign_mcp_bearer_token(agent_did, "agent")
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
        "agent_id": wallet.did,
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

