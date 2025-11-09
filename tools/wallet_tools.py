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

tools_guest = [
    {
        "name": "create_identity",
        "description": "Generate a Decentralized Identifier (DID) for the agent and create a new wallet to store agent verifiable credentials",
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
                "owner_identity_provider": {
                    "type": "string",
                    "description": "Identity provider for owners",
                    "enum": ["google", "github", "wallet"],
                    "default": "google"
                },
                "owner_login": {
                    "type": "string",
                    "description": "One or more user login separated by a comma (Google email, Github login, personal wallet DID)"
                },
                "profile": {
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
            "required": ["owner_identity_provider", "owner_login"]
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
        "name": "get_attestation_list",
        "description": "List all attestations of the wallet",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [""]
        }
    },
    {
        "name": "get_attestation",
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

def call_get_attestation(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    # Query attestations linked to this wallet
    attestation_id = arguments.get("attestation_id")
    attestation = Attestation.query.filter_by(id=attestation_id).first()
    structured = {"attestation": attestation.vc}
    return _ok_content([{"type": "text", "text": "An attestations of the Agent"}], structured=structured)


def call_get_attestation_list(wallet_did, config) -> Dict[str, Any]:
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
        "owner_login": this_wallet.owner_login,
        "ecosystem_profile": this_wallet.ecosystem_profile,
        "agent_framework": this_wallet.agent_framework,
        "owner_identity_provider": this_wallet.owner_identity_provider
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
    owner_identity_provider = arguments.get("owner_identity_provider")
    owner_login = arguments.get("owner_login").split(",")
    agent_card_url = arguments.get("agentcard_url")
    agent_did = "did:web:wallet4agent.com:" + secrets.token_hex(16)
    jwk_2 = deterministic_jwk.jwk_ed25519_from_passphrase(agent_did + "#key-2")
    jwk_1 = deterministic_jwk.jwk_p256_from_passphrase(agent_did + "#key-1")
    # add alg for DID Document only
    jwk_1["alg"] = "ES256"
    jwk_2["alg"] = "EdDSA"
    jwk_1.pop("d", None)
    jwk_2.pop("d", None)
    url = mode.server + "did/" + urllib.parse.quote(agent_did, safe="")
    url = mode.server + "did/" + agent_did
    did_document = create_did_web_document(agent_did, jwk_1, jwk_2, url, agent_card_url=agent_card_url)
    dev_token = oidc4vc.sign_mcp_bearer_token(agent_did, "dev")
    agent_token = oidc4vc.sign_mcp_bearer_token(agent_did, "agent")
    wallet = Wallet(
        dev_token=dev_token,
        agent_token=agent_token,
        owner_login=json.dumps(owner_login),
        owner_identity_provider=owner_identity_provider,
        ecosystem_profile=arguments.get("ecosystem_profile", "DIIP V4"),
        agent_framework=arguments.get("agent_framework", "None"),
        did=agent_did,
        did_document=json.dumps(did_document),
        url=url
    )
    for user_login in owner_login:
        if arguments.get("owner_identity_provider") == "google":
            email = user_login
            login = email
            owner = User.query.filter_by(email=email).first()
        elif arguments.get("owner_identity_provider") == "github":
            owner = User.query.filter_by(email=user_login).first()
            email = ""
            login = user_login
        elif arguments.get("owner_identity_provider") == "wallet":
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
    message_text = json.dumps(owner_login) + " from " + owner_identity_provider
    message.message("A new wallet for AI Agent has been created", "thierry.thevenet@talao.io", message_text, mode)
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def create_did_web_document(did, jwk_1, jwk_2, url, agent_card_url=False):
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
            },
            {
                "id": did + "#key-2",
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk_2
            }
        ],
        "assertionMethod" : [
            did + "#key-1",
            did + "#key-2"
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

