import json
import base64
from typing import Any, Dict, List, Optional
from db_model import Wallet, db, User
import secrets
import logging
from sqlalchemy import and_
from routes import wallet
from utils import deterministic_jwk, oidc4vc
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
                    "description": "Identity provider for owner",
                    "enum": ["google", "github", "wallet"],
                    "default": "google"
                },
                "owner_login": {
                    "type": "string",
                    "description": "Google email, Github login, personal wallet DID"
                }
            },
            "required": ["owner_identity_provider", "owner_login"]
        }
    }
]

tools_agent = [
    {
        "name": "request_attestation",
        "description": "Request the verifiable credential which is offered and store it in the wallet",
        "inputSchema": {
            "type": "object",
            "properties": {
                "credential_offer": {
                    "type": "string",
                    "description": "OIDC4VCI credential offer "
                },
                "agent_id": {
                    "type": "string",
                    "description": "Agent decentralized identifier. Use did:web:wallet4agent:demo for testing and demo.",
                }
            },
            "required": ["agent_id", "credential_offer"]
        }
    },
    {
        "name": "verify",
        "description": "Verify an Agent identity through its attestations",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent decentralized identifier. Use did:web:wallet4agent:demo for testing and demo.",
                }
            },
            "required": ["agent_id"]
        }
    }
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
        "description": "Get all information about an agent identity",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
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


# agent tool
def call_request_attestation(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    credential_offer = arguments.get("credential_offer")
    wallet_did = arguments.get("agent_id")
    mode = config["MODE"]
    attestation, text = wallet.wallet(wallet_did, credential_offer, mode)
    if not attestation:
        return _ok_content([{"type": "text", "text": text}], is_error=True)     
    structured = {
        "attestation": attestation
    }
    text = "attestation is stored"
    return _ok_content([{"type": "text", "text": text}], structured=structured)


# dev tool
def call_get_data(agent_id, config) -> Dict[str, Any]:
    mode = config["MODE"]
    this_wallet = Wallet.query.filter(Wallet.did == agent_id).one_or_none()
    structured = {
        "agent_id": this_wallet.did,
        "dev_bearer_token": this_wallet.dev_token,
        "agent_bearer_token": this_wallet.agent_token,
        "wallet_url": mode.server + "did/" + urllib.parse.quote(this_wallet.did, safe=""),
        "did_document": json.loads(this_wallet.did_document),
        "owner_login": this_wallet.owner_login,
        "owner_identity_provider": this_wallet.owner_identity_provider
    }
    return _ok_content([{"type": "text", "text": "All data"}], structured=structured)
    

def call_rotate_bearer_token(agent_id, config) -> Dict[str, Any]:
    this_wallet = Wallet.query.filter(Wallet.did == agent_id).one_or_none()
    dev_token = oidc4vc.sign_mcp_bearer_token(agent_id, "dev")
    agent_token = oidc4vc.sign_mcp_bearer_token(agent_id, "agent")
    this_wallet.dev_token = dev_token
    this_wallet.agent_token = agent_token
    db.session.commit()
    text = "New token available"
    structured = {
        "agent_id": this_wallet.did,
        "dev_bearer_token": dev_token,
        "agent_bearer_token": agent_token,
        "wallet_url": this_wallet.url
    }
    return _ok_content([{"type": "text", "text": text}], structured=structured)
    
    
# guest tool
def call_create_identity(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    mode = config["MODE"]
    owner_identity_provider = arguments.get("owner_identity_provider")
    owner_login = arguments.get("owner_login")
    if not owner_login or not owner_identity_provider:
        return _ok_content([{"type": "text", "text": "Owner login or identity provider missing"}], is_error=True)
    agent_card_url = arguments.get("agentcard_url")
    agent_did = "did:web:wallet4agent.com:" + secrets.token_hex(16)
    jwk_2 = deterministic_jwk.jwk_ed25519_from_passphrase(agent_did + "#key-2")
    jwk_1 = deterministic_jwk.jwk_p256_from_passphrase(agent_did + "#key-1")
    # add alg for DID Document only
    jwk_1["alg"] = "ES256"
    jwk_2["alg"] = "EdDSA"
    jwk_1.pop("d", None)
    jwk_2.pop("d", None)
    did_document = create_did_web_document(agent_did, jwk_1, jwk_2, agent_card_url=agent_card_url)
    dev_token = oidc4vc.sign_mcp_bearer_token(agent_did, "dev")
    agent_token = oidc4vc.sign_mcp_bearer_token(agent_did, "agent")
    wallet = Wallet(
        dev_token=dev_token,
        agent_token=agent_token,
        owner_login=owner_login,
        owner_identity_provider=owner_identity_provider,
        did=agent_did,
        did_document=json.dumps(did_document),
        url=mode.server + "did/" + urllib.parse.quote(agent_did, safe="")
    )
    if arguments.get("owner_identity_provider") == "google":
        email = owner_login
        login = email
        user = User.query.filter_by(email=email).first()
    elif arguments.get("owner_identity_provider") == "github":
        user = User.query.filter_by(email=owner_login).first()
        email = ""
        login = owner_login
    elif arguments.get("owner_identity_provider") == "wallet":
        login = owner_login
        user = User.query.filter_by(login=owner_login).first()
        email = ""
    else:
        email = ""
        login = owner_login
    if not user:
        user = User(
            email=email,
            login=login,
            registration="wallet_creation",
            subscription="free",
            profile_picture="default_picture.jpeg",
        )
    db.session.add(user)  
    db.session.add(wallet)
    db.session.commit()
    text = "New agent identifier and wallet created."
    
    structured = {
        "agent_id": wallet.did,
        "dev_bearer_token": wallet.dev_token,
        "agent_bearer_token": wallet.agent_token,
        "wallet_url": wallet.url
    }
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def create_did_web_document(did, jwk_1, jwk_2, agent_card_url=False):
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
        "authentication" : [
            did + "#key-1",
            did + "#key-2"
        ],
        "assertionMethod" : [
            did + "#key-1",
            did + "#key-2"
        ]
    }
    if agent_card_url:
        document["service"] = []
        document["service"].append(
            {
                "id": "#a2a",
                "type": "A2AService",
                "serviceEndpoint": agent_card_url
            }
        )
    return document

