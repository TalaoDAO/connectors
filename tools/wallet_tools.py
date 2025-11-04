import json
import base64
from typing import Any, Dict, List, Optional
from db_model import Wallet, db, User
import secrets
import logging
from sqlalchemy import and_
from routes import wallet
from utils import deterministic_jwk

tools = [
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
    },
    {
        "name": "create_identity",
        "description": "Generate a Decentralized Identifier (DID) for the agent and create a new wallet to store agent attestations",
        "inputSchema": {
            "type": "object",
            "properties": {
                "did_method": {
                    "type": "string",
                    "description": "Optional DID method to be used if no agent_id is provided (did:jwk or did:web by default).",
                    "enum": ["did:jwk", "did:web"]
                },
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
                    "enum": ["google", "github", "wallet", "Test"],
                    "default": "wallet"
                },
                "owner_login": {
                    "type": "string",
                    "description": "email for Google, login github, DID"
                },
                "name": {
                    "type": "string",
                    "description": "Name of the wallet",
                },
                
            },
            "required": ["owner_identity_provider", "owner_login"]
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


def call_request_attestation(arguments: Dict[str, Any], api_key: str, config: dict) -> Dict[str, Any]:
    credential_offer = arguments.get("credential_offer")
    wallet_did = arguments.get("agent_id")
    attestation, text = wallet.wallet(wallet_did, credential_offer)
    if not attestation:
        return _ok_content([{"type": "text", "text": text}], is_error=True)     
    structured = {
        "attestation": attestation
    }
    text = "attestation is stored"
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def call_create_identity(arguments: Dict[str, Any], api_key: str, config: dict) -> Dict[str, Any]:
    agent_card_url = arguments.get("agentcard_url")
    owner_login = arguments.get("owner_login")
    did_method = arguments.get("did_method", "did:web")
    optional_path = secrets.token_hex(16)
    if did_method == "did:web":
        agent_did = "did:web:wallet4agent.com:" + optional_path
        jwk_2 = deterministic_jwk.jwk_ed25519_from_passphrase(agent_did + "#key-2")
        jwk_1 = deterministic_jwk.jwk_p256_from_passphrase(agent_did + "#key-2")
        # add alg for DID Document only
        jwk_1["alg"] = "ES256"
        jwk_2["alg"] = "EdDSA"
        jwk_1.pop("d", None)
        jwk_2.pop("d", None)
        did_document = create_did_web_document(agent_did, jwk_1, jwk_2, agent_card_url=agent_card_url)
    else:
        jwk_1_string = json.dumps(jwk_1, separators=(",", ":"), sort_keys=True)
        encoded_jwk = base64.urlsafe_b64encode(jwk_1_string.encode("utf-8")).rstrip(b"=").decode("utf-8")
        agent_did = "did:jwk:" + encoded_jwk
        did_document = create_did_jwk_document(agent_did, jwk_1_string)
        
    token = secrets.token_hex(16)
    wallet = Wallet(
        token=token,
        workload_id="spiffe://wallet4agent.com/" + optional_path,
        optional_path=optional_path,
        owner_login=arguments.get("owner_login"),
        owner_identity_provider=arguments.get("owner_identity_provider"),
        description=arguments.get("description"),
        did=agent_did,
        did_document=json.dumps(did_document),
        url=config["SERVER"] + optional_path,
        callback=config["SERVER"] + optional_path + "/callback"
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
        "bearer_token": wallet.token,
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

def create_did_jwk_document(did, jwk):
    document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": "did:jwk:${base64url-value}",
        "verificationMethod": [
            {
            "id": did + "#0",
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": jwk
            }
        ],
        "assertionMethod": [did + "#0"],
        "authentication": [did + "#0"],
        "capabilityInvocation": [did + "#0"],
        "capabilityDelegation": [did + "#0"],
        "keyAgreement": [did + "#0"]
    }
    return document