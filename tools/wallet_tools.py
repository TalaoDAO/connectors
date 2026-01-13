import json
from typing import Any, Dict, List, Optional
from db_model import Wallet, db, Attestation
import secrets
import logging
from utils import oidc4vc, message
import hashlib
from universal_registrar import UniversalRegistrarClient
from routes import agent_chat
import uuid
import requests
import base64
from datetime import datetime
import linked_vp

# do not provide this tool to an LLM
tools_guest = [
    {
        "name": "create_account",
        "description": "Create aan account for a human or a company. This tool will generate a decentralized identifier(DID) and a data wallet.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_type": {
                    "type": "string",
                    "description": "Human or Company as a the owner of the Agents",
                    "enum": ["human", "company"],
                    "default": "human"
                },
                "notification_email": {
                    "type": "string",
                    "description": "Email used for notification and authentication. Email must be confirmed to make the account active",
                },
                "did_method": {
                    "type": "string",
                    "description": "Optional DID Method, did:web (DNS based) by default or did:cheqd (blockchain based)",
                    "enum": ["did:web", "did:cheqd"],
                    "default": "did:cheqd"
                }
            },
            "required": ["notification_email"]
        }
    }
]


tools_for_did = [
    {
        "name": "register_wallet_as_chat_agent",
        "description": (
            "Attach this wallet and DID to a Chat AI agent for demo or testing. "
            "You will be able to access to the Chat through the URL https://wallet4agent.com/agent/<my-chat>."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_identifier": {
                    "type": "string",
                    "description": "Identifier of the agent"
                },
                "chat-name": {
                    "type": "string",
                    "description": (
                        "Short profile name for the chat agent."
                        " If omitted, a name will be derived from the DID."
                    )
                }
            },
            "required": ["agent_identifier", "chat-name"]
        }
    },
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
                "agent_identifier": {
                    "type": "string",
                    "description": "Identifier of the agent"
                },
                "attestation_id": {
                    "type": "integer",
                    "description": (
                        "The local Attestation ID (from get_attestations_of_this_wallet "
                        "structuredContent.id) to publish."
                    )
                }
            },
            "required": ["agent_identifier", "attestation_id"]
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
                "agent_identifier": {
                    "type": "string",
                    "description": "Identifier of the agent"
                },
                "attestation_id": {
                    "type": "integer",
                    "description": (
                        "The local Attestation ID (from get_attestations_of_this_wallet "
                        "structuredContent.id) to unpublish."
                    )
                }
            },
            "required": ["agent_identifier", "attestation_id"]
        }
    }
]

tools_owner = []

tools_admin = [
    {
        "name": "create_agent_identifier_and_wallet",
        "description": "Option 1 : Generate a Decentralized Identifier (DID) for the Agent and create a wallet to store Agent attestations as verifiable credentials.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "did_method": {
                    "type": "string",
                    "description": "Optional DID Method, did:web (DNS based) by default or did:cheqd (blockchain based)",
                    "enum": ["did:web", "did:cheqd"],
                    "default": "did:web"
                },
                "agentcard_url": {
                    "type": "string",
                    "description": "Your AgentCard url if it exists, example: https://my-agent.example.com/.well-known/agent-card.json"
                },
                "mcp_client_authentication": {
                    "type": "string",
                    "description": "Authentication between MCP client and MCP server for agent. Admins use PAT",
                    "enum": ["Personal Access Token (PAT)", "OAuth 2.0 Client Credentials Grant", "Agntcy Badge"],
                    "default": "Personal Access Token (PAT)"
                }
            },
            "required": []
        }
    },
    {
        "name": "create_agent_wallet",
        "description": "Option 2: Create only a wallet to store Agent attestations as verifiable credentials.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_identifier": {
                    "type": "string",
                    "description": "Input your Agent identifier"
                },
                "agentcard_url": {
                    "type": "string",
                    "description": "Your AgentCard url if it exists, example: https://my-agent.example.com/.well-known/agent-card.json"
                },
                "mcp_client_authentication": {
                    "type": "string",
                    "description": "Authentication between MCP client and MCP server for agent. Admins use PAT",
                    "enum": ["Personal Access Token (PAT)", "OAuth 2.0 Client Credentials Grant", "Agntcy Badge"],
                    "default": "Personal Access Token (PAT)"
                }
            },
            "required": ["agent_identifier"]
        }
    },
    {
        "name": "get_account_configuration",
        "description": "Get the wallet configuration data and DID Document.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_wallet_configuration",
        "description": "Get the wallet configuration data and DID Document.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_identifier": {
                    "type": "string",
                    "description": "Identifier of the agent"
                }
            },
            "required": ["agent_identifier"]
        }
    },
    {
        "name": "describe_identity_document",
        "description": (
            "Return a human-readable description of this Agent's DID Document "
            "(verification methods, authentication methods, services, Linked VPs). "
            "Use this to understand how the Agent appears to the outside world."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_identifier": {
                    "type": "string",
                    "description": "Identifier of the agent"
                }
            },
            "required": ["agent_identifier"]
        }
    },
    {
        "name": "update_configuration",
        "description": (
            "Add configuration for OAuth between MCP client and server and "
            "specific features for VCs and the OIDC4VC protocol. "
            "You can also register a public key for OAuth2 private_key_jwt "
            "client authentication."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_identifier": {
                    "type": "string",
                    "description": "Identifier of the agent"
                },
                "notification_email": {
                    "type": "string",
                    "description": "This email is used to notify about Agent actions if human in the loop"
                },
                "sign": {
                    "type": "boolean",
                    "description": "Authorize Agent to sign",
                    "default": True
                },
                "publish_unpublish": {
                    "type": "boolean",
                    "description": "Authorize Agent to publish or unpublish attestations",
                    "default": True
                },
                "receive_credentials": {
                    "type": "boolean",
                    "description": "Authorize Agent to receive credentials",
                    "default": True
                },
                "ecosystem": {
                    "type": "string",
                    "description": "Ecosystem profile",
                    "enum": ["DIIP V4", "DIIP V3", "EWC", "ARF"],
                },
                "agentcard_url": {
                    "type": "string",
                    "description": "Optional AgentCard URL."
                },
                "client_public_key": {
                    "type": "string",
                    "description": (
                        "Public key as a JWK (JSON Web Key) encoded as a JSON string. "
                        "This key will be stored in the wallet as 'client_public_key' "
                        "and can be used for OAuth 2.0 private_key_jwt client "
                        "authentication to the Authorization Server."
                    )
                }
            },
            "required": ["agent_identifier"]
        }
    },
    {
        "name": "delete_wallet",
        "description": "Delete wallet and attestations",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_identifier": {
                    "type": "string",
                    "description": "Confirm agent identifier of the wallet to delete."
                }
            },
            "required": ["agent_identifier"]
        }
    },
    # {
    #    "name": "rotate_personal_access_token",
    #    "description": "Rotate one of the bearer personal access tokens (PAT)",
    #    "inputSchema": {
    #        "type": "object",
    #        "properties": {
    #            "role": {
    #                "type": "string",
    #                "description": "Choose the token to rotate",
    #                "enum": ["agent", "admin"],
    #                "default": "admin"
    #            },
    #            "agent_identifier": {
    #                "type": "string",
    #                "description": "Confirm agent identifier."
    #            }
    #        },
    #        "required": ["agent_identifier"]
    #  }
    # },
    # {
    #    "name": "add_authentication_key",
    #    "description": "Add an authentication public key. This key will be published in the DID Document but not stored by the wallet.",
    #   "inputSchema": {
    #        "type": "object",
    #        "properties": {
    #            "public_key": {
    #                "type": "string",
    #                "description": "Public key as a JWK (JSON Web Key) encoded as a JSON string. "
    #            },
    #            "controller": {
    #                "type": "string",
    #                "description": "Optional. It must be a DID. By default the key controller will be the DID Document controller. "
    #            }
    #        },
    #        "required": ["public_key"]
    #    }
    # },
    {
        "name": "get_attestations_of_an_agent",
        "description": "Get all attestations of oen of your agents",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_identifier": {
                    "type": "string",
                    "description": "Agent identifier."
                }
            },
            "required": ["agent_identifier"]
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


# for admin
def call_delete_wallet(agent_identifier) -> Dict[str, Any]:
    """
    Delete a wallet and its related data from the database.

    - Removes the Wallet row identified by `agent_identifier`
    - Removes all Attestations linked to this wallet
    - Returns a structured summary of what was deleted
    """

    # Look up the wallet
    wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
    if not wallet:
        text = f"Wallet not found for gnet identifier: {agent_identifier}"
        return _ok_content(
            [{"type": "text", "text": text}],
            is_error=True,
        )

    # Query attestations linked to this wallet
    attestations_list = Attestation.query.filter_by(agent_identifier=agent_identifier).all()
    number_of_attestations = len(attestations_list)

    # Capture info before deletion
    structured = {
        "agent_identifier": agent_identifier,
        "number_of_attestations_deleted": number_of_attestations,
        "deleted": True,
    }

    # First delete attestations, then wallet
    for att in attestations_list:
        db.session.delete(att)
        db.session.delete(wallet)
    db.session.commit()

    text = (
        f"Agent {agent_identifier} has been deleted, along with wallets and "
        f"{number_of_attestations} attestation(s)."
    )

    return _ok_content(
        [{"type": "text", "text": text}],
        structured=structured,
    )


# admin tool
def call_get_account_configuration(agent_identifier, config) -> Dict[str, Any]:
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()

    # Turn all DB columns into a dict
    structured = {
        column.name: getattr(this_wallet, column.name)
        for column in Wallet.__table__.columns
    }
    attestations = Attestation.query.filter(Attestation.agent_identifier == agent_identifier).all()
    structured["nb_attestations"] = len(attestations)
    structured["nb_attestations_published"] = len(json.loads(this_wallet.linked_vp))
    if structured.get("created_at"):
        structured["created_at"] = structured.get("created_at").isoformat()
    if structured.get("did_document"):
        structured["did_document"] = json.loads(structured["did_document"])
    
    wallet_list = Wallet.query.filter(Wallet.owner == agent_identifier).all()
    agent_owned = [wallet.agent_identifier for wallet in wallet_list if wallet.agent_identifier != agent_identifier]
    
    structured["agent_owned"] = agent_owned
    final_structured = {key: value for key, value in structured.items() if key in ["owner", "type", "status", "did_document", "contact_email", "agent_owned"]}
    
    return _ok_content(
        [{"type": "text", "text": "All data"}],
        structured=final_structured,
    )
    
def call_get_wallet_configuration(arguments, owner_identifier, config) -> Dict[str, Any]:
    agent_identifier = arguments.get("agent_identifier")
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
    if not this_wallet:
        return _ok_content(
            [{"type": "text", "text": "Wallet not found for this agent_identifier"}],
            is_error=True,
        )
    if this_wallet.owner != owner_identifier:
        return _ok_content(
            [{"type": "text", "text": "This wallet is controlled by your account"}],
            is_error=True,
        )
        
    # Turn all DB columns into a dict
    structured = {
        column.name: getattr(this_wallet, column.name)
        for column in Wallet.__table__.columns
    }
    attestations = Attestation.query.filter(Attestation.agent_identifier == agent_identifier).all()
    structured["nb_attestations"] = len(attestations)
    structured["nb_attestations_published"] = len(json.loads(this_wallet.linked_vp))
    if structured.get("created_at"):
        structured["created_at"] = structured.get("created_at").isoformat()
    if structured.get("did_document"):
        structured["did_document"] = json.loads(structured["did_document"])
    
    structured["OIDC4VCWalletService"] = structured["url"]
    final_structured = {key: value for key, value in structured.items() if key in ["OIDC4VCWalletService", "owner", "agentcard_url", "did_document", "mcp_authentication", "nb_attestations", "created_at", "nb_attestations_published"]}
    
    return _ok_content(
        [{"type": "text", "text": "All data"}],
        structured=final_structured,
    )

"""   
def call_rotate_personal_access_token(arguments, agent_identifier) -> Dict[str, Any]:
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
    structured = {
        "agent_identifier": agent_identifier,
        "OIDC4VCWalletService": this_wallet.url
    }
    if arguments.get("role") == "admin":
        admin_pat, admin_pat_jti = oidc4vc.generate_access_token(agent_identifier, "admin", "pat")
        this_wallet.admin_pat_jti = admin_pat_jti
        structured["admin_personal_access_token"] = admin_pat
        text = "New personal access token available for admin. Copy this access token which is not stored."
    else:
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(agent_identifier, "agent", "pat", duration=90*25*60*60)
        this_wallet.agent_pat_jti = agent_pat_jti
        structured["agent_personal_access_token"] = agent_pat
        text = "New personal access token available for agent. Copy this access token which is not stored."
    db.session.commit()
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def call_add_authentication_key(arguments, agent_identifier, config) -> Dict[str, Any]:
    # Find the wallet for this agent
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
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
    did = this_wallet.agent_identifier
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
    if arguments.get("controller") and arguments.get("controller").startswith("did:"):
        new_verification_method["controller"] = arguments.get("controller")

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
        "agent_identifier": this_wallet.agent_identifier,
        "OIDC4VCWalletService": this_wallet.url,
        "did_document": did_document,
        "added_key_id": verification_method_id,
    }
    return _ok_content([{"type": "text", "text": text}], structured=structured)
"""


def hash_client_secret(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def call_create_agent_identifier_and_wallet(arguments: Dict[str, Any], owner_identifier, config: dict) -> Dict[str, Any]:
    mode = config["MODE"]
    manager = config["MANAGER"]

    owner_wallet = Wallet.query.filter_by(agent_identifier=owner_identifier).first()

    # Normalise agent_name → "my-agent" instead of "my agent"
    raw_agent_name = arguments.get("agent_name", "") or ""
    agent_name = "-".join(raw_agent_name.split()) or None

    # Initialise Universal Registrar client (local docker-compose: http://localhost:9080/1.0)
    client = UniversalRegistrarClient()
    method = arguments.get("did_method")
    wallet_identifier = str(uuid.uuid4())
    agentcard_url = arguments.get("agentcard_url")
    if agentcard_url:
        try:
            result = requests.get(agentcard_url, timeout=10)
            result.raise_for_status()
            result.json()
        except Exception:
            return _ok_content(
                    [{"type": "text", "text": "Agent Card is not available"}],
                    is_error=True,
                )

    # Create DID + DID Document using the Universal Registrar
    if method == "did:web":
        # did:web: use P-256 key in KMS; vm_id = did#key-1
        agent_did, did_document, key_id = client.create_did_web(
            manager,
            wallet_identifier,
            mode,
            agentcard_url,
            controller=None,   # keep the agent controller of its DID document
            name=agent_name)

    elif method == "did:cheqd":
        # did:cheqd: 2-step signPayload flow, with key in local KMS
        agent_did, did_document, key_id = client.create_did_cheqd(
            manager,
            wallet_identifier,
            mode,
            agentcard_url,
            controller=None,  # keep the agent controller of its DID document
            network="testnet",  # "testnet" or "mainnet"
        )
    else:
        return _ok_content(
            [{"type": "text", "text": f"Unsupported DID method: {method}"}],
            is_error=True,
        )
    
    wallet_url = f"{mode.server.rstrip('/')}/wallets/{wallet_identifier}"

    if not did_document:
        return _ok_content(
            [{"type": "text", "text": "DID Document registration failed"}],
            is_error=True,
        )

    mcp_authentication = arguments.get("mcp_client_authentication")
    
    # Create / update admins and wallet in DB
    wallet = Wallet(
        agentcard_url=agentcard_url,
        type="agent",
        owner=owner_identifier,
        mcp_authentication=mcp_authentication,
        agent_identifier=agent_did,
        wallet_identifier=wallet_identifier,
        did_document=json.dumps(did_document),
        url=wallet_url,
        notification_email=owner_wallet.notification_email,
    )
    if mcp_authentication == "OAuth 2.0 Client Credentials Grant":
        client_secret = secrets.token_urlsafe(64)
        wallet.client_secret_hash = oidc4vc.hash_client_secret(client_secret)
    elif mcp_authentication == "Personal Access Token (PAT)":
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(agent_did, "agent", "pat", duration=90 * 24 * 60 * 60)
        wallet.agent_pat_jti = agent_pat_jti

    db.session.add(wallet)
    db.session.commit()
    
    # Build structured response
    structured = {
        "agent_identifier": agent_did,
        "owner": owner_identifier,
        "OIDC4VCWalletService": wallet.url
    }
 
    if mcp_authentication == "OAuth 2.0 Client Credentials Grant":
        structured["agent_client_id"] = agent_did
        structured["agent_client_secret"] = client_secret
        structured["authorization_server"] = mode.server

        text = (
            "New agent identifier and wallet created.\n"
            f"Agent DID: {agent_did}\n"
            f"OIDC4VCWalletService: {wallet.url}\n"
            "Copy your admin personal access token and OAuth client credentials from the secure console; " 
            "they are not stored and will not be shown again. Add the OIDC4VCWalletService in the Agent Card."
        )
    else:
        structured["agent_personal_access_token"] = agent_pat

        text = (
            "New agent identifier and wallet created.\n"
            f"Agent DID: {agent_did}\n"
            f"OIDC4VCWalletService: {wallet.url}\n"
            "Copy the agent personal access token and the admin personal access token from the secure console;"
            "they are not stored and will not be shown again. Add the OIDC4VCWalletService in the Agent Card."
        )

    # Notify
    message_text = "Wallet created"
    message.message(
        f"A new DID: {agent_did} and wallet for AI Agent have been created",
        "thierry.thevenet@talao.io",
        message_text,
        mode,
    )

    return _ok_content([{"type": "text", "text": text}], structured=structured)


# admin
def call_update_configuration(
    arguments: Dict[str, Any],
    owner_identifier: str,
    config: dict = None,
) -> Dict[str, Any]:
    """
    Update this Agent's wallet configuration.

    Can update:
      - ecosystem_profile (via 'ecosystem' string)
      - agentcard_url (A2AService in DID Document, id = did + '#a2a')
      - client_public_key (public JWK for OAuth2 private_key_jwt client auth)
    """
    # 0. Load wallet
    agent_identifier = arguments.get("agent_identifier")
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
    if not this_wallet:
        return _ok_content(
            [{"type": "text", "text": "Wallet not found for this agent_identifier"}],
            is_error=True,
        )

    updated: Dict[str, Any] = {}

    # ecosystem profile
    if "ecosystem" in arguments and arguments.get("ecosystem"):
        eco = arguments["ecosystem"]
        this_wallet.ecosystem_profile = eco
        updated["ecosystem_profile"] = eco
    
    # publish or unpublish
    if "publish_unpublish" in arguments and arguments.get("publish_unpublish"):
        pub = arguments["publish_unpublish"]
        this_wallet.publish_unpublish = pub
        updated["publish_unpublish"] = pub
        
    if "sign" in arguments and arguments.get("sign"):
        sign = arguments["sign"]
        this_wallet.sign = sign
        updated["sign"] = sign
        
    if "receive_credentials" in arguments and arguments.get("receive_credentials"):
        rc = arguments["receive_credentials"]
        this_wallet.receive_credentials = rc
        updated["receive_credentials"] = rc
    
    if "notification_email" in arguments and arguments.get("notification_email"):
        ne = arguments["notification_email"]
        this_wallet.notification_email = ne
        updated["notification_email"] = ne

    # agentcard_url (stored in DID Document as A2AService with id did + '#a2a')
    if "agentcard_url" in arguments:
        agentcard_url = arguments.get("agentcard_url") or None

        # Load DID Document strictly; if it is broken we fail rather than wipe it.
        if this_wallet.did_document:
            try:
                did_document = json.loads(this_wallet.did_document)
            except Exception:
                logging.exception("Invalid DID Document in wallet while updating configuration")
                return _ok_content(
                    [{"type": "text", "text": "Stored DID Document is invalid JSON; cannot update AgentCard URL."}],
                    is_error=True,
                )
            services = did_document.get("service", []) or []
            a2a_id = f"{this_wallet.agent_identifier}#a2a"

            # Remove existing A2AService entries for that id
            new_services = [s for s in services if s.get("id") != a2a_id]
            if agentcard_url:
                new_services.append(
                    {
                        "id": a2a_id,
                        "type": "A2AService",
                        "serviceEndpoint": agentcard_url,
                    }
                )
            did_document["service"] = new_services
            this_wallet.did_document = json.dumps(did_document)
        updated["agentcard_url"] = agentcard_url

    # client_public_key for JWT client authentication (private_key_jwt)
    if "client_public_key" in arguments and arguments.get("client_public_key"):
        public_key_raw = arguments["client_public_key"]

        # Accept either a JSON string or already-parsed dict
        if isinstance(public_key_raw, str):
            try:
                jwk_obj = json.loads(public_key_raw)
            except Exception:
                logging.exception("Invalid JSON for client_public_key")
                return _ok_content(
                    [{"type": "text", "text": "Invalid JSON for 'client_public_key' (expected JWK)"}],
                    is_error=True,
                )
        elif isinstance(public_key_raw, dict):
            jwk_obj = public_key_raw
        else:
            return _ok_content(
                [{"type": "text", "text": "client_public_key must be a JSON string or object (JWK)"}],
                is_error=True,
            )

        # Strip any private JWK params, just in case
        for k in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]:
            jwk_obj.pop(k, None)

        # Store canonical JSON in DB
        this_wallet.client_public_key = json.dumps(jwk_obj)
        updated["client_public_key"] = jwk_obj

    # Persist
    db.session.commit()

    # Build a structured response (JSON-safe)
    client_pk = None
    if this_wallet.client_public_key:
        try:
            client_pk = json.loads(this_wallet.client_public_key)
        except Exception:
            client_pk = None

    structured = {
        "agent_identifier": agent_identifier,
        "OIDC4VCWalletService": this_wallet.url,
        "ecosystem_profile": this_wallet.ecosystem_profile,
        "publish_unpublish": this_wallet.publish_unpublish,
        "sign": this_wallet.sign,
        "receive_credentials": this_wallet.receive_credentials,
        "client_public_key": client_pk,
        "updated_fields": updated,
    }

    text = (
        "Wallet configuration has been updated."
        if updated
        else "No configuration changes were applied (no updatable fields provided)."
    )

    return _ok_content(
        [{"type": "text", "text": text}],
        structured=structured,
    )


# tool
def call_describe_identity_document(arguments) -> Dict[str, Any]:
    """
    Dev tool: inspect and summarize the DID Document (if it exists) associated with this Agent's wallet.
    """
    target_agent = arguments.get("agent_identifier")
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == target_agent).first()
    if not this_wallet:
        return _ok_content(
            [{"type": "text", "text": f"No wallet found for Agent DID {target_agent}."}],
            is_error=True,
        )

    try:
        did_document = json.loads(this_wallet.did_document or "{}")
    except Exception:
        did_document = {}
        
    if not did_document:
        structured = {
            "agent_identifier": target_agent
        }
        text = "There is no DID Document for this Agent"
    else:

        vm_list = did_document.get("verificationMethod", [])
        auth = did_document.get("authentication", [])
        assertion = did_document.get("assertionMethod", [])
        services = did_document.get("service", [])

        linked_vp_services = [
            s for s in services if s.get("type") == "LinkedVerifiablePresentation"
        ]

        structured = {
            "agent_identifier": target_agent,
            "controller": did_document.get("controller"),
            "did_document": did_document,
            "verification_methods": vm_list,
            "authentication": auth,
            "assertionMethod": assertion,
            "services": services,
            "linked_vp_services": linked_vp_services,
        }

        text_lines = [
            f"DID Document for Agent {target_agent}:",
            f"- verification methods: {len(vm_list)}",
            f"- authentication refs: {len(auth)}",
            f"- assertionMethod refs: {len(assertion)}",
            f"- services: {len(services)}",
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


def call_register_wallet_as_chat_agent(arguments, identifier, config) -> Dict[str, Any]:
    
    agent_identifier = arguments.get("agent_identifier")
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
    if not this_wallet:
        return _ok_content(
            [{"type": "text", "text": "Wallet not found for this agent_identifier"}],
            is_error=True,
        )
    profile = arguments.get("chat-name")
    if not profile:
        profile = agent_identifier.split(":")[-1]
    profile = profile.lower()
    
    this_wallet.chat_profile = profile
    this_wallet.is_chat_agent = True
    db.session.commit()

    mode = config["MODE"]
    wallet_profile = this_wallet.ecosystem_profile
    agent_chat.register_agent_profile(profile, agent_identifier, wallet_profile)

    text = (
        f"Chat agent profile '{profile}' registered for DID {agent_identifier} ."
    )
    structured = {
        "chat_url": mode.server + "agent/" + profile,
        "agent_identifier": agent_identifier
    }
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def call_create_agent_wallet(arguments: Dict[str, Any], owner_identifier: str, config: dict) -> Dict[str, Any]:
    mode = config["MODE"]
    manager = config["MANAGER"]
    agent_identifier = arguments.get("agent_identifier")
    owner_wallet = Wallet.query.filter_by(agent_identifier=owner_identifier).first()
    
    wallet = Wallet.query.filter_by(agent_identifier=agent_identifier).first()
    # cannot create more than 1 wallet per agent TODO
    if wallet:
        return _ok_content(
                [{"type": "text", "text": "This Agent has already one wallet: " + wallet.url}],
                is_error=True,
            )

    # Initialise Universal Registrar client (local docker-compose: http://localhost:9080/1.0)
    client = UniversalRegistrarClient()
    result = client.create_only_wallet(agent_identifier, manager)
    if not result:
        return _ok_content(
                [{"type": "text", "text": "Identifier not supported"}],
                is_error=True,
            )
    wallet_identifier = str(uuid.uuid4())
    wallet_url = f"{mode.server.rstrip('/')}/wallets/{wallet_identifier}"
    
    agentcard_url = arguments.get("agentcard_url")
    if agentcard_url:
        try:
            result = requests.get(agentcard_url, timeout=10)
            result.raise_for_status()
            result.json()
        except Exception:
            return _ok_content(
                    [{"type": "text", "text": "Agent Card is not available"}],
                    is_error=True,
                )
    
    admin_pat, admin_pat_jti = oidc4vc.generate_access_token(agent_identifier, "admin", "pat")
    mcp_authentication = arguments.get("mcp_client_authentication")

    # Create / update admins and wallet in DB
    wallet = Wallet(
        admin_pat_jti=admin_pat_jti,
        agentcard_url=agentcard_url,
        type="agent",
        owner=owner_identifier,
        mcp_authentication=mcp_authentication,
        agent_identifier=agent_identifier,
        wallet_identifier=wallet_identifier,
        url=wallet_url,
        notification_email=owner_wallet.notification_email,
        receive_credentials=arguments.get("receive_credentials")
    )
    if mcp_authentication == "OAuth 2.0 Client Credentials Grant":
        client_secret = secrets.token_urlsafe(64)
        wallet.client_secret_hash = oidc4vc.hash_client_secret(client_secret)
    elif mcp_authentication == "Personal Access Token (PAT)":
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(agent_identifier, "agent", "pat")
        wallet.agent_pat_jti = agent_pat_jti
        
    
    db.session.add(wallet)
    db.session.commit()
    
    # ----------------------------------------------------------------------
    # 6) Build structured response
    # ----------------------------------------------------------------------
    structured = {
        "agent_identifier": agent_identifier,
        "owner": owner_identifier,
        "admin_personal_access_token": admin_pat,
        "OIDC4VCWalletService": wallet.url
    }
    
    if mcp_authentication == "OAuth 2.0 Client Credentials Grant":
        structured["agent_client_id"] = agent_identifier
        structured["agent_client_secret"] = client_secret
        structured["authorization_server"] = mode.server

        text = (
            "New wallet created.\n"
            f"Agent Identifier: {agent_identifier}\n"
            f"OIDC4VCWalletService: {wallet.url}\n"
            "Copy your admin personal access token and OAuth client credentials from the secure console; "
            "they are not stored and will not be shown again."
        )
    elif mcp_authentication == "Agntcy Badge":
        text = (
            "New wallet created.\n"
            f"Agent Identifier: {agent_identifier}\n"
            f"OIDC4VCWalletService: {wallet.url}\n"
            "Use your Agntcy Badge to connect your Agent. Use your Admin PAT to configure the wallet."
        )
    else:
        structured["agent_personal_access_token"] = agent_pat
        text = (
            "New wallet created.\n"
            f"Agent Identifier: {agent_identifier}\n"
            f"OIDC4VCWalletService: {wallet.url}\n"
            "Copy the agent personal access token and the admin personal access token from the secure console; "
            "they are not stored and will not be shown again."
        )

    # ----------------------------------------------------------------------
    # 7) Notify admin / user
    # ----------------------------------------------------------------------
    message_text = "Wallet created"
    message.message(
        "A new wallet for AI Agent has been created",
        "thierry.thevenet@talao.io",
        message_text,
        mode,
    )

    return _ok_content([{"type": "text", "text": text}], structured=structured)


def call_create_account(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    mode = config["MODE"]
    manager = config["MANAGER"]

    # Initialise Universal Registrar client (local docker-compose: http://localhost:9080/1.0)
    client = UniversalRegistrarClient()
    method = arguments.get("did_method")
    account_type = arguments.get("account_type")
    wallet_identifier = str(uuid.uuid4())

    # Create DID + DID Document using the Universal Registrar
    if method == "did:web":
        # did:web: use P-256 key in KMS; vm_id = did#key-1
        did, did_document, key_id = client.create_did_web(
            manager,
            wallet_identifier,
            mode,
            None)

    elif method == "did:cheqd":
        # did:cheqd: 2-step signPayload flow, with key in local KMS
        did, did_document, key_id = client.create_did_cheqd(
            manager,
            wallet_identifier,
            mode,
            None,
            network="testnet",  # "testnet" or "mainnet"
        )
    else:
        return _ok_content(
            [{"type": "text", "text": f"Unsupported DID method: {method}"}],
            is_error=True,
        )
    
    if not did_document:
        return _ok_content(
            [{"type": "text", "text": "DID Document registration failed"}],
            is_error=True,
        )

    # Generate admin PAT
    admin_pat, admin_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat")
    
    # Create / update admins and wallet in DB
    wallet = Wallet(
        type=account_type,
        owner=did,
        admin_pat_jti=admin_pat_jti,
        agent_identifier=did,
        notification_email=arguments.get("notification_email"),
        wallet_identifier=wallet_identifier,
        did_document=json.dumps(did_document),
        url=f"{mode.server.rstrip('/')}/wallets/{wallet_identifier}"
    )
    db.session.add(wallet)
    db.session.commit()
    
    # Build structured response
    structured = {
        "account_identifier": did,
        "admin_personal_access_token": admin_pat,
        "OIDC4VCWalletService": wallet.url
    }
    text = (
        "New account with decentralized identifier (DID) and wallet created.\n"
        f"Account Identifier: {did}\n"
        f"OIDC4VCWalletService: {wallet.url}\n"
        "Copy the admin personal access token from the secure console;"
        "this token is not stored and will not be shown again."
        "Check the DID Document through the Universal Resolver: https://dev.uniresolver.io/"
    )

    # Notify
    message_text = f"Wallet and DID created for {account_type}: {did}."
    subject = "New DID and wallet"
    message.message(subject, "thierry.thevenet@talao.io", message_text, mode)

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
        "wallet_identifier": att.wallet_identifier,
        "agent_identifier": att.agent_identifier,
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

# for admin
def call_get_attestations_of_an_agent(
    target_agent: str,
    identifier) -> Dict[str, Any]:
    """
    List all attestations stored for and Agent's wallet if the agnet is owned by thd admin.

    - Looks up Attestation rows by agent_identifier
    - For each one, tries to decode the underlying VC / SD-JWT
    - Returns both human-readable text blocks and a structured JSON payload
      suitable for an Agent.
    """
    
    target_wallet = Wallet.query.filter(Wallet.agent_identifier == target_agent).first()
    if not target_wallet:
        text = f"This agent is not found: {target_agent}"
        return _ok_content(
            [{"type": "text", "text": text}],
            is_error=True,
        )
    if target_wallet.owner != identifier:
        text = f"You are not the owner of this agent: {target_agent}"
        return _ok_content(
            [{"type": "text", "text": text}],
            is_error=True,
        )

    logging.info("Listing attestations for agent %s", target_agent)
    attestations = (
        Attestation.query
        .filter_by(agent_identifier=target_agent)
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
                "wallet_identifier": att.wallet_identifier,
                "agent_identifier": att.agent_identifier,
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
        "agent_identifier": target_agent,
        "attestations": items,
    }

    return _ok_content(
        [{"type": "text", "text": text}],
        structured=structured,
    )
    
    

def call_publish_attestation(arguments: Dict[str, Any], identifier: str, config: dict) -> Dict[str, Any]:
    """
    Agent tool: publish an existing Attestation as a Linked Verifiable Presentation
    service in the Agent's DID Document.

    - Keeps the VC in the Attestation row
    - Updates wallet.linked_vp
    - Updates DID Document (service entry)
    - For did:cheqd, also updates the DID on-ledger via Universal Registrar
    """
    agent_identifier = arguments.get("agent_identifier")
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
    if not this_wallet.publish_unpublish:
        return _ok_content(
            [{"type": "text", "text": "Agent cannot publish attestations."}],
            is_error=True,
        )
        
    message_text = "Agent publishes an attestation"
    message.admin_message(this_wallet, message_text, config["MODE"])
    
    attestation_id = arguments.get("attestation_id")
    if attestation_id is None:
        return _ok_content(
            [{"type": "text", "text": "Missing 'attestation_id' argument."}],
            is_error=True,
        )

    mode = config["MODE"]
    manager = config["MANAGER"]

    att = Attestation.query.filter_by(id=attestation_id, agent_identifier=agent_identifier).one_or_none()
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
        "agent_identifier": att.agent_identifier,
        "service_id": service_id,
        "published": True
    }
    text = (
        f"Attestation #{att.id} has been published as a Linked Verifiable "
        f"Presentation with service id {service_id}. Anyone can now access and read this attestation"
    )
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def call_unpublish_attestation(arguments: Dict[str, Any], identifier: str, config: dict) -> Dict[str, Any]:
    """
    Agent tool: unpublish a previously published Attestation.

    - Removes the Linked VP from wallet.linked_vp
    - Removes the LinkedVerifiablePresentation service from the DID Document
    - For did:cheqd, also updates the DID on-ledger via Universal Registrar
    - Keeps the Attestation (VC) stored locally, but sets published=False
    """
    agent_identifier = arguments.get("agent_identifier")
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
    if not this_wallet.publish_unpublish:
        return _ok_content(
            [{"type": "text", "text": "Agent cannot unpublish attestations."}],
            is_error=True,
        )
    
    message_text = "Agent unpublishes an attestation"
    message.admin_message(this_wallet, message_text, config["MODE"])
    
    attestation_id = arguments.get("attestation_id")
    if attestation_id is None:
        return _ok_content(
            [{"type": "text", "text": "Missing 'attestation_id' argument."}],
            is_error=True,
        )

    mode = config["MODE"]
    manager = config["MANAGER"]

    att = Attestation.query.filter_by(id=attestation_id, agent_identifier=agent_identifier).one_or_none()
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
        "agent_identifier": att.agent_identifier,
        "service_id": service_id,
        "published": False,
        "unpublished": True,
    }
    text = (
        f"Attestation #{att.id} has been unpublished and is no longer exposed "
        f"as a Linked Verifiable Presentation in the DID Document. Nobody can access to this attestation anymore."
    )
    return _ok_content([{"type": "text", "text": text}], structured=structured)
