import json
from typing import Any, Dict, List, Optional
from db_model import Wallet, db, User, Attestation
import secrets
from flask import current_app
import logging
from utils import oidc4vc, message
import hashlib
from universal_registrar import UniversalRegistrarClient
from routes import agent_chat
import uuid
#from agntcy import agntcy_create_agent_and_badge_rest


# do not provide this tool to an LLM
tools_guest = [
    {
        "name": "create_agent_identifier_and_wallet",
        "description": "Generate a Decentralized Identifier (DID) for the Agent and create a wallet to store Agent attestations as verifiable credentials.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_framework": {
                    "type": "string",
                    "description": "Agent framework as Agntcy",
                    "enum": ["None", "Agntcy", "A2A"],
                    "default": "None"
                },
                "did_method": {
                    "type": "string",
                    "description": "Optional DID Method, did:web by default",
                    "enum": ["did:web", "did:cheqd"],
                    "default": "did:web"
                },
                "ecosystem_profile": {
                    "type": "string",
                    "description": "Ecosystem profile",
                    "enum": ["DIIP V4", "DIIP V3", "EWC", "ARF"],
                    "default": "DIIP V3"
                },
                "always_human_in_the_loop": {
                    "type": "boolean",
                    "description": "Always human in the loop",
                    "default": True
                },
                "receive_credentials": {
                    "type": "boolean",
                    "description": "Authorize Agent to receive attestations as verifiable credentials",
                    "default": True
                }, 
                "publish_unpublish": {
                    "type": "boolean",
                    "description": "Authorize Agent to publish or unpublish attestations",
                    "default": False
                },
                "sign": {
                    "type": "boolean",
                    "description": "Authorize Agent to sign message and payload",
                    "default": False
                },
                "mcp_client_authentication": {
                    "type": "string",
                    "description": "Authentication between MCP client and MCP server for agent. Admins use PAT",
                    "enum": ["Personal Access Token (PAT)", "OAuth 2.0 Client Credentials Grant"],
                    "default": "Personal Access Token (PAT)"
                },
                "admins_identity_provider": {
                    "type": "string",
                    "description": "Identity provider for admins",
                    "enum": ["google", "github"],
                    "default": "google"
                },
                "admins_login": {
                    "type": "string",
                    "description": "One or more admin login separated by a comma (Google email, Github login ). This login will be needed to accept new attestations offer."
                },
                "notification_email": {
                    "type": "string",
                    "description": "This email is used to notify about Agent actions if human in the loop"
                }
            },
            "required": ["admins_identity_provider", "admins_login"]
        }
    },
    {
        "name": "create_agent_wallet",
        "description": "Create a wallet to store Agent attestations as verifiable credentials.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_identifier": {
                    "type": "string",
                    "description": "Input your Agent identifier"
                },
                "agent_framework": {
                    "type": "string",
                    "description": "Agent framework as Agntcy",
                    "enum": ["None", "Agntcy", "A2A"],
                    "default": "None"
                },
                "ecosystem_profile": {
                    "type": "string",
                    "description": "Ecosystem profile",
                    "enum": ["DIIP V4", "DIIP V3", "EWC", "ARF"],
                    "default": "DIIP V3"
                },
                "always_human_in_the_loop": {
                    "type": "boolean",
                    "description": "Always human in the loop",
                    "default": True
                },
                "receive_credentials": {
                    "type": "boolean",
                    "description": "Authorize Agent to receive attestations as verifiable credentials",
                    "default": True
                }, 
                "sign": {
                    "type": "boolean",
                    "description": "Authorize Agent to sign message and payload",
                    "default": False
                },
                "mcp_client_authentication": {
                    "type": "string",
                    "description": "Authentication between MCP client and MCP server for agent. Admins use PAT",
                    "enum": ["Personal Access Token (PAT)", "OAuth 2.0 Client Credentials Grant"],
                    "default": "Personal Access Token (PAT)"
                },
                "admins_identity_provider": {
                    "type": "string",
                    "description": "Identity provider for admins",
                    "enum": ["google", "github"],
                    "default": "google"
                },
                "admins_login": {
                    "type": "string",
                    "description": "One or more admin login separated by a comma (Google email, Github login ). This login will be needed to accept new attestations offer."
                },
                "notification_email": {
                    "type": "string",
                    "description": "This email is used to notify about Agent actions if human in the loop"
                }
            },
            "required": ["agent_identifier", "admins_identity_provider", "admins_login"]
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
                "my-chat": {
                    "type": "string",
                    "description": (
                        "Short profile name for the chat agent."
                        " If omitted, a name will be derived from the DID."
                    )
                }
            },
            "required": []
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

tools_admin = [
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
    },
    {
        "name": "get_configuration",
        "description": "Get the wallet configuration data and DID Document.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
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
            "properties": {},
            "required": []
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
                "always_human_in_the_loop": {
                    "type": "boolean",
                    "description": "Always human in the loop",
                    "default": True
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
                "agent_framework": {
                    "type": "string",
                    "description": "Agent framework",
                    "enum": ["None"],
                    "default": "None"
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
            }
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
                    "description": "Confirm agent identifier to delete."
                }
            },
            "required": ["agent_identifier"]
        }
    },
    {
        "name": "rotate_personal_access_token",
        "description": "Rotate one of the bearer personal access tokens (PAT)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "role": {
                    "type": "string",
                    "description": "Choose the token to rotate",
                    "enum": ["agent", "admin"],
                    "default": "admin"
                },
                "agent_identifier": {
                    "type": "string",
                    "description": "Confirm agent identifier."
                }
            },
            "required": ["agent_identifier"]
        }
    },
    {
        "name": "add_authentication_key",
        "description": "Add an authentication public key. This key will be published in the DID Document but not stored by the wallet.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "public_key": {
                    "type": "string",
                    "description": "Public key as a JWK (JSON Web Key) encoded as a JSON string. "
                },
                "controller": {
                    "type": "string",
                    "description": "Optional. It must be a DID. By default the key controller will be the DID Document controller. "
                }
            },
            "required": ["public_key"]
        }
    },
    {
        "name": "get_attestations_of_this_wallet",
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

def issue_agent_badge(agent_identifier: str, agent_name, agent_description, mode) -> dict:
    """
    Creates AGNTCY agent + badge via REST and returns result dict:
      { app_id, app, badge }
    """
    # Use the service key to create the agent app & issue badge
    api_key = current_app.config["AGNTCY_ORG_API_KEY"]

    # IMPORTANT: this should be a stable per-agent URL you serve
    # (A2A well-known URL for that agent)
    well_known_url = mode.server.rstrip("/") + f"/agents/{agent_identifier}/.well-known/a2a.json"

    return agntcy_create_agent_and_badge_rest(
        api_key=api_key,
        agent_name=agent_name or agent_identifier,      # or a nicer display name
        well_known_url=well_known_url,
        agent_description=agent_description or "wallet4agent provisioned agent",
        config=current_app.config,
    )


# for admin
def call_delete_wallet(agent_identifier) -> Dict[str, Any]:
    """
    Delete a wallet and its related data from the database.

    - Removes the Wallet row identified by `agent_identifier`
    - Removes all Attestations linked to this wallet
    - Returns a structured summary of what was deleted
    """

    # Look up the wallet
    wallets = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).all()
    if not wallets:
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
    for w in wallets:
        db.session.delete(w)
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
def call_get_configuration(agent_identifier, config) -> Dict[str, Any]:
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
    
    # remove useless info
    final_structured = {key: value for key, value in structured.items() if key not in ["id", "agent_pat_jti", "admin_pat_jti", "linked_vp"]}
    
    return _ok_content(
        [{"type": "text", "text": "All data"}],
        structured=final_structured,
    )
    

def call_rotate_personal_access_token(arguments, agent_identifier) -> Dict[str, Any]:
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
    structured = {
        "agent_identifier": agent_identifier,
        "wallet_url": this_wallet.url
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
        "wallet_url": this_wallet.url,
        "did_document": did_document,
        "added_key_id": verification_method_id,
    }
    return _ok_content([{"type": "text", "text": text}], structured=structured)



def hash_client_secret(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def call_create_agent_identifier_and_wallet(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    mode = config["MODE"]
    manager = config["MANAGER"]

    # Normalise agent_name → "my-agent" instead of "my agent"
    raw_agent_name = arguments.get("agent_name", "") or ""
    agent_name = "-".join(raw_agent_name.split()) or None

    admins_identity_provider = arguments.get("admins_identity_provider")
    admins_login = (arguments.get("admins_login") or "").split(",")
    agent_card_url = arguments.get("agentcard_url")
    agent_framework = arguments.get("agent_framework", "None")

    # 1) Initialise Universal Registrar client (local docker-compose: http://localhost:9080/1.0)
    client = UniversalRegistrarClient()
    method = arguments.get("did_method")
    a2a_endpoint = agent_card_url

    # ----------------------------------------------------------------------
    # 2) Create DID + DID Document using the Universal Registrar
    # ----------------------------------------------------------------------
    if method == "did:web":
        # did:web: use P-256 key in KMS; vm_id = did#key-1
        agent_did, did_document, key_id = client.create_did_web(
            manager=manager,
            mode=mode,
            agent_card_url=a2a_endpoint,
            name=agent_name)

    elif method == "did:cheqd":
        # did:cheqd: 2-step signPayload flow, with key in local KMS
        agent_did, did_document, key_id = client.create_did_cheqd(
            manager=manager,
            mode=mode,
            agent_card_url=a2a_endpoint,
            network="testnet",  # "testnet" or "mainnet"
        )
    else:
        return _ok_content(
            [{"type": "text", "text": f"Unsupported DID method: {method}"}],
            is_error=True,
        )
    wallet_identifier = str(uuid.uuid4())
    wallet_url = f"{mode.server.rstrip('/')}/wallets/{wallet_identifier}"

    if not did_document:
        return _ok_content(
            [{"type": "text", "text": "DID Document registration failed"}],
            is_error=True,
        )

    # ----------------------------------------------------------------------
    # 4) Generate admin + agent PATs
    # ----------------------------------------------------------------------
    admin_pat, admin_pat_jti = oidc4vc.generate_access_token(agent_did, "admin", "pat")
    agent_pat, agent_pat_jti = oidc4vc.generate_access_token(
        agent_did, "agent", "pat", duration=90 * 24 * 60 * 60
    )

    mcp_authentication = arguments.get("mcp_client_authentication")
    client_secret = secrets.token_urlsafe(64)

    # ----------------------------------------------------------------------
    # 5) Create / update admins and wallet in DB
    # ----------------------------------------------------------------------

    wallet = Wallet(
        admin_pat_jti=admin_pat_jti,
        agent_pat_jti=agent_pat_jti,
        mcp_authentication=mcp_authentication,
        client_secret_hash=oidc4vc.hash_client_secret(client_secret),
        admins_identity_provider=admins_identity_provider,
        admins_login=json.dumps(admins_login),
        agent_framework=agent_framework,
        agent_identifier=agent_did,
        wallet_identifier=wallet_identifier,
        did_document=json.dumps(did_document),
        url=wallet_url,
        always_human_in_the_loop=arguments.get("always_human_in_the_loop"),
        publish_unpublish=arguments.get("publish_unpublish"),
        sign=arguments.get("sign"),
        notification_email=arguments.get("notification_email"),
        receive_credentials=arguments.get("receive_credentials")
    )
    # If your Wallet model has a key_id column, you can also store:
    # wallet.key_id = key_id

    for user_login in admins_login:
        if admins_identity_provider == "google":
            email = user_login
            login = email
            admin = User.query.filter_by(email=email).first()
        elif admins_identity_provider == "github":
            admin = User.query.filter_by(email=user_login).first()
            email = ""
            login = user_login
        else:
            return _ok_content(
                [{"type": "text", "text": "Identity provider not supported"}],
                is_error=True,
            )

        if not admin:
            admin = User(
                email=email,
                login=login,
                registration="wallet_creation",
                subscription="free",
            )
        db.session.add(admin)

    db.session.add(wallet)
    db.session.commit()
    
    # ----------------------------------------------------------------------
    # 6) Build structured response
    # ----------------------------------------------------------------------
    structured = {
        "agent_identifier": agent_did,
        "admin_personal_access_token": admin_pat,
        "wallet_url": wallet.url
    }
    
    
    if mcp_authentication == "OAuth 2.0 Client Credentials Grant":
        structured["agent_client_id"] = agent_did
        structured["agent_client_secret"] = client_secret
        structured["authorization_server"] = mode.server

        text = (
            "New agent identifier and wallet created.\n"
            f"Agent DID: {agent_did}\n"
            f"Wallet URL: {wallet.url}\n"
            "Copy your admin personal access token and OAuth client credentials from the secure console; "
            "they are not stored and will not be shown again."
        )
    else:
        structured["agent_personal_access_token"] = agent_pat

        text = (
            "New agent identifier and wallet created.\n"
            f"Agent DID: {agent_did}\n"
            f"Wallet URL: {wallet.url}\n"
            "Copy the agent personal access token and the admin personal access token from the secure console; "
            "they are not stored and will not be shown again."
        )

    # ----------------------------------------------------------------------
    # 7) Notify admin / user
    # ----------------------------------------------------------------------
    message_text = "Wallet created for " + " ".join(admins_login)
    message.message(
        "A new wallet for AI Agent has been created",
        "thierry.thevenet@talao.io",
        message_text,
        mode,
    )

    return _ok_content([{"type": "text", "text": text}], structured=structured)


# admin
def call_update_configuration(
    arguments: Dict[str, Any],
    agent_identifier: str,
    config: dict = None,
) -> Dict[str, Any]:
    """
    Update this Agent's wallet configuration.

    Can update:
      - always_human_in_the_loop (bool)
      - ecosystem_profile (via 'ecosystem' string)
      - agent_framework (string)
      - agentcard_url (A2AService in DID Document, id = did + '#a2a')
      - client_public_key (public JWK for OAuth2 private_key_jwt client auth)
    """
    # 0. Load wallet
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).one_or_none()
    if not this_wallet:
        return _ok_content(
            [{"type": "text", "text": "Wallet not found for this agent_identifier"}],
            is_error=True,
        )

    updated: Dict[str, Any] = {}

    # 1. human-in-the-loop
    if "always_human_in_the_loop" in arguments:
        value = bool(arguments.get("always_human_in_the_loop"))
        this_wallet.always_human_in_the_loop = value
        updated["always_human_in_the_loop"] = value

    # 2. ecosystem profile
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

    # 3. agent framework
    if "agent_framework" in arguments and arguments.get("agent_framework"):
        af = arguments["agent_framework"]
        this_wallet.agent_framework = af
        updated["agent_framework"] = af

    # 4. agentcard_url (stored in DID Document as A2AService with id did + '#a2a')
    if "agentcard_url" in arguments:
        agentcard_url = arguments.get("agentcard_url") or None

        # Load DID Document strictly; if it is broken we fail rather than wipe it.
        try:
            did_document = (
                json.loads(this_wallet.did_document)
                if isinstance(this_wallet.did_document, str) and this_wallet.did_document
                else {}
            )
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

    # 5. client_public_key for JWT client authentication (private_key_jwt)
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

    # 6. Persist
    db.session.commit()

    # 7. Build a structured response (JSON-safe)
    client_pk = None
    if this_wallet.client_public_key:
        try:
            client_pk = json.loads(this_wallet.client_public_key)
        except Exception:
            client_pk = None

    structured = {
        "agent_identifier": this_wallet.agent_identifier,
        "wallet_url": this_wallet.url,
        "ecosystem_profile": this_wallet.ecosystem_profile,
        "publish_unpublish": this_wallet.publish_unpublish,
        "sign": this_wallet.sign,
        "receive_credentials": this_wallet.receive_credentials,
        "agent_framework": this_wallet.agent_framework,
        "always_human_in_the_loop": this_wallet.always_human_in_the_loop,
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
def call_describe_identity_document(agent_identifier) -> Dict[str, Any]:
    """
    Dev tool: inspect and summarize the DID Document associated with this Agent's wallet.
    """
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).one_or_none()
    if not this_wallet:
        return _ok_content(
            [{"type": "text", "text": f"No wallet found for Agent DID {agent_identifier}."}],
            is_error=True,
        )

    try:
        did_document = json.loads(this_wallet.did_document or "{}")
    except Exception:
        did_document = {}

    vm_list = did_document.get("verificationMethod", [])
    auth = did_document.get("authentication", [])
    assertion = did_document.get("assertionMethod", [])
    services = did_document.get("service", [])

    linked_vp_services = [
        s for s in services if s.get("type") == "LinkedVerifiablePresentation"
    ]

    structured = {
        "agent_identifier": agent_identifier,
        "did_document": did_document,
        "verification_methods": vm_list,
        "authentication": auth,
        "assertionMethod": assertion,
        "services": services,
        "linked_vp_services": linked_vp_services,
    }

    text_lines = [
        f"DID Document for Agent {agent_identifier}:",
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


def call_register_wallet_as_chat_agent(arguments, agent_identifier, config) -> Dict[str, Any]:
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).one_or_none()
    if not this_wallet:
        return _ok_content(
            [{"type": "text", "text": "Wallet not found for this agent_identifier"}],
            is_error=True,
        )
    profile = arguments.get("my-chat")
    if not profile:
        # ex : did:web:wallet4agent.com:myagent  -> "myagent"
        #      did:cheqd:testnet:xxx-yyy-zzz    -> dernière partie
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


def call_create_agent_wallet(arguments: Dict[str, Any], agent_identifier, config: dict) -> Dict[str, Any]:
    mode = config["MODE"]
    manager = config["MANAGER"]

    admins_identity_provider = arguments.get("admins_identity_provider")
    admins_login = (arguments.get("admins_login") or "").split(",")
    agent_identifier = arguments.get("agent_identifier") or agent_identifier
    
    wallets = Wallet.query.filter_by(agent_identifier=agent_identifier).all()
    # cannot create more than 1 wallet per agent
    if wallets:
        return _ok_content(
                [{"type": "text", "text": "This Agent has one wallet"}],
                is_error=True,
            )

    # 1) Initialise Universal Registrar client (local docker-compose: http://localhost:9080/1.0)
    client = UniversalRegistrarClient()
    result = client.create_only_wallet(agent_identifier, manager)
    if not result:
        return _ok_content(
                [{"type": "text", "text": "Identifier not supported"}],
                is_error=True,
            )
    wallet_identifier = str(uuid.uuid4())
    wallet_url = f"{mode.server.rstrip('/')}/wallets/{wallet_identifier}"
    
    admin_pat, admin_pat_jti = oidc4vc.generate_access_token(agent_identifier, "admin", "pat")
    agent_pat, agent_pat_jti = oidc4vc.generate_access_token(agent_identifier, "agent", "pat")
    mcp_authentication = arguments.get("mcp_client_authentication")
    
    client_secret = secrets.token_urlsafe(64)

    # ----------------------------------------------------------------------
    # 5) Create / update admins and wallet in DB
    # ----------------------------------------------------------------------

    wallet = Wallet(
        admin_pat_jti=admin_pat_jti,
        agent_pat_jti=agent_pat_jti,
        mcp_authentication=mcp_authentication,
        client_secret_hash=oidc4vc.hash_client_secret(client_secret),
        admins_identity_provider=admins_identity_provider,
        admins_login=json.dumps(admins_login),
        agent_identifier=agent_identifier,
        wallet_identifier=wallet_identifier,
        url=wallet_url,
        always_human_in_the_loop=arguments.get("always_human_in_the_loop"),
        publish_unpublish=0,
        sign=arguments.get("sign"),
        notification_email=arguments.get("notification_email"),
        receive_credentials=arguments.get("receive_credentials")
    )
    # If your Wallet model has a key_id column, you can also store:
    # wallet.key_id = key_id

    for user_login in admins_login:
        if admins_identity_provider == "google":
            email = user_login
            login = email
            admin = User.query.filter_by(email=email).first()
        elif admins_identity_provider == "github":
            admin = User.query.filter_by(email=user_login).first()
            email = ""
            login = user_login
        else:
            return _ok_content(
                [{"type": "text", "text": "Identity provider not supported"}],
                is_error=True,
            )

        if not admin:
            admin = User(
                email=email,
                login=login,
                registration="wallet_creation",
                subscription="free",
            )
        db.session.add(admin)

    db.session.add(wallet)
    db.session.commit()
    
    # ----------------------------------------------------------------------
    # 6) Build structured response
    # ----------------------------------------------------------------------
    structured = {
        "agent_identifier": agent_identifier,
        "admin_personal_access_token": admin_pat,
        "agent_personal_access_token": agent_pat,
        "wallet_url": wallet.url
    }
    
    
    if mcp_authentication == "OAuth 2.0 Client Credentials Grant":
        structured["agent_client_id"] = agent_identifier
        structured["agent_client_secret"] = client_secret
        structured["authorization_server"] = mode.server

        text = (
            "New agent identifier and wallet created.\n"
            f"Agent DID: {agent_identifier}\n"
            f"Wallet URL: {wallet.url}\n"
            "Copy your admin personal access token and OAuth client credentials from the secure console; "
            "they are not stored and will not be shown again."
        )
    else:
        structured["agent_personal_access_token"] = agent_pat

        text = (
            "New agent identifier and wallet created.\n"
            f"Agent DID: {agent_identifier}\n"
            f"Wallet URL: {wallet.url}\n"
            "Copy the agent personal access token and the admin personal access token from the secure console; "
            "they are not stored and will not be shown again."
        )

    # ----------------------------------------------------------------------
    # 7) Notify admin / user
    # ----------------------------------------------------------------------
    message_text = "Wallet created for " + " ".join(admins_login)
    message.message(
        "A new wallet for AI Agent has been created",
        "thierry.thevenet@talao.io",
        message_text,
        mode,
    )

    return _ok_content([{"type": "text", "text": text}], structured=structured)