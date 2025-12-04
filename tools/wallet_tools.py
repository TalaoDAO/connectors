import json
from typing import Any, Dict, List, Optional
from db_model import Wallet, db, User, Attestation
import secrets
import logging
from utils import oidc4vc, message
import hashlib
from datetime import datetime
import base64
from universal_registrar import UniversalRegistrarClient
import linked_vp

# do not provide this tool to an LLM
tools_guest = [
    {
        "name": "create_agent_identifier_and_wallet",
        "description": "Generate an identifier (DID) for the Agent in the ecosystem and create a new wallet to store Agent digital credentials as verifiable credentials.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_name": {
                    "type": "string",
                    "description": "Optional agent name. If it exists this name will be used to create the DID of the Agent."                    
                },
                "did_method": {
                    "type": "string",
                    "description": "Optionl DID Method, did:web by default",
                    "enum": ["did:web", "did:cheqd"],
                    "default": "did:web"
                },
                "ecosystem_profile": {
                    "type": "string",
                    "description": "Ecosystem profile",
                    "enum": ["DIIP V4", "DIIP V3", "EWC", "ARF"],
                    "default": "DIIP V3"
                },
                "mcp_client_authentication": {
                    "type": "string",
                    "description": "Authentication between MCP client and MCP server for agent. Dev and admin use PAT",
                    "enum": ["Personal Access Token (PAT)", "OAuth 2.0 Client Credentials Grant"],
                    "default": "Personal Access Token (PAT)"
                },
                "owners_identity_provider": {
                    "type": "string",
                    "description": "Identity provider for owners",
                    "enum": ["google", "github"],
                    "default": "google"
                },
                "owners_login": {
                    "type": "string",
                    "description": "One or more user login separated by a comma (Google email, Github login or personal email). This login will be needed to accept new attestations offer."
                }
            },
            "required": ["owners_identity_provider", "owners_login"]
        }
    }
]


tools_dev = [
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
        "name": "create_OASF",
        "description": "Add an OASF record to the DID Document as a Linked VP. The Open Agent Schema Framework (OASF) is a standardized schema system for defining and managing AI agents and MCP server.",
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
        "name": "delete_identity",
        "description": "Delete agent identifier and wallet",
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
                    "enum": ["agent", "dev"],
                    "default": "dev"
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


# for dev
def call_delete_identity(wallet_did) -> Dict[str, Any]:
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


# dev tool
def call_get_configuration(agent_identifier, config) -> Dict[str, Any]:
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()

    # Turn all DB columns into a dict
    structured = {
        column.name: getattr(this_wallet, column.name)
        for column in Wallet.__table__.columns
    }
    attestations = Attestation.query.filter(Attestation.wallet_did == agent_identifier).all()
    structured["nb_attestations"] = len(attestations)
    structured["nb attestations_published"] = len(json.loads(this_wallet.linked_vp))
    if structured.get("created_at"):
        structured["created_at"] = structured.get("created_at").isoformat()
    if structured.get("did_document"):
        structured["did_document"] = json.loads(structured["did_document"])
    
    # remove useless info
    final_structured = {key: value for key, value in structured.items() if key not in ["id", "agent_pat_jti", "dev_pat_jti"]}
    
    return _ok_content(
        [{"type": "text", "text": "All data"}],
        structured=final_structured,
    )
    

def call_rotate_personal_access_token(arguments, agent_identifier) -> Dict[str, Any]:
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    structured = {
        "agent_identifier": agent_identifier,
        "wallet_url": this_wallet.url
    }
    if arguments.get("role") == "dev":
        dev_pat, dev_pat_jti = oidc4vc.generate_access_token(agent_identifier, "dev", "pat")
        this_wallet.dev_pat_jti = dev_pat_jti
        structured["dev_personal_access_token"] = dev_pat
        text = "New personal access token available for dev. Copy this access token which is not stored."
    else:
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(agent_identifier, "agent", "pat", duration=90*25*60*60)
        this_wallet.agent_pat_jti = agent_pat_jti
        structured["agent_personal_access_token"] = agent_pat
        text = "New personal access token available for agent. Copy this access token which is not stored."
    db.session.commit()
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
        "agent_identifier": this_wallet.did,
        "wallet_url": this_wallet.url,
        "did_document": did_document,
        "added_key_id": verification_method_id,
    }
    return _ok_content([{"type": "text", "text": text}], structured=structured)



def hash_client_secret(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()



# guest tool

from typing import Dict, Any


def call_create_agent_identifier_and_wallet(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    mode = config["MODE"]
    manager = config["MANAGER"]

    # Normalise agent_name → "my-agent" instead of "my agent"
    raw_agent_name = arguments.get("agent_name", "") or ""
    agent_name = "-".join(raw_agent_name.split()) or None

    owners_identity_provider = arguments.get("owners_identity_provider")
    owners_login = (arguments.get("owners_login") or "").split(",")
    agent_card_url = arguments.get("agentcard_url")

    # 1) Initialise Universal Registrar client (local docker-compose: http://localhost:9080/1.0)
    client = UniversalRegistrarClient()

    method = arguments.get("did_method")

    # Build service endpoints dynamically from your mode.server
    # e.g. https://wallet4agent.com/agents/<did> or similar
    # Here we keep it simple: OIDC4VP and A2A entrypoints under your base server URL.
    a2a_endpoint = agent_card_url or (mode.server.rstrip("/") + "/a2a-card")

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

    wallet_url = mode.server.rstrip("/") + "/" + agent_did

    if not did_document:
        return _ok_content(
            [{"type": "text", "text": "DID Document registration failed"}],
            is_error=True,
        )

    # ----------------------------------------------------------------------
    # 4) Generate dev + agent PATs
    # ----------------------------------------------------------------------
    dev_pat, dev_pat_jti = oidc4vc.generate_access_token(agent_did, "dev", "pat")
    agent_pat, agent_pat_jti = oidc4vc.generate_access_token(
        agent_did, "agent", "pat", duration=90 * 24 * 60 * 60
    )

    mcp_authentication = arguments.get("mcp_client_authentication")
    client_secret = secrets.token_urlsafe(64)

    # ----------------------------------------------------------------------
    # 5) Create / update owners and wallet in DB
    # ----------------------------------------------------------------------

    wallet = Wallet(
        dev_pat_jti=dev_pat_jti,
        agent_pat_jti=agent_pat_jti,
        mcp_authentication=mcp_authentication,
        client_secret_hash=oidc4vc.hash_client_secret(client_secret),
        owners_identity_provider=owners_identity_provider,
        owners_login=json.dumps(owners_login),
        agent_framework="None",
        did=agent_did,
        did_document=json.dumps(did_document),
        url=wallet_url,
    )
    # If your Wallet model has a key_id column, you can also store:
    # wallet.key_id = key_id

    for user_login in owners_login:
        if owners_identity_provider == "google":
            email = user_login
            login = email
            owner = User.query.filter_by(email=email).first()
        elif owners_identity_provider == "github":
            owner = User.query.filter_by(email=user_login).first()
            email = ""
            login = user_login
        #elif owners_identity_provider == "wallet":
        #    login = user_login
        #    owner = User.query.filter_by(login=user_login).first()
        #    email = ""
        else:
            return _ok_content(
                [{"type": "text", "text": "Identity provider not supported"}],
                is_error=True,
            )

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

    # ----------------------------------------------------------------------
    # 6) Build structured response
    # ----------------------------------------------------------------------
    structured = {
        "agent_identifier": agent_did,
        "dev_personal_access_token": dev_pat,
        "wallet_url": wallet.url,
    }

    if mcp_authentication == "OAuth 2.0 Client Credentials Grant":
        structured["agent_client_id"] = agent_did
        structured["agent_client_secret"] = client_secret
        structured["authorization_server"] = mode.server

        text = (
            "New agent identifier and wallet created.\n"
            f"Agent DID: {agent_did}\n"
            f"Wallet URL: {wallet.url}\n"
            "Copy your dev personal access token and OAuth client credentials from the secure console; "
            "they are not stored and will not be shown again."
        )
    else:
        structured["agent_personal_access_token"] = agent_pat

        text = (
            "New agent identifier and wallet created.\n"
            f"Agent DID: {agent_did}\n"
            f"Wallet URL: {wallet.url}\n"
            "Copy the agent personal access token and the dev personal access token from the secure console; "
            "they are not stored and will not be shown again."
        )

    # ----------------------------------------------------------------------
    # 7) Notify admin / user
    # ----------------------------------------------------------------------
    message_text = "Wallet created for " + " ".join(owners_login)
    message.message(
        "A new wallet for AI Agent has been created",
        "thierry.thevenet@talao.io",
        message_text,
        mode,
    )

    return _ok_content([{"type": "text", "text": text}], structured=structured)


# dev
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
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
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
        a2a_id = f"{this_wallet.did}#a2a"

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
        "agent_identifier": this_wallet.did,
        "wallet_url": this_wallet.url,
        "ecosystem_profile": this_wallet.ecosystem_profile,
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
def call_create_oasf(agent_identifier, config):
    manager = config["MANAGER"]
    mode = config["MODE"]
    with open("OASF.json", "r", encoding="utf-8") as f:
        oasf_json = json.load(f)
    oasf_json["id"] = agent_identifier
    oasf_json["disclosure"] = ["all"]
    oasf_json["vct"] = "urn:ai-agent:oasf:0001"
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    profile = this_wallet.ecosystem_profile
    if profile == "DIIP V3":
        draft = 13
    else:
        draft = 15
    cred = oidc4vc.sign_sdjwt_by_agent(oasf_json, agent_identifier, manager, draft=draft, duration=360*24*60*60)
    success, message = linked_vp.store_and_publish(cred, agent_identifier, manager, mode, published=True, type="OASF")
    if success:
        structured = {
            "success": True,
            "message": message
        }
        text = f"{message} for Agent {agent_identifier}"
        return _ok_content([{"type": "text", "text": text}], structured=structured)

    logging.warning("Failed to publish OASF record as LInked VP " + message)
    text = f"Failed to publish OASF record"
    return _ok_content([{"type": "text", "text": text}], is_error=True)
