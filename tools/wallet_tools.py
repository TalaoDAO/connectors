import json
from typing import Any, Dict, List, Optional
from db_model import Wallet, db, User
import secrets
import logging
from db_model import Attestation
from utils import oidc4vc, message
import hashlib
import random, string
from datetime import datetime
import base64

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
    if structured.get("created_at"):
        structured["created_at"] = structured.get("created_at").isoformat()
    if structured.get("did_document"):
        structured["did_document"] = json.loads(structured["did_document"])
    
    structured.pop("id", None)
    return _ok_content(
        [{"type": "text", "text": "All data"}],
        structured=structured,
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
        "dev_bearer_token": this_wallet.dev_token,
        "agent_bearer_token": this_wallet.agent_token,
        "wallet_url": this_wallet.url,
        "did_document": did_document,
        "added_key_id": verification_method_id,
    }
    return _ok_content([{"type": "text", "text": text}], structured=structured)



def hash_client_secret(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()



# guest tool
def call_create_agent_identifier_and_wallet(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    mode = config["MODE"]
    manager = config["MANAGER"]
    agent_name = "-".join(arguments.get("agent_name", "").split())
    owners_identity_provider = arguments.get("owners_identity_provider")
    owners_login = arguments.get("owners_login").split(",")
    agent_card_url = arguments.get("agentcard_url")
    
    # if did:web / persistent agent
    if not agent_name:
        agent_name = secrets.token_hex(16)
    agent_did = "did:web:wallet4agent.com:" + agent_name 
    # test if DID already exists
    one_wallet = Wallet.query.filter(Wallet.did == agent_did).one_or_none()
    if one_wallet:
        random_numbers = ''.join(random.choice(string.digits) for _ in range(3))
        agent_did += "-" + random_numbers 
    
    key_id = manager.create_or_get_key_for_tenant(agent_did + "#key-1")  # remove for testing
    jwk, kid, alg = manager.get_public_key_jwk(key_id) # remove for testing
    jwk = json.dumps({})
    url = mode.server + agent_did
    did_document = create_did_document(agent_did, jwk, url, agent_card_url=agent_card_url)
    dev_pat, dev_pat_jti = oidc4vc.generate_access_token(agent_did, "dev", "pat")
    agent_pat, agent_pat_jti = oidc4vc.generate_access_token(agent_did, "agent", "pat", duration=90*24*60*60)
    mcp_authentication = arguments.get("mcp_client_authentication")
    client_secret = secrets.token_urlsafe(64)
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
    structured = {
        "agent_identifier": agent_did,
        "dev_personal_access_token": dev_pat,
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

    # send message
    message_text = "Wallet created for " + " ".join(owners_login)
    message.message("A new wallet for AI Agent has been created", "thierry.thevenet@talao.io", message_text, mode)
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def create_did_document(did, jwk_1, url, agent_card_url=False):
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
            # Keep the same ID and type as in create_did_document()
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
    print("avant signature =", oasf_json)
    cred = oidc4vc.sign_sdjwt_by_agent(oasf_json, agent_identifier, manager, draft=13, duration=360*24*60*60)
    success, message = store_and_publish(cred, agent_identifier, manager, mode, published=True)
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



def store_and_publish(cred, agent_identifier, manager, mode, published=False):
    """ The OASF attestation is unique"""
    # store attestation
    vcsd = cred.split("~") 
    vcsd_jwt = vcsd[0]
    try:
        attestation_header = oidc4vc.get_header_from_token(vcsd_jwt)
        attestation_payload = oidc4vc.get_payload_from_token(vcsd_jwt)
    except Exception:
        return None, "Attestation is in an incorrect format and cannot be stored"

    # attestation as a service id
    #id = secrets.token_hex(16)
    service_id = agent_identifier + "#OASF"
    
    if published:
        result = publish(service_id, cred, mode.server, manager)
        if not result:
            logging.warning("publish failed")
            published = False
    
    attestation = Attestation.query.filter(Attestation.service_id == service_id).one_or_none()    
    if not attestation:
        attestation = Attestation(
                wallet_did=agent_identifier,
                service_id=service_id,
                vc=cred,
                vc_format=attestation_header.get("typ"),
                issuer=attestation_payload.get("iss"),
                vct=attestation_payload.get("vct"),
                name=attestation_payload.get("name",""),
                description=attestation_payload.get("description",""),
                published=published
            )
        db.session.add(attestation)
        text = "New OASF has been stored"
    else:
        attestation.vc = cred
        attestation.name = attestation_payload.get("name","")
        attestation.description = attestation_payload.get("description","")
        attestation.published = published
        text = "OASF has been updated"
    db.session.commit()
    if attestation: 
        logging.info("credential is stored as attestation #%s", attestation.id)
    
    return True, text


# helper: base64url without padding
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def publish(service_id, attestation, server, manager):
    wallet_did = service_id.split("#")[0]
    id = service_id.split("#")[1]

    this_wallet = Wallet.query.filter(Wallet.did == wallet_did).one_or_none()
    if this_wallet is None:
        logging.error("Wallet not found for DID %s", wallet_did)
        return None

    try:
        did_document = json.loads(this_wallet.did_document or "{}")
    except Exception:
        logging.exception("Invalid DID Document in wallet")
        return None

    sd_jwt_presentation = attestation.strip()
    if not sd_jwt_presentation.endswith("~"):
        sd_jwt_presentation = sd_jwt_presentation + "~"

    sd_jwt_plus_kb = sign_and_add_kb(sd_jwt_presentation, wallet_did, manager)
    if not sd_jwt_plus_kb:
        return None

    vp_resource = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation", "EnvelopedVerifiablePresentation"],
        "id": "data:application/dc+sd-jwt," + sd_jwt_plus_kb,
    }

    # Update linked_vp JSON: single entry for key "OASF"
    try:
        linked_vp_json = json.loads(this_wallet.linked_vp or "{}")
    except Exception:
        linked_vp_json = {}
    linked_vp_json[id] = vp_resource
    this_wallet.linked_vp = json.dumps(linked_vp_json)

    # Update DID Document service entries:
    # remove any existing LinkedVerifiablePresentation for this id / OASF
    service_array = did_document.get("service", []) or []
    endpoint = server + "service/" + wallet_did + "/" + id

    new_services = []
    for s in service_array:
        # Keep all services except:
        #  - exact same id, or
        #  - LinkedVerifiablePresentation with same endpoint
        if s.get("id") == service_id:
            continue
        if s.get("type") == "LinkedVerifiablePresentation" and s.get("serviceEndpoint") == endpoint:
            continue
        new_services.append(s)

    new_service = {
        "id": service_id,
        "type": "LinkedVerifiablePresentation",
        "serviceEndpoint": endpoint,
    }
    new_services.append(new_service)

    did_document["service"] = new_services
    this_wallet.did_document = json.dumps(did_document)

    db.session.commit()
    logging.info("attestation is published")

    return {
        "service_id": service_id,
        "service": new_service,
        "verifiable_presentation": vp_resource,
    }


    
def sign_and_add_kb(sd_jwt, wallet_did, manager):
    sd_jwt_presentation = sd_jwt.split("~")[0]
    now = int(datetime.utcnow().timestamp())
    nonce = secrets.token_urlsafe(16)
    vm = wallet_did + "#key-1"
    key_id = manager.create_or_get_key_for_tenant(vm)
    jwk, kid, alg = manager.get_public_key_jwk(key_id)

    # sd_hash = b64url( SHA-256( ascii(SD-JWT-presentation) ) )
    digest = hashlib.sha256(sd_jwt_presentation.encode("ascii")).digest()
    sd_hash = base64url_encode(digest)

    header = {
        "typ": "kb+jwt",
        "alg": alg,
    }
    payload = {
        "iat": now,
        "aud": wallet_did,
        "nonce": nonce,
        "sd_hash": sd_hash,
    }
    kb_token = manager.sign_jwt_with_key(key_id, header=header, payload=payload)
    return sd_jwt_presentation + "~" + kb_token  # compact JWS
    
