import json
from typing import List, Dict, Any
from flask import request, jsonify, render_template
from openai import OpenAI
from utils import oidc4vc
import logging
from db_model import Wallet



# Short acknowledgement words that should be treated as confirmations
ACK_WORDS = {"yes", "ok", "okay", "done", "yep", "yeah", "sure", "alright", "go ahead"}

# Patterns that indicate the assistant is asking for explicit confirmation
CONFIRMATION_PATTERNS = (
    "may i ",
    "do you want me to",
    "should i ",
    "shall i ",
    "do you want me to start",
    "do you want me to send",
    "may i send",
    "may i start",
    "if you'd like,"
)


# Your MCP server endpoint (public HTTPS)
MCP_SERVER_URL = "https://wallet4agent.com/mcp"

# --------- PROFILES / DIDs / PATs ---------
ALLOWED_PROFILES = {"demo", "demo2", "diipv4", "arf", "ewc"}

# Map profile -> DID
AGENT_DIDS: Dict[str, str] = {
    profile: f"did:web:wallet4agent.com:{profile}" for profile in ALLOWED_PROFILES
}

MCP_AGENT_PATS: Dict[str, str] = {}
MCP_DEV_PATS: Dict[str, str] = {}
conversation_histories: Dict[str, List[Dict[str, str]]] = {}
pending_confirmations: Dict[str, str | None] = {}


# Load OpenAI API key from keys.json
_keys = json.load(open("keys.json", "r"))
openai_key = _keys["openai"]
client = OpenAI(api_key=openai_key)


def init_app(app):
    app.add_url_rule('/chat', view_func=chat, methods=['GET', 'POST'])
    app.add_url_rule('/agent', view_func=agent_page, methods=['POST', 'GET'])
    app.add_url_rule('/agent/<profile>', view_func=agent_page_profile, methods=['POST', 'GET'])
    app.add_url_rule('/agent/register', view_func=register_agent_endpoint, methods=['POST'])
    
    with app.app_context():
        
        for profile, did in AGENT_DIDS.items():
            if profile not in conversation_histories:
                wallet_profile = ecosystem(profile)
                register_agent_profile(profile, did, wallet_profile)
                logging.info(f"Initialized built-in chat agent profile '{profile}' with DID {did}")
        
        wallets = Wallet.query.filter(Wallet.agent_identifier.like("did:web:wallet4agent.com:%")).all()
        for w in wallets:
            profile = w.agent_identifier.split(":")[-1]
            if profile not in AGENT_DIDS:
                wallet_profile = getattr(w, "ecosystem_profile", None) or ecosystem(profile)
                register_agent_profile(profile, w.agent_identifier, wallet_profile)
                logging.info(f"Registered chat agent profile '{profile}' for DID {w.agent_identifier}")
        
        extra_agents = Wallet.query.filter(Wallet.is_chat_agent == True).all()        
        for w in extra_agents:
            profile = w.agent_identifier.split(":")[-1]
            profile = profile.lower()
            if profile not in AGENT_DIDS:
                wallet_profile = getattr(w, "ecosystem_profile", None) or ecosystem(profile)
                register_agent_profile(profile, w.agent_identifier, wallet_profile)
                logging.info(f"Re-registered chat agent profile '{profile}' for DID {w.agent_identifier} from DB")


def ecosystem(wallet_profile):
    if wallet_profile in ["demo", "demo2", "cheqd"]:
        return "DIIP V3"
    elif wallet_profile == "diipv4":
        return "DIIP V4"
    else:
        return "EUDIW-ARF"


def _normalize_profile(profile) -> str:
    """
    Normalize and validate profile name.
    - default to 'demo' when no profile is provided or unknown.
    """
    if not profile:
        return "demo"
    profile = profile.lower()
    return profile if profile in ALLOWED_PROFILES else "demo"


def _build_system_message(agent_did: str, ecosystem) -> Dict[str, str]:
    """
    Build the system prompt for a given agent DID.
    """
    content = (
        "You are an AI Agent connected to the Wallet4Agent MCP server in *agent* role.\n\n"
        f"Your identity (DID) is fixed and already created: {agent_did}. "
        "This DID identifies you as an Agent.\n"
        "Your wallet is already attached to this DID and you are authenticated with an "
        "Agent-level bearer token (Agent PAT) that is managed outside the chat.\n\n"
        f"You are compliant with the ecosystem: {ecosystem}" 
        "Your owner is the company Web3 Digital Wallet (Talao)"
        "\n\n"

        "OBJECTIVE:\n"
        "- Demonstrate what an Agent with a Wallet4Agent wallet can do through the MCP server.\n"
        "- You normally operate using the existing Agent wallet. However, if the user asks "
        "  how to create a DID, how to attach a wallet to an Agent, or how to create a new "
        "  Wallet4Agent instance, you SHOULD explain the steps, even though you will not "
        "  actually create those resources yourself.\n\n"

        "HIGH-PRIORITY RULES (take precedence over anything else):\n"
        "- When you ask the user for confirmation to perform a specific action (for example, "
        "  sending a verification email or starting agent authentication) and they reply with a "
        "  short acknowledgement such as 'yes', 'ok', 'okay', 'sure', 'go ahead', or similar, "
        "  you MUST treat that reply as approval of your most recent concrete proposal and you "
        "  MUST execute the corresponding MCP tool flow immediately.\n\n"

        "CONFIRMATIONS & FLOW CONTROL:\n"
        "- When you finish a message by proposing a specific action or asking a concrete question "
        "  (for example: 'May I send an over-18 verification email to thierry@altme.io now?' or "
        "  'Do you want me to start authentication for DID did:web:wallet4agent.com:demo2?') and "
        "  the user responds with a short acknowledgement, you MUST interpret that as approval "
        "  of your latest concrete proposal in your previous message.\n"
        "- In that case, immediately proceed with the action using MCP tools instead of changing "
        "  topic, re-introducing yourself, or proposing new options.\n\n"

        "SEMANTIC CHOICE ANSWERS:\n"
        "- When you ask the user a multiple-choice question (for example: 'Which would you like "
        "  me to verify: your profile, or your over-18 status?') and the user replies with a "
        "  short phrase that clearly corresponds to one of the choices (such as 'my age', "
        "  'age', 'over 18', 'over18', 'profile', 'my profile'), you MUST interpret that reply "
        "  as the direct answer to your question.\n"
        "- If the user reply combines a confirmation word with a choice (for example: 'yes over18', "
        "  'yes, my age', 'ok profile'), you MUST treat that as both (a) confirmation and (b) "
        "  selection of that option.\n"
        "- Never ask the user again to provide information (such as email or verification type) "
        "  if you already have that information from earlier in the conversation.\n\n"
        
        "ATTENTIONS FOR ATTESTATIONS:\n"
        "- If the user asks for attestations / credentials / Linked Verifiable Presentations "
        "  of ANY DID (including another agent), you MUST first call the MCP tool "
        "  'get_attestations_of_another_agent' with 'agent_identifier' equal to that DID.\n"
        "- Only after you have tried the tool and received a response may you explain "
        "  limitations (for example, DID not resolvable, no LinkedVerifiablePresentation "
        "  services, etc.). Never claim you 'cannot access' another agent's attestations "
        "  unless the tool result actually indicates that.\n\n"

        "EMAIL MEMORY:\n"
        "- As soon as the user provides text that looks like an email address (for example "
        "  something containing '@' and a domain like '.com', '.io', '.fr'), you MUST store it "
        "  mentally as the current email to use for this verification flow.\n"
        "- From that point on, you MUST NOT claim that you 'do not have the email' or ask again "
        "  for the email unless the user explicitly changes it.\n\n"

        "INTERNAL DETAILS (never mention to the user):\n"
        "- You MUST NOT mention internal identifiers, Redis keys, opaque IDs, or any "
        "  low-level workflow details in your replies. These are only for your internal tool calls.\n"
        "- If something goes wrong (for example, a verification is 'not_found' or expired), "
        "  apologize in plain language and suggest simple next steps such as 'please click the "
        "  link in the email again' or 'let's restart the verification', without mentioning any "
        "  internal technical cause.\n\n"

        "AVAILABLE MCP TOOLS (agent role):\n"
        "- 'describe_wallet4agent': explain what the Wallet4Agent server and its wallet do.\n"
        "- 'help_wallet4agent': explain how to install Wallet4Agent, create a DID, "
        "  and attach a wallet to an Agent.\n"
        "- 'get_this_agent_data': inspect your own agent_identifier (DID), wallet URL, and wallet metadata.\n"
        "- 'get_attestations_of_this_wallet': list all attestations (verifiable credentials) in your wallet.\n"
        "- 'get_attestations_of_another_agent': Fetch published attestations of another Agent with its DID.\n"
        "- 'accept_credential_offer': accept an OIDC4VCI credential offer for this Agent.\n"
        "- 'sign_text_message': sign a text message using your DID keys.\n"
        "- 'sign_json_payload': sign a json payload using your DID keys.\n"
        "- 'publish_attestation': publish any attestation in the DID Document. \n"
        "- 'unpublish_attestation': unpublish any attestation of the DID Document. \n"
        "- 'start_user_verification': send a verification email to a human user.\n"
        "- 'poll_user_verification': check the current result of the most recent user verification.\n"
        "- 'start_agent_authentication': start an authentication of another Agent DID.\n"
        "- 'poll_agent_authentication': check the current result of the most recent agent authentication.\n\n"
    )
    
    did_cheqd_context = (
        "CHEQD DID DESCRIPTION:\n"
        "- As an AI Agent you use a did:cheqd Decentralized Identifier.\n"
        "- did:cheqd is anchored on the cheqd network, a decentralized identity blockchain built on Cosmos SDK and Tendermint.\n"
        "- It provides a tamper-resistant and censorship-resistant identity layer with high throughput and low fees.\n"
        "- did:cheqd identifiers are long-lived, globally resolvable, and designed for trustable interactions with real-world entities.\n"
        "\n"
        "KEY CAPABILITIES:\n"
        "- You can create, update, deactivate, and resolve DIDs via the Universal Registrar and Universal Resolver.\n"
        "- did:cheqd supports secure key management, verification methods, and service endpoints.\n"
        "- It enables issuing and verifying privacy-preserving Verifiable Credentials, including zero-knowledge proofs.\n"
        "- The network supports payment rails for usage-based identity transactions (e.g., credential issuance fees).\n"
        "\n"
        "USE CASES:\n"
        "- Strong identity for autonomous agents interacting across ecosystems.\n"
        "- Trusted communication where cryptographic guarantees are required.\n"
        "- Secure presentation and verification of credentials.\n"
        "- Interoperability with W3C DID standards and SSI open-source tooling.\n"
        "\n"
        "TECHNICAL NOTES:\n"
        "- did:cheqd supports mainnet and testnet environments.\n"
        "- Interaction is possible through REST, RPC, CLI, SDKs, and DID registrar drivers.\n"
        "- The DID Document may contain keys, authentication methods, assertion methods, and service endpoints.\n"
        "- Updates occur through signed on-chain or registrar operations.\n"
        "\n"
        "SUMMARY:\n"
        "- did:cheqd gives you a durable, cryptographically verifiable identity optimized for decentralized trust, "
        "credential ecosystems, and machine-to-machine interoperability.\n\n"
    )

    did_web_context = (
        "WEB DID DESCRIPTION:\n"
        "- As an AI Agent you use a did:web Decentralized Identifier.\n"
        "- did:web derives its trust model from the existing DNS + HTTPS security infrastructure.\n"
        "- The DID Document is hosted on a web server at a well-known URL associated with a domain you control.\n"
        "- Example: did:web:example.com resolves to https://example.com/.well-known/did.json\n"
        "- Identity ownership is proven through control of the domain and its HTTPS certificates.\n"
        "\n"
        "KEY CAPABILITIES:\n"
        "- did:web allows you to publish keys, verification methods, and service endpoints without blockchain dependencies.\n"
        "- Updating a DID Document is simple: modify the hosted did.json file and redeploy it.\n"
        "- Works seamlessly with Verifiable Credentials, signature suites, and W3C DID Core standards.\n"
        "- Integrates with the Universal Resolver and many SSI and cryptographic frameworks.\n"
        "- Enables service discovery (messaging, agent endpoints, credential services, API URLs, etc.).\n"
        "\n"
        "TRUST MODEL:\n"
        "- did:web relies on the security of TLS certificates and DNS domain ownership.\n"
        "- Trust anchoring is centralized but globally interoperable and widely adopted.\n"
        "- It is ideal when identity needs to be tied to an organization, domain, or hosted service.\n"
        "\n"
        "USE CASES:\n"
        "- Web-based agents and services needing publicly discoverable identities.\n"
        "- Organizations wanting a DID anchored to their existing domain name.\n"
        "- Easy onboarding into decentralized identity ecosystems without blockchain requirements.\n"
        "- Rapid development, demos, proofs-of-concept, and interoperability pilots.\n"
        "\n"
        "TECHNICAL NOTES:\n"
        "- DID Documents are hosted as JSON-LD at known URL paths defined by the DID Web Method spec.\n"
        "- Supported formats include HTTPS-based domains and subdomains, and encoded paths for nested structures.\n"
        "- Verification keys, authentication methods, assertion methods, and service endpoints are supported.\n"
        "- Resolution uses standard HTTPS GET operations and does not require node infrastructure.\n"
        "\n"
        "SUMMARY:\n"
        "- did:web provides you with a stable, domain-anchored, easily updateable identity suited for service agents, "
        "web integrations, organizational identities, and fast deployments where DNS-based trust is acceptable.\n\n"
    )

    if agent_did.startswith("did:cheqd"):
        content += did_cheqd_context
    else:
        content += did_web_context

    return {"role": "system", "content": content}


def register_agent_profile(profile: str, did: str, wallet_profile: str | None = None) -> None:
    """
    Enregistre dynamiquement un agent de chat :
    - profile : identifiant court (demo, demo2, diipv4, arf, ewc, cheqd, etc.)
    - did : DID complet (did:web:..., did:cheqd:..., etc.)
    - wallet_profile : ex. 'DIIP V3', 'DIIP V4', 'EUDIW-ARF'
    """
    profile = profile.lower()
    ALLOWED_PROFILES.add(profile)
    AGENT_DIDS[profile] = did

    # Essayez de récupérer le wallet pour ce DID pour réutiliser les JTI existants
    wallet = Wallet.query.filter(Wallet.agent_identifier == did).first()
    if wallet:
        jti_agent = wallet.agent_pat_jti or profile
        jti_admin = wallet.admin_pat_jti or profile
    else:
        # fallback : ancien comportement
        jti_agent = profile
        jti_admin = profile

    # PAT Agent
    pat_agent, _ = oidc4vc.generate_access_token(
        did,
        "agent",
        "pat",
        jti=jti_agent,
        duration=360 * 24 * 60 * 60,
    )
    MCP_AGENT_PATS[profile] = pat_agent

    # PAT Admin / dev
    pat_admin, _ = oidc4vc.generate_access_token(
        did,
        "admin",
        "pat",
        jti=jti_admin,
        duration=360 * 24 * 60 * 60,
    )
    MCP_DEV_PATS[profile] = pat_admin

    # Historique de conversation avec message système
    eco = wallet_profile or ecosystem(profile)
    conversation_histories[profile] = [
        _build_system_message(did, eco)
    ]

    # Pas de flow de confirmation en cours au départ
    pending_confirmations[profile] = None



# --------- CORE CALL TO GPT + MCP ---------

def call_agent(prompt: str, history: List[Dict[str, str]], profile: str) -> str:
    """
    Call GPT with MCP tools enabled (Agent role, for the given profile)
    and return the assistant text reply as a string.
    """
    profile = _normalize_profile(profile)
    messages = history + [{"role": "user", "content": prompt}]

    # Build MCP tool configuration for the Agent role
    mcp_tool_config: Dict[str, Any] = {
        "type": "mcp",
        "server_label": "wallet4agent",
        "server_url": MCP_SERVER_URL,
        "allowed_tools": [
            # Agent-level wallet tools
            "help_wallet4agent",
            "get_this_agent_data",
            "get_attestations_of_this_wallet",
            "get_attestations_of_another_agent",
            "accept_credential_offer",
            "sign_text_message",
            "sign_json_payload",
            "publish_attestation",
            "unpublish_attestation",
            # Agent-level verifier tools (to check human users and agents)
            "start_user_verification",
            "poll_user_verification",
            "start_agent_authentication",
            "poll_agent_authentication",
        ],
        "require_approval": "never",
    }

    # Attach Authorization header so the MCP server sees us as the right agent profile
    pat = MCP_AGENT_PATS[profile]
    mcp_tool_config["headers"] = {"Authorization": f"Bearer {pat}"}

    response = client.responses.create(
        model="gpt-5.1",
        tools=[mcp_tool_config],
        input=messages,
    )

    texts: List[str] = []
    try:
        for item in response.output:
            if getattr(item, "type", None) == "message":
                for c in item.content:
                    if getattr(c, "type", None) == "output_text":
                        texts.append(c.text)
    except Exception:
        texts.append(str(response))

    reply_text = "\n".join(texts).strip()

    # Update history for this profile
    history.append({"role": "user", "content": prompt})
    if reply_text:
        history.append({"role": "assistant", "content": reply_text})

    # Detect if this assistant message is asking for confirmation
    lower_reply = reply_text.lower()
    if any(pattern in lower_reply for pattern in CONFIRMATION_PATTERNS):
        pending_confirmations[profile] = reply_text
    else:
        pending_confirmations[profile] = None

    return reply_text


# --------- HTTP ENDPOINTS ---------

def agent_page_profile(profile):
    """
    Render the web chat UI for a specific Agent profile.
    Example: /agent/demo2 or /agent/diipv4
    """
    normalized = _normalize_profile(profile)
    profile_name = AGENT_DIDS[normalized]
    
    return render_template("agent_chat.html", profile=normalized, profile_name=profile_name)


def agent_page():
    """
    Render the web chat UI for the default 'demo' Agent profile.
    Endpoint: /agent
    """
    return render_template("agent_chat.html", profile="demo", profile_name="did:web:wallet4agent.com:demo")


def chat():
    """
    JSON endpoint used by the web UI.

    Request JSON:
    { "message": "What can your wallet do?" }

    Optional query parameter:
    ?profile=demo2   (defaults to 'demo' if omitted or unknown)

    Response JSON:
    { "reply": "...assistant text..." }
    """
    data = request.get_json(force=True, silent=True) or {}
    user_message = data.get("message", "").strip()
    profile = _normalize_profile(request.args.get("profile"))
        
    if not user_message:
        return jsonify({"error": "missing 'message' in JSON body"}), 400

    # Get per-profile conversation history and pending confirmation
    history = conversation_histories[profile]
    pending_confirmation = pending_confirmations[profile]

    # If the user sends only a short acknowledgement, rewrite it with context
    if user_message.lower() in ACK_WORDS:
        if pending_confirmation:
            # The user is confirming the last *explicit* proposal that needed confirmation.
            snippet = pending_confirmation[-1000:]
            user_message = (
                "The user is confirming your previous concrete proposal. "
                "Treat this as explicit approval and proceed with that exact flow.\n\n"
                "Here is the proposal the user is confirming:\n"
                "```" + snippet + "```"
            )
            pending_confirmations[profile] = None
        else:
            # Fallback: no known pending action; interpret 'yes' in context
            last_assistant = None
            for msg in reversed(history):
                if msg.get("role") == "assistant":
                    last_assistant = msg.get("content", "")
                    break

            if last_assistant:
                snippet = last_assistant[-1000:]
                user_message = (
                    "The user answered only with a short acknowledgement like 'yes', "
                    "but there is no explicit pending action tracked. "
                    "Please interpret this 'yes' in context of your previous message:\n"
                    "```" + snippet + "```\n"
                    "If that message contained multiple options, pick the most likely one. "
                    "If it didn't actually request confirmation, ask the user to clarify."
                )

    reply = call_agent(user_message, history, profile)
    return jsonify({"reply": reply})


def register_agent_endpoint():
    """
    Endpoint appelé par le client MCP après création d'un DID.
    Body JSON attendu :
    {
      "profile": "cheqd-demo",
      "did": "did:cheqd:testnet:xxxx-....",
      "ecosystem": "DIIP V3"   # optionnel
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    profile = data.get("profile")
    did = data.get("did")
    ecosystem_profile = data.get("ecosystem")

    if not profile or not did:
        return jsonify({"error": "profile and did are required"}), 400

    register_agent_profile(profile, did, ecosystem_profile)
    return jsonify({"status": "ok", "profile": profile, "did": did})
