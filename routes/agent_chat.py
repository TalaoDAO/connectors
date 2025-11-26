import json
from typing import List, Dict, Any

from flask import Flask, request, jsonify, render_template
from openai import OpenAI
from utils import oidc4vc
import logging


# --------- OpenAI + MCP CONFIG ---------

# Load OpenAI API key from keys.json
_keys = json.load(open("keys.json", "r"))
openai_key = _keys["openai"]
client = OpenAI(api_key=openai_key)


def init_app(app):
    app.add_url_rule('/chat', view_func=chat, methods=['GET', 'POST'])
    app.add_url_rule('/agent', view_func=agent_page, methods=['POST', 'GET'])
    app.add_url_rule('/agent/<profile>', view_func=agent_page_profile, methods=['POST', 'GET'])


# Your MCP server endpoint (public HTTPS)
MCP_SERVER_URL = "https://wallet4agent.com/mcp"

# --------- PROFILES / DIDs / PATs ---------

# Allowed profiles
ALLOWED_PROFILES = {"demo", "demo2", "diipv4", "arf", "ewc"}

# Map profile -> DID
AGENT_DIDS: Dict[str, str] = {
    profile: f"did:web:wallet4agent.com:{profile}" for profile in ALLOWED_PROFILES
}

def ecosystem(wallet_profile):
    if wallet_profile in ["demo", "demo2"]:
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


# Generate an Agent PAT per profile once at startup
MCP_AGENT_PATS: Dict[str, str] = {}
for profile, did in AGENT_DIDS.items():
    pat, _jti = oidc4vc.generate_access_token(
        did,
        "agent",
        "pat",
        jti=profile,
        duration=360 * 24 * 60 * 60,
    )
    MCP_AGENT_PATS[profile] = pat


# Optional dev PAT (still using demo DID, if you need it somewhere else)
MCP_DEV_PAT, _jti = oidc4vc.generate_access_token(
    AGENT_DIDS["demo"],
    "dev",
    "pat",
    jti="demo-dev",
    duration=360 * 24 * 60 * 60,
)


# --------- HELPER: SYSTEM MESSAGE PER PROFILE ---------

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
        "- 'explain_how_to_install_wallet4agent': explain how to install Wallet4Agent, create a DID, "
        "  and attach a wallet to an Agent.\n"
        "- 'get_this_wallet_data': inspect your own agent_identifier (DID), wallet URL, and wallet metadata.\n"
        "- 'get_attestations_of_this_wallet': list all attestations (verifiable credentials) in your wallet.\n"
        "- 'get_attestations_of_another_agent': list published attestations of another Agent DID.\n"
        "- 'accept_credential_offer': accept an OIDC4VCI credential offer for this Agent.\n"
        "- 'sign_text_message': sign a text message using your DID keys.\n"
        "- 'sign_json_payload': sign a json payload using your DID keys.\n"
        "- 'start_user_verification': send a verification email to a human user.\n"
        "- 'poll_user_verification': check the current result of the most recent user verification.\n"
        "- 'start_agent_authentication': start an authentication of another Agent DID.\n"
        "- 'poll_agent_authentication': check the current result of the most recent agent authentication.\n\n"
    )
    return {"role": "system", "content": content}


# --------- FLASK APP ---------

app = Flask(__name__, template_folder="templates", static_folder="static")


# --------- GLOBAL STATE: PER PROFILE ---------

# Map profile -> conversation history list
conversation_histories: Dict[str, List[Dict[str, str]]] = {
    profile: [_build_system_message(AGENT_DIDS[profile], ecosystem(profile))]
    for profile in ALLOWED_PROFILES
}

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
)

# Map profile -> last assistant message that actually asked for confirmation
pending_confirmations = {
    profile: None for profile in ALLOWED_PROFILES
}


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
            "describe_wallet4agent",
            "explain_how_to_install_wallet4agent",
            "get_this_wallet_data",
            "get_attestations_of_this_wallet",
            "get_attestations_of_another_agent",
            "accept_credential_offer",
            "sign_text_message",
            "sign_json_payload",
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
    return render_template("agent_chat.html", profile=normalized)


def agent_page():
    """
    Render the web chat UI for the default 'demo' Agent profile.
    Endpoint: /agent
    """
    return render_template("agent_chat.html", profile="demo")


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
