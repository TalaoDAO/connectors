import json
from typing import List, Dict

from flask import Flask, request, jsonify, render_template
from openai import OpenAI
from utils import oidc4vc
import logging


# --------- OpenAI + MCP CONFIG ---------

# Load OpenAI API key + demo agent PAT from keys.json
_keys = json.load(open("keys.json", "r"))
openai_key = _keys["openai"]
client = OpenAI(api_key=openai_key)

def init_app(app):
    app.add_url_rule('/chat',  view_func=chat, methods=['GET', 'POST'])
    app.add_url_rule('/agent',  view_func=agent_page, methods=['POST', 'GET'])


# Your MCP server endpoint (public HTTPS)
MCP_SERVER_URL = "https://wallet4agent.com/mcp"

# For information only: the demo Agent DID
DEMO_AGENT_DID = "did:web:wallet4agent.com:demo"

# Encrypted PAT for the demo agent did:web:wallet4agent.com:demo
MCP_AGENT_PAT, _jti = oidc4vc.generate_access_token(DEMO_AGENT_DID, "agent", "pat", jti="demo", duration=360*24*60*60)

# --------- FLASK APP ---------

app = Flask(__name__, template_folder="templates", static_folder="static")


# --------- GLOBAL CONVERSATION STATE ---------
# NOTE: this is process-wide. For a multi-user deployment, use per-session storage.
conversation_history: List[Dict[str, str]] = []

conversation_history = [
    {
        "role": "system",
        "content": (
            "You are an AI Agent connected to the Wallet4Agent MCP server in *agent* role.\n\n"
            "Your identity (DID) is fixed and already created: "
            f"'{DEMO_AGENT_DID}'. This DID identifies you as an Agent.\n"
            "Your wallet is already attached to this DID and you are authenticated with an "
            "Agent-level bearer token (Agent PAT) that is managed outside the chat.\n\n"
            "OBJECTIVE:\n"
            "- Demonstrate what an Agent with a Wallet4Agent wallet can do through the MCP server.\n"
            "- You are not here to create new agents or wallets, only to use the existing one.\n\n"
            "AVAILABLE MCP TOOLS (agent role):\n"
            "- 'describe_wallet4agent': explain what the Wallet4Agent server and its wallet do.\n"
            "- 'get_this_wallet_data': inspect your own agent_identifier (DID), wallet URL, and wallet metadata.\n"
            "- 'get_attestations_of_this_wallet': list all attestations (verifiable credentials) in your wallet.\n"
            "- 'get_attestations_of_another_agent': list published attestations of another Agent DID.\n"
            "- 'accept_credential_offer': accept an OIDC4VCI credential offer for this Agent.\n"
            "- 'start_user_verification' + 'poll_user_verification': verify a human user (email or wallet) "
            "  and read the result as an Agent.\n\n"
            "HOW TO BEHAVE:\n"
            "- Speak in the first person as this Agent (for example: 'My DID is ...', 'My wallet can prove ...').\n"
            "- When the user asks what you can do or wants an overview, first call the MCP prompt "
            "'explain_wallet4agent' or directly call the tool 'describe_wallet4agent'.\n"
            "- When the user wants to know YOUR identity or credentials, call the prompt "
            "'inspect_this_agent_wallet' or use 'get_this_wallet_data' and 'get_attestations_of_this_wallet'.\n"
            "- When the user gives you another Agent DID, use 'get_attestations_of_another_agent' to inspect it.\n"
            "- When the user provides a 'credential_offer' URL or JSON, use 'accept_credential_offer'.\n"
            "- When the user wants to prove age/email/wallet, use 'start_user_verification' then "
            "'poll_user_verification' with the returned user_id.\n\n"
            "SECURITY & SECRETS:\n"
            "- Never ask the user to paste personal access tokens, client secrets, or JWTs into the chat.\n"
            "- Never invent or reveal PATs, access tokens, or any secret material.\n"
            "- You may mention that you are authenticated as an Agent, but the actual token value "
            "is never shown or handled in the chat.\n\n"
            "FOCUS:\n"
            "- Keep answers short and practical (2–4 sentences) unless the user explicitly asks for more details.\n"
            "- Always try to show concrete things you can do *now* with your wallet, not just theory.\n"
        ),
    }
]


# --------- CORE CALL TO GPT + MCP ---------


def call_agent(prompt: str, history: List[Dict[str, str]]) -> str:
    """
    Call GPT with MCP tools enabled (Agent role, using the demo Agent wallet)
    and return the assistant text reply as a string.
    """
    messages = history + [
        {
            "role": "user",
            "content": prompt,
        }
    ]

    # Build MCP tool configuration for the Agent role
    mcp_tool_config: Dict[str, any] = {
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
            # Agent-level verifier tools (to check human users)
            "start_user_verification",
            "poll_user_verification",
            "start_agent_authentication",
            "poll_agent_authentication"
        ],
        "require_approval": "never",
    }

    # Attach Authorization header so the MCP server sees us as role='agent'
    if MCP_AGENT_PAT:
        mcp_tool_config["headers"] = {
            "Authorization": f"Bearer {MCP_AGENT_PAT}"
        }

    response = client.responses.create(
        model="gpt-5.1",
        tools=[mcp_tool_config],
        input=messages,
    )
    
    logging.info("response in chat = %s", response.output)

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

    history.append({"role": "user", "content": prompt})
    if reply_text:
        history.append({"role": "assistant", "content": reply_text})

    return reply_text


# --------- HTTP ENDPOINTS ---------


def agent_page():
    """
    Render the web chat UI for the demo Agent wallet assistant.
    Even though the route is named '/guest-agent', this assistant behaves as
    the demo Agent with DID did:web:wallet4agent.com:demo.
    """
    return render_template("agent_chat.html")


def chat():
    """
    JSON endpoint used by the web UI.

    Request JSON:
      { "message": "What can your wallet do?" }

    Response JSON:
      { "reply": "...assistant text..." }
    """
    data = request.get_json(force=True, silent=True) or {}
    user_message = data.get("message", "").strip()

    if not user_message:
        return jsonify({"error": "missing 'message' in JSON body"}), 400

    global conversation_history
    reply = call_agent(user_message, conversation_history)
    return jsonify({"reply": reply})

