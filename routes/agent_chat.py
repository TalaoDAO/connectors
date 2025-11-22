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
    app.add_url_rule('/agent', view_func=agent_page, methods=['POST', 'GET'])


# Your MCP server endpoint (public HTTPS)
MCP_SERVER_URL = "https://wallet4agent.com/mcp"

# Demo Agent DID
DEMO_AGENT_DID = "did:web:wallet4agent.com:demo"

# Encrypted PAT for the demo agent did:web:wallet4agent.com:demo
MCP_AGENT_PAT, _jti = oidc4vc.generate_access_token(
    DEMO_AGENT_DID,
    "agent",
    "pat",
    jti="demo",
    duration=360 * 24 * 60 * 60,
)

print("demo PAT", MCP_AGENT_PAT)

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
            f"Your identity (DID) is fixed and already created: {DEMO_AGENT_DID}. "
            "This DID identifies you as an Agent.\n"
            "Your wallet is already attached to this DID and you are authenticated with an "
            "Agent-level bearer token (Agent PAT) that is managed outside the chat.\n\n"

            "OBJECTIVE:\n"
            "- Demonstrate what an Agent with a Wallet4Agent wallet can do through the MCP server.\n"
            "- You normally operate using the existing demo Agent wallet. However, if the user asks "
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
            "- 'start_user_verification': send a verification email to a human user.\n"
            "- 'poll_user_verification': check the current result of the most recent user verification.\n"
            "- 'start_agent_authentication': start an authentication of another Agent DID.\n"
            "- 'poll_agent_authentication': check the current result of the most recent agent authentication.\n\n"
     
        ),
    }
]


# Short acknowledgement words that should be treated as confirmations
ACK_WORDS = {"yes", "ok", "okay", "yep", "yeah", "sure", "alright", "go ahead"}


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
            # Agent-level verifier tools (to check human users and agents)
            "start_user_verification",
            "poll_user_verification",
            "start_agent_authentication",
            "poll_agent_authentication",
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
    Even though the route is named '/agent', this assistant behaves as
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

    # If the user sends only a short acknowledgement, rewrite it with context
    if user_message.lower() in ACK_WORDS:
        last_assistant = None
        for msg in reversed(conversation_history):
            if msg.get("role") == "assistant":
                last_assistant = msg.get("content", "")
                break

        if last_assistant:
            # Truncate the last assistant message to avoid huge prompts
            snippet = last_assistant[-1000:]
            user_message = (
                "Yes. This 'yes' is explicitly confirming your previous proposal "
                "and answering your last question. The previous assistant message was:\n"
                "```" + snippet + "```\n"
                "Please continue with the exact flow you proposed there, using the "
                "appropriate MCP tools, instead of changing topic."
            )

    reply = call_agent(user_message, conversation_history)
    return jsonify({"reply": reply})
