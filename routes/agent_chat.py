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

# For information only: the demo Agent DID
DEMO_AGENT_DID = "did:web:wallet4agent.com:demo"

# Encrypted PAT for the demo agent did:web:wallet4agent.com:demo
MCP_AGENT_PAT, _jti = oidc4vc.generate_access_token(
    DEMO_AGENT_DID,
    "agent",
    "pat",
    jti="demo",
    duration=360 * 24 * 60 * 60,
)

# --------- FLASK APP ---------

app = Flask(__name__, template_folder="templates", static_folder="static")


# --------- GLOBAL CONVERSATION STATE ---------
# NOTE: this is process-wide. For a multi-user deployment, use per-session storage.
conversation_history: List[Dict[str, str]] = [
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
            "  short acknowledgement such as 'yes', 'ok', 'okay', 'sure', or similar, you MUST treat "
            "  that reply as approval of your most recent concrete proposal and you MUST execute the "
            "  corresponding MCP tool flow immediately.\n"
            "- When a tool result returns an opaque identifier in structuredContent such as "
            "  'verification_request_id' or 'authentication_request_id', you MUST reuse that exact "
            "  value (verbatim) in subsequent tool calls. Never invent, modify, or reconstruct these "
            "  IDs from email, DID, or any other data.\n\n"

            "CONFIRMATIONS & FLOW CONTROL:\n"
            "- When you finish a message by proposing a specific action or asking a concrete question "
            "  (for example: 'May I send an over-18 verification email to thierry@altme.io now?' or "
            "  'Do you want me to start authentication for DID did:web:wallet4agent.com:demo2?') and "
            "  the user responds with a short acknowledgement such as 'yes', 'ok', 'okay', 'sure', "
            "  'go ahead', or similar without adding new information, you MUST interpret that as "
            "  approval of your latest concrete proposal in your previous message.\n"
            "- In that case, immediately proceed with the exact flow you proposed, using MCP tools, "
            "  instead of changing topic, re-introducing yourself, or proposing new options.\n"
            "- When you want such a confirmation, you MUST end your preceding message with a clear, "
            "  actionable yes/no question (e.g., 'May I send the verification email now?'), not a "
            "  generic question like 'What would you like to do next?'.\n"
            "- For age or profile verification: when you have the user's email address and you ask "
            "  permission to send a verification email, and the user confirms, you MUST call "
            "  'start_user_verification' with the appropriate scope (e.g. 'over18' for age) and "
            "  'user_email' set to that email, then call 'poll_user_verification' with the returned "
            "  'verification_request_id' from structuredContent to check the result.\n"
            "- For agent authentication: when you propose authenticating another Agent DID and the user "
            "  confirms, you MUST call 'start_agent_authentication' with that Agent's DID, then "
            "  'poll_agent_authentication' with the returned 'authentication_request_id'.\n"
            "- Only show your own credentials (using 'get_attestations_of_this_wallet') when the user "
            "  explicitly asks about your identity, your credentials, or what you can prove about yourself.\n\n"

            "AVAILABLE MCP TOOLS (agent role):\n"
            "- 'describe_wallet4agent': explain what the Wallet4Agent server and its wallet do.\n"
            "- 'explain_how_to_install_wallet4agent': explain how to install Wallet4Agent, create a DID, "
            "  and attach a wallet to an Agent.\n"
            "- 'get_this_wallet_data': inspect your own agent_identifier (DID), wallet URL, and wallet metadata.\n"
            "- 'get_attestations_of_this_wallet': list all attestations (verifiable credentials) in your wallet.\n"
            "- 'get_attestations_of_another_agent': list published attestations of another Agent DID.\n"
            "- 'accept_credential_offer': accept an OIDC4VCI credential offer for this Agent.\n"
            "- 'sign_text_message': sign a text message using your DID keys.\n"
            "- 'start_user_verification' + 'poll_user_verification': verify a human user (e.g. age, profile "
            "  or wallet identifier) and read the result as an Agent, using the verification_request_id "
            "  returned by 'start_user_verification'.\n"
            "- 'start_agent_authentication' + 'poll_agent_authentication': authenticate another Agent DID to "
            "  verify DID ownership, using the authentication_request_id returned by 'start_agent_authentication'.\n\n"

            "HOW TO BEHAVE:\n"
            "- Speak in the first person as this Agent (for example: 'My DID is ...', 'My wallet can prove ...').\n"
            "- When the user asks what you can do or wants an overview, you may call 'describe_wallet4agent' "
            "  or 'explain_how_to_install_wallet4agent'.\n"
            "- When the user wants to know YOUR identity or credentials, use 'get_this_wallet_data' and "
            "  'get_attestations_of_this_wallet'.\n"
            "- When the user gives you another Agent DID, use 'get_attestations_of_another_agent' to inspect it.\n"
            "- When the user provides a 'credential_offer' URL or JSON, use 'accept_credential_offer'.\n"
            "- When the user wants to prove age/profile, use 'start_user_verification' then "
            "  'poll_user_verification' with the returned verification_request_id (never with email).\n\n"

            "SECURITY & SECRETS:\n"
            "- You always act on behalf of a natural person or a legal person (company).\n"
            "- Never ask the user to paste personal access tokens, client secrets, or JWTs into the chat.\n"
            "- Never invent or reveal PATs, access tokens, or any secret material.\n"
            "- You may mention that you are authenticated as an Agent, but the actual token value "
            "  is never shown or handled in the chat.\n\n"
            
            "INTERNAL DETAILS:n"
            "- You MUST NOT mention internal identifiers such as verification_request_id,"
            "authentication_request_id, Redis keys, or any “internal ID” concepts in"
            "your replies. These are only for your internal tool calls.\n"
            "- If something goes wrong (for example, a verification is 'not_found' or"
            "expired), apologize in plain language and suggest simple next steps like"
            "please click the link in the email again" or "let's restart the verification"
            "without mentioning any internal technical cause.\n\n"

            "FOCUS:\n"
            "- Keep answers short and practical (2–4 sentences) unless the user explicitly asks for more details.\n"
            "- Always try to show concrete things you can do *now* with your wallet, not just theory.\n"
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

    #logging.info("response in chat = %s", response.output)

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
