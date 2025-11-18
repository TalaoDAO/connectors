# wallet_prompts_for_guest.py
"""
Prompt definitions for the Wallet4Agent MCP server (GUEST-facing flows).

These prompts are used when the caller is a *guest* (no auth header).
The end-user is your customer, and the goal is to help them:

1. Understand what Wallet4Agent is and what an Agent + wallet are.
2. Create a brand new Agent identifier + wallet using the
   `create_agent_identifier_and_wallet` tool.

They are NOT shown directly to the human end-user; they are instructions
to the calling LLM agent on how to talk to the human and how to use the tools.
"""

from typing import Any, Dict, List, Callable

# ---------------------------------------------------------------------------
# Prompt metadata for `prompts/list` (guest role)
# ---------------------------------------------------------------------------

prompts_guest: List[Dict[str, Any]] = [
    {
        "name": "learn_wallet4agent_as_guest",
        "description": (
            "Explain to a new user (guest) what Wallet4Agent is, what an Agent "
            "identifier and wallet are, and how they can later act as a Developer "
            "and as an Agent once the wallet is created. This prompt should guide "
            "the model to use `describe_wallet4agent` and then explain it in "
            "simple, onboarding-friendly terms."
        ),
        "arguments": [],
    },
    {
        "name": "create_agent_wallet_for_guest",
        "description": (
            "Guide a guest user through creating a brand-new Agent identifier "
            "and wallet using `create_agent_identifier_and_wallet`. The model "
            "must explain what information is needed (owners_identity_provider, "
            "owners_login, and authentication mode), call the tool, and then "
            "clearly explain the returned agent_identifier, wallet_url, and "
            "tokens (dev_personal_access_token and agent credentials) and "
            "remind the user to copy them immediately."
        ),
        "arguments": [],
    },
]

# ---------------------------------------------------------------------------
# Prompt builders for `prompts/get`
# Each returns:
#   {
#       "description": "...",
#       "messages": [
#           { "role": "assistant", "content": { "type": "text", "text": "..." } },
#           { "role": "user",      "content": { "type": "text", "text": "..." } },
#       ]
#   }
# ---------------------------------------------------------------------------


def get_prompt_learn_wallet4agent_as_guest(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prompt: learn_wallet4agent_as_guest
    Use-case: onboarding explanation for a brand-new guest user.
    """
    assistant_text = (
        "You are helping a *human guest* understand Wallet4Agent and how they can "
        "create a new Agent identifier and wallet.\n\n"
        "You have access to the tool `describe_wallet4agent`.\n\n"
        "Your workflow:\n"
        "1. Briefly ask the user what they want to do (for example: create a new "
        "   Agent identity for their application or agent).\n"
        "2. Call `describe_wallet4agent` once to get an up-to-date description of "
        "   this MCP server, its wallet model, and the available roles.\n"
        "3. Using that description, explain in simple, non-technical terms:\n"
        "   - What Wallet4Agent is (a managed identity + credential wallet for "
        "     Agents, Companies, and Users).\n"
        "   - What an 'Agent identifier' (DID) is in this ecosystem.\n"
        "   - What a 'wallet' is (where their Agent's verifiable credentials are "
        "     stored and managed).\n"
        "   - The three roles: Guest, Developer (Dev), and Agent, and how a Guest "
        "     can become a Dev for an Agent by creating a wallet.\n"
        "4. Explain that, as a guest (with no Authorization header), they can call "
        "   a single tool `create_agent_identifier_and_wallet` to go from zero to "
        "   a configured Agent + wallet, as described in the documentation.\n"
        "5. Offer to walk them through the actual creation flow if they are ready.\n"
        "6. Use friendly, reassuring language; assume they may not know what DID, "
        "   verifiable credentials, or OAuth are, so give short, human examples.\n"
        "Do not expose raw internal errors; if a tool call fails, apologize and "
        "summarize the failure in simple language."
    )

    user_text = (
        "Explain to me, as a new guest, what Wallet4Agent is and how I can create "
        "a new Agent identifier and wallet."
    )

    return {
        "description": "Explain Wallet4Agent and the Guest → Agent creation flow.",
        "messages": [
            {
                "role": "assistant",
                "content": {"type": "text", "text": assistant_text},
            },
            {
                "role": "user",
                "content": {"type": "text", "text": user_text},
            },
        ],
    }


def get_prompt_create_agent_wallet_for_guest(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prompt: create_agent_wallet_for_guest
    Use-case: guide a guest user through creating a new Agent identifier + wallet.
    """
    assistant_text = (
        "You are helping a *human guest* create a brand-new Agent identifier and "
        "wallet using the `create_agent_identifier_and_wallet` tool.\n\n"
        "According to the documentation, this tool will:\n"
        "- Create a new Agent DID: e.g. did:web:wallet4agent.com:<id>.\n"
        "- Create a wallet entry for that Agent.\n"
        "- Attach one or more human/organization owners via:\n"
        "  - owners_identity_provider (e.g. 'google', 'github', 'personal data wallet').\n"
        "  - owners_login (email or username, comma-separated for multiple).\n"
        "- Generate a dev_personal_access_token (Dev PAT).\n"
        "- And, depending on the 'authentication' choice, either:\n"
        "  - an agent_personal_access_token (Agent PAT), or\n"
        "  - OAuth 2.0 client credentials (agent_client_id, agent_client_secret, authorization_server).\n\n"
        "Your workflow:\n"
        "1. Explain at a high level what will happen when a new Agent + wallet is "
        "   created, and that this action is for *their* application or agent.\n"
        "2. Ask the user the minimum information required to call the tool:\n"
        "   a. owners_identity_provider: suggest typical values like 'google' or "
        "      'github', or 'personal data wallet' if appropriate.\n"
        "   b. owners_login: usually an email like 'dev@example.com'. If they have "
        "      multiple owners, they can provide a comma-separated list.\n"
        "   c. authentication mode: briefly explain the tradeoff:\n"
        "      - 'Personal Access Token (PAT)' — simplest for testing or single-agent setups.\n"
        "      - 'OAuth 2.0 Client Credentials Grant' — better for production, with\n"
        "        an authorization server and access tokens.\n"
        "3. Confirm with the user that they are ready to create the Agent + wallet.\n"
        "4. Call `create_agent_identifier_and_wallet` with the values they provided.\n"
        "5. On success, read the structuredContent from the tool result and explain:\n"
        "   - agent_identifier: the DID of the new Agent.\n"
        "   - wallet_url: a URL where the Agent's wallet can be inspected.\n"
        "   - dev_personal_access_token: the Developer PAT that lets them manage\n"
        "     configuration, rotate tokens, etc.\n"
        "   - If authentication = 'Personal Access Token (PAT)': the `agent_personal_access_token`.\n"
        "   - If authentication = 'OAuth 2.0 Client Credentials Grant': the\n"
        "     `agent_client_id`, `agent_client_secret`, and `authorization_server`.\n"
        "6. VERY IMPORTANT: clearly tell the user that dev_personal_access_token and "
        "   any agent_personal_access_token or agent_client_secret are *not stored "
        "   in clear text* and cannot be retrieved later. They must copy them now "
        "   and store them securely.\n"
        "7. Offer simple next steps:\n"
        "   - How to act as a Developer using the Dev PAT (Authorization: Bearer <dev_pat>).\n"
        "   - How the Agent will authenticate (using the Agent PAT or OAuth client credentials).\n"
        "8. If the tool returns an error, explain the situation in friendly terms and "
        "   help the user correct any obvious mistakes (e.g., missing owners_login).\n\n"
        "Always speak in clear, customer-friendly language and assume they may not "
        "be familiar with identity jargon. Avoid dumping raw JSON; summarize the "
        "important fields instead."
    )

    user_text = (
        "Help me, as a guest user, create a new Agent identifier and wallet and "
        "explain what I need to copy and keep safe."
    )

    return {
        "description": "Create a new Agent identifier + wallet for a guest user.",
        "messages": [
            {
                "role": "assistant",
                "content": {"type": "text", "text": assistant_text},
            },
            {
                "role": "user",
                "content": {"type": "text", "text": user_text},
            },
        ],
    }


# ---------------------------------------------------------------------------
# Registry mapping prompt name -> builder function
# ---------------------------------------------------------------------------

PROMPT_GETTERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "learn_wallet4agent_as_guest": get_prompt_learn_wallet4agent_as_guest,
    "create_agent_wallet_for_guest": get_prompt_create_agent_wallet_for_guest,
}


def build_prompt_messages(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Central entry point to build a prompt result (for prompts/get).
    """
    try:
        builder = PROMPT_GETTERS[name]
    except KeyError:
        raise KeyError(f"Unknown guest prompt name: {name}")
    return builder(arguments)
