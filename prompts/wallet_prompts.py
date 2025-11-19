# agent_prompt.py
"""
Prompt definitions for the Wallet4Agent MCP server (agent-facing tools).

These prompts are "helper workflows" for an AI agent that has access to the
Wallet4Agent tools defined in wallet_tools_for_agent.py.

They are NOT shown directly to the human end-user; they are instructions
to the calling LLM agent on how to use the tools.
"""

from typing import Any, Dict, List, Callable

# ---------------------------------------------------------------------------
# Prompt metadata for `prompts/list`
# ---------------------------------------------------------------------------

prompts_agent: List[Dict[str, Any]] = [
    {
        "name": "learn_wallet4agent",
        "description": (
            "Explain what the Wallet4Agent MCP server and its wallet do, and "
            "how an AI agent can use the available tools. Internally, this "
            "should guide the model to first call `describe_wallet4agent`, "
            "then summarize the result for the calling agent."
        ),
        "arguments": []
    },
    {
        "name": "inspect_this_agent_wallet",
        "description": (
            "Inspect this Agent's wallet to understand its basic metadata and "
            "the attestations (verifiable credentials) it currently holds. "
            "Internally, this should guide the model to call "
            "`get_this_wallet_data` and `get_attestations_of_this_wallet`."
        ),
        "arguments": []
    },
    {
        "name": "inspect_other_agent_attestations",
        "description": (
            "Look up another Agent's DID and summarize the attestations it has "
            "published as Linked Verifiable Presentations in its DID Document. "
            "Internally, this should guide the model to call "
            "`get_attestations_of_another_agent`."
        ),
        "arguments": [
            {
                "name": "agent_identifier",
                "description": (
                    "The DID of the Agent that should be inspected "
                    "(for example: did:web:wallet4agent.com:demo:abc...)."
                ),
                "required": True,
            }
        ],
    },
    {
        "name": "accept_credential_offer_and_summarize",
        "description": (
            "Accept an OIDC4VCI credential offer on behalf of this Agent and "
            "summarize the resulting attestation for the calling agent. "
            "Internally, this should guide the model to call "
            "`accept_credential_offer`, then explain the new credential in "
            "plain language without exposing secrets."
        ),
        "arguments": [
            {
                "name": "credential_offer",
                "description": (
                    "An OIDC4VCI credential_offer or credential_offer_uri as "
                    "provided by an external issuer."
                ),
                "required": True,
            }
        ],
    },
]

# ---------------------------------------------------------------------------
# Prompt builders for `prompts/get`
# Each function returns a dict with:
#   {
#       "description": "...",
#       "messages": [
#           { "role": "system", "content": [ { "type": "text", "text": "..." } ] },
#           { "role": "user",   "content": [ { "type": "text", "text": "..." } ] },
#       ]
#   }
# ---------------------------------------------------------------------------


def get_prompt_learn_wallet4agent(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prompt: learn_wallet4agent
    Use-case: self-description and capability discovery for the calling agent.
    """
    system_text = (
        "You are an assistant helping another AI agent understand the "
        "Wallet4Agent MCP server and its wallet.\n\n"
        "You have access to the MCP tool `describe_wallet4agent`.\n\n"
        "Your workflow:\n"
        "1. Call `describe_wallet4agent` once.\n"
        "2. Read the structured content and text returned by the tool.\n"
        "3. Summarize for the calling agent:\n"
        "   - What this server is and what a 'wallet' means here.\n"
        "   - Who or what an 'Agent' represents, and that the Agent is identified by a DID.\n"
        "   - Make it clear that the DID identifies the Agent, while the wallet is an "
        "     attached component that stores and manages the Agent's credentials.\n"
        "   - What 'attestations' or 'verifiable credentials' are in this context.\n"
        "4. Provide a concise, practical explanation of when the calling agent "
        "   should use each tool.\n"
        "Do not expose raw secret material; only describe capabilities and "
        "high-level concepts."
    )

    user_text = (
        "Explain what the Wallet4Agent MCP server and its wallet do, and how I, "
        "as an AI agent, can use its tools."
    )

    return {
        "description": "Explain Wallet4Agent and its tools to the calling agent.",
        "messages": [
            {
                "role": "assistant",
                "content": {"type": "text", "text": system_text},
            },
            {
                "role": "user",
                "content": {"type": "text", "text": user_text},
            },
        ],
    }


def get_prompt_inspect_this_agent_wallet(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prompt: inspect_this_agent_wallet
    Use-case: give the calling agent a human-readable overview of its own wallet.
    """
    system_text = (
        "You are an identity and credential assistant for an AI agent that has "
        "an attached Wallet4Agent wallet.\n\n"
        "You have access to two MCP tools:\n"
        "- `get_this_wallet_data`: returns high-level metadata such as the "
        "  Agent's DID (agent_identifier) and details about its attached wallet "
        "  (wallet endpoint URL, number of attestations, and whether a human is "
        "  always kept in the loop).\n"
        "Your workflow:\n"
        "1. Call `get_this_wallet_data` once.\n"
        "2. Call `get_attestations_of_this_wallet` once.\n"
        "3. Combine both results into a clear explanation for the calling agent:\n"
        "   - Identify the Agent's DID (this is the Agent's identity).\n"
        "   - Identify the attached wallet endpoint URL and summarize how many "
        "     attestations it stores and whether a human is in the loop.\n"
        "4. Highlight what the wallet can already prove about the agent and what "
        "   might be missing for future interactions.\n"
        "Avoid dumping raw JSON unless explicitly useful; instead, summarize "
        "important details in natural language."
    )
    user_text = (
        "Inspect this Agent's identity (its DID) and its attached wallet, and "
        "summarize their metadata and stored attestations for me."
    )

    return {
        "description": "Inspect the current Agent's wallet and explain what it can prove.",
        "messages": [
            {
                "role": "assistant",
                "content": {"type": "text", "text": system_text},
            },
            {
                "role": "user",
                "content": {"type": "text", "text": user_text},
            },
        ],
    }


def get_prompt_inspect_other_agent_attestations(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prompt: inspect_other_agent_attestations
    Use-case: resolve another Agent's DID and summarize its public attestations.
    """
    agent_identifier = arguments.get("agent_identifier", "")

    system_text = (
        "You are evaluating the public trust signals of another Agent in the "
        "Wallet4Agent ecosystem.\n\n"
        "You have access to the MCP tool `get_attestations_of_another_agent`, "
        "which resolves an Agent's DID and returns attestations discovered in "
        "its DID Document (typically Linked Verifiable Presentations).\n\n"
        "Your workflow:\n"
        "1. Call `get_attestations_of_another_agent` with the provided "
        "   agent_identifier (DID).\n"
        "2. Inspect the returned attestations. For each one, if possible, "
        "   identify:\n"
        "   - The issuer or source (e.g., organization, platform).\n"
        "   - What the credential claims about the Agent (e.g., role, "
        "     membership, capabilities).\n"
        "3. Summarize for the calling agent:\n"
        "   - How many attestations exist.\n"
        "   - The most important trust and capability signals.\n"
        "   - Any obvious limitations or missing credentials.\n"
        "4. Be careful not to overstate trust; only claim what the attestations "
        "   actually support.\n"
        "If no attestations are found, clearly state that and suggest that more "
        "credentials may be needed for higher assurance."
    )

    user_text = (
        f"Inspect the public attestations of Agent DID `{agent_identifier}` and "
        "summarize what can be inferred about its trust and capabilities."
    )

    return {
        "description": (
            "Resolve another Agent's DID and summarize its published attestations."
        ),
        "messages": [
            {
                "role": "assistant",
                "content": {"type": "text", "text": system_text},
            },
            {
                "role": "user",
                "content": {"type": "text", "text": user_text},
            },
        ],
    }


def get_prompt_accept_credential_offer_and_summarize(
    arguments: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Prompt: accept_credential_offer_and_summarize
    Use-case: accept a credential offer and explain the resulting attestation.
    """
    credential_offer = arguments.get("credential_offer", "")

    system_text = (
        "You help an AI agent accept verifiable credentials into its "
        "Wallet4Agent wallet.\n\n"
        "You have access to the MCP tool `accept_credential_offer`, which "
        "accepts an OIDC4VCI credential offer on behalf of the Agent and "
        "returns a structured attestation (typically a Verifiable Credential).\n\n"
        "Your workflow:\n"
        "1. Call `accept_credential_offer` with the provided credential_offer "
        "   (or credential_offer_uri).\n"
        "2. Inspect the returned attestation structure.\n"
        "3. Summarize in clear, high-level terms:\n"
        "   - Who issued the credential (if identifiable).\n"
        "   - What the credential claims (subject, role, rights, attributes).\n"
        "   - How this credential might be useful for the Agent in future "
        "     interactions (e.g., authentication, authorization, proof of "
        "     membership).\n"
        "4. Do not expose raw secret material or full JWTs unless absolutely "
        "   necessary; focus on the meaning and implications.\n"
        "5. Explicitly state whether the attestation appears to be successfully "
        "   issued and ready to be stored or presented later."
    )

    user_text = (
        "Accept this credential offer into the Agent's wallet and summarize "
        "the resulting attestation:\n\n"
        f"{credential_offer}"
    )

    return {
        "description": (
            "Accept a credential offer for this Agent and explain the new attestation."
        ),
        "messages": [
            {
                "role": "assistant",
                "content": {"type": "text", "text": system_text},
            },
            {
                "role": "user",
                "content": {"type": "text", "text": user_text},
            },
        ],
    }


# ---------------------------------------------------------------------------
# Registry mapping prompt name -> builder function
# Your MCP server's `prompts/get` handler can use this.
# ---------------------------------------------------------------------------

PROMPT_GETTERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "learn_wallet4agent": get_prompt_learn_wallet4agent,
    "inspect_this_agent_wallet": get_prompt_inspect_this_agent_wallet,
    "inspect_other_agent_attestations": get_prompt_inspect_other_agent_attestations,
    "accept_credential_offer_and_summarize": (
        get_prompt_accept_credential_offer_and_summarize
    ),
}


def get_prompt_definition(name: str) -> Dict[str, Any]:
    """
    Helper: return the prompt metadata (for prompts/list) for a given name.
    """
    for p in prompts_agent:
        if p["name"] == name:
            return p
    raise KeyError(f"Unknown prompt name: {name}")


def build_prompt_messages(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Helper: central entry point to build a prompt result (for prompts/get).
    """
    try:
        builder = PROMPT_GETTERS[name]
    except KeyError:
        raise KeyError(f"Unknown prompt name: {name}")
    return builder(arguments)
