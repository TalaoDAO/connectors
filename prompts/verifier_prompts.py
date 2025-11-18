# verifier_prompts.py
"""
Prompt definitions for the verifier tools (start_user_verification, poll_user_verification).

These prompts are helper workflows for an AI agent that wants to verify a human
user using their data wallet (e.g., eID / EUDI wallet) via QR code.

They are NOT shown directly to the human end-user; they are instructions
to the calling LLM agent on how to use the verifier tools in verifier_tools.py.
"""

from typing import Any, Dict, List, Callable

# ---------------------------------------------------------------------------
# Prompt metadata for `prompts/list`
# ---------------------------------------------------------------------------

prompts_agent: List[Dict[str, Any]] = [
    {
        "name": "verify_over18_with_data_wallet",
        "description": (
            "Guide a human user to prove they are over 18 using their data wallet. "
            "The agent should check if the user has a compatible wallet, then call "
            "`start_user_verification` with scope 'over18', display the QR code or "
            "link, wait for the scan, and finally call `poll_user_verification` "
            "to get the result."
        ),
        "arguments": []
    },
    {
        "name": "verify_email_with_data_wallet",
        "description": (
            "Guide a human user to share a verified email using their data wallet. "
            "The agent should check if the user has a compatible wallet, then call "
            "`start_user_verification` with scope 'email', display the QR code or "
            "link, wait for the scan, and then call `poll_user_verification` to "
            "obtain the verified email."
        ),
        "arguments": []
    },
    {
        "name": "verify_profile_with_data_wallet",
        "description": (
            "Guide a human user to share verified identity data (first name, last "
            "name, birth date) using their data wallet. The agent should check if "
            "the user has a compatible wallet, then call `start_user_verification` "
            "with scope 'profile', display the QR code or link, wait for the scan, "
            "and then call `poll_user_verification` to obtain the profile data."
        ),
        "arguments": []
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


def get_prompt_verify_over18_with_data_wallet(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prompt: verify_over18_with_data_wallet
    Use-case: help the agent verify that the human user is over 18 using a data wallet.
    """
    assistant_text = (
        "You are an assistant helping another AI agent verify that a human user "
        "is at least 18 years old using the verifier tools exposed by this MCP server.\n\n"
        "You have access to the following MCP tools:\n"
        "- `start_user_verification` with scope 'over18': this returns a user_id "
        "  and a deeplink URL that can be encoded as a QR code (the tool already "
        "  returns an image block and a text link).\n"
        "- `poll_user_verification`: this lets you poll the verification result for "
        "  a given user_id and get the claims returned by the user's data wallet.\n\n"
        "Your workflow when this prompt is used:\n"
        "1. Ask the human user whether they have a compatible data wallet "
        "   (for example, an eID / EUDI wallet or similar identity wallet on their "
        "   smartphone).\n"
        "2. If the user does NOT have such a wallet or does not want to use it, "
        "   politely explain that you cannot automatically obtain a cryptographic "
        "   proof of being over 18 from this verifier, and stop there.\n"
        "3. If the user DOES have a wallet and agrees to use it:\n"
        "   a. Call the `start_user_verification` tool with scope 'over18'.\n"
        "   b. The tool will return content blocks including a QR code (image) and "
        "      a textual link, as well as a structured `user_id` and `oidc4vp_request`.\n"
        "   c. Display or describe the QR code / link to the user and clearly "
        "      instruct them to scan it with their data wallet app.\n"
        "   d. Ask the user to tell you when they have finished the flow on their phone.\n"
        "4. If the user refuses to scan or says they cannot scan, stop showing or "
        "   insisting on the QR code and explain that you cannot complete the "
        "   verification.\n"
        "5. Once the user confirms that they have scanned and completed the wallet "
        "   flow on their smartphone:\n"
        "   a. Call `poll_user_verification` with the `user_id` returned by "
        "      `start_user_verification`.\n"
        "   b. Inspect the returned structured data. Determine whether the status "
        "      indicates success and whether the claims confirm that the user is "
        "      over 18.\n"
        "   c. Summarize the result clearly, e.g. 'The data wallet confirms this "
        "      user is over 18' or 'Verification failed / incomplete'.\n"
        "6. Do not expose raw secrets or internal tokens; only describe the result "
        "   and relevant attributes in human-readable terms.\n"
        "7. If the result is still pending, tell the user that you are still "
        "   waiting for them to complete the flow in their wallet and ask them to "
        "   confirm once they are done."
    )

    user_text = (
        "Help me verify that the human user is at least 18 years old using their "
        "data wallet and the QR-code-based verifier flow."
    )

    return {
        "description": "Verify the human user is over 18 using a data wallet.",
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


def get_prompt_verify_email_with_data_wallet(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prompt: verify_email_with_data_wallet
    Use-case: help the agent obtain a verified email address via the user's data wallet.
    """
    assistant_text = (
        "You are an assistant helping another AI agent obtain a verified email "
        "address for a human user using the data-wallet-based verifier tools.\n\n"
        "You have access to:\n"
        "- `start_user_verification` with scope 'email': creates a QR-based wallet "
        "  request that asks the user's data wallet to share a verified email.\n"
        "- `poll_user_verification`: polls the status and returns the claims, "
        "  including the verified email when successful.\n\n"
        "Your workflow for this use-case:\n"
        "1. Ask the human user if they have a compatible data wallet on their "
        "   smartphone and if they are willing to use it to share a verified email.\n"
        "2. If the user does not have a wallet or does not want to use it, explain "
        "   that you cannot obtain an automated proof of email from this verifier "
        "   and stop the QR process.\n"
        "3. If the user agrees and has a wallet:\n"
        "   a. Call `start_user_verification` with scope 'email'.\n"
        "   b. The tool will return a QR code image and a link (in the content "
        "      blocks), plus a `user_id` and `oidc4vp_request` in the structured "
        "      content.\n"
        "   c. Display or describe the QR code / link and instruct the user to "
        "      scan it with their data wallet app.\n"
        "   d. Ask the user to let you know when they have completed the wallet "
        "      flow on their phone.\n"
        "4. If the user refuses or cannot scan, stop showing or pushing the QR "
        "   code and explain that email verification cannot continue.\n"
        "5. Once the user confirms they are done:\n"
        "   a. Call `poll_user_verification` with the `user_id` from "
        "      `start_user_verification`.\n"
        "   b. Inspect the returned structured data and extract any verified email "
        "      claim.\n"
        "   c. Summarize the outcome clearly, e.g. 'Verified email: user@example.com' "
        "      or 'Verification failed or incomplete'.\n"
        "6. Avoid printing raw tokens or sensitive internal fields; focus on the "
        "   verified email and status.\n"
        "7. If the status is still pending, tell the user you are waiting for their "
        "   wallet to finish and ask them to confirm completion."
    )

    user_text = (
        "Help me get a verified email for the human user using their data wallet "
        "with the QR-code-based verifier flow."
    )

    return {
        "description": "Obtain a verified email from the user's data wallet.",
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


def get_prompt_verify_profile_with_data_wallet(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prompt: verify_profile_with_data_wallet
    Use-case: help the agent obtain verified identity data (first name, last name,
    birth date) via the user's data wallet.
    """
    assistant_text = (
        "You are an assistant helping another AI agent obtain a verified identity "
        "profile (first name, last name, birth date) for a human user using the "
        "data-wallet-based verifier tools.\n\n"
        "You have access to:\n"
        "- `start_user_verification` with scope 'profile': this asks the user's "
        "  data wallet to share profile attributes such as first name, last name, "
        "  and birth date.\n"
        "- `poll_user_verification`: polls the status and returns the claims "
        "  associated with the verification session.\n\n"
        "Your workflow for this use-case:\n"
        "1. Ask the human user if they have a compatible data wallet on their "
        "   smartphone and if they are willing to use it to share their profile "
        "   (first name, last name, birth date).\n"
        "2. If the user does not have a wallet or declines, explain that you "
        "   cannot obtain a cryptographic proof of identity via this verifier and "
        "   stop the QR process.\n"
        "3. If the user agrees and has a wallet:\n"
        "   a. Call `start_user_verification` with scope 'profile'.\n"
        "   b. The tool will return a QR code image and a link in the content "
        "      blocks, plus `user_id` and `oidc4vp_request` in structured "
        "      content.\n"
        "   c. Present the QR code / link and instruct the user to scan it with "
        "      their data wallet app.\n"
        "   d. Ask the user to tell you when they have finished the flow on their "
        "      smartphone.\n"
        "4. If the user refuses or cannot scan, stop presenting the QR code and "
        "   explain that profile verification cannot be completed.\n"
        "5. Once the user confirms completion:\n"
        "   a. Call `poll_user_verification` with the `user_id` from the "
        "      initial call.\n"
        "   b. Inspect the returned structured data and extract the profile "
        "      attributes (first name, last name, birth date, and any others).\n"
        "   c. Summarize these attributes in clear language, making it obvious "
        "      that they come from the user's data wallet.\n"
        "6. Do not expose raw tokens or sensitive internal fields; only show the "
        "   verified profile values and status.\n"
        "7. If the status is still pending, tell the user you are waiting for the "
        "   wallet to finish and ask them to confirm when they are done."
    )

    user_text = (
        "Help me obtain a verified identity profile (first name, last name, birth "
        "date) for the human user using their data wallet and the QR-code-based "
        "verifier flow."
    )

    return {
        "description": "Obtain a verified profile from the user's data wallet.",
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
    "verify_over18_with_data_wallet": get_prompt_verify_over18_with_data_wallet,
    "verify_email_with_data_wallet": get_prompt_verify_email_with_data_wallet,
    "verify_profile_with_data_wallet": get_prompt_verify_profile_with_data_wallet,
}


def build_prompt_messages(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Central entry point to build a prompt result (for prompts/get).
    """
    try:
        builder = PROMPT_GETTERS[name]
    except KeyError:
        raise KeyError(f"Unknown verifier prompt name: {name}")
    return builder(arguments)
