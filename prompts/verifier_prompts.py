# verifier_prompts.py
"""
Prompts for email-based identity wallet verification.
No QR code is ever referenced. The only flow is:
1. Ask user for email
2. start_user_verification(scope, user_email)
3. Inform the user that an email was sent
4. User opens the email on smartphone → wallet opens
5. poll_user_verification(user_id)
6. Summarize verified information
"""

from typing import Any, Dict, List, Callable

# ----------------------------------------------------------------------------
# Prompt metadata for prompts/list
# ----------------------------------------------------------------------------

prompts_agent: List[Dict[str, Any]] = [
    {
        "name": "verify_over18_with_data_wallet",
        "description": (
            "Guide a human user to prove they are over 18 using email-based "
            "identity wallet verification. The assistant must request the user's "
            "email address, send a verification email via the start_user_verification "
            "tool, and then poll for the verification result using poll_user_verification."
        ),
        "arguments": []
    },
    {
        "name": "verify_profile_with_data_wallet",
        "description": (
            "Guide a human user to share a verified identity profile (first name, "
            "last name, birth date) using email-based wallet verification. The "
            "assistant must ask for the user's email, initiate verification via "
            "start_user_verification, and poll for completion."
        ),
        "arguments": []
    },
]

# ----------------------------------------------------------------------------
# Prompt builders for prompts/get
# ----------------------------------------------------------------------------

def get_prompt_verify_over18_with_data_wallet(arguments: Dict[str, Any]) -> Dict[str, Any]:
    assistant_text = (
        "You are assisting another AI agent in verifying that a human user is over 18 "
        "using an email-based identity wallet flow.\n\n"
        "Workflow:\n"
        "1. Ask the user for the email address they want to use for verification.\n"
        "2. Call the tool start_user_verification with:\n"
        "       - scope = 'over18'\n"
        "       - user_email = <email the user provides>\n"
        "   This sends the user a verification email.\n"
        "3. Tell the user: \"I have sent you an email. Open it on your smartphone and "
        "tap the link to start the verification in your identity wallet.\"\n"
        "4. After the user indicates they have clicked the link and completed the wallet "
        "flow, call poll_user_verification(user_id).\n"
        "5. Interpret the result: if the wallet confirms the user is over 18, summarize "
        "success. If incomplete or failed, explain clearly.\n\n"
        "Rules:\n"
        "- Do not mention QR codes or scanning.\n"
        "- Only use the email-based flow.\n"
        "- Do not reveal internal tokens or backend values.\n"
    )

    user_text = "Help me verify that the user is over 18 using email-based wallet verification."

    return {
        "description": "Email-based over-18 verification using an identity wallet.",
        "messages": [
            {"role": "assistant", "content": {"type": "text", "text": assistant_text}},
            {"role": "user", "content": {"type": "text", "text": user_text}},
        ],
    }


def get_prompt_verify_profile_with_data_wallet(arguments: Dict[str, Any]) -> Dict[str, Any]:
    assistant_text = (
        "You are assisting another AI agent in retrieving a verified identity profile "
        "from a human user via email-based wallet verification.\n\n"
        "Workflow:\n"
        "1. Ask the user for their email address.\n"
        "2. Call start_user_verification with:\n"
        "       - scope = 'profile'\n"
        "       - user_email = <email>\n"
        "   This sends a verification email.\n"
        "3. Tell the user to open the email on their smartphone and tap the link, which "
        "opens their identity wallet.\n"
        "4. After they confirm completion, call poll_user_verification(user_id).\n"
        "5. Extract the verified profile data (first name, last name, birth date) from "
        "the result and summarize it.\n\n"
        "Rules:\n"
        "- Never mention QR codes.\n"
        "- Only describe the email-based wallet flow.\n"
        "- Do not display internal identifiers or credentials.\n"
    )

    user_text = "Help me obtain the user's verified profile using email-based wallet verification."

    return {
        "description": "Email-based profile verification via identity wallet.",
        "messages": [
            {"role": "assistant", "content": {"type": "text", "text": assistant_text}},
            {"role": "user", "content": {"type": "text", "text": user_text}},
        ],
    }


# ----------------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------------

PROMPT_GETTERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "verify_over18_with_data_wallet": get_prompt_verify_over18_with_data_wallet,
    "verify_profile_with_data_wallet": get_prompt_verify_profile_with_data_wallet,
}


def build_prompt_messages(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name not in PROMPT_GETTERS:
        raise KeyError(f"Unknown verifier prompt name: {name}")
    return PROMPT_GETTERS[name](arguments)
