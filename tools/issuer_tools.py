
import json
from typing import Any, Dict, List, Optional, Tuple
import copy
import requests
import uuid
from routes import issuer
from db_model import Wallet
from OBO import OBO_credential
import logging
from utils import log
from datetime import datetime


CODE_LIFE = 1000

# Public DID resolvers (Uniresolver-compatible)
RESOLVER_LIST = [
    "https://unires:test@unires.talao.co/1.0/identifiers/",
    "https://dev.uniresolver.io/1.0/identifiers/",
    "https://resolver.cheqd.net/1.0/identifiers/",
]
# lifetime in seconds
LIFESPAN = {"10 minutes": 10*60, "1 hour": 60*60, "6 hours": 6*60*60, "1 day": 24*60*60, "1 month": 30*24*60*60}

tools_guest: List[Dict[str, Any]] = []
tools_agent: List[Dict[str, Any]] = []

tools_admin: List[Dict[str, Any]] = [
    {
        "name": "issue_OBO",
        "description": "Issue an On Behalf Of attestation to an Agent",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User identifier",
                },
                "delegate_agent": {
                    "type": "string",
                    "description": "The delegate Agent (DID) which receives the On Behalf Of attestation",
                },
                "task_id": {
                    "type": "string",
                    "description": "Identifier describing the delegated task.",
                },
                "lifetime": {
                    "type": "string",
                    "description": "life time of the OBO delegation",
                    "enum": ["10 minutes", "1 hour", "6 hours", "1 day", "1 month" ],
                    "default": "1 hour"
                }
            },
            "required": ["delegate_agent", "task_id"],
        },
    }
]



def _ok_content(
    blocks: List[Dict[str, Any]],
    structured: Optional[Dict[str, Any]] = None,
    is_error: bool = False,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"content": blocks}
    if structured is not None:
        out["structuredContent"] = structured
    if is_error:
        out["isError"] = True
    return out


def _try_resolve(delegate_agent: str, timeout: int = 10) -> Tuple[Optional[dict], Optional[str]]:
    if not delegate_agent or not isinstance(delegate_agent, str):
        return None, "missing_agent_identifier"
    if delegate_agent.startswith("did:"):
        last_err: Optional[str] = None
        for base in RESOLVER_LIST:
            try:
                url = base.rstrip("/") + "/" + delegate_agent
                resp = requests.get(url, timeout=timeout)
                if resp.status_code >= 400:
                    last_err = f"resolver_http_{resp.status_code}"
                    continue
                payload = resp.json() if resp.content else {}
                # Uniresolver response typically: {didDocument: {...}}
                doc = payload.get("didDocument") or payload.get("did_document") or payload.get("document")
                if isinstance(doc, dict) and doc:
                    return doc, None
                # Some resolvers may return the DID Document directly
                if isinstance(payload, dict) and payload.get("id") == delegate_agent:
                    return payload, None
                last_err = "did_document_missing"
            except Exception as e:
                last_err = str(e)
                continue
        return None, last_err or "resolver_failed"
    else:
        wallet = Wallet.query.filter(Wallet.agent_identifier == delegate_agent).first()
        url = wallet.agentcard_url
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code >= 400:
                last_err = f"resolver_http_{resp.status_code}"
                return None, last_err
            payload = resp.json() if resp.content else {}
        except Exception:
            return None, last_err
        return payload, None


def _find_oidc4vc_wallet_endpoints(doc: dict) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    if "@context" in doc:
        services = doc.get("service")
        if not services:
            return None, 'No services available in did_document'
        endpoint = None
        for serv in services:
            if serv["type"] == "OIDC4VCWalletService":
                endpoint = serv["serviceEndpoint"]
                if isinstance(endpoint, list):
                    endpoint = endpoint[0]
                break
        if endpoint:
            return endpoint, None
        return None, "wallet_endpoints_not_found_in_did_document"
    else:
        endpoint = doc.get("OIDC4VCWalletService")
        if not endpoint:
            return None, "wallet_endpoints_not_found_in_agent_card"
        return endpoint, None


def _deliver_credential_offer_to_wallet(credential_offer_endpoint, credential_offer_str)-> Tuple[bool, str]:
    # Try GET
    url = credential_offer_endpoint.strip("/") + "?" + credential_offer_str
    logging.info("credential offer sent to delegate agent =  %s", url)
    try:
        resp = requests.get(url, timeout=10, allow_redirects=False, headers={"Accept": "application/json"})
        if 200 <= resp.status_code < 400:
            return True, "delivered"
        logging.warning("delivery failed with status: %s", resp.status_code)
        return False, "delegate agent wallet failed to receive"
    except Exception as e:
        logging.warning("delivery failed %s", str(e))
        return False, f"delivery failed: {str(e)}"


def call_issue_OBO(arguments: dict, agent_identifier: str, config: dict) -> Dict[str, Any]:
    red = config["REDIS"]
    delegate_agent = arguments.get("delegate_agent")
    task_id = arguments.get("task_id")
    lifetime = LIFESPAN.get(arguments.get("lifetime")) # in seconds

    # Build VC
    vc = copy.deepcopy(OBO_credential)
    vc["sub"] = delegate_agent
    vc["exp"] = int(datetime.timestamp(datetime.now())) + lifetime
    vc["obo"]["principal"]["id"] = arguments.get("user_id")
    vc["obo"]["task_id"] = task_id
    vc["obo"]["actor"]["id"] = delegate_agent
    vc["obo"]["delegator"]["id"] = agent_identifier
    vc["disclosure"] = ["all"]

    # NOTE: placeholder pre-authorized code; should be generated per session
    code = str(uuid.uuid4())
    wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
    if not wallet:
        return _ok_content(
            [{"type": "text", "text": "Wallet not found"}],
            structured={"error": "wallet_not_found", "agent_identifier": agent_identifier},
            is_error=True,
        )
    ecosystem_profile = wallet.ecosystem_profile
    if ecosystem_profile == "DIIP V3":
        draft = 13
    elif ecosystem_profile == "ARF":
        draft = 18
    else:
        draft = 15
        
    session_data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "task_id": task_id,
        "vc": {"OBO": vc},
        "pre-authorized_code": code,
        "status_list": False,
        "agent_identifier": agent_identifier,
        "wallet_identifier": wallet.wallet_identifier,
        "target_agent": delegate_agent,
        "draft": draft,
        #"issuer_state": "issuer_state"
    }

    # get credential_offer as a string
    credential_offer_str = issuer.get_credential_offer(session_data)
    red.setex(code, CODE_LIFE, json.dumps(session_data))

    # Resolve -> DID Document or agent card
    doc, err = _try_resolve(delegate_agent)
    structured = {}
    if doc is None:
        structured["delivery"] = {"result": False, "reason": "resolution_failed", "detail": err}
        return _ok_content([{"type": "text", "text": err}], structured=structured, is_error=True)

    # Extract wallet endpoints from DID Doc (per user-provided DID Doc structure)
    wallet_eps, err2 = _find_oidc4vc_wallet_endpoints(doc)
    if not wallet_eps:
        structured["delivery"] = {"result": False, "reason": "wallet_endpoints_not_found", "detail": err2}
        return _ok_content([{"type": "text", "text": err}], structured=structured, is_error=True)
    
    wallet_openid_configuration_endpoint = wallet_eps + "/.well-known/openid-configuration"
    result = requests.get(wallet_openid_configuration_endpoint, timeout=10)
    try:
        coe = result.json()["credential_offer_endpoint"]
    except Exception:
        coe = wallet_eps  # fallback
    
    # deliver credential offer to delegate agent
    ok, status = _deliver_credential_offer_to_wallet(coe, credential_offer_str)
    structured = {
        "task_id": task_id,
        "delegate_agent": delegate_agent, 
        "status": status,
        "lifetime_in_seconds": lifetime
    }
    text = f"OBO for task {task_id} delivered with success to delegate agent {delegate_agent} "
    if wallet.log:
        log.log_wallet_event(
            wallet_id=agent_identifier,
            event_type="obo.issue",
            details={"delegate_agent": arguments.get("delegate_agent"), "task_id": arguments.get("task_id")},
            actor=agent_identifier,
        )

    return _ok_content([{"type": "text", "text": text}], structured=structured, is_error=False)
