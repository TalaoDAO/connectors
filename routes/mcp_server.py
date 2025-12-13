import json
from typing import Any, Dict, List, Optional
import logging
from flask import request, jsonify, current_app, make_response, Response
from db_model import Wallet
from tools import wallet_tools, verifier_tools, wallet_tools_for_agent
from utils import oidc4vc
import importlib
from datetime import datetime
from prompts import wallet_prompts, verifier_prompts, wallet_prompts_for_guest
import uuid
import os
from functools import lru_cache
from agntcy import agntcy_verify_badge_rest



PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "MCP server for data wallet"
SERVER_VERSION = "1.4.0"
AGENT_PROMPT_MODULES = [wallet_prompts, verifier_prompts]
GUEST_PROMPT_MODULES = [wallet_prompts_for_guest]

LEVELS = {
    "trace":   logging.DEBUG,   # MCP may send "trace"; map it to DEBUG
    "debug":   logging.DEBUG,
    "info":    logging.INFO,
    "warn":    logging.WARNING,
    "warning": logging.WARNING,
    "error":   logging.ERROR,
}

def init_app(app):
    
    def jrpc_result(_id, result):
        return {"jsonrpc":"2.0","id":_id,"result":result}, 200, {"Content-Type":"application/json"}

    def jrpc_ok(_id):
        return jrpc_result(_id, {})

        # --------- helpers ---------
        
    def config() -> dict:
        config = {
            "VERIFIER_API_START": current_app.config["MODE"].server + "verifier/wallet/start",
            "PULL_STATUS_BASE": current_app.config["MODE"].server + "verifier/wallet/pull",
            "PUBLIC_BASE_URL": "https://wallet4agent.com",
            "REDIS": current_app.config["REDIS"],
            "MODE": current_app.config["MODE"],
            "SERVER": current_app.config["MODE"].server,
            "MANAGER": current_app.config["MANAGER"],
            "MYENV": current_app.config["MYENV"]
        }
        return config
    
    def _agntcy_enabled() -> bool:
        return bool(current_app.config.get("AGNTCY_ORG_API_KEY")) and bool(
            current_app.config.get("AGNTCY_IDENTITY_REST_BASE_URL")
        )
        
    def _extract_subject_did(verification_result: dict) -> Optional[str]:
        # try common flat fields
        for k in ("sub", "subject", "did"):
            v = verification_result.get(k)
            if isinstance(v, str) and v:
                return v

        # try nested VC structures
        vc = verification_result.get("verifiableCredential") or verification_result.get("vc")
        if isinstance(vc, dict):
            subj = vc.get("credentialSubject") or {}
            if isinstance(subj, dict):
                did = subj.get("id") or subj.get("did")
                if isinstance(did, str) and did:
                    return did
        return None


    def _verify_agntcy_badge(jose_badge: str) -> Optional[dict]:
        """
        Verify an AGNTCY badge (JOSE string) using REST.
        Returns the verification response dict if valid, else None.
        """
        if not jose_badge or not _agntcy_enabled():
            return None

        try:
            result = agntcy_verify_badge_rest(
                org_api_key=current_app.config["AGNTCY_ORG_API_KEY"],
                badge_jose=jose_badge,
                config=current_app.config,
            )

            # VerificationResult shape depends on API, but you should treat a boolean "status"
            # or "verified" as success.
            verified = False
            if isinstance(result, dict):
                verified = bool(result.get("verified")) or bool(result.get("status"))

            if not verified:
                return None

            return result

        except Exception as e:
            logging.warning("AGNTCY REST badge verification failed: %s", str(e))
            return None


    def _bearer_or_api_key():
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()
        return request.headers.get("X-AGNTCY-BADGE") or request.headers.get("X-API-KEY")

    def expired_token_response():
        body = {
            "error": "invalid_token",
            "error_description": "The access token expired",
        }

        return Response(
            json.dumps(body),
            status=401,
            mimetype="application/json",
            headers={
                "WWW-Authenticate": (
                    'Bearer error="invalid_token", '
                    'error_description="The access token expired"'
                )
            },
        )
    
    def get_role_and_agent_id():
        token = _bearer_or_api_key()
        if not token:
            logging.warning("no access token")
            return "guest", None

        # --- 1) Existing Wallet4Agent PAT/OAuth decrypt path ---
        try:
            access_token = json.loads(oidc4vc.decrypt_string(token))
            role = access_token.get("role")
            agent_identifier = access_token.get("sub")
            jti = access_token.get("jti")
            exp = access_token.get("exp")
            typ = access_token.get("type")
            logging.info("agent=%s role=%s auth=%s", agent_identifier, role, typ)

            # expiration check (existing)
            now = int(datetime.timestamp(datetime.now()))
            if exp and exp < now:
                logging.warning("access token expired")
                return "expired", None

            if not role:
                return "guest", None

            this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()

            if typ == "pat":
                try:
                    if jti == this_wallet.admin_pat_jti and role == "admin":
                        return role, agent_identifier
                    elif jti == this_wallet.agent_pat_jti and role == "agent":
                        return role, agent_identifier
                    else:
                        return "guest", None
                except Exception as e:
                    logging.warning(str(e))
                    return "guest", None
            else:
                # oauth path (existing)
                return role, agent_identifier

        except Exception as e:
            logging.info("Not a Wallet4Agent token (decrypt failed): %s", str(e))

        # --- 2) NEW: AGNTCY badge verification path ---
        badge = _verify_agntcy_badge(token)
        if not badge:
            return "guest", None

        subject_did = _extract_subject_did(badge)

        if not subject_did:
            logging.warning("AGNTCY badge verified but missing subject DID")
            return "guest", None
        logging.info("AGNTCY badge authenticated for DID %s", subject_did)

        # Map verified DID -> your wallet DB row
        this_wallet = Wallet.query.filter(Wallet.did == subject_did).one_or_none()
        if not this_wallet:
            logging.warning("AGNTCY subject DID has no wallet in Wallet4Agent DB: %s", subject_did)
            return "guest", None

        # Decide role mapping:
        # simplest: any verified badge => agent role for that DID
        return "agent", subject_did
    
    
    def _error(code: int, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        e = {"code": code, "message": message}
        if data is not None:
            e["data"] = data
        return {"jsonrpc": "2.0", "error": e}

    # --------- MCP: discovery/info (optional convenience) ---------
    @app.get("/mcp/healthz")
    def healthz():
        return jsonify({"ok": True})
    
    @app.get("/mcp/info")
    def mcp_info():
        return jsonify({
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
            "protocolVersion": PROTOCOL_VERSION,
            "endpoints": {"rpc": config()["SERVER"] + "mcp"},
            "auth": {
                "type": "bearer",
                "scheme": "Bearer",
                "header": "Authorization",
                "description": "Use Authorization: Bearer <token> to authenticate"
            },
            "description": (
                "Wallet4Agent MCP server. "
            "Thank to this tool the Agent has now its own credential wallet. The tool allows to manage digital and verifiable credentials for humans, "
                "organizations, and AI agents, and exposes tools to inspect, "
                "store, and present those credentials."
            ),
            "about": {
                "role": "Agent wallet and digital credential orchestrator",
                "wallet_definition": (
                    "A wallet is a secure software component that stores and manages "
                    "digital credentials (including W3C Verifiable Credentials and "
                    "SD-JWT VCs) for a subject or for an AI agent acting on their behalf."
                )
            }
        })
    # Agntcy endpoint for the platform
    @app.get("/.well-known/vcs.json")
    def well_known_vcs():
        badges = current_app.config.get("AGNTCY_SERVER_BADGES_JSON", {})
        return jsonify(badges)

    @app.get("/manifest.json")
    def manifest():
        manifest = json.load(open("manifest.json", "r"))
        manifest["tools"].extend(wallet_tools_for_agent.tools_agent)
        manifest["tools"].extend(verifier_tools.tools_agent)
        return jsonify(manifest)
            
    @app.get("/mcp/tools_list")
    def mcp_tools_list():
        modules = ["tools.wallet_tools", "tools.verifier_tools", "tools.wallet_tools_for_agent"]
        constants = ["tools_guest", "tools_admin", "tools_agent"]
        tools_list = {"tools": []}
        for module_name in modules:
            module = importlib.import_module(module_name) 
            for const in constants:
                if hasattr(module, const):
                    tools_list["tools"].extend(getattr(module, const))
        return jsonify(tools_list)

    def _agent_manifest(did: str) -> dict:
        base = current_app.config["MODE"].server.rstrip("/")
        # Minimal manifest: identity + where to find badge + where MCP is
        return {
            "name": "wallet4agent-agent",
            "version": "1.0.0",
            "subject": {
                "did": did,
                "type": "Agent"
            },
            "authentication": {
                "badge_endpoint": f"{base}/agents/{did}/.well-known/vcs.json",
                "authorization_header": "Authorization: Bearer <AGNTCY_BADGE_JWT>"
            },
            "mcp": {
                "server": f"{base}/mcp"
            }
        }
    
    @app.get("/agents/<path:agent_did>/manifest.json")
    def agent_manifest(agent_did: str):
        # only return for wallets you actually manage
        wallet = Wallet.query.filter(Wallet.did == agent_did).one_or_none()
        if not wallet:
            return jsonify({"error": "unknown_did"}), 404
        return jsonify(_agent_manifest(agent_did))

    @app.get("/agents/<path:agent_did>/.well-known/vcs.json")
    def agent_well_known_vcs(agent_did: str):
        wallet = Wallet.query.filter(Wallet.did == agent_did).one_or_none()
        if not wallet or not getattr(wallet, "agntcy_agent_badge", None):
            return jsonify({"vcs": []}), 200
        # publish as "vcs": ["<compact-jws>"] (common pattern)
        return jsonify({"vcs": [wallet.agntcy_agent_badge]})
    
    # A2A endpoint for each agent
    @app.get("/agents/<path:agent_did>/.well-known/a2a.json")
    def agent_well_known_a2a(agent_did: str):
        wallet = Wallet.query.filter(Wallet.did == agent_did).one_or_none()
        if not wallet:
            return jsonify({"error": "unknown_did"}), 404

        base = current_app.config["MODE"].server.rstrip("/")
        # Minimal “Agent Card”-style payload
        return jsonify({
            "id": agent_did,
            "name": wallet.agent_name or agent_did,
            "description": wallet.agent_description,
            "service": {
                "mcp": f"{base}/mcp",
                "wallet": f"{base}/agents/{agent_did}",
            },
            "wellKnown": {
                "vcs": f"{base}/agents/{agent_did}/.well-known/vcs.json",
            }
        })

    
    # --------- CORS for /mcp ---------  
    def _add_cors(resp):
        origin = request.headers.get("Origin")
        allow = current_app.config.get("CORS_ALLOWED_ORIGINS", "*")
        # wildcard public API (recommended for published server)
        if allow == "*":
            resp.headers["Access-Control-Allow-Origin"] = "*"
        else:
            if origin and origin in allow:
                resp.headers["Access-Control-Allow-Origin"] = origin
                resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-KEY, Authorization, X-AGNTCY-BADGE"
        resp.headers["Access-Control-Max-Age"] = "600"
        return resp

    @app.after_request
    def _cors_after(resp):
        if request.path.startswith("/mcp"):
            return _add_cors(resp)
        return resp

    # --------- Tool catalog ---------
        # --------- Tool catalog ---------
    def _tools_list(role, agent_identifier=None) -> Dict[str, Any]:
        """
        Return the list of tools available for the caller, taking into account:
        - role: guest / admin / agent
        - Wallet feature flags for agents:
            - wallet.receive_credentials -> tools_agent_receive_credentials
            - wallet.sign              -> tools_agent_sign
            - wallet.publish_unpublish -> tools_agent_publish_unpublish
        - tools_agent_others is ALWAYS available to agents
        """
        logging.info("tools have been called")

        # ----- guest / admin: keep old behaviour -----
        if role in ("guest", "admin"):
            tools: List[Dict[str, Any]] = []
            modules = ["tools.wallet_tools", "tools.wallet_tools_for_agent", "tools.verifier_tools"]
            constant = "tools_" + role
            for module_name in modules:
                module = importlib.import_module(module_name)
                if hasattr(module, constant):
                    tools.extend(getattr(module, constant))
            return {"tools": tools}

        # ----- agent: feature-gated by Wallet flags -----
        if role == "agent":
            tools: List[Dict[str, Any]] = []

            # 1) "Others" are always available to agents
            #    (resolve_agent_identifier, get_this_agent_data, get_attestations_xxx,
            #     describe_wallet4agent, help_wallet4agent, ...)
            tools.extend(wallet_tools_for_agent.tools_agent_others)

            # 2) Verifier tools for agents are always available as well
            if hasattr(verifier_tools, "tools_agent"):
                tools.extend(verifier_tools.tools_agent)

            # 3) Feature-gated groups based on Wallet flags
            this_wallet = Wallet.query.filter_by(did=agent_identifier).one_or_none() if agent_identifier else None
            if not this_wallet:
                # No wallet: only "others" + verifier tools
                logging.warning("No wallet found for agent DID %s in _tools_list", agent_identifier)
                return {"tools": tools}

            # receive_credentials -> accept_credential_offer
            if this_wallet.receive_credentials:
                print("add credentials")
                tools.extend(wallet_tools_for_agent.tools_agent_receive_credentials)

            # sign -> sign_text_message, sign_json_payload
            if this_wallet.sign:
                print("add sign")
                tools.extend(wallet_tools_for_agent.tools_agent_sign)

            # publish_unpublish -> publish_attestation, unpublish_attestation
            if this_wallet.publish_unpublish:
                print("add publish")
                tools.extend(wallet_tools_for_agent.tools_agent_publish_unpublish)

            return {"tools": tools}

        # Fallback: unknown role
        return {"tools": []}


    # --------- Prompt catalog ---------
    def _prompts_list(role) -> Dict[str, Any]:
        logging.info("prompts have beenn called")
        prompts = []
        if role == "agent":
            if hasattr(wallet_prompts, "prompts_agent"):
                prompts.extend(wallet_prompts.prompts_agent)
            if hasattr(verifier_prompts, "prompts_agent"):
                prompts.extend(verifier_prompts.prompts_agent)
        elif role == "guest":
            if hasattr(wallet_prompts_for_guest, "prompts_guest"):
                prompts.extend(wallet_prompts_for_guest.prompts_guest)
        return {"prompts": prompts}

    # --------- Resource catalog ---------
    def _resources_list(role) -> Dict[str, Any]:
        logging.info("resources have been called")
        resources: List[Dict[str, Any]] = []
        if role in ["guest", "agent"]:
            # Developer-specific documentation
            resources.append({
                "uri": "wallet4agent/docs/get_started",
                "name": "Wallet4Agent – Getting Started for Developers",
                "description": (
                    "Markdown documentation that explains how to create an agent "
                    "identity and wallet, use the admin personal access token, and "
                    "configure authentication (PAT or OAuth 2.0)."
                ),
                "mimeType": "text/markdown",
            })
        if role == "agent":
            # 1) This agent's wallet overview
            resources.append({
                "uri": "wallet4agent/this_agent",
                "name": "This agent identity and wallet",
                "description": (
                    "High-level overview of this Agent's identity (its DID) and its attached "
                    "wallet: the Agent DID, the wallet endpoint URL, number of attestations, "
                    "and whether a human is always kept in the loop."
                ),
                "mimeType": "application/json",
            })

            # 2) This agent's wallet attestations
            resources.append({
                "uri": "wallet4agent/this_agent/attestations",
                "name": "This Agent's attestations",
                "description": (
                    "All attestations (verifiable credentials) currently held by this Agent. "
                    "The Agent is identified by its DID; the credentials are stored in its "
                    "attached wallet. Use this resource to see what has been issued about "
                    "this Agent (or its human/organization admin)."
                ),
                "mimeType": "application/json",
            })

            # 3) Another agent's attestations (templated by DID)
            resources.append({
                "uri": "wallet4agent/agent/{did}/attestations",
                "name": "Another Agent's published attestations",
                "description": (
                    "Template resource. Replace {did} with a specific Agent DID to retrieve "
                    "the attestations that Agent has published (for example via Linked "
                    "Verifiable Presentations in its DID Document). These attestations are "
                    "about the Agent identified by that DID, not about a particular wallet."
                ),
                "mimeType": "application/json",
            })

            # 4) Self-description of the Wallet4Agent MCP server
            resources.append({
                "uri": "wallet4agent/description",
                "name": "Wallet4Agent server description",
                "description": (
                    "Human-readable description of what the Wallet4Agent MCP server "
                    "and its wallet do, plus structured information about the role "
                    "of the wallet for AI agents."
                ),
                "mimeType": "application/json",
            })

        return {"resources": resources}

    # --------- MCP JSON-RPC endpoint ---------
    @app.route("/mcp", methods=["POST", "OPTIONS"])
    def mcp():
        
        if request.method == "OPTIONS":
            return _add_cors(make_response("", 204))
        
        # check https authorization
        role, agent_identifier = get_role_and_agent_id()
        if role == "expired":
            return expired_token_response()
        logging.info("role = %s",role)
    
        req = request.get_json(force=True, silent=False)
        logging.info("request received = %s", json.dumps(req, indent=2))

        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or "method" not in req:
            rid = req.get("id") if isinstance(req, dict) else None
            return _error(-32600, "Invalid Request") | {"id": rid}

        method = req["method"]
        req_id = req.get("id")
        params = req.get("params") or {}
        
        if method and method.startswith("notifications/"):
            return ("", 202)      
        # ping basic 
        elif method == "ping":
            return jsonify({"jsonrpc": "2.0", "result": {}, "id": req_id})
        
        elif method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": True},
                    "prompts": {"listChanged": True},
                    "resources": {"listChanged": True},
                    "logging": {}
                },
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}
            }
            resp = jsonify({"jsonrpc": "2.0", "result": result, "id": req_id})
            resp.headers["MCP-Session-Id"] = str(uuid.uuid4())
            return resp

        # tools/list
        elif method == "tools/list":
            return jsonify({"jsonrpc": "2.0", "result": _tools_list(role, agent_identifier), "id": req_id})
        
        # prompts/list
        elif method == "prompts/list":
            return jsonify({"jsonrpc": "2.0", "result": _prompts_list(role), "id": req_id})
        
        # resources/list
        elif method == "resources/list":
            return jsonify({"jsonrpc": "2.0", "result": _resources_list(role), "id": req_id})
            
        # trace and debug
        elif method == "logging/setLevel":
            level_str = (params.get("level") or "").lower()
            py_level = LEVELS.get(level_str)
            if py_level is None:
                py_level = logging.INFO
            logging.getLogger().setLevel(py_level)
            return jrpc_ok(req_id)
        
        elif method == "prompts/get":
            name = params.get("name")
            arguments = params.get("arguments") or {}

            if not name:
                return jsonify(_error(-32602, "Missing prompt name") | {"id": req_id})

            prompt_result = None
            any_builder = False

            # Try each prompt module (wallet_prompts, verifier_prompts, ...)
            if role == "agent":
                modules = AGENT_PROMPT_MODULES
            elif role == "guest":
                modules = GUEST_PROMPT_MODULES
            else:
                modules = []
            for mod in modules:
                builder = getattr(mod, "build_prompt_messages", None)
                if builder is None:
                    continue
                any_builder = True
                try:
                    prompt_result = builder(name, arguments)
                    break  # found it
                except KeyError:
                    # This module doesn't know this prompt name; try the next one
                    continue

            if not any_builder:
                return jsonify(
                    _error(-32601, "Prompts not configured on server") | {"id": req_id}
                )

            if prompt_result is None:
                return jsonify(
                    _error(-32601, f"Unknown prompt: {name}") | {"id": req_id}
                )

            return jsonify({"jsonrpc": "2.0", "result": prompt_result, "id": req_id})

        # resources/template
        elif method.startswith("resources/template"):
            return jsonify(
                    _error(-32602, "Unauthorized: resources template are not available.")
                    | {"id": req_id}
                )
        
        # resources/read    
        elif method == "resources/read":
            uri = params.get("uri")
            if not uri:
                return jsonify(_error(-32602, "Missing resource uri") | {"id": req_id})

            if not role in ["agent", "guest"]:
                return jsonify(
                    _error(-32001, "Unauthorized: resources are only available to agent role")
                    | {"id": req_id}
                )

            # Helper to adapt tool-style output to resources/read output
            def _resource_result_from_tool_output(tool_out: Dict[str, Any], uri: str) -> Dict[str, Any]:
                # Concatenate all text blocks from the tool output
                texts = []
                for block in tool_out.get("content", []):
                    if isinstance(block, dict) and block.get("type") == "text":
                        txt = block.get("text", "")
                        if txt:
                            texts.append(txt)

                text_payload = "\n".join(texts) if texts else ""

                contents = [
                    {
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": text_payload,
                    }
                ]

                result: Dict[str, Any] = {"contents": contents}
                if "structuredContent" in tool_out:
                    result["structuredContent"] = tool_out["structuredContent"]
                return result


            # 1) This agent's data
            if uri == "wallet4agent/this_agent":
                if not agent_identifier:
                    return jsonify(
                        _error(-32001, "Missing agent identifier for this_wallet") | {"id": req_id}
                    )
                tool_out = wallet_tools_for_agent.call_get_this_agent_data(agent_identifier)
                return jsonify({
                    "jsonrpc": "2.0",
                    "result": _resource_result_from_tool_output(tool_out, uri),
                    "id": req_id,
                })

            # 2) This agent's wallet attestations
            if uri == "wallet4agent/this_agent/attestations":
                if not agent_identifier:
                    return jsonify(
                        _error(-32001, "Missing agent identifier for attestations") | {"id": req_id}
                    )
                tool_out = wallet_tools_for_agent.call_get_attestations_of_this_wallet(
                    agent_identifier, config()
                )
                return jsonify({
                    "jsonrpc": "2.0",
                    "result": _resource_result_from_tool_output(tool_out, uri),
                    "id": req_id,
                })

            # 3) Another agent's attestations: wallet4agent/agent/{did}/attestations
            if uri.startswith("wallet4agent/agent/") and uri.endswith("/attestations"):
                # uri = wallet4agent/agent/<did>/attestations
                parts = uri.split("/")
                if len(parts) < 4:
                    return jsonify(
                        _error(-32602, "Invalid agent attestations uri") | {"id": req_id}
                    )
                target_did = "/".join(parts[2:-1])  # support ':' etc. inside DID
                tool_out = wallet_tools_for_agent.call_get_attestations_of_another_agent(
                    target_did
                )
                return jsonify({
                    "jsonrpc": "2.0",
                    "result": _resource_result_from_tool_output(tool_out, uri),
                    "id": req_id,
                })

            # 4) Wallet4Agent description
            if uri == "wallet4agent/description":
                tool_out = wallet_tools_for_agent.call_describe_wallet4agent()
                return jsonify({
                    "jsonrpc": "2.0",
                    "result": _resource_result_from_tool_output(tool_out, uri),
                    "id": req_id,
                })
                
            # 5) Developer documentation: get_started.md
            if uri == "wallet4agent/docs/get_started":
                try:
                    # Adjust path if get_started.md is in a different directory
                    with open("documentation/get_started.md", "r", encoding="utf-8") as f:
                        md_text = f.read()
                except Exception as e:
                    return jsonify(
                        _error(-32001, "Could not read developer documentation", {"detail": str(e)})
                        | {"id": req_id}
                    )

                result = {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/markdown",
                            "text": md_text,
                        }
                    ]
                }
                # Optionally add a small structuredContent hint
                result["structuredContent"] = {
                    "title": "Wallet4Agent — Getting Started from Zero to Agent",
                    "role": "guest",
                    "format": "markdown",
                }
                return jsonify({"jsonrpc": "2.0", "result": result, "id": req_id})
            
            # Unknown resource
            return jsonify(
                _error(-32601, f"Unknown resource uri: {uri}") | {"id": req_id}
            )

        # tools/call
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}  
            
            def _get_wallet_for_agent(agent_identifier: Optional[str]) -> Optional[Wallet]:
                if not agent_identifier:
                    return None
                return Wallet.query.filter_by(did=agent_identifier).one_or_none()
    
    
            if name == "start_user_verification":
                if not arguments.get("user_email"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"User email missing"}}
                if role != "agent":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                scope = arguments.get("scope")
                # For public test profiles, simplest rule: token must equal verifier_id
                if scope not in {"over18","profile"}:
                    return jsonify({"jsonrpc":"2.0","id":req_id,
                                        "error":{"code":-32001,"message":"Unauthorized: scope missing or not supported"}})
                out = verifier_tools.call_start_user_verification(arguments, agent_identifier, config())
            
            elif name == "register_wallet_as_chat_agent":
                if role != "admin":
                    return {"jsonrpc": "2.0", "id": req_id,
                            "error": {"code": -32001, "message": "Unauthorized: unauthorized token "}}
                out = wallet_tools.call_register_wallet_as_chat_agent(arguments, agent_identifier, config())
            
            elif name == "start_agent_authentication":
                if role != "agent":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if not arguments.get("agent_identifier"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: agent_identifier missing"}}
                target_agent = arguments.get("agent_identifier")
                if target_agent == agent_identifier:
                    return jsonify({"jsonrpc":"2.0","id":req_id,
                                        "error":{"code":-32001,"message":"Unauthorized: same agent"}})
                out = verifier_tools.call_start_agent_authentication(target_agent, agent_identifier, config())
            
            elif name == "poll_user_verification":
                if role != "agent":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = verifier_tools.call_poll_user_verification(arguments, agent_identifier, config())
                
            elif name == "poll_agent_authentication":
                if role != "agent":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = verifier_tools.call_poll_agent_authentication(arguments, agent_identifier, config())
            
            elif name == "create_agent_identifier_and_wallet":
                
                if role != "guest":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                
                if not arguments.get("admins_login") or not arguments.get("admins_identity_provider"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: admins_login or admin_identity_provider missing "}}        
                out = wallet_tools.call_create_agent_identifier_and_wallet(arguments, config())
            
            elif name == "add_authentication_key":
                if role != "admin":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if not arguments.get("public_key"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: public_key missing "}}  
                out = wallet_tools.call_add_authentication_key(arguments, agent_identifier, config())
            
            elif name == "get_configuration":
                if role != "admin":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools.call_get_configuration(agent_identifier, config())

            elif name == "update_configuration":
                if role != "admin":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools.call_update_configuration(arguments, agent_identifier, config())
                
            elif name == "get_this_agent_data":
                if role != "agent":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools_for_agent.call_get_this_agent_data(agent_identifier)
            
            elif name == "describe_wallet4agent":
                out = wallet_tools_for_agent.call_describe_wallet4agent()
            
            elif name == "help_wallet4agent":
                out = wallet_tools_for_agent.call_help_wallet4agent()
            
            elif name == "delete_identity":
                if role != "admin":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if agent_identifier != arguments.get("agent_identifier"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: agent_identifier missing "}}
                out = wallet_tools.call_delete_identity(agent_identifier)
            
            elif name == "get_attestations_of_this_wallet":
                if role not in ["admin", "agent"]:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools_for_agent.call_get_attestations_of_this_wallet(agent_identifier, config())
                
            elif name == "sign_text_message":
                if role not in ["agent"]:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if not arguments.get("message"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: message missing "}}
                this_wallet = _get_wallet_for_agent(agent_identifier)
                if not this_wallet.sign:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: message signing"}}
                
                out = wallet_tools_for_agent.call_sign_text_message(arguments, agent_identifier, config())
            
            elif name == "sign_json_payload":
                if role not in ["agent"]:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if not arguments.get("payload"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: payload missing"}}
                
                this_wallet = _get_wallet_for_agent(agent_identifier)
                if not this_wallet.sign:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: payload signing"}}
                    
                out = wallet_tools_for_agent.call_sign_json_payload(arguments, agent_identifier, config())
            
            elif name == "get_attestations_of_another_agent":
                target_agent_identifier = arguments.get("agent_identifier")
                if not target_agent_identifier:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: agent_identifier missing "}}       
                if role not in ["agent"]:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools_for_agent.call_get_attestations_of_another_agent(target_agent_identifier)
                    
            elif name == "rotate_personal_access_token":
                if role != "admin":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if agent_identifier != arguments.get("agent_identifier"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: agent_identifier missing "}}
                out = wallet_tools.call_rotate_personal_access_token(arguments, agent_identifier)
            
            elif name == "describe_identity_document":
                if role != "admin":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools.call_describe_identity_document(agent_identifier)
            
            elif name == "accept_credential_offer":
                if role not in ["agent"]:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if not arguments.get("credential_offer"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: missing credential_offer"}}
                this_wallet = _get_wallet_for_agent(agent_identifier)
                if not this_wallet.receive_credentials:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: receive attestation"}}
                out = wallet_tools_for_agent.call_accept_credential_offer(arguments, agent_identifier, config())
            
            elif name == "publish_attestation":
                if role not in ["agent", "admin"]:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if not arguments.get("attestation_id"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: missing attestation_id"}}
                this_wallet = _get_wallet_for_agent(agent_identifier)
                if not this_wallet.publish_unpublish:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: publish attestation"}}
                out = wallet_tools_for_agent.call_publish_attestation(arguments, agent_identifier, config())
            
            elif name == "unpublish_attestation":
                if role not in ["agent", "admin"]:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if not arguments.get("attestation_id") and arguments.get("attestation_id") != 0:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: missing attestation_id"}}
                this_wallet = _get_wallet_for_agent(agent_identifier)
                if not this_wallet.publish_unpublish:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unpublish attestation"}}
                out = wallet_tools_for_agent.call_unpublish_attestation(arguments, agent_identifier, config())
            
            elif name == "resolve_agent_identifier":
                if role not in ["agent"]:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if not arguments.get("agent_identifier"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: agent identifier is missing²"}}
                out = wallet_tools_for_agent.call_resolve_agent_identifier(arguments)
            else:
                return jsonify(_error(-32601, f"Unknown tool: {name}") | {"id": req_id})
            
            logging.info("tool response = %s", json.dumps({"jsonrpc": "2.0", "result": out, "id": req_id}, indent=2))
            return jsonify({"jsonrpc": "2.0", "result": out, "id": req_id})

        # unknown method
        return jsonify(_error(-32601, f"Method not found: {method}") | {"id": req_id})

