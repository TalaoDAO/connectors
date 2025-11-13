import json
from typing import Any, Dict, List, Optional
import logging
from flask import request, jsonify, current_app, make_response
from db_model import Verifier, Wallet
from utils.kms import decrypt_json
from tools import wallet_tools, verifier_tools
from utils import oidc4vc
import importlib

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "MCP server for data wallet"
SERVER_VERSION = "1.3.0"

 
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

    def jrpc_error(_id, code=-32603, message="Internal error"):
        return {"jsonrpc":"2.0","id":_id,"error":{"code":code,"message":message}}, 200, {"Content-Type":"application/json"}
    
        # --------- helpers ---------
        
    def config() -> dict:
        config = {
            "VERIFIER_API_START": current_app.config["MODE"].server + "verifier/wallet/start",
            "PULL_STATUS_BASE": current_app.config["MODE"].server + "verifier/wallet/pull",
            "PUBLIC_BASE_URL": "https://wallet4agent.com",
            "REDIS": current_app.config["REDIS"],
            "MODE": current_app.config["MODE"],
            "SERVER": current_app.config["MODE"].server,
            "MANAGER": current_app.config["MANAGER"]
        }
        return config
    
    def _bearer_or_api_key():
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()
        return request.headers.get("X-API-KEY")

    def get_role_and_agent_id() -> str:
        bearer_token = _bearer_or_api_key()
        if not bearer_token:
            logging.info("no Bearer token")
            return "guest", None 
        try:
            role = oidc4vc.get_payload_from_token(bearer_token).get("role")
            agent_identifier = oidc4vc.get_payload_from_token(bearer_token).get("sub")
            print(role, agent_identifier)
            oidc4vc.verif_token(bearer_token)
        except Exception as e:
            print(str(e))
            logging.warning("verif token failed with role = %s and agent_identifier = %s", role, agent_identifier)
            return "guest", None
        if not role:
            return "guest", None
        
        # check if token is still valid for this agent_identifier
        this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
        try:
            if bearer_token == this_wallet.dev_token:
                return "dev", agent_identifier
            elif bearer_token == this_wallet.agent_token:
                return "agent", agent_identifier
            else:
                return "guest", None
        except Exception as e:
            logging.warning(str(e))
            return "guest", None
        
    
    
    def _ok_content(blocks: List[Dict[str, Any]], structured: Optional[Dict[str, Any]] = None, is_error: bool = False) -> Dict[str, Any]:
        out: Dict[str, Any] = {"content": blocks}
        if structured is not None:
            out["structuredContent"] = structured
        if is_error:
            out["isError"] = True
        return out

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


    @app.get("/manifest.json")
    def manifest():
        manifest = json.load(open("manifest.json", "r"))
        manifest["tools"].extend(wallet_tools.tools_agent)
        manifest["tools"].extend(verifier_tools.tools_agent)
        return jsonify(manifest)
            
    @app.get("/mcp/tools_list")
    def mcp_tools_list():
        modules = ["tools.wallet_tools", "tools.verifier_tools"]
        constants = ["tools_guest", "tools_dev", "tools_agent"]
        tools_list = {"tools": []}
        for module_name in modules:
            module = importlib.import_module(module_name) 
            for const in constants:
                if hasattr(module, const):
                    tools_list["tools"].extend(getattr(module, const))
        return jsonify(tools_list)

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
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-KEY, Authorization"
        resp.headers["Access-Control-Max-Age"] = "600"
        return resp

    @app.after_request
    def _cors_after(resp):
        if request.path.startswith("/mcp"):
            return _add_cors(resp)
        return resp

    # --------- Tool catalog ---------
    def _tools_list(role) -> Dict[str, Any]:
        modules = ["tools.wallet_tools", "tools.verifier_tools"]
        constant = "tools_" + role
        tools_list = {"tools": []}
        for module_name in modules:
            module = importlib.import_module(module_name) 
            if hasattr(module, constant):
                tools_list["tools"].extend(getattr(module, constant))
        return tools_list

    # --------- MCP JSON-RPC endpoint ---------
    @app.route("/mcp", methods=["POST", "OPTIONS"])
    def mcp():
        logging.info("header = %s", request.headers)
        if request.method == "OPTIONS":
            return _add_cors(make_response("", 204))
    
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

        # initialize handshake
        elif method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": True},
                    "logging": {}
                },
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}
            }
            return jsonify({"jsonrpc": "2.0", "result": result, "id": req_id})

        # tools/list
        elif method == "tools/list":
            role, agent_identifier = get_role_and_agent_id()
            logging.info("role = %s",role)
            return jsonify({"jsonrpc": "2.0", "result": _tools_list(role), "id": req_id})
                
    
        # trace and debug
        elif method == "logging/setLevel":
            level_str = (params.get("level") or "").lower()
            py_level = LEVELS.get(level_str)
            if py_level is None:
                py_level = logging.INFO
            logging.getLogger().setLevel(py_level)

            return jrpc_ok(req_id)

        # tools/call
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}         
            role, agent_identifier = get_role_and_agent_id()

    
            if name == "start_user_verification":
                if role != "agent":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                scope = arguments.get("scope")
                # For public test profiles, simplest rule: token must equal verifier_id
                if scope not in {"email","over18","profile", "wallet_identifier"}:
                    return jsonify({"jsonrpc":"2.0","id":req_id,
                                        "error":{"code":-32001,"message":"Unauthorized: scope missing or not supported"}})
                out = verifier_tools.call_start_user_verification(arguments, config())
            
            elif name == "poll_user_verification":
                if role != "agent":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = verifier_tools.call_poll_user_verification(arguments, config())
            
            elif name == "create_agent_identifier_and_wallet":
                if role == "agent":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if not arguments.get("owners_login") or not arguments.get("owners_identity_provider"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: owner_login or owner_identity_provider missing "}}        
                out = wallet_tools.call_create_agent_identifier_and_wallet(arguments, config())
            
            elif name == "add_authentication_key":
                if role != "dev":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if not arguments.get("public_key"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: public_key missing "}}  
                out = wallet_tools.call_add_authentication_key(arguments, agent_identifier, config())
            
            elif name == "get_identity_data":
                if role != "dev":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools.call_get_identity_data(agent_identifier, config())
                
            elif name == "get_this_wallet_data":
                if role != "agent":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools.call_get_this_wallet_data(agent_identifier)
            
            elif name == "describe_wallet4agent":
                if role != "agent":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools.call_describe_wallet4agent()
            
            elif name == "delete_wallet":
                if role != "dev":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools.call_delete_wallet(agent_identifier, config())
            
            elif name == "get_attestations_of_this_wallet":
                if role not in ["dev", "agent"]:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools.call_get_attestations_of_this_wallet(agent_identifier, config())
                
            elif name == "get_attestations_of_another_agent":
                target_agent_identifier = arguments.get("agent_identifier")
                if not target_agent_identifier:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: agent_identifier missing "}}       
                if role not in ["agent"]:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools.call_get_attestations_of_another_agent(target_agent_identifier)
                     
            elif name == "rotate_bearer_token":
                if role != "dev":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools.call_rotate_bearer_token(arguments, agent_identifier, config())
            
            elif name == "accept_credential_offer":
                if role not in ["agent"]:
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                if not arguments.get("credential_offer"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: missing credential_offer"}}
                out = wallet_tools.call_accept_credential_offer(arguments, agent_identifier, config())

            else:
                return jsonify(_error(-32601, f"Unknown tool: {name}") | {"id": req_id})
            
            logging.info("tool response = %s", json.dumps({"jsonrpc": "2.0", "result": out, "id": req_id}, indent=2))
            return jsonify({"jsonrpc": "2.0", "result": out, "id": req_id})

        # unknown method
        return jsonify(_error(-32601, f"Method not found: {method}") | {"id": req_id})

