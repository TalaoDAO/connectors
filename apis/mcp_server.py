import io
import json
import base64
import uuid
from typing import Any, Dict, List, Optional
import logging
import requests
from flask import request, jsonify, current_app, make_response
from db_model import Verifier
from utils.kms import decrypt_json
from tools import wallet_tools, verifier_tools
from utils import oidc4vc
import importlib

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "MCP server for data wallet"
SERVER_VERSION = "1.1.0"

 
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
            "SERVER": current_app.config["MODE"].server
        }
        return config
    
    def _bearer_or_api_key():
        auth = request.headers.get("Authorization", "")
        print("auth = ", auth)
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()
        return request.headers.get("X-API-KEY")

    def get_role_and_agent_id() ->str:
        bearer_token = _bearer_or_api_key()
        try:
            role = oidc4vc.get_payload_from_token(bearer_token).get("role")
            agent_id = oidc4vc.get_payload_from_token(bearer_token).get("sub")
            oidc4vc.verif_token(bearer_token)
        except Exception as e:
            logging.info("incorrect token = %s", str(e))
            return jsonify({"jsonrpc":"2.0","id":req_id, "error":{"code":-32001,"message":"Unauthorized token"}})
        if not role:
            role = "guest"
            agent_id = None
        return role, agent_id 
        
    
    
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
            "endpoints": {"rpc": "/mcp"},
            "auth": {
                "type": "bearer",
                "scheme": "Bearer",
                "header": "Authorization",
                "description": "Use Authorization: Bearer <token> to authenticate"
            }
        })


    @app.get("/manifest.json")
    def manifest():
        file = json.load(open("manifest.json", "r"))
        return jsonify(file)
            
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
        tools_list = {"tools": []}   
        #tools_list["tools"].extend(verifier_tools.tools)
        if role == "guest":
            tools_list["tools"].extend(wallet_tools.tool_guest)
        if role == "dev":
            tools_list["tools"].extend(wallet_tools.tools_dev)
        if role == "agent":
            tools_list["tools"].extend(verifier_tools.tools_agent)
        return tools_list


    # --------- MCP JSON-RPC endpoint ---------
    @app.route("/mcp", methods=["POST", "OPTIONS"])
    def mcp():
        logging.info("header %s", request.headers)
        
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
        
        # Get API key as Authorization bearer or X-API-KEY
        api_key = _bearer_or_api_key()
        
        # ping basic 
        if method == "ping":
            return jsonify({"jsonrpc": "2.0", "result": {}, "id": req_id})

        # initialize handshake
        if method == "initialize":
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
        if method == "tools/list":
            role, agent_id = get_role_and_agent_id()
            print("role = ",role)
            return jsonify({"jsonrpc": "2.0", "result": _tools_list(role), "id": req_id})
                
    
        # trace and debug
        if method == "logging/setLevel":
            level_str = (params.get("level") or "").lower()
            py_level = LEVELS.get(level_str)
            if py_level is None:
                py_level = logging.INFO
            logging.getLogger().setLevel(py_level)

            return jrpc_ok(req_id)

        # tools/call
        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            api_key = _bearer_or_api_key()
            
            role, agent_id = get_role_and_agent_id()
            
            def check_api_key():
                if not api_key:
                    return jsonify({"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: missing token"}})
                
            
            if name == "get_supported_verification_scopes":
                check_api_key()
                out = _ok_content([{"type":"text","text":"Scopes and profiles"}],
                        structured={
                            "profiles": {
                                "0000": "wallet identifier",
                                "0001": "email",
                                "0002": "over 18 proof",
                                "0003": "first name, last name and birth date"
                            },
                            "auth": "Send X-API-KEY header. For test profiles, key = verifier_id (0000, 0001, 0002, 0003)."
                        })  
    
            elif name == "start_verification":
                verifier_id = arguments.get("verifier_id")
                # For public test profiles, simplest rule: token must equal verifier_id
                
                if verifier_id in {"0000","0001","0002", "0003"}:
                    if api_key != verifier_id:
                        return jsonify({"jsonrpc":"2.0","id":req_id,
                                        "error":{"code":-32001,"message":"Unauthorized: key/verifier mismatch"}})
                    out = verifier_tools.call_start_verification(arguments, api_key, config())
                else:
                    mcp_verifier = Verifier.query.filter(Verifier.application_api_verifier_id == verifier_id).one_or_none()
                    if not mcp_verifier:
                        return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: missing verifier"}}
                    
                    expected_key = decrypt_json(mcp_verifier.application_api)["verifier_secret"]
                    if expected_key != api_key:
                        return jsonify({"jsonrpc":"2.0","id":req_id,
                                        "error":{"code":-32001,"message":"Unauthorized: key/verifier mismatch"}})
                    
                    out = verifier_tools.call_start_verification(arguments, api_key, config())
            
            elif name == "poll_verification":
                check_api_key()
                out = verifier_tools.call_poll_verification(arguments, api_key, config())
            
            elif name == "revoke_verification_flow":
                check_api_key()
                out = verifier_tools.call_revoke_verification_flow(arguments, config())
            
            elif name == "create_identity":
                if role == "agent":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools.call_create_identity(arguments, api_key, config())
            
            elif name == "get_data":
                if role != "dev":
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: unauthorized token "}}
                out = wallet_tools.call_get_data(agent_id)
            
            elif name == "request_attestation":
                if not arguments.get("credential_offer"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: missing credential_offer"}}
                if not arguments.get("agent_id"):
                    return {"jsonrpc":"2.0","id":req_id,
                                "error":{"code":-32001,"message":"Unauthorized: missing agent_id"}}
                out = wallet_tools.call_request_attestation(arguments, api_key, config())

            else:
                return jsonify(_error(-32601, f"Unknown tool: {name}") | {"id": req_id})
            
            logging.info("tool response = %s", json.dumps({"jsonrpc": "2.0", "result": out, "id": req_id}, indent=2))
            return jsonify({"jsonrpc": "2.0", "result": out, "id": req_id})

        # unknown method
        return jsonify(_error(-32601, f"Method not found: {method}") | {"id": req_id})

