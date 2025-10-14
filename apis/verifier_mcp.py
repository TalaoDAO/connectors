
# verifier_mcp.py — MCP-compliant server (spec 2025-06-18)
# Exposes your verifier APIs to AI agents with a pull model.
#
# Integration:
#   from apis import verifier_mcp
#   verifier_mcp.init_app(app)
#
# Config expected in current_app.config (set in main.py):
#   PUBLIC_BASE_URL   -> default "https://wallet-connectors.com"
#   VERIFIER_API_BASE -> default MODE.server + "verifier/app"
#   PULL_STATUS_BASE  -> default MODE.server + "verifier/wallet/pull"
#   VERIFIER_API_KEY  -> OPTIONAL default key if caller doesn't send X-API-KEY
#
# Transport/auth:
#   - HTTP JSON-RPC 2.0 at POST /mcp
#   - Custom header X-API-KEY (forwarded to upstream /verifier/app)
#
# MCP compliance highlights (2025-06-18):
#   - Supports "initialize", "tools/list", and "tools/call"
#   - tools/call uses params.arguments (not args)
#   - Result uses {"content":[...], "structuredContent":{...}} block format
#   - Provides image/text blocks; redacts raw tokens in structuredContent
#
import io
import json
import base64
import uuid
from typing import Any, Dict, List, Optional

import requests
from flask import request, jsonify, current_app, make_response, current_app

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "MCP server for data wallet"
SERVER_VERSION = "0.2.0"

def init_app(app):
    # --------- helpers ---------
    def _cfg(key: str, default: Optional[str] = None) -> str:
        if key in current_app.config:
            return current_app.config[key]
        # fallbacks using MODE.server if available
        if key == "VERIFIER_API_BASE":
            return current_app.config["MODE"].server + "verifier/app"
        if key == "PULL_STATUS_BASE":
            return current_app.config["MODE"].server + "verifier/wallet/pull"
        if key == "PUBLIC_BASE_URL":
            return "https://wallet-connectors.com"
        return default

    def _qr_png_b64(text: str) -> Optional[str]:
        """Return base64 PNG of QR for 'text'; None if qrcode not available."""
        try:
            import qrcode
        except Exception:
            return None
        img = qrcode.make(text)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()

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
            "auth": {"type": "api_key", "header": "X-API-KEY"}
        })
        
    @app.get("/mcp/tools_list")
    def mcp_toold_list():
        return jsonify(_tools_list())

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
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-KEY"
        resp.headers["Access-Control-Max-Age"] = "600"
        return resp

    @app.after_request
    def _cors_after(resp):
        if request.path.startswith("/mcp"):
            return _add_cors(resp)
        return resp

    # --------- Tool catalog ---------
    def _tools_list() -> Dict[str, Any]:
        return {
            "tools": [
                {
                    "name": "start_wallet_verification",
                    "description": "Create an OIDC4VP authorization request (QR + deeplink) via the Verifier API.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "verifier_id": {"type": "string", "description": "Verifier/application identifier."},
                            "session_id": {"type": "string", "description": "Optional caller-provided session id."},
                            "scope": {"type": "string",
                                "enum": ["email", "phone", "profile", "over18", "custom", "wallet_identifier"],
                                "description": "Optional scope hint. 'wallet_identifier' means ID-token only."}
                        },
                        "required": ["verifier_id"]
                    }
                },
                {
                    "name": "poll_wallet_verification",
                    "description": "Poll current status for a session; returns structured status and redacted wallet_data.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string"}
                        },
                        "required": ["session_id"]
                    }
                },
                {
                    "name": "revoke_wallet_flow",
                    "description": "Acknowledge cleanup for a session id (back-end TTL handles actual expiration).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string"}
                        },
                        "required": ["session_id"]
                    }
                }
            ]
        }

    # --------- Tool implementations ---------
    def _call_start_wallet_verification(arguments: Dict[str, Any], verifier_api_key: Optional[str]) -> Dict[str, Any]:
        verifier_api_base = _cfg("VERIFIER_API_BASE")
        pull_status_base = _cfg("PULL_STATUS_BASE")
        public_base_url = _cfg("PUBLIC_BASE_URL")
        # required
        verifier_id = arguments.get("verifier_id")
        if not verifier_id:
            return _ok_content(
                [{"type": "text", "text": "verifier_id is required"}],
                structured={"error": "invalid_arguments", "missing": ["verifier_id"]},
                is_error=True
            )
        
        # optional session_id
        session_id = arguments.get("session_id") or str(uuid.uuid4())
        
        scope = arguments.get("scope")
        if scope == "wallet_identifier":
            scope = None
        
        # supported scope
        if scope not in [None, "email", "phone", "profile", "custom", "over18"]:
            return _ok_content(
                [{"type": "text", "text": "scope is not supported"}],
                structured={"error": "invalid_arguments"},
                is_error=True
            )
        
        payload = {"verifier_id": verifier_id, "session_id": session_id, "scope": scope}

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        fwd_key = verifier_api_key or _cfg("VERIFIER_API_KEY")
        if fwd_key:
            headers["X-API-KEY"] = fwd_key

        try:
            r = requests.post(verifier_api_base, json=payload, headers=headers, timeout=30)
        except Exception as e:
            return _ok_content(
                [{"type": "text", "text": f"Network error calling verifier API: {e}"}],
                structured={"error": "network_error", "detail": str(e)},
                is_error=True
            )
        if r.status_code >= 400:
            txt = r.text
            try:
                err = r.json()
            except Exception:
                err = {"status": r.status_code, "body": txt}
            return _ok_content(
                [{"type": "text", "text": f"Verifier API error {r.status_code}"}],
                structured={"error": "upstream_error", "upstream": err},
                is_error=True
            )

        data = r.json()
        deeplink = data.get("url")
        sess = data.get("session_id", session_id)

        # Build structured flow info
        flow = {
            "session_id": sess,
            "deeplink_url": deeplink,
            "pull_url": f"{pull_status_base.rstrip('/')}/{sess}",
            "public_base_url": public_base_url
        }

        blocks: List[Dict[str, Any]] = []
        b64 = _qr_png_b64(deeplink) if deeplink else None
        if b64:
            blocks.append({"type": "image", "data": b64, "mimeType": "image/png"})
        # Always include a text hint
        text_hint = f"Scan the QR code (if shown) or open wallet link:\n{deeplink}" if deeplink else "No deeplink URL returned."
        blocks.append({"type": "text", "text": text_hint})
        return _ok_content(blocks, structured=flow)

    def _call_poll_wallet_verification(arguments: Dict[str, Any], verifier_api_key: Optional[str]) -> Dict[str, Any]:
        pull_status_base = _cfg("PULL_STATUS_BASE")
        session_id = arguments.get("session_id")
        if not session_id:
            return _ok_content(
                [{"type": "text", "text": "session_id is required"}],
                structured={"error": "invalid_arguments", "missing": ["session_id"]},
                is_error=True
            )

        try:
            r = requests.get(f"{pull_status_base.rstrip('/')}/{session_id}", timeout=20)
            payload = r.json()
        except Exception as e:
            return _ok_content(
                [{"type": "text", "text": f"Network error polling status: {e}"}],
                structured={"error": "network_error", "detail": str(e)},
                is_error=True
            )

        status = payload.get("status", "pending")

        # current oidc4vp: claims merged at the top level (exclude status/session_id)
        claims = {k: v for k, v in payload.items() if k not in ("status", "session_id")}

        structured = {"status": status, "session_id": session_id, **claims}

        # Human-friendly text block (special hint for wallet_identifier scope)
        text_blocks = []
        scope = claims.get("scope")
        if scope == "wallet_identifier" and claims.get("wallet_identifier"):
            text_blocks.append({
                "type": "text",
                "text": f'Wallet identifier: {claims.get("wallet_identifier")}'
            })
        # Always include the full JSON as text for debugging/visibility
        text_blocks.append({"type": "text", "text": json.dumps(structured, ensure_ascii=False)})

        return _ok_content(text_blocks, structured=structured)


    def _call_revoke_wallet_flow(arguments: Dict[str, Any], verifier_api_key: Optional[str]) -> Dict[str, Any]:
        session_id = arguments.get("session_id")
        structured = {"ok": True, "session_id": session_id}
        return _ok_content([{"type": "text", "text": "Flow revoked (TTL cleanup handled server-side)."}], structured=structured)

    # --------- MCP JSON-RPC endpoint ---------
    @app.route("/mcp", methods=["POST", "OPTIONS"])
    def mcp():
        
        if request.method == "OPTIONS":
            return _add_cors(make_response("", 204))
    
        req = request.get_json(force=True, silent=False)
        print("request = ", req)

        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or "method" not in req:
            rid = req.get("id") if isinstance(req, dict) else None
            return _error(-32600, "Invalid Request") | {"id": rid}

        method = req["method"]
        req_id = req.get("id")
        params = req.get("params") or {}
        api_key = request.headers.get("X-API-KEY") or _cfg("VERIFIER_API_KEY")

        # initialize handshake
        if method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"listChanged": False},
                    "prompts": {"listChanged": False},
                    "logging": {}
                },
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}
            }
            return jsonify({"jsonrpc": "2.0", "result": result, "id": req_id})

        # tools/list
        if method == "tools/list":
            return jsonify({"jsonrpc": "2.0", "result": _tools_list(), "id": req_id})

        # tools/call
        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if name == "start_wallet_verification":
                out = _call_start_wallet_verification(arguments, api_key)
            elif name == "poll_wallet_verification":
                out = _call_poll_wallet_verification(arguments, api_key)
            elif name == "revoke_wallet_flow":
                out = _call_revoke_wallet_flow(arguments, api_key)
            else:
                return jsonify(_error(-32601, f"Unknown tool: {name}") | {"id": req_id})
            print("tool response = ", {"jsonrpc": "2.0", "result": out, "id": req_id})
            return jsonify({"jsonrpc": "2.0", "result": out, "id": req_id})

        # unknown method
        return jsonify(_error(-32601, f"Method not found: {method}") | {"id": req_id})
