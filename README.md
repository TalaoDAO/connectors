
# MCP Server for Data Wallets (EUDI / OIDC4VP)

Connect **EUDI-compliant wallets** (e.g., Talao) to **AI agents** via the **Model Context Protocol (MCP)**.  
This server wraps your **OAuth 2.0 / OIDC4VP** verifier API and exposes a **pull-based** flow to agents (no webhooks).

> ✅ MCP Spec: **2025-06-18** — uses `params.arguments`, returns `result.content` (blocks) + `result.structuredContent`.

---

## ✨ Features

- **MCP tools**: start a wallet presentation, poll status, and revoke/cleanup
- **Pull model** (agent polls your verifier): simpler than webhooks
- **QR + deep link**: returned as MCP content blocks (image + text)
- **Token redaction**: `vp_token` / `id_token` are redacted by default
- **Spec-compliant**: MCP 2025‑06‑18 content shapes and JSON-RPC semantics
- **Works with** EUDI-compliant wallets (including Talao)

---

## 🗂️ Project layout (key files)

```
main.py                 # Flask app factory; wires routes via init_app()
verifier_mcp.py         # MCP server (HTTP JSON-RPC at /mcp)
oidc4vp.py              # OIDC4VP bridge with pull endpoint for status
templates/home.html     # Landing page (overview + examples)
templates/flow.html     # Demo QR + live polling page
test_mcp_flask_demo.py  # Minimal test UI that hits /mcp (optional)
```

> The app **does not** require environment variables; config is set in `main.py` (see below).

---

## ⚙️ Configuration

Set these in `main.py` before calling `init_app(app)`:

```python
app.config.update({
    # Public URLs (use https in production)
    "PUBLIC_BASE_URL":   "https://wallet-connectors.com",

    # Your existing verifier endpoints (wrapped by the MCP server)
    "VERIFIER_API_BASE": "https://wallet-connectors.com/verifier/app",
    "PULL_STATUS_BASE":  "https://wallet-connectors.com/verifier/wallet/pull",

    # Optional default key (used if client didn't send X-API-KEY)
    "VERIFIER_API_KEY":  "0000",

    # CORS: allow "*" for public use, or provide a set of origins
    "CORS_ALLOWED_ORIGINS": "*",  # or {"https://wallet-connectors.com", "https://partner.com"}
})
```

---

## 🚀 Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt  # flask, requests, qrcode, (optional) flask-cors
python main.py                   # or: gunicorn -w 3 -b 0.0.0.0:8000 main:app
```

Open the test UI (if using `test_mcp_flask_demo.py`):

```bash
pip install flask requests
python test_mcp_flask_demo.py
# Visit http://localhost:5055
```

---

## 🔌 Endpoints

- `POST /mcp` — **MCP JSON-RPC** endpoint
- `GET  /mcp/info` — server metadata (name, version, protocolVersion)
- `GET  /mcp/healthz` — liveness check

Your wrapped verifier endpoints (already exist in your backend):

- `POST VERIFIER_API_BASE` — start presentation (returns `url`, `session_id`)
- `GET  PULL_STATUS_BASE/<session_id>` — poll status (returns `status`, claims…)

---

## 🧰 MCP Tools

### 1) `start_wallet_verification`

Create an OIDC4VP authorization request (returns **QR image** + **deeplink**).

**Arguments**
```json
{
  "verifier_id": "string",
  "session_id": "string (optional)",
  "mode": "audit | test (optional)",
  "presentation": "object (optional)",
  "scope": "email | phone | profile | over18 | custom | wallet_identifier (optional)"
}
```

> `wallet_identifier` maps to **no scope** in the OIDC layer, producing an **ID-token only** flow (wallet DID).

**JSON-RPC example**
```bash
curl -s https://wallet-connectors.com/mcp \
  -H 'Content-Type: application/json' \
  -H 'X-API-KEY: <X-API-KEY>' \
  -d '{
    "jsonrpc":"2.0",
    "id":2,
    "method":"tools/call",
    "params":{
      "name":"start_wallet_verification",
      "arguments":{"verifier_id":"0000","scope":"profile"}
    }
  }' | jq
```

**Result shape**
```json
{
  "result": {
    "content": [
      {"type":"image","data":"<base64-png>", "mimeType":"image/png"},
      {"type":"text", "text":"Scan the QR or open: openid4vp://..."}
    ],
    "structuredContent": {
      "session_id": "3e02ac7e-da66-4dd1-9abe-30348dcc728f",
      "deeplink_url": "openid4vp://...?request_uri=...",
      "pull_url": "https://wallet-connectors.com/verifier/wallet/pull/3e02...",
      "public_base_url": "https://wallet-connectors.com"
    }
  }
}
```

---

### 2) `poll_wallet_verification`

Check the current status and retrieve wallet claims.

**Arguments**
```json
{ "session_id": "string" }
```

**Statuses**
- `pending` — user hasn’t approved yet
- `verified` — wallet approved; claims present
- `denied` — user rejected or flow expired

**Result shape**
```json
{
  "result": {
    "content": [
      {"type":"text","text":"{\"status\":\"verified\",...}"}
    ],
    "structuredContent": {
      "status": "verified",
      "session_id": "3e02ac7e-da66-4dd1-9abe-30348dcc728f",
      "access": true,
      "scope": "profile",
      "wallet_identifier": "did:jwk:...",
      "first_name": "John",
      "last_name": "DOE"
    }
  }
}
```
> The server accepts **flattened** claims from `oidc4vp.py` or nested `wallet_data`. Tokens are **redacted** if present.

---

### 3) `revoke_wallet_flow`

Acknowledge cleanup for a session (backend TTL performs actual deletion).

**Arguments**
```json
{ "session_id": "string" }
```

**Result shape**
```json
{
  "result": {
    "content":[{"type":"text","text":"Flow revoked (TTL cleanup handled server-side)."}],
    "structuredContent":{"ok":true,"session_id":"..."}
  }
}
```

---

## 🔐 Auth & CORS

- **Auth**: clients must send `X-API-KEY: <your-verifier-key>`
- **CORS**: browser clients require preflight (`OPTIONS /mcp`)
  - Public mode: set `CORS_ALLOWED_ORIGINS="*"` (no cookies; API key in header)
  - Strict mode: provide a set of allowed origins

**Quick preflight test**

```bash
curl -i -X OPTIONS https://wallet-connectors.com/mcp \
  -H 'Origin: https://example.org' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type,x-api-key'
```

Expect `204` and:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, X-API-KEY
```

---

## 🧪 Test UI (QR + Poll)

You can use the minimal demo app to render the QR and live-poll:

```bash
python test_mcp_flask_demo.py
# then open http://localhost:5055 and enter your /mcp URL + X-API-KEY
```

---

## 🏭 Production deployment

**Gunicorn**
```bash
gunicorn -w 3 -b 0.0.0.0:8000 main:app
```

**Dockerfile (example)**
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["gunicorn","-w","3","-b","0.0.0.0:8000","main:app"]
```

**Nginx (ensure `OPTIONS` passes with CORS headers)**
```nginx
location /mcp {
  if ($request_method = OPTIONS) {
    add_header Access-Control-Allow-Origin *;
    add_header Access-Control-Allow-Methods "POST, OPTIONS";
    add_header Access-Control-Allow-Headers "Content-Type, X-API-KEY";
    add_header Access-Control-Max-Age 600;
    return 204;
  }
  proxy_pass http://127.0.0.1:8000/mcp;
}
```

---

## 🛡️ Security & Privacy

- No cookies; **API key only** (`X-API-KEY`) for auth
- Redact `vp_token` / `id_token` in MCP responses
- Keep logs free of raw tokens and PII
- Enforce rate limits and request IDs in production

---

## 🧩 MCP compliance (2025‑06‑18)

- `initialize`: returns `protocolVersion` `"2025-06-18"`, `capabilities`, and `serverInfo`
- `tools/list`: tool metadata with `inputSchema`
- `tools/call`: uses `params.arguments` (not `args`)
- Tool results: `result.content` (array of **blocks**) + `result.structuredContent` (JSON)

---

## 🆘 Troubleshooting

- **CORS preflight fails**  
  Ensure `OPTIONS /mcp` returns **204** with `Access-Control-*` headers; set `CORS_ALLOWED_ORIGINS="*"` in `main.py` for public use.

- **Browser prints only `[ { "type": "text", ... } ]`**  
  Parse `result.structuredContent` for machine JSON; `content[]` is human-readable blocks (image/text).

- **Agent stuck on `pending`**  
  Confirm the wallet approved the presentation and that `oidc4vp.py` returns `status: "verified"` to `PULL_STATUS_BASE/<session_id>`.

- **Scope mismatch**  
  Use `"wallet_identifier"` when you want ID-token-only (no PEX/DCQL). The MCP server maps that to **no scope** for `oidc4vp.py`.

---

## 📄 License

Choose a license (e.g., MIT or Apache‑2.0) and place it in `LICENSE`.
