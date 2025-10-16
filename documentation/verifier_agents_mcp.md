# MCP Wallet Verification for AI Agents — **Complete Developer Guide & API Reference**

Connect **EUDI‑compliant data wallets** (e.g., **Talao**) to **AI agents** using the **Model Context Protocol (MCP)** and **OIDC4VP (pull model)**.  
This service bridges decentralized identity wallets with AI systems such as ChatGPT, VS Code, or custom agents.

- **Base URL:** `https://wallet-connectors.com`
- **MCP RPC endpoint:** `POST https://wallet-connectors.com/mcp`
- **Spec version:** MCP **2025‑06‑18** (`params.arguments`, `result.content[]`, `result.structuredContent`)
- **Protocol model:** OIDC4VP (pull) — no webhooks required

> This guide covers: authentication, test profiles, tool reference, examples, integrations, and best practices.

---

## 🔐 1. Authentication

- Preferred: `Authorization: Bearer <token>`  
- Also accepted: `X-API-KEY: <token>`

For public test profiles, **token = verifier_id** (`0000`, `0001`, `0002`).

No cookies or OAuth are used. Each MCP call must include the header.

---

## 🧠 2. Test Verifier Profiles (ready to use)

| `verifier_id` | OIDC4VP Draft | Verifier identity | Description | X-API-KEY |
|---------------|---------------|------------------|--------------|-----------|
| `0000` | Draft 20 | Redirect-URI | Baseline for DIIP v3 / Draft 20 wallets | `0000` |
| `0001` | Draft 20 | DID (Decentralized Identifier) | Same as 0000 but verifier identifies via DID | `0001` |
| `0002` | Draft 25 | DID | Newer flow for Draft 25 wallets | `0002` |

> Use these IDs and keys for sandbox testing.  
> To register your own verifier or Presentation Definition (custom claims), see **Section 11**.

---

## 🧩 3. Available Tools (MCP methods)

### `start_wallet_verification`
Starts a new OIDC4VP flow and returns a QR + deeplink for user authentication.

**Arguments:**
- `verifier_id` *(required)* — one of your registered verifier profiles  
- `scope` *(optional)* — `profile`, `email`, `phone`, `over18`, `wallet_identifier`, or `custom`  
- `session_id` *(optional)* — custom session (else generated)
- `mode`, `presentation` *(optional)* — advanced options

**Returns:**  
`content[]` (QR image, helper text) + `structuredContent` JSON with:
```json
{
  "session_id": "...",
  "deeplink_url": "openid4vp://...?request_uri=...",
  "pull_url": "https://wallet-connectors.com/verifier/wallet/pull/...",
  "public_base_url": "https://wallet-connectors.com"
}
```

### `poll_wallet_verification`
Poll verification status for a `session_id`.

**Returns:**
```json
{
  "status": "pending | verified | denied",
  "session_id": "...",
  "scope": "profile",
  "claims": {...}
}
```
Tokens (`vp_token`, `id_token`) are **redacted**; only derived claims are returned.

### `revoke_wallet_flow`
Acknowledge cleanup after completion. Useful for front‑ends; the backend TTL handles expiry.

---

## 🎯 4. Scopes and Returned Claims

| Scope | Returned claims (in `structuredContent`) | Notes |
|---|---|---|
| `profile` | `family_name`, `given_name`, `birth_date` | OIDF standard |
| `email` | `email_address`, `email` | eIDAS v2 PID |
| `phone` | `mobile_phone_number`, `phone` | eIDAS v2 PID |
| `wallet_identifier` | Wallet DID or JWK thumbprint | ID‑token only flow |
| `over18` | `over_18` (boolean) | Wallet‑dependent format |
| `custom` | As defined in your Presentation Definition | Requires registration |

---

## ⚡ 5. Quick Start (curl)

### List tools
```bash
curl -s https://wallet-connectors.com/mcp   -H 'Content-Type: application/json'   -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq
```

### Start (Demo 0000)
```bash
curl -s https://wallet-connectors.com/mcp   -H 'Content-Type: application/json' -H 'Accept: application/json' -H 'X-API-KEY: 0000'   -d '{
    "jsonrpc":"2.0",
    "id":"start",
    "method":"tools/call",
    "params":{
      "name":"start_wallet_verification",
      "arguments":{"verifier_id":"0000","scope":"profile"}
    }
  }' | jq
```

### Poll
```bash
curl -s https://wallet-connectors.com/mcp   -H 'Content-Type: application/json' -H 'Accept: application/json' -H 'X-API-KEY: 0000'   -d '{
    "jsonrpc":"2.0",
    "id":"poll",
    "method":"tools/call",
    "params":{
      "name":"poll_wallet_verification",
      "arguments":{"session_id":"<SESSION_ID>"}
    }
  }' | jq
```

---

## 💻 6. Minimal Client Snippets

### JavaScript (browser or Node)
```js
const MCP = "https://wallet-connectors.com/mcp";
const KEY = "0000";

const rpc = async (method, params, id="1") => {
  const res = await fetch(MCP, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json", "X-API-KEY": KEY },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params })
  });
  return res.json();
};

const start = await rpc("tools/call", { name: "start_wallet_verification", arguments: { verifier_id: "0000", scope: "profile" } });
console.log(start.result.structuredContent.deeplink_url);

const poll = await rpc("tools/call", { name: "poll_wallet_verification", arguments: { session_id: start.result.structuredContent.session_id } });
console.log(poll.result.structuredContent.status);
```

### Python (requests)
```py
import requests, time

MCP = "https://wallet-connectors.com/mcp"
HDR = {"Content-Type":"application/json","Accept":"application/json","X-API-KEY":"0000"}

def rpc(method, params, id="1"):
    return requests.post(MCP, headers=HDR, json={"jsonrpc":"2.0","id":id,"method":method,"params":params}).json()

start = rpc("tools/call", {"name":"start_wallet_verification","arguments":{"verifier_id":"0000","scope":"profile"}})
sid = start["result"]["structuredContent"]["session_id"]

while True:
    poll = rpc("tools/call", {"name":"poll_wallet_verification","arguments":{"session_id":sid}})
    status = poll["result"]["structuredContent"]["status"]
    print(status)
    if status != "pending": break
    time.sleep(2)
```

---

## 🧠 7. Integration with ChatGPT or VS Code

### ChatGPT Desktop
Add to `~/.config/openai/mcp/servers.json`:

```json
{
  "wallet-connectors": {
    "command": "bash",
    "args": ["-lc", "echo ready"],
    "env": { "X_API_KEY": "0000" },
    "transport": {
      "type": "http",
      "url": "https://wallet-connectors.com/mcp",
      "headers": {
        "X-API-KEY": "0000",
        "Accept": "application/json"
      }
    }
  }
}
```

Restart ChatGPT → check *Settings → MCP Servers*.

### VS Code
Create `.vscode/mcp.json`:

```json
{
  "servers": {
    "wallet-connectors": {
      "transport": {
        "type": "http",
        "url": "https://wallet-connectors.com/mcp",
        "headers": { "X-API-KEY": "0000" }
      }
    }
  }
}
```

Reload and open the MCP panel.

---

## 🧩 8. Response Anatomy

### Generic shape
```json
{
  "result": {
    "content": [ /* image/text blocks */ ],
    "structuredContent": { /* JSON */ }
  }
}
```

### Example — `start_wallet_verification`
```json
{
  "result": {
    "content": [
      { "type": "image", "data": "<base64‑PNG>", "mimeType": "image/png" },
      { "type": "text", "text": "Scan or open deeplink: openid4vp://..." }
    ],
    "structuredContent": {
      "session_id": "3e02ac7e‑...",
      "deeplink_url": "openid4vp://...?request_uri=...",
      "pull_url": "https://wallet-connectors.com/verifier/wallet/pull/..."
    }
  }
}
```

### Example — `poll_wallet_verification`
```json
{
  "result": {
    "structuredContent": {
      "status": "verified",
      "session_id": "3e02‑...",
      "wallet_identifier": "did:jwk:...",
      "first_name": "John",
      "last_name": "DOE"
    }
  }
}
```

---

## ⚙️ 9. Error Handling

| Type | Location | Example |
|------|-----------|----------|
| JSON‑RPC error | Top‑level `error` | `{"error":{"code":401,"message":"Missing or invalid X-API-KEY"}}` |
| Tool‑level error | Inside `result` | `"result":{"isError":true,"structuredContent":{"error":"invalid_arguments"}}` |

**Common causes**
- `401` — invalid/missing API key  
- `400` — malformed arguments  
- `upstream_error` — verifier returned 4xx/5xx  
- `network_error` — unreachable wallet service

---

## 🧩 10. Best Practices

- Poll every **1–2 s** until `status != "pending"`  
- Use minimal scopes — request only necessary claims  
- Handle both flattened and nested claim structures  
- Redacted tokens: `vp_token` / `id_token` are never exposed  
- Enable CORS with proper headers for browser clients

---

## 🧩 11. Register Your Own Verifier

Public profiles (`0000–0002`) are shared sandbox verifiers.  
Register to obtain a **dedicated verifier_id** and API key for:
- Private deployments
- Custom drafts (OIDC4VP 20, 25, 26)
- Unique verifier identities (DID, JWKS, etc.)
- Custom Presentation Definitions (PEX/DCQL)

Visit [wallet‑connectors.com](https://wallet-connectors.com) for registration.

---

## 🧰 12. Developer & Metadata Endpoints

| Endpoint | Description |
|-----------|--------------|
| `GET /mcp/info` | Returns `{ name, version, protocolVersion, endpoints, auth }` |
| `GET /mcp/healthz` | Returns `{ ok: true }` |

---

## 💡 13. Troubleshooting

- **Missing API key (401)** → Include `X-API-KEY` or `Authorization` header  
- **Pending forever** → Ensure wallet supports selected draft/scope  
- **Invalid session** → Use latest `session_id` from `start_wallet_verification`  
- **Browser CORS error** → Include `Content-Type`, `Accept`, and `X-API-KEY` headers  
- **Tool error** ≠ **RPC error** → inspect both layers (`error` vs `result.isError`)

---

## 📘 14. Privacy & Security

- No cookies or persistent storage.  
- API keys are per verifier; rotate periodically.  
- Tokens (`id_token`, `vp_token`) never leave the verifier backend.  
- Redacted responses ensure no personally identifiable raw data exposure.

---

## 🧾 15. Versioning & Changelog

- **1.3.0** — Comprehensive unified developer documentation; test profiles; best practices.  
- **1.2.0** — Added ChatGPT / VS Code setup; sample clients.  
- **1.1.0** — Structured MCP 2025‑06‑18 compliance.  
- **1.0.0** — Initial release.

---

**Maintainer:** [Talao DAO](https://github.com/TalaoDAO) • MIT License
