# MCP Server for Data Wallets — **Complete Remote Usage & Integration Guide**

Connect **EUDI‑compliant wallets** (e.g., **Talao**) to **AI agents** via the **Model Context Protocol (MCP)**.  
This hosted service exposes your OIDC4VP verifier as MCP tools using a **pull** model (no webhooks or callbacks).

- **Base URL**: [https://wallet-connectors.com](https://wallet-connectors.com) 
- **MCP RPC endpoint**: `POST https://wallet-connectors.com/mcp` 
- **Manifest**: [https://wallet-connectors.com/manifest.json](https://wallet-connectors.com/manifest.json)
- **Spec version**: MCP **2025‑06‑18** — uses `params.arguments`; returns `result.content` (blocks) + `result.structuredContent`.

> ✅ This README explains both **how to use** and **how to integrate** the Wallet Connectors MCP server with ChatGPT, VS Code, or your own clients.  
> No self‑hosting is required.

---

## 🚀 Quick Setup for MCP Clients

### 🧠 ChatGPT Desktop (Developer Preview)

1. Locate your config file:  
   `~/.config/openai/mcp/servers.json` (create if missing)

2. Add this block:

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

3. Restart ChatGPT → open *Settings → MCP Servers* → see **wallet‑connectors** appear.

### 🧩 VS Code MCP Extension

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

Then reload VS Code → open the MCP panel.

---

## 🔑 Authentication

Send your verifier key in a header on **every** call:
```
X-API-KEY: <YOUR_VERIFIER_KEY>
```

Use **0000** as `verifier_id` and `X-API-KEY` for demo/testing with [Talao wallet](https://talao.io).  
Other verifier profiles are available at [wallet‑connectors.com](https://wallet-connectors.com).

No cookies or OAuth are used.

---

## 🧩 Available Tools

| Tool | Purpose | Key arguments | Returns (`structuredContent`) |
|------|----------|---------------|-------------------------------|
| `start_wallet_verification` | Start an OIDC4VP flow and get a **deeplink** + **QR** | `verifier_id` (required), optional `scope`, `session_id`, `mode`, `presentation` | `session_id`, `deeplink_url`, `pull_url`, `public_base_url` |
| `poll_wallet_verification` | Poll verification status | `session_id` | `status` (`pending / verified / denied`), plus wallet claims (tokens redacted) |
| `revoke_wallet_flow` | Acknowledge cleanup for a session | `session_id` | `{ ok: true, session_id }` |

**Supported scopes:**  
`profile`, `email`, `phone`, `over18`, `wallet_identifier`, `custom`

Using `wallet_identifier` maps to **no scope** in the OIDC layer — produces an **ID‑token only** flow (wallet DID).

---

## 🧠 Scope → Returned Claims

| scope | Returned claims | Notes |
|---|---|---|
| `email` | `email_address`, `email` | Provided as **PID** (eIDAS v2 rulebook). |
| `phone` | `mobile_phone_number`, `phone` | Provided as **PID**. |
| `profile` | `family_name`, `given_name`, `birth_date` | OIDF standard scope. |
| `wallet_identifier` | `wallet_identifier` (wallet DID or public key thumbprint) | ID‑token only flow. |
| `over18` | `over_18` (boolean) or age‑attestation | Wallet‑dependent format. |
| `custom` | Defined by your Presentation Definition | Requires registration with your PEX/DCQL. |

---

## 🧪 Quick Start (curl)

List tools:
```bash
curl -s https://wallet-connectors.com/mcp   -H 'Content-Type: application/json'   -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq
```

Start a flow (demo mode, 0000):
```bash
curl -s https://wallet-connectors.com/mcp   -H 'Content-Type: application/json'   -H 'Accept: application/json'   -H 'X-API-KEY: 0000'   -d '{
    "jsonrpc":"2.0",
    "id":"start",
    "method":"tools/call",
    "params":{
      "name":"start_wallet_verification",
      "arguments":{"verifier_id":"0000","scope":"profile"}
    }
  }' | jq
```

Poll until verified:
```bash
curl -s https://wallet-connectors.com/mcp   -H 'Content-Type: application/json'   -H 'Accept: application/json'   -H 'X-API-KEY: 0000'   -d '{
    "jsonrpc":"2.0",
    "id":"poll",
    "method":"tools/call",
    "params":{
      "name":"poll_wallet_verification",
      "arguments":{"session_id":"<SESSION_ID_FROM_START>"}
    }
  }' | jq
```

---

## 🧩 Response Shapes (MCP 2025‑06‑18)

All tool results return:

```json
{
  "result": {
    "content": [ /* array of blocks (text/image/...) */ ],
    "structuredContent": { /* machine-readable JSON */ }
  }
}
```

### `start_wallet_verification` — example result
```json
{
  "result": {
    "content": [
      {"type":"image","data":"<base64-PNG>", "mimeType":"image/png"},
      {"type":"text","text":"Scan the QR or open: openid4vp://...?request_uri=..."}
    ],
    "structuredContent": {
      "session_id": "3e02ac7e-da66-4dd1-9abe-30348dcc728f",
      "deeplink_url": "openid4vp://...?request_uri=https://.../request_uri/abc",
      "pull_url": "https://wallet-connectors.com/verifier/wallet/pull/3e02...",
      "public_base_url": "https://wallet-connectors.com"
    }
  }
}
```

### `poll_wallet_verification` — example result
```json
{
  "result": {
    "content": [{ "type":"text","text":"{"status":"verified","session_id":"3e02..."}" }],
    "structuredContent": {
      "status": "verified",
      "session_id": "3e02ac7e-da66-4dd1-9abe-30348dcc728f",
      "scope": "profile",
      "wallet_identifier": "did:jwk:...",
      "first_name": "John",
      "last_name": "DOE"
    }
  }
}
```

> Claims may be **flattened** or nested under `wallet_data`.  
> Raw `vp_token` and `id_token` are **redacted**.

---

## 💻 Minimal Clients

### JavaScript (Browser)
```js
const mcpUrl = "https://wallet-connectors.com/mcp";
const apiKey = "<X-API-KEY>";

async function rpc(method, params) {
  const res = await fetch(mcpUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "X-API-KEY": apiKey
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
  });
  return res.json();
}

const start = await rpc("tools/call", {
  name: "start_wallet_verification",
  arguments: { verifier_id: "0000", scope: "profile" }
});
const flow = start.result.structuredContent;
console.log(flow.deeplink_url);

const poll = await rpc("tools/call", {
  name: "poll_wallet_verification",
  arguments: { session_id: flow.session_id }
});
console.log(poll.result.structuredContent.status);
```

### Python (requests)
```py
import requests, time

MCP = "https://wallet-connectors.com/mcp"
HDR = {"Content-Type":"application/json","Accept":"application/json","X-API-KEY":"0000"}

def rpc(method, params):
    body = {"jsonrpc":"2.0","id":"1","method":method,"params":params}
    return requests.post(MCP, headers=HDR, json=body, timeout=30).json()

start = rpc("tools/call", {"name":"start_wallet_verification","arguments":{"verifier_id":"0000","scope":"profile"}})
flow = start["result"]["structuredContent"]
print("deeplink:", flow["deeplink_url"], "session:", flow["session_id"])

while True:
    poll = rpc("tools/call", {"name":"poll_wallet_verification","arguments":{"session_id": flow["session_id"]}})
    status = poll["result"]["structuredContent"]["status"]
    print("status:", status)
    if status != "pending": break
    time.sleep(2)
```

---

## 🌐 Browser Clients & CORS

- Supports preflight (`OPTIONS /mcp`)
- Use `Accept: application/json` + `Content-Type: application/json`
- Call directly from any origin

---

## ⚠️ Error Handling

Two layers:

1️⃣ **JSON‑RPC errors** — top‑level:
```json
{"error":{"code":401,"message":"Missing or invalid X-API-KEY"}}
```
2️⃣ **Tool‑level errors** — inside `result`:
```json
{"result":{"isError":true,"structuredContent":{"error":"invalid_arguments","missing":["verifier_id"]}}}
```

Common messages: `401`, `400`, `upstream_error`, `network_error`

---

## 🔒 Privacy & Security

- Header‑only auth (`X-API-KEY`) — rotate regularly  
- `vp_token` / `id_token` are **redacted**  
- Implement polling backoff (1–2 s)

---

## 📈 Demos

- **Web QR demo** → renders QR & polls until verified → `examples/web-demo.html`
- **CLI demo** → runs full flow → `examples/demo.mjs`

---

## 🧰 Developer Resources

- `GET /mcp/info` → `{ name, version, protocolVersion, endpoints, auth }`
- `GET /mcp/healthz` → `{ ok: true }`
- Spec: [Model Context Protocol 2025‑06‑18](https://github.com/modelcontextprotocol/spec)
- Home: [https://wallet-connectors.com](https://wallet-connectors.com)

---

## 🗓️ Changelog

- **1.2.0** — Unified README with full examples & setup for ChatGPT + VS Code  
- **1.1.0** — Added quick‑install, helper clients, and demo scripts  
- **1.0.0** — Initial release, MCP 2025‑06‑18 compliance

---

**Maintainer:** [Talao DAO](https://github.com/TalaoDAO) • MIT License
