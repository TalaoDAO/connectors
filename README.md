
# MCP Server for Data Wallets — **Remote Usage Guide**

Connect **EUDI‑compliant wallets** (e.g., **Talao**) to **AI agents** via the **Model Context Protocol (MCP)**.  
This hosted service exposes your OIDC4VP verifier as MCP tools using a **pull** model (no webhooks).

- **Base URL**: `https://wallet-connectors.com`
- **MCP RPC endpoint**: `POST https://wallet-connectors.com/mcp`
- **Spec**: MCP **2025‑06‑18** — uses `params.arguments`; returns `result.content` (blocks) + `result.structuredContent`.

> This README explains **how to consume the remote service**. There are no self‑hosting or deployment steps here.

---

## Authentication

Send your verifier key in a header on **every** call:
```
X-API-KEY: <YOUR_VERIFIER_KEY>
```

Use **0000** as the verifier_id and verifier_key for testing purpose with Talao wallet `https://talao.io` 

No cookies or OAuth are used by this MCP endpoint.

---

## What you get (tools)

| Tool | Purpose | Key arguments | Returns (structuredContent) |
|---|---|---|---|
| `start_wallet_verification` | Start an OIDC4VP flow and get a **deeplink** + **QR** | `verifier_id` (required), optional `scope`, optional `session_id`, optional `mode`, optional `presentation` | `session_id`, `deeplink_url`, `pull_url`, `public_base_url` |
| `poll_wallet_verification` | Poll the flow status | `session_id` | `status` (`pending` \| `verified` \| `denied`), plus wallet claims (tokens redacted) |
| `revoke_wallet_flow` | Acknowledge cleanup for a session | `session_id` | `{ ok: true, session_id }` |

**Scopes** supported by `start_wallet_verification`:
- `profile`, `email`, `phone`, `over18`, `custom`, `wallet_identifier`
- Using `wallet_identifier` maps to **no scope** in the OIDC layer, producing an **ID‑token only** flow (wallet DID).

---

## Quick start (curl)

List tools:
```bash
curl -s https://wallet-connectors.com/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq
```

Start a flow:
```bash
curl -s https://wallet-connectors.com/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'X-API-KEY: <X-API-KEY>' \
  -d '{
    "jsonrpc":"2.0",
    "id":"start1",
    "method":"tools/call",
    "params":{
      "name":"start_wallet_verification",
      "arguments":{"verifier_id":"0000","scope":"profile"}
    }
  }' | jq
```

Use the `session_id` from the previous response to poll:
```bash
curl -s https://wallet-connectors.com/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'X-API-KEY: <X-API-KEY>' \
  -d '{
    "jsonrpc":"2.0",
    "id":"poll1",
    "method":"tools/call",
    "params":{
      "name":"poll_wallet_verification",
      "arguments":{"session_id":"<SESSION_ID_FROM_START>"}
    }
  }' | jq
```

---

## Response shapes (MCP 2025‑06‑18)

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
      {"type":"text", "text":"Scan the QR or open: openid4vp://...?request_uri=..."}
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

### `poll_wallet_verification` — example result (verified)
```json
{
  "result": {
    "content": [
      {"type":"text","text":"{\"status\":\"verified\",\"session_id\":\"3e02...\"}"}
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
> Claims may be **flattened** at the top level (as above) or nested under `wallet_data`. Raw `vp_token` / `id_token` are **redacted**.

---

## Minimal client snippets

### JavaScript (browser)
```js
const mcpUrl = "https://wallet-connectors.com/mcp";
const apiKey = "<X-API-KEY>";

// 1) start
const startBody = {
  jsonrpc: "2.0",
  id: "start",
  method: "tools/call",
  params: {
    name: "start_wallet_verification",
    arguments: { verifier_id: "0000", scope: "profile" }
  }
};
const startRes = await fetch(mcpUrl, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-API-KEY": apiKey
  },
  body: JSON.stringify(startBody)
}).then(r => r.json());
const flow = startRes?.result?.structuredContent;
console.log("deeplink:", flow.deeplink_url, "session:", flow.session_id);

// 2) poll
const pollBody = {
  jsonrpc: "2.0",
  id: "poll",
  method: "tools/call",
  params: {
    name: "poll_wallet_verification",
    arguments: { session_id: flow.session_id }
  }
};
const pollRes = await fetch(mcpUrl, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-API-KEY": apiKey
  },
  body: JSON.stringify(pollBody)
}).then(r => r.json());
const status = pollRes?.result?.structuredContent?.status;
console.log("status:", status);
```

### Python (requests)
```py
import requests, json

MCP = "https://wallet-connectors.com/mcp"
HDR = {"Content-Type": "application/json", "Accept": "application/json", "X-API-KEY": "<X-API-KEY>"}

def rpc(method, params, id="1"):
    body = {"jsonrpc":"2.0","id":id,"method":method,"params":params}
    r = requests.post(MCP, headers=HDR, json=body, timeout=30)
    r.raise_for_status()
    return r.json()

# start
start = rpc("tools/call", {"name":"start_wallet_verification","arguments":{"verifier_id":"0000","scope":"profile"}}, id="start")
flow = start["result"]["structuredContent"]
print("deeplink:", flow["deeplink_url"], "session:", flow["session_id"])

# poll
poll = rpc("tools/call", {"name":"poll_wallet_verification","arguments":{"session_id": flow["session_id"]}}, id="poll")
print("status:", poll["result"]["structuredContent"]["status"])
```

### Node (fetch)
```js
import fetch from "node-fetch";

const MCP = "https://wallet-connectors.com/mcp";
const HDR = { "Content-Type":"application/json", "Accept":"application/json", "X-API-KEY":"<X-API-KEY>" };

const rpc = async (method, params, id="1") => {
  const res = await fetch(MCP, { method:"POST", headers:HDR, body: JSON.stringify({ jsonrpc:"2.0", id, method, params }) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
};

const start = await rpc("tools/call", { name:"start_wallet_verification", arguments:{ verifier_id:"0000", scope:"profile" } }, "start");
const flow  = start.result.structuredContent;
const poll  = await rpc("tools/call", { name:"poll_wallet_verification", arguments:{ session_id: flow.session_id } }, "poll");
console.log("status:", poll.result.structuredContent.status);
```

---

## Browser clients & CORS

- The service supports browser **preflight** (`OPTIONS /mcp`) and returns permissive headers.
- Always include `Accept: application/json` and `Content-Type: application/json`.
- You can host your page anywhere; just call `https://wallet-connectors.com/mcp` with the API key header.

---

## Error handling

There are **two** error layers:

1) **JSON‑RPC errors** (top‑level `error`):
```json
{
  "jsonrpc": "2.0",
  "id": "poll",
  "error": { "code": 401, "message": "Missing or invalid X-API-KEY" }
}
```

2) **Tool‑level errors** (successful JSON‑RPC with `result.isError: true`):
```json
{
  "jsonrpc": "2.0",
  "id": "start",
  "result": {
    "isError": true,
    "content": [{ "type":"text","text":"verifier_id is required" }],
    "structuredContent": { "error":"invalid_arguments","missing":["verifier_id"] }
  }
}
```

**Common codes/messages**
- `401` missing/invalid API key
- `400` invalid arguments (e.g., missing `verifier_id` or `session_id`)
- `upstream_error` when the verifier API returns a 4xx/5xx
- `network_error` if the upstream call fails

---

## End‑to‑end flow at a glance

```
Agent → /mcp tools/call start_wallet_verification
          ↳ structuredContent: session_id + deeplink_url + pull_url + QR image block

User  → scans QR / opens deeplink in wallet and approves

Agent → /mcp tools/call poll_wallet_verification (repeat until status != pending)
          ↳ structuredContent: { status: verified | denied, claims... }
```

---

## Privacy & security

- No cookies; header‑based auth only (`X-API-KEY`).
- `vp_token` / `id_token` are redacted from MCP responses.
- Keep your API key secret; rotate if you suspect exposure.
- Implement client‑side backoff when polling (`1–2s`) to respect rate limits.

---

## Metadata endpoints

- `GET https://wallet-connectors.com/mcp/info` → `{ name, version, protocolVersion, endpoints, auth }`
- `GET https://wallet-connectors.com/mcp/healthz` → `{ ok: true }`

---

## Changelog (surface)

- **0.2.0** — MCP 2025‑06‑18 compliance; `params.arguments`; `content[]` + `structuredContent`; QR as image block; token redaction.
