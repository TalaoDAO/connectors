
# MCP Server for Wallet Data Verification

**Audience:** developers building AI agents that need to authenticate a user with their **data wallet** (EUDI-compatible, e.g., Talao) using **MCP** + **OIDC4VP** (pull model).

This guide shows how to:
- Start a verification flow (get QR + deeplink)
- Poll for status and retrieve wallet claims
- Test with predefined **verifier profiles** (no signup required)
- Understand responses & handle errors

> **Base URL:** `https://wallet-connectors.com`  
> **MCP endpoint:** `POST https://wallet-connectors.com/mcp`  
> **Spec:** MCP **2025-06-18** (`params.arguments`, `result.content[]`, `result.structuredContent`)

---

## 1) Test Profiles (ready to use)

| `verifier_id` | Target wallets / draft | Verifier identity scheme | Notes | **X-API-KEY** |
|---|---|---|---|---|
| `0000` | OIDC4VP **Draft 20** (e.g., **DIIP v3**) | Redirect-URI | Classic flow; good baseline for Draft 20 wallets | `0000` |
| `0001` | OIDC4VP **Draft 20** | **DID** (decentralized identifier) | Same as 0000 but verifier identifies via DID | `0001` |
| `0002` | OIDC4VP **Draft 25** | **DID** | For wallets targeting Draft 25 | `0002` |

> **API key = verifier_id** for these public test profiles.  
> To design your **own wallet profile** (custom draft/scheme) or your **own Presentation Definition** (request more than email/phone/etc.), you must **register** to obtain a dedicated verifier and key.

---

## 2) Tools (MCP)

- **`start_wallet_verification`**  
  Create an OIDC4VP authorization request. Returns:
  - `content[]` → human blocks (QR image, helper text)
  - `structuredContent` → machine JSON (`session_id`, `deeplink_url`, `pull_url`, …)

- **`poll_wallet_verification`**  
  Check status for a `session_id`. Returns:
  - `structuredContent.status` in `{ "pending", "verified", "denied" }`
  - Wallet data/claims (tokens are **redacted**)

- **`revoke_wallet_flow`**  
  Acknowledge cleanup (useful for UIs). Backend TTL handles actual expiry.

**Common arguments**

- `verifier_id` (required for `start_wallet_verification`) → one of `0000, 0001, 0002` (or your own)
- `scope` (optional) → one of `profile`, `email`, `phone`, `over18`, `custom`, `wallet_identifier`  
  - `wallet_identifier` maps to **no scope** (ID-token only; returns the wallet DID)
- `session_id` (optional on start; server can generate; required for poll)

---

## 3) Quick Start (curl)

**List tools**
```bash
curl -s https://wallet-connectors.com/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq
```

**Start (Draft 20, redirect-URI)**
```bash
curl -s https://wallet-connectors.com/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'X-API-KEY: 0000' \
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

**Start (Draft 20 with DID)**
```bash
curl -s https://wallet-connectors.com/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'X-API-KEY: 0001' \
  -d '{
    "jsonrpc":"2.0",
    "id":"start2",
    "method":"tools/call",
    "params":{
      "name":"start_wallet_verification",
      "arguments":{"verifier_id":"0001","scope":"profile"}
    }
  }' | jq
```

**Start (Draft 25 with DID)**
```bash
curl -s https://wallet-connectors.com/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'X-API-KEY: 0002' \
  -d '{
    "jsonrpc":"2.0",
    "id":"start3",
    "method":"tools/call",
    "params":{
      "name":"start_wallet_verification",
      "arguments":{"verifier_id":"0002","scope":"profile"}
    }
  }' | jq
```

The response includes:
- `result.content[]` → first item may be an `image` block (QR, base64 PNG), plus a text hint
- `result.structuredContent.session_id` → use this to poll
- `result.structuredContent.deeplink_url` → `openid4vp://…` (you can also display it)

**Poll**
```bash
curl -s https://wallet-connectors.com/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'X-API-KEY: 0000' \
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
- `structuredContent.status` becomes `verified` (or `denied`) when the user approves/rejects in their wallet.
- Claims appear alongside the status (tokens are redacted).

---

## 4) Minimal Client Snippets

### JavaScript (browser)
```js
const MCP = "https://wallet-connectors.com/mcp";
const KEY = "0000"; // or 0001 / 0002

const rpc = async (method, params, id) => {
  const res = await fetch(MCP, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "X-API-KEY": KEY
    },
    body: JSON.stringify({ jsonrpc:"2.0", id, method, params })
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
};

// 1) start
const start = await rpc("tools/call", {
  name: "start_wallet_verification",
  arguments: { verifier_id: "0000", scope: "profile" }
}, "start");

const flow = start.result.structuredContent;
console.log(flow.deeplink_url, flow.session_id);

// 2) poll (repeat with backoff until status !== pending)
const poll = await rpc("tools/call", {
  name: "poll_wallet_verification",
  arguments: { session_id: flow.session_id }
}, "poll");

console.log(poll.result.structuredContent.status);
```

### Python (requests)
```py
import requests, time

MCP = "https://wallet-connectors.com/mcp"
HDR = {"Content-Type":"application/json","Accept":"application/json","X-API-KEY":"0002"}  # pick your profile

def rpc(method, params, id="1"):
    r = requests.post(MCP, headers=HDR, json={"jsonrpc":"2.0","id":id,"method":method,"params":params}, timeout=30)
    r.raise_for_status()
    return r.json()

start = rpc("tools/call", {"name":"start_wallet_verification","arguments":{"verifier_id":"0002","scope":"profile"}}, "start")
sid = start["result"]["structuredContent"]["session_id"]

while True:
    poll = rpc("tools/call", {"name":"poll_wallet_verification","arguments":{"session_id": sid}}, "poll")
    status = poll["result"]["structuredContent"].get("status","pending")
    print("status:", status)
    if status != "pending": break
    time.sleep(1.5)
```

---

## 5) Response Anatomy

All tool results (MCP 2025-06-18):
```json
{
  "result": {
    "content": [ /* blocks: image/text/... */ ],
    "structuredContent": { /* machine JSON */ }
  }
}
```

**Start → structuredContent**
```json
{
  "session_id": "3e02ac7e-da66-4dd1-9abe-30348dcc728f",
  "deeplink_url": "openid4vp://...?request_uri=...",
  "pull_url": "https://wallet-connectors.com/verifier/wallet/pull/3e02...",
  "public_base_url": "https://wallet-connectors.com"
}
```

**Poll → structuredContent**
```json
{
  "status": "verified",
  "session_id": "3e02ac7e-...",
  "scope": "profile",
  "wallet_identifier": "did:jwk:...",   // if wallet_identifier / ID-token flow
  "first_name": "John",
  "last_name": "DOE"
  // tokens like "vp_token"/"id_token" are redacted if present
}
```

> Some wallets return claims flattened at the top level; older flows may put them under `wallet_data`. The server accepts both; your agent should read `result.structuredContent`.

---

## 6) Best Practices

- **Polling backoff:** 1–2 seconds between polls until `status !== "pending"`.
- **Scopes:** request only what you need (`profile`, `email`, `phone`, `over18`, `custom`, or `wallet_identifier` for DID only).
- **Images:** the QR comes as a base64 PNG in `content[]` → `type: "image"`.
- **Security:** never log raw tokens; they’re redacted in responses by default.
- **CORS:** browser clients are supported; service responds to preflight (`OPTIONS /mcp`).

---

## 7) Register to customize

Public test profiles (`0000/0001/0002`) are for **evaluation**.  
To:
- Define **your own wallet profile** (different draft, verifier identity scheme, response mode),
- Provide a **custom Presentation Definition** (PEX/DCQL) to request additional claims beyond email/phone,

please **register** to obtain a dedicated `verifier_id` and `X-API-KEY`.

---

## 8) Troubleshooting

- **`401 Missing X-API-KEY`** → send header; the key must match the `verifier_id` (for public profiles).
- **Stuck on `pending`** → user hasn’t approved; verify wallet supports the chosen draft/scheme, and that you’re polling the correct `session_id`.
- **CORS errors (browser)** → call `https://wallet-connectors.com/mcp` with `Content-Type`, `Accept`, and `X-API-KEY`.
- **Tool error vs RPC error**  
  - RPC error: top-level `"error": {...}`  
  - Tool error: `"result.isError": true` with `result.structuredContent.error`
