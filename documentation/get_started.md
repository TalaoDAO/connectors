# Wallet4Agent — **Getting Started from Zero to Agent**

Spin up a **brand-new Agent identity + wallet**, configure it as a **developer**, and plug your Agent to the MCP server using **PAT** or **OAuth 2.0 Client Credentials** (including `private_key_jwt` with JWK keys).

- **Base URL:** `https://wallet4agent.com`
- **MCP RPC endpoint:** `POST https://wallet4agent.com/mcp`
- **Spec version:** MCP **2025-06-18** (`params.arguments`, `result.content[]`, `result.structuredContent`)
- **Identity model:** `did:web` for agents, backed by a Wallet4Agent DID Document + credentials

> This guide explains: how to start from nothing, how to access as a **developer**, and how to define the **client authentication method** for your Agent.

---

## 🧭 1. Mental model

There are **three roles**:

1. **Guest**  
   - No auth header.  
   - Can bootstrap a new Agent identity + wallet.

2. **Developer (Dev)**  
   - Uses a `dev_personal_access_token`.  
   - Manages configuration, tokens, keys, lifecycle of the Agent wallet.

3. **Agent**  
   - Uses either:
     - an **Agent Personal Access Token (PAT)**, or  
     - an **OAuth 2.0 access token** (Client Credentials flow, secret or `private_key_jwt`).  
   - Calls Agent-level tools (read wallet data, accept credential offers, etc.).

All three talk to the same **MCP endpoint**:

```text
POST https://wallet4agent.com/mcp
Content-Type: application/json
```

---

## 🚀 2. Zero → Agent in one call (Guest)

As a **guest** (no auth header), call the tool:

- `create_agent_identifier_and_wallet`

This will:

- Create a **new Agent DID** (`did:web:wallet4agent.com:<id>`).
- Create a **wallet entry** for that Agent.
- Attach it to one or more **owners** (human/organization) via:
  - `owners_identity_provider` (e.g. `google`, `github`, `personal data wallet`)
  - `owners_login` (email or username list)
- Generate:
  - a **developer PAT**: `dev_personal_access_token`
  - and, depending on `authentication`:
    - an **agent PAT**, or
    - a pair of **OAuth client credentials** + AS URL.

### 2.1 Request (no Authorization header)

```bash
curl -s https://wallet4agent.com/mcp   -H "Content-Type: application/json"   -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "create_agent_identifier_and_wallet",
      "arguments": {
        "owners_identity_provider": "google",        // or "github", "personal data wallet"
        "owners_login": "dev@example.com",           // comma-separated list if multiple
        "authentication": "Personal Access Token (PAT)" 
        // or: "OAuth 2.0 Client Credentials Grant"
      }
    }
  }'
```

### 2.2 Typical response (excerpt)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "New agent identifier and wallet created. Copy agent personal access token and dev personal access token as they are not stored."
      }
    ],
    "structuredContent": {
      "agent_identifier": "did:web:wallet4agent.com:<id>",
      "wallet_url": "https://wallet4agent.com/did/<id>",
      "dev_personal_access_token": "<dev_pat>",

      // If authentication = "Personal Access Token (PAT)":
      "agent_personal_access_token": "<agent_pat>"

      // If authentication = "OAuth 2.0 Client Credentials Grant":
      // "agent_client_id": "did:web:wallet4agent.com:<id>",
      // "agent_client_secret": "<agent_client_secret>",
      // "authorization_server": "https://wallet4agent.com"
    }
  }
}
```

> ✅ **Important:** copy `dev_personal_access_token` (and `agent_personal_access_token` / `agent_client_secret` if present).  
> They are **not stored in clear text** and cannot be retrieved later.

---

## 👨‍💻 3. Acting as a Developer (Dev PAT)

From now on, you act as “**Dev for this Agent**” using:

- `Authorization: Bearer <dev_personal_access_token>`

You can:

- Inspect configuration: `get_configuration`
- Update configuration: `update_configuration`
- Rotate tokens: `rotate_personal_access_token`
- Manage keys for OAuth: `add_authentication_key`
- Inspect attestations: `get_attestations_of_this_wallet`
- Delete the identity: `delete_identity`

### 3.1 Dev header

```bash
export DEV_PAT="<dev_personal_access_token>"
```

Every dev call:

```bash
-H "Authorization: Bearer $DEV_PAT"
```

### 3.2 Get configuration

```bash
curl -s https://wallet4agent.com/mcp   -H "Content-Type: application/json"   -H "Authorization: Bearer $DEV_PAT"   -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "get_configuration",
      "arguments": {}
    }
  }' | jq
```

`structuredContent` will show (depending on implementation):

- `agent_identifier`
- `wallet_url`
- `mcp_authentication` (current mode: PAT vs OAuth2)
- `ecosystem_profile`, `agent_framework`, ...
- `always_human_in_the_loop`
- Possibly `client_public_key` if already configured.

---

## 🔐 4. Choosing the Agent’s client authentication method

You can choose between:

1. **Agent PAT**  
   - Simple: Agent uses a `Bearer` token to call MCP.
   - Best for prototypes, single environment.

2. **OAuth 2.0 Client Credentials**  
   - Agent identified by `client_id` (Agent DID) + `client_secret` or `private_key_jwt`.
   - Best for production deployments and integration with Authorisation Server policies.

You already chose a **default** mode when calling `create_agent_identifier_and_wallet` (`authentication` argument).

As a dev, you can refine things with:

- `update_configuration`
- `rotate_personal_access_token`
- `add_authentication_key`

---

## 🔑 5. Option A — Agent PAT only

If you selected:

```json
"authentication": "Personal Access Token (PAT)"
```

you received:

- `agent_personal_access_token`

The Agent simply calls MCP like this:

```bash
export AGENT_PAT="<agent_personal_access_token>"
```

```bash
curl -s https://wallet4agent.com/mcp   -H "Content-Type: application/json"   -H "Authorization: Bearer $AGENT_PAT"   -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "get_this_wallet_data",
      "arguments": {}
    }
  }'
```

> Agent-level tools include:
> - `get_this_wallet_data`
> - `get_attestations_of_this_wallet`
> - `get_attestations_of_another_agent`
> - `accept_credential_offer`

If you need a new PAT (compromise, rotation):

```bash
curl -s https://wallet4agent.com/mcp   -H "Content-Type: application/json"   -H "Authorization: Bearer $DEV_PAT"   -d '{
    "jsonrpc": "2.0",
    "id": "rot",
    "method": "tools/call",
    "params": {
      "name": "rotate_personal_access_token",
      "arguments": {
        "for": "agent"   // or "dev"
      }
    }
  }'
```

Response will include the **new** PAT in `structuredContent` — copy it immediately.

---

## 🧾 6. Option B — OAuth 2.0 Client Credentials

If you selected:

```json
"authentication": "OAuth 2.0 Client Credentials Grant"
```

`create_agent_identifier_and_wallet` returns:

- `agent_client_id` = Agent DID (`did:web:wallet4agent.com:<id>`)
- `agent_client_secret`
- `authorization_server` (AS base URL for discovery)

### 6.1 Get an access token (client_secret_basic / client_secret_post)

**Discover token endpoint** from the AS URL (example):

```bash
export AS_BASE="https://wallet4agent.com"
curl -s $AS_BASE/.well-known/openid-configuration | jq '.token_endpoint'
# -> "https://wallet4agent.com/oauth/token"   (example)
```

#### client_secret_post

```bash
export CLIENT_ID="did:web:wallet4agent.com:<id>"
export CLIENT_SECRET="<agent_client_secret>"
export TOKEN_ENDPOINT="https://wallet4agent.com/oauth/token"
export RESOURCE="https://wallet4agent.com"

curl -s $TOKEN_ENDPOINT   -d "grant_type=client_credentials"   -d "client_id=$CLIENT_ID"   -d "client_secret=$CLIENT_SECRET"   -d "resource=$RESOURCE" | jq
```

#### client_secret_basic

```bash
curl -s $TOKEN_ENDPOINT   -u "$CLIENT_ID:$CLIENT_SECRET"   -d "grant_type=client_credentials"   -d "resource=$RESOURCE" | jq
```

Typical response:

```json
{
  "access_token": "<agent_access_token>",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

### 6.2 Use the access token with MCP

```bash
export AGENT_ACCESS_TOKEN="<agent_access_token>"

curl -s https://wallet4agent.com/mcp   -H "Content-Type: application/json"   -H "Authorization: Bearer $AGENT_ACCESS_TOKEN"   -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "get_this_wallet_data",
      "arguments": {}
    }
  }'
```

---

## 🔏 7. Option C — OAuth 2.0 with `private_key_jwt` (JWK)

For stronger security, the Agent can authenticate to the AS using a **JWK public key** and `private_key_jwt`:

1. The Agent holds a **private JWK** (P-256 / `ES256`).
2. As a dev, you register the **public JWK** in Wallet4Agent via `update_configuration`.
3. The Agent obtains access tokens using Client Credentials + `client_assertion` JWT.

### 7.1 Dev: register the public JWK

Assume you have:

```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "...",
  "y": "..."
}
```

Call:

```bash
curl -s https://wallet4agent.com/mcp   -H "Content-Type: application/json"   -H "Authorization: Bearer $DEV_PAT"   -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "update_configuration",
      "arguments": {
        "client_public_key": "{ "kty":"EC", "crv":"P-256", "x":"...", "y":"..." }"
      }
    }
  }' | jq
```

Wallet4Agent stores this in the wallet (e.g. `client_public_key`) and the Authorization Server uses it to verify `client_assertion` JWTs.

### 7.2 Agent: obtain token with `private_key_jwt`

High-level flow:

1. Agent builds a JWT:
   - `iss` = `CLIENT_ID` (Agent DID)  
   - `sub` = `CLIENT_ID`  
   - `aud` = token endpoint URL (`https://wallet4agent.com/oauth/token`)  
   - signed with its **private JWK** (`ES256`).

2. Agent calls the token endpoint:

```bash
curl -s $TOKEN_ENDPOINT   -d "grant_type=client_credentials"   -d "resource=$RESOURCE"   -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"   -d "client_assertion=<signed_jwt>" | jq
```

3. Response:

```json
{
  "access_token": "<agent_access_token>",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

4. The Agent then uses `Authorization: Bearer <agent_access_token>` on MCP just like in 6.2.

---

## 🛠 8. Tool overview by role

**Guest tools**

- `describe_wallet4agent`  
- `create_agent_identifier_and_wallet`

**Developer tools** (requires `dev_personal_access_token`)

- `get_configuration`
- `update_configuration`
- `rotate_personal_access_token`
- `add_authentication_key`
- `get_attestations_of_this_wallet`
- `delete_identity`

**Agent tools** (Agent PAT or OAuth2 access token)

- `get_this_wallet_data`
- `get_attestations_of_this_wallet`
- `get_attestations_of_another_agent`
- `accept_credential_offer`

---

## 🔎 9. MCP configuration examples (ChatGPT / VS Code)

### 9.1 ChatGPT Desktop (HTTP MCP)

`~/.config/openai/mcp/servers.json`:

```json
{
  "wallet4agent": {
    "transport": {
      "type": "http",
      "url": "https://wallet4agent.com/mcp"
    }
  }
}
```

- As **guest**, call `create_agent_identifier_and_wallet`.  
- Once you have `dev_personal_access_token`, you can configure headers in your MCP client
  to include `Authorization: Bearer <dev_pat>` for dev tools (details depend on the MCP host).

### 9.2 VS Code MCP

`.vscode/mcp.json`:

```json
{
  "servers": {
    "wallet4agent": {
      "transport": {
        "type": "http",
        "url": "https://wallet4agent.com/mcp"
      }
    }
  }
}
```

Then use the MCP panel to:

- Discover tools.
- Call `create_agent_identifier_and_wallet` as guest.
- Copy `dev_personal_access_token` / Agent credentials.
- Reconfigure with auth headers where supported.

---

## 🧰 10. Troubleshooting & tips

- **I lost my PAT / client_secret**  
  - You cannot read secrets back. As Dev, call `rotate_personal_access_token` for a new PAT.  
  - For client credentials, generate a new `client_secret` and update your Agent config.

- **401 from MCP**  
  - Check `Authorization` header:
    - Dev calls → `Bearer <dev_personal_access_token>`  
    - Agent calls → `Bearer <agent_personal_access_token>` or OAuth access token.

- **401 from token endpoint (`invalid_client` / `invalid_client_credentials`)**  
  - For `client_secret_basic`: ensure Basic auth uses full DID (`did:web:...`) and secret.  
  - For `client_secret_post`: check `client_id`, `client_secret`, and `resource`.  
  - For `private_key_jwt`: verify that:
    - `client_public_key` matches the private JWK,  
    - `iss == sub == client_id`,  
    - `aud` equals the token endpoint,  
    - `exp` is in the future.

- **Which mode should I use?**
  - **Just testing:** Agent PAT is simplest.  
  - **Production / multi-tenant:** OAuth2 Client Credentials with either secret or `private_key_jwt`.

---

**Maintainer:** [Talao DAO](https://github.com/TalaoDAO) • MCP Wallet4Agent  
Issues / feedback: via the contact form linked on the home page.
