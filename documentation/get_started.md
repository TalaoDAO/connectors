# Getting Started with Wallet4Agent

Wallet4Agent allows you to provision **trusted identity** and **credential wallets** for AI Agents — aligned with the EUDI Wallet architecture.  
Your agents can authenticate, receive verifiable credentials, present proofs, and act **On‑Behalf‑Of** humans or companies.

All capabilities are exposed through a remote **MCP Server** compatible with any MCP‑enabled agent framework.

---

# 1. 🚀 Overview

A typical flow:

1. A **Developer** creates **one account** as either:
   - a **Human** (personal developer), or  
   - a **Company** (organization controlling agents).  
   This creates a DID and a base wallet.

2. Using this **Human or Company account**, the developer connects to the **Wallet4Agent MCP Server**.

3. Through MCP, the developer creates **one or more Agent wallets** (each with its own DID and wallet).

4. For each Agent, the developer receives:
   - an **Admin Personal Access Token (admin_pat)**  
   - an **Agent Personal Access Token (agent_pat)** *or* OAuth2 client credentials  

5. Using the **Admin token**, the developer configures each agent (keys, ecosystem, OBO, publishing rules).

6. Using the **Agent token**, the agent receives credentials, authenticates, signs data, presents proofs, and interacts with users and other agents.

All interactions happen through:

```
POST https://wallet4agent.com/mcp
```

You can create **as many Agent wallets as you want** under the same Human or Company account.

---

# 2. 🧩 Roles and Authentication

## **2.1 Developer (Human or Company account)**  
Created with:

```
create_account
```

A developer account:
- Owns all Agent wallets
- Receives notifications
- Issues On‑Behalf‑Of delegations
- Controls wallet policies

This account has a DID and wallet like any EUDI‑style identity.

---

## **2.2 Admin (per Agent)**  
Authenticated using:

```
Authorization: Bearer <admin_personal_access_token>
```

An Admin can:
- Configure the Agent wallet
- Register OAuth keys
- Rotate tokens
- Set ecosystem (DIIP, EWC, ARF…)
- Set AgentCard
- Delete the Agent wallet
- Inspect attestations

Each Agent has its **own Admin token**.

---

## **2.3 Agent**  
Authenticated using:
- `Bearer <agent_personal_access_token>`
- OAuth2 Client Credentials
- OAuth2 private_key_jwt

The Agent:
- Receives credentials
- Publishes Linked VPs
- Signs messages
- Authenticates to other agents
- Verifies users
- Acts On‑Behalf‑Of its owner

---

# 3. 🧑‍💼 Create a Human or Company Account

Tool:

```
create_account
```

Creates:
- A DID
- A wallet
- An owner identity (Human or Company)

Example:

```json
{
  "name": "create_account",
  "arguments": {
    "account_type": "company",
    "notification_email": "dev@mycompany.com",
    "did_method": "did:web"
  }
}
```

You now have:
- A **Company DID**
- A **Company wallet**
- The right to create and control Agents

---

# 4. 🤖 Creating Agent Wallets

Authenticated as your **Human or Company account**.

Tool:

```
create_agent_identifier_and_wallet
```

Creates:
- An Agent DID
- An Agent wallet
- DID Document
- MCP credentials

Returns:
- Agent DID
- Wallet URL
- Admin PAT
- Agent PAT or OAuth credentials

You can repeat this **as many times as you want**.

---

# 5. 🛠 Admin Tools

Authenticated with:

```
Authorization: Bearer <admin_pat>
```

## get_account_configuration  
Returns owner (Human/Company) wallet data.

## get_wallet_configuration  
Returns configuration of one Agent wallet.

## update_configuration  
Configure:
- Ecosystem profile
- AgentCard
- OAuth keys
- Human‑in‑the‑loop rules

## delete_wallet  
Deletes the Agent wallet and all its credentials.

---

# 6. 🔐 Agent Authentication Modes

## PAT

```
Authorization: Bearer <agent_pat>
```

## OAuth2 Client Credentials

```
POST /oauth/token
grant_type=client_credentials
client_id=<agent_did>
client_secret=<agent_secret>
```

## OAuth2 private_key_jwt

Agent signs a JWT with a registered public key.

---

# 7. 🎫 Agent Wallet Capabilities

Agents can:

- Accept credentials
- Store them
- Publish Linked VPs
- Resolve other agents
- Authenticate
- Sign data
- Verify users

Tools include:
- accept_credential_offer  
- get_attestations_of_this_wallet  
- publish_attestation  
- unpublish_attestation  
- resolve_agent_identifier  

---

# 8. 🔄 Agent‑to‑Agent Trust

Agents authenticate using **OIDC4VP**.

Tools:
- start_agent_authentication  
- poll_agent_authentication  

This provides cryptographic proof of the other agent’s DID, keys, and published claims.

---

# 9. 👤 User Verification

Agents can verify humans by email‑based wallet flows.

Tools:
- start_user_verification  
- poll_user_verification  

Supports:
- Profile verification
- Over‑18 proof

---

# 10. ✍ Cryptographic Signing

Agents can sign:

- Raw text
- JSON payloads

Tools:
- sign_text_message  
- sign_json_payload  

This proves the Agent controls its DID keys.

---

# 11. 📦 On‑Behalf‑Of (OBO) Delegation

The **Human or Company** can issue **mandates** to Agents:

```
issue_OBO
```

This creates a Verifiable Credential that says:

> “This Agent is authorized to perform task X on my behalf until time Y.”

This is the legal and cryptographic foundation of delegated AI action.

---

# 12. 🎯 Next Steps

- Create your Human or Company account  
- Connect it to MCP  
- Create Agent wallets  
- Issue OBO mandates  
- Attach credentials  
- Go live with trusted AI agents
