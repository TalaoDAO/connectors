# Getting Started with Wallet4Agent

Wallet4Agent allows you to provision a **trusted identity** and a **credential wallet** for any AI Agent.  
With it, your agent can authenticate, receive verifiable credentials, present proofs, and interact safely with users and services.

Wallet4Agent exposes its capabilities through a remote **MCP Server**, compatible with any MCP-enabled agent framework. DIDs creation (DNS based or blockchain based), VC issuers and verifiers are provided in minutes out of the box through tools.

---

# 1. 🚀 Overview

A typical flow:

1. A **Guest** (no auth) creates a new **Agent Identifier (DID)** and its associated **wallet**.  
2. The Guest receives:  
   - a **Admin Personal Access Token (admin_pat)**  
   - an **Agent Personal Access Token (agent_pat)** *or* OAuth2 client credentials  
3. Using the **Admin token**, the developer configures the agent (update configuration, rotate tokens, register authentication keys).  
4. Using the **Agent token**, the agent collects credentials, presents proofs, authenticates to others, and manages attestations.

All interactions happen through:

```
POST https://wallet4agent.com/mcp
```

---

# 2. 🧩 Roles and Authentication

## **2.1 Guest (no authentication)**  
A Guest can:

- Create a new Agent identity  
- Create its wallet  
- Retrieve initial Developer and Agent credentials  

## **2.2 Admin**  
Authenticated using:  
```
Authorization: Bearer <dev_personal_access_token>
```

An admin can:

- Manage configuration  
- Register OAuth client keys  
- Rotate the agent’s PAT  
- Create or update OASF  
- Delete the agent’s identity  
- Inspect wallet content  

## **2.3 Agent**  
Authenticated using:

- `Bearer <agent_personal_access_token>`
- OAuth2 Client Credentials Access Token  
- OAuth2 private_key_jwt Access Token  

---

# 3. 🆕 Creating an Agent Identity & Wallet (Guest)

Tool:

```
create_agent_identifier_and_wallet
```

Creates:

- **DID**
- **Wallet**
- **DID Document**
- **Owner registration**

Returns:

- Developer PAT  
- Agent PAT *or* OAuth credentials  
- Wallet URL  
- Agent Identifier (DID)

### Example

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "create_agent_identifier_and_wallet",
    "arguments": {
      "owners_identity_provider": "google",
      "owners_login": "someone@example.com",
      "did_method": "did:web",
      "mcp_client_authentication": "Personal Access Token (PAT)"
    }
  }
}
```

---

# 4. 🛠 Admin Tools

Authenticated with:

```
Authorization: Bearer <admin_pat>
```

## **4.1 get_configuration**

Returns agent metadata and DID doc.

## **4.2 update_configuration**

Used to:

- Set runtime metadata  
- Register JWK for OAuth private_key_jwt  
- Update agentcard URL  
- Update ecosystem_profile  

## **4.3 rotate_personal_access_token**

Rotates admin or agent PAT.

## **4.4 add_authentication_key**

Registers a new public JWK.

## **4.5 delete_identity**

Removes DID, wallet, attestations.

---

# 5. 🔐 Authentication Modes for the Agent

## **5.1 PAT**

```
Authorization: Bearer <agent_pat>
```

## **5.2 OAuth2 Client Credentials**

```
POST <authorization_server>/oauth/token
grant_type=client_credentials
client_id=<agent_did>
client_secret=<agent_client_secret>
resource=https://wallet4agent.com
```

## **5.3 OAuth2 private_key_jwt**

Agent signs a JWT assertion.  
Developer must register a `client_public_key`.

---

# 6. 🤖 Agent Tools

## **6.1 get_this_agent_data**  
Retrieve DID, wallet summary, attestations, config.

## **6.2 get_attestations_of_this_wallet**

Returns local attestations.

## **6.3 accept_credential_offer**

Supports JWT-VC, SD-JWT, JSON-LD.

```json
{
  "name": "accept_credential_offer",
  "arguments": { "credential_offer": "<offer>" }
}
```

---

# 7. 🔄 Interacting with Other Agents

## **7.1 get_attestations_of_another_agent**

Fetch public/published attestations.

Supports:

- JSON-LD VP  
- JWT VP  
- SD-JWT envelopes  
- EnvelopedVP  

## **7.2 start_agent_authentication**  
## **7.3 poll_agent_authentication**

OIDC4VP-based agent-to-agent authentication.

---

# 8. 👤 User Verification

## **start_user_verification**  
Sends email to user.

## **poll_user_verification**  
Returns:

- pending  
- verified  
- refused  
- expired  

---

# 9. ✍ Signing Tools

## **sign_text_message**

Signs raw text.

## **sign_json_payload**

Signs structured JSON.

---

# 10. 📦 OASF

Developer tool:

```
create_OASF
```

Creates or updates the agent's OASF metadata.

---

# 11. 📚 Complete Tool Reference

## Guest Tools
- create_agent_identifier_and_wallet  
- describe_wallet4agent  

## Admin Tools
- get_configuration  
- update_configuration  
- rotate_personal_access_token  
- add_authentication_key  
- get_attestations_of_this_wallet  
- create_OASF  
- delete_identity  

## Agent Tools
- get_this_agent_data  
- get_attestations_of_this_wallet  
- get_attestations_of_another_agent  
- accept_credential_offer  
- sign_text_message  
- sign_json_payload  
- start_user_verification  
- poll_user_verification  
- start_agent_authentication  
- poll_agent_authentication  
- help_wallet4agent
- publish_attestations
- unpublish_attestations

---

# 12. 🎯 Next Steps

- Browse use cases  
- Try the live demo agent  
- Connect your agent framework  
- Issue credentials from any OIDC4VCI or SD-JWT issuer  

Wallet4Agent lets your AI Agent evolve from a chat interface into a **trusted autonomous digital actor**.
