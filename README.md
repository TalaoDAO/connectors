# 🏗️ Wallet4Agent — Technical Stack Overview  
### **For developers building trusted AI Agents able to interact with persons, companies, services, and other agents**  

Wallet4Agent provides the **trust layer** that AI Agents need to operate safely in the real world.  
This document explains the technical components, standards, and identity mechanisms behind the platform.

---

# 1. 🎯 Purpose of Wallet4Agent

AI Agents increasingly take actions, access data, and collaborate.  
To do this safely, they must be able to:

- 🆔 Prove **who they are**
- 👤 Prove **who owns or controls them**
- 📄 Hold **verifiable credentials**
- 🔐 Sign actions and data securely
- 🔗 Trust **users**, **companies**, and **other agents**
- 🪪 Authenticate to external systems without fragile API keys

Wallet4Agent provides AI Agents with:

- **A DID-based identity**
- **A secure wallet for credentials**
- **Cloud KMS-backed signing keys**
- **Interoperability with OIDC4VCI, OIDC4VP, SD‑JWT, JSON-LD, OAuth2**
- **An MCP server interface for agents**

Everything is standards‑based and interoperable.

---

# 2. 🧱 Architecture Overview

Wallet4Agent is built with three coordinated layers:

## 2.1 🖥️ MCP Server (Model Context Protocol)
- Single endpoint:  
  `POST https://wallet4agent.com/mcp`
- Exposes all operations as **tools**:
  - Identity creation
  - Credential issuance
  - Verification flows
  - Signing operations
  - Configuration

## 2.2 👛 Identity Wallet
Manages:

- The Agent’s DID & DID Document  
- Stored credentials (SD‑JWT VC, VC JSON‑LD)  
- Linked Verifiable Presentations  
- Wallet metadata & service endpoints  

## 2.3 🔐 Authorization & Verification Layer
Supports:

- OAuth2 access tokens
- OIDC4VCI (credential issuance)
- OIDC4VP (presentation)
- User verification flows
- Agent‑to‑Agent authentication

All complex cryptographic and identity logic stays in Wallet4Agent.  
Your agent simply calls MCP tools.

---

# 3. 🆔 Identity Layer (DID & DID Documents)

Each AI Agent receives a **Decentralized Identifier (DID)** compliant with the W3C DID Core specification.

Wallet4Agent supports **two DID methods**:

---

## **3.1 🌐 did:web (DNS-based identity)**  
A DID anchored on a domain.

```
did:web:wallet4agent.com:<agent-id>
```

⭐ Characteristics:

- Easy to resolve using HTTPS  
- DID Document lives at:  
  `https://wallet4agent.com/did/<agent-id>`  
- Perfect for SaaS agents  
- Human-readable, infrastructure-friendly  
- Works well for corporate or platform-linked AI agents  

🔗 DID:web specification:  
https://www.w3.org/TR/did-spec-registries/#did-method-web

---

## **3.2 ⛓️ did:cheqd (ledger-based identity)**  
A DID anchored on the **Cheqd decentralized ledger**.

```
did:cheqd:<network>:<identifier>
```

⭐ Characteristics:

- Tamper-resistant DID Document stored on-ledger  
- Supports **ledger-anchored keys**, rotations, service endpoints  
- Ideal for:
  - High-assurance identity
  - Regulated environments
  - Trust registries
  - Decentralized compliance ecosystems  

🔗 DID:cheqd specification:  
https://docs.cheqd.io/identity/

---

# 4. 📄 DID Documents

Regardless of DID method, the DID Document exposes:

- 🔑 Public keys  
- 🔐 Authentication methods  
- 📌 Service endpoints  
- 🧾 Linked Verifiable Presentations  
- 🧬 Key types (JWK, Ed25519, etc.)  

DID Documents are **automatically updated** when:

- Keys rotate  
- New developer or agent keys are registered  
- Credentials are published as Linked VPs  
- Authentication methods change  

External agents and services use the DID Document to verify signatures, credentials, and linked proofs.

---

# 5. 🔗 Linked Verifiable Presentations (Linked VP)

Linked VP allows Wallet4Agent to **publish verifiable credentials inside the DID Document** as references.

Why this matters:

- Public credentials become discoverable  
- Third parties can verify agent capabilities  
- Useful for:
  - Corporate mandates
  - Agent capabilities
  - Service trust signals
  - Compliance proofs  

Supported formats:

- 🟦 SD‑JWT VC  
- 🟩 JWT‑VC / JWT‑VP  
- 🟪 JSON‑LD VC / VP  

Specification:  
https://identity.foundation/linked-vp/spec/v1.0.0/

---

# 6. 🔐 Cryptography & Key Management

## 6.1 🗝️ Cloud KMS–backed keys (non-exportable)
Each agent has a dedicated **cloud KMS key**.

Used for:

- Signing Verifiable Presentations  
- Proofs of key ownership in OIDC4VCI  
- JWTs for OAuth2 client authentication  
- Internal signature operations  

Benefits:

- Private key **never leaves KMS**  
- Agent identity is tied to a secure execution environment  
- High‑assurance signatures

## 6.2 🔑 Developer-supplied keys
Developers may register additional public JWKs:

- For OAuth `private_key_jwt`  
- For agent frameworks managing their own keys  
- For corporate signing keys  

Wallet4Agent stores the public keys; developers retain the private keys.

---

# 7. 🔑 Authentication Methods

Wallet4Agent supports **three** agent authentication flows:

## 7.1 🔹 Agent Personal Access Token (PAT)

```
Authorization: Bearer <agent_pat>
```

Simple and effective for development or local agents.

## 7.2 🔹 OAuth2 Client Credentials  

Agent receives:

- `client_id` = Agent DID  
- `client_secret`  

Then exchanges using:

```
grant_type=client_credentials
```

Ideal for most production requests.

## 7.3 🔹 OAuth2 private_key_jwt  

Strongest method:

- Developer registers a public JWK  
- Agent signs a JWT with its private key  
- Wallet4Agent validates it using the registered public JWK  

Useful for hardware-backed keys and enterprise infrastructures.

---

# 8. 🧾 Credential Issuance (OIDC4VCI)

Wallet4Agent handles complete credential issuance flows:

- Fetch issuer metadata  
- Obtain OAuth tokens  
- Create **proof of key ownership** signed by the agent's KMS key  
- Request credentials  
- Store as attestations  

Supported formats:

- 🟦 SD‑JWT VC  
- 🟩 VC JSON‑LD  

Agents only call MCP tools — Wallet4Agent does all protocol-level work.

---

# 9. 🧪 Verification (OIDC4VP)

Wallet4Agent supports verification of:

- Natural persons  
- Other agents  
- Credential-based access  

Agents can:

- Start user verification  
- Poll status  
- Receive verified attributes safely  
- Authenticate peer agents  

The agent never sees sensitive tokens; only derived, safe claims are returned.

---

# 10. 📦 Credential Storage & Retrieval

Wallet4Agent stores credentials as **attestations**, including:

- Format  
- Issuer  
- VCT/VC type  
- Expiry  
- Encrypted payload  
- Publication status (for Linked VP)  

Agents can:

- List their credentials  
- Accept new ones  
- Access credentials of other agents (if published)

---

# 11. 🌐 OAuth Protected Resource Metadata

Published under:

```
/.well-known/oauth-protected-resource/mcp
```

Includes:

- Supported authentication methods  
- Resource identifiers  
- Trusted authorization servers  

Enables automatic configuration by OAuth2 clients and gateways.

---

# 12. 🛡️ Responsible AI Features

Wallet4Agent supports human-in-the-loop requirements:

```json
{
  "always_human_in_the_loop": true
}
```

Used for:

- High-risk operations  
- Sensitive credential acceptance  
- Escalation to human review  

---


## 🧩 13. Summary for Developers

If you are an Agent developer, Wallet4Agent gives you:

| Feature | What you get |
|--------|--------------|
| 🆔 Agent identity | DID + DID Document |
| 🔑 Authentication | Dev PAT, Agent PAT, OAuth2 Client Credentials, `private_key_jwt` |
| 🔐 Cryptographic keys | Cloud KMS signatures, non‑exportable |
| 📜 Credential issuance | Full OIDC4VCI support (SD‑JWT VC & VC JSON‑LD) |
| ✅ Credential verification | OIDC4VP with simple MCP tools and safe derived claims |
| 👤 Human interaction | QR code → wallet → verified attributes |
| 🤝 Inter‑agent trust | Ability to inspect credentials of other agents (when authorized) |
| ⚙️ Configuration | Auth mode, keys, policies all manageable via MCP |
| 🛡️ Security | KMS, OAuth2, DID rotation & key updates, role‑separated tokens |

Your AI Agent becomes a **verifiable digital entity**, capable of participating in decentralized and regulated digital identity ecosystems while preserving security and accountability.

---

**Maintainer:** Wallet4Agent (Web3 Digital Wallet / Talao )  
For feedback or additional documentation, use the contact channels on the Wallet4Agent website.

| Standard                            | Purpose                                | Link                                                                                                                                                   |
| ----------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **DID Core**                        | Core DID specification                 | [https://www.w3.org/TR/did-core/](https://www.w3.org/TR/did-core/)                                                                                     |
| **Linked Verifiable Presentations** | Public VCs in DID Documents            | [https://identity.foundation/linked-vp/spec/v1.0.0/](https://identity.foundation/linked-vp/spec/v1.0.0/)                                               |
| **OIDC4VCI**                        | Credential issuance                    | [https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) |
| **OIDC4VP**             | Credential presentation                | [https://openid.net/specs/openid-4-verifiable-presentations-1_0.html](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)             |
| **W3C Verifiable Credentials**      | VC Data Model                          | [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)                                                                   |
| **SD-JWT VC (IETF)**                | Selective disclosure credential format | [https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-12.html](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-12.html)               |
