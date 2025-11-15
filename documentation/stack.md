# Wallet4Agent — Technical Stack Overview  
_For developers building AI Agents with verifiable, accountable identity_

This document provides a **clean, implementation‑independent** overview of the technical architecture and protocols used by **Wallet4Agent**.  
It is written for **Agent developers** consuming Wallet4Agent — **not for contributors modifying the internal codebase**.  
No internal code or repository access is required.

The goal is to understand:

- What protocols Wallet4Agent supports  
- How identity, signatures, and keys work  
- How the MCP server authenticates and authorizes Agents  
- How credentials are issued, verified, stored, and exposed  
- How KMS‑bound keys guarantee security and accountability  

---

# 1. Purpose of Wallet4Agent

AI agents must be able to:

- Present **verifiable, externally issued credentials**
- Prove **who they belong to** and **who controls them**
- Interact with **users**, **organizations**, **infrastructures**, and **other agents** in a trustworthy way  
- Use signed, KMS‑protected keys for high‑assurance cryptography
- Participate in **decentralized** and **regulated** digital ID ecosystems

Wallet4Agent provides exactly that.  
It turns any AI agent into a **verifiable digital entity** with:

- A **DID (Decentralized Identifier)**
- A **wallet** that can hold credentials
- A **full cryptographic stack**, including signatures bound to cloud KMS
- A **standards‑compliant interface** exposed through **MCP (Model Context Protocol)**

---

# 2. Architecture Overview

Wallet4Agent is composed of:

## 2.1 MCP Server (Model Context Protocol)

This is the main interface used by AI Agents.

- Single endpoint:  
  `POST https://wallet4agent.com/mcp`
- JSON-RPC based  
- All identity, credential, verification, and configuration operations are exposed as tools
- Access is controlled using **Bearer tokens** (PAT or OAuth2 access tokens)

AI Agents interact with Wallet4Agent **exclusively through MCP tools**, allowing:

- Wallet creation  
- Credential issuance  
- Credential storage  
- Verification of user wallets (OIDC4VP)  
- Agent/agent trust checks  
- Updating authentication keys  
- Rotating personal access tokens  
- Querying DID and attestation state  

No internal API or database knowledge is required.

---

# 3. Identity Layer (DID & DID Document)

Each agent created through Wallet4Agent receives a **W3C DID**, typically:

```
did:web:wallet4agent.com:<unique-id>
```

This DID has:

- A publicly reachable **DID Document**
- Cryptographic methods required to verify:
  - Agent signatures
  - Credential presentations
  - OAuth2 `private_key_jwt` assertions (if enabled)
- Public keys needed by verifiers (Agents, servers, issuers)

The DID Document is automatically updated when the developer:

- Adds a new public key  
- Rotates an authentication key  
- Enables/disables certain capabilities  

This allows external systems to trust the agent automatically.

---

# 4. Cryptography & Key Management

## 4.1 KMS-Bound Keys (Server-controlled signing keys)

Wallet4Agent uses a **per-agent, per-tenant cloud KMS key**.

Key characteristics:

- EC key (P-256 or secp256k1)
- Non-exportable (private key never leaves KMS)
- Bound to the **cloud workload identity** (IAM Role)
- Used for:
  - Issuing OIDC4VCI proofs of key ownership
  - Signing presentations
  - Constructing DID-linked verifiable proofs
  - Internal verifiable operations

This ensures:

- The agent identity is **cryptographically anchored**  
- The key cannot be stolen or exported  
- Every signature has accountability (bound to a specific deployment environment)

These keys appear publicly via the DID Document as JWK values, but **only the public part**.

## 4.2 Developer-supplied keys

Developers may add additional public keys to the wallet (via MCP):

- For **OAuth2 private_key_jwt** client authentication
- For external agent frameworks requiring their own signing keys
- For protocol-specific needs

Only **public keys** are stored; private material remains under the developer’s control.

---

# 5. Authentication & Authorization

Wallet4Agent supports multiple agent authentication methods:

## 5.1 Developer Authentication

Developers authenticate using a **Developer Personal Access Token** (Dev PAT).

- Returned once when the agent wallet is created
- Used to configure the agent (e.g., update auth keys)
- Allows full administrative control of that particular agent wallet
- Never persisted in clear-text; only the token’s JTI is stored

## 5.2 Agent Authentication Options

### Option A — **Agent Personal Access Token (PAT)**

Simple bearer token:

- Similar to GitHub/GitLab PATs
- Best for testing and low-risk deployments
- Can be rotated by the developer

### Option B — **OAuth 2.0 Client Credentials**

The agent acts as an OAuth client, using:

#### Method 1 — `client_secret_post`  
#### Method 2 — `client_secret_basic`  

Suitable for automated / production workloads.

Wallet4Agent functions as the **Authorization Server (AS)** for issuing access tokens to agents.

#### Method 3 — `private_key_jwt`

Highest-security method:

- Developer registers a **public JWK** as the agent’s client key
- Agent signs `client_assertion` JWTs with its private key
- Wallet4Agent verifies using the public JWK previously added

---

# 6. Verifiable Credential Issuance (OIDC4VCI)

Wallet4Agent handles **credential issuance** from external issuers through standard **OIDC4VCI**.

Supported credential formats:

- **SD‑JWT VC** (`vc+sd-jwt`, `dc+sd-jwt`)
- **W3C VC JSON-LD** (1.1)

High-level flow:

1. Developer / agent receives a **credential offer** link
2. Wallet4Agent fetches issuer metadata:
   - `/openid-credential-issuer`
   - `/oauth-authorization-server`
3. Wallet4Agent acts as OAuth client
4. Wallet4Agent obtains credential issuance access token
5. Wallet4Agent creates **proof of key ownership**, signed with the KMS key
6. Wallet4Agent requests the credential
7. Credential is stored as an **Attestation** in the agent’s wallet
8. Agent can retrieve or present this credential via MCP tools

All issuance operations use the agent’s KMS-bound key to prove identity.

---

# 7. Verifying Users (OIDC4VP / OpenID4VP)

Wallet4Agent integrates with external **verifier services** to validate **user identities** using OIDC4VP.

The agent can:

1. Start a verification request  
2. Receive a QR code or deeplink  
3. Ask the end-user to scan it with their digital wallet  
4. Poll the verification status  
5. Retrieve structured claims returned by the verifier:
   - Email  
   - Over-18 flag  
   - Profile attributes  
   - Assurance level  
   - Wallet-specific identifiers  

The agent **never sees raw tokens** — only safe, derived claims.

---

# 8. Credential Storage & Retrieval

Agents may store **multiple credentials**, each recorded as:

- Format type (SD-JWT / VC JSON-LD)
- Issuer
- VCT / credential type
- Issue timestamp
- Full verifiable credential

MCP tools allow:

- Listing credentials  
- Retrieving credential details  
- Querying credentials held by another agent  
- Accepting new credentials via credential offers  

---

# 9. Protected Resource Metadata (OAuth PRM)

Wallet4Agent publishes metadata conforming to **RFC 9728**:

`/.well-known/oauth-protected-resource/mcp`

Indicates:

- Supported auth methods
- Bound access tokens
- Associated Authorization Server
- Resource identifiers

This helps well-behaved OAuth clients (agents) automatically discover how to authenticate.

---

# 10. Responsible AI & Human-in-the-loop

Each agent wallet includes a parameter:

- `always_human_in_the_loop`

Agents or developers may use this flag to:

- Require human approval for credential acceptance
- Display prompts before high-value interactions
- Offer transparency logs in the DID Document or wallet UI

This is optional but recommended for sensitive use cases.

---

# 11. Why Wallet4Agent is Secure by Design

Wallet4Agent provides:

✔ **Immutable cryptographic identity**  
✔ **Cloud KMS non-exportable keys**  
✔ **Strict role separation (Guest / Dev / Agent)**  
✔ **DID Document publicly verifiable keys**  
✔ **RFC-compliant OAuth flows**  
✔ **Full interoperability with EUDI, OIDC4VP, OIDC4VCI**  
✔ **Zero-knowledge token processing for user verification**  
✔ **Accountability anchored to real owners**  

It is designed for **industrial-grade, agentic systems** where identity matters.

---

# 12. Summary for Developers

If you are an agent developer, Wallet4Agent gives you:

| Feature | What you get |
|--------|--------------|
| Agent identity | DID + DID Document |
| Authentication | PAT, OAuth2, private_key_jwt |
| Cryptographic keys | Cloud KMS signatures, non-exportable |
| Credential issuance | Full OIDC4VCI support |
| Credential verification | OIDC4VP with simple MCP tools |
| Interaction with humans | QR code → wallet → verified claims |
| Inter-agent trust | Check another agent’s credentials |
| Configuration | Modify auth modes, keys, policies via MCP |
| Security | KMS, OAuth, DID rotation & key updates |

Your AI agent becomes a **verifiable digital entity** capable of participating in decentralized and regulated digital identity ecosystems.

---

**Maintainer:** Wallet4Agent (Web3 Digital Wallet)  
For feedback or additional documentation, contact the team via the website.
