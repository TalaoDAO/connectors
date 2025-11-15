# Wallet4Agent — **Technical Stack Overview**  

_For developers building AI Agents with verifiable, accountable identity_

This document provides a **clean, implementation‑independent** overview of the technical architecture and protocols used by **Wallet4Agent**.  
It is written for **Agent developers** consuming Wallet4Agent — **not for contributors modifying the internal codebase**.  
No internal code or repository access is required.

The goal is to understand:

- 🧱 **Architecture** — how Wallet4Agent is structured  
- 🆔 **Identity** — how DIDs and DID Documents are used  
- 🔐 **Keys & KMS** — how signatures and key material are handled  
- 🔑 **Authentication** — how Agents and Developers authenticate  
- 📜 **Protocols** — OIDC4VCI (issuance), OpenID4VP (verification), OAuth2, MCP  
- 📦 **Credentials** — how they are issued, stored, and exposed to your Agent  

---

## 🧭 1. Purpose of Wallet4Agent

AI agents must be able to:

- Present **verifiable, externally issued credentials**
- Prove **who they belong to** and **who controls them**
- Interact with **users**, **organizations**, **infrastructures**, and **other agents** in a trustworthy way  
- Use signed, KMS‑protected keys for high‑assurance cryptography
- Participate in **decentralized** and **regulated** digital identity ecosystems

Wallet4Agent provides exactly that.  
It turns any AI agent into a **verifiable digital entity** with:

- A **DID (Decentralized Identifier)**
- A **wallet** that can hold credentials
- A **full cryptographic stack**, including signatures bound to cloud KMS
- A **standards‑compliant interface** exposed through **MCP (Model Context Protocol)**

---

## 🏗️ 2. Architecture Overview

Wallet4Agent is composed of three main layers, all exposed through **MCP tools**:

1. **MCP Server**  
   - Single RPC endpoint:  
     `POST https://wallet4agent.com/mcp`  
   - JSON‑RPC based (`tools/list`, `tools/call`, `initialize`, `ping`, etc.)  
   - All operations (identity, credentials, verification, configuration) are available as tools.

2. **Identity Wallet**  
   - Maintains a **DID** and **DID Document** for each Agent.  
   - Stores and manages **verifiable credentials** (SD‑JWT VC, VC JSON‑LD).  
   - Publishes public keys and optional Linked Verifiable Presentations.

3. **Authorization & Verification Layer**  
   - Issues and validates **access tokens** for Agents (OAuth2).  
   - Integrates with external **credential issuers** (OIDC4VCI).  
   - Integrates with external **verifiers** (OpenID4VP / OIDC4VP) for user identity checks.

As an Agent developer, you only need to:

- Call the **MCP endpoint**  
- Provide the correct **Authorization** header  
- Use the documented **tools** (e.g. `create_agent_identifier_and_wallet`, `get_this_wallet_data`, `accept_credential_offer`, `start_user_verification`).

No database access, internal APIs, or KMS commands are required.

---

## 🆔 3. Identity Layer (DID & DID Document)

Each agent created through Wallet4Agent receives a **W3C DID**, typically:

```text
did:web:wallet4agent.com:<unique-id>
```

This DID is associated with a **DID Document** that:

- Is publicly reachable (e.g. `https://wallet4agent.com/did/<unique-id>`)
- Contains:
  - **Verification methods** (public keys as JWK or other forms)
  - **Authentication methods** (which keys can authenticate the Agent)
  - Optional **service endpoints** and references to Linked VPs

The DID Document is automatically updated when the developer:

- Adds a new public key  
- Rotates an authentication key  
- Enables or disables certain capabilities  

This allows external systems (other agents, verifiers, infrastructures) to:

- Resolve the DID  
- Discover the corresponding public keys  
- Verify signatures and presentations from that Agent.

---


### 🔗 3.1 Linked Verifiable Presentations (Linked VP)

Linked Verifiable Presentations (Linked VP) allow Wallet4Agent to publish **public verifiable credentials directly inside a DID Document**...

### 🌐 3.2 DID Resolution (How Agents Discover Other Agents)

Any system can resolve a DID using a universal resolver such as https://dev.uniresolver.io/...
## 🔐 4. Cryptography & Key Management

### 4.1 KMS‑Bound Keys (Server‑controlled signing keys)

Wallet4Agent uses a **per‑agent, cloud KMS key** for critical signatures.

Key characteristics:

- **Asymmetric EC key** (e.g. P‑256 or secp256k1)
- **Non‑exportable** — the private key never leaves the cloud KMS
- Bound to the **cloud workload identity** (e.g. an IAM Role)
- Used for:
  - Issuing **OIDC4VCI proofs of key ownership**
  - Signing **verifiable presentations**
  - Constructing **DID‑linked proofs**
  - Other internal verifiable operations

This ensures:

- The agent identity is **cryptographically anchored** to a specific workload  
- The key cannot be stolen or exported  
- Every signature has **auditable accountability** (bound to the deployment environment)

In public documents (like the DID Document), these keys appear as JWK values, but **only the public part** is published. The private key remains in KMS.

### 4.2 Developer‑supplied keys

Developers may add additional **public keys** to the wallet (via MCP tools). Typical uses:

- **OAuth2 `private_key_jwt` client authentication**  
- Keys managed by **external agent frameworks**  
- Protocol‑specific keys that must be exposed in the DID Document

Only **public keys** are stored and published.  
The developer keeps and manages the corresponding private keys.

---

## 🔑 5. Authentication & Authorization

Wallet4Agent supports multiple actor roles and authentication mechanisms.

### 5.1 Developer Authentication (Dev PAT)

Developers authenticate using a **Developer Personal Access Token** (Dev PAT):

- Returned **once** when the agent wallet is created  
- Used to configure the agent (e.g. update auth keys, rotate tokens)  
- Grants full administrative control of that particular agent’s wallet  
- Never persisted in clear‑text; only a token identifier is stored for validation

All **administrative tools** (configuration, rotation, key management, deletion) require a valid Dev PAT.

### 5.2 Agent Authentication Options

Agents authenticate separately from Developers. Available options:

#### Option A — **Agent Personal Access Token (PAT)**

- Simple bearer token:  
  `Authorization: Bearer <agent_personal_access_token>`
- Similar in spirit to GitHub/GitLab PATs
- Best for:
  - Rapid prototyping
  - Single environment deployments
  - Low‑risk integrations
- Tokens can be rotated by the developer via MCP.

#### Option B — **OAuth 2.0 Client Credentials**

Agents can act as **OAuth clients**, obtaining access tokens from the authorization server associated with Wallet4Agent.

Supported client authentication methods:

1. `client_secret_post`  
2. `client_secret_basic`  

In both cases, the agent is identified by:

- `client_id` = Agent DID (e.g. `did:web:wallet4agent.com:<id>`)  
- `client_secret` = secret generated by Wallet4Agent and returned once to the developer

Wallet4Agent functions as the **Authorization Server (AS)** issuing OAuth2 access tokens for Agents.  
The Agent then calls the MCP endpoint with:

```text
Authorization: Bearer <access_token>
```

#### Option C — **OAuth 2.0 with `private_key_jwt`**

For higher security and strong binding to keys controlled by the developer, Wallet4Agent also supports **`private_key_jwt`**:

- Developer registers a **public JWK** as the agent’s client key (via an MCP configuration tool)
- Agent holds and protects the **private part** of that JWK
- When requesting an access token, the agent signs a `client_assertion` JWT with that key
- Wallet4Agent validates the assertion using the registered public JWK

This method is ideal when:

- You already manage keys in secure hardware (HSM, KMS in your own stack, secure enclaves)
- You want to avoid long‑lived client secrets
- You need cryptographically strong, auditable client authentication

---

## 📜 6. Verifiable Credential Issuance (OIDC4VCI)

Wallet4Agent handles **credential issuance** from external issuers using **OIDC4VCI**.

Supported credential formats:

- **SD‑JWT VC** (`dc+sd-jwt`)
- **W3C VC JSON‑LD** (2.0)

High‑level flow (from the Agent or Developer perspective):

1. You obtain a **credential offer** (URL or JSON) from a trusted issuer.  
2. The Agent instructs Wallet4Agent, via MCP, to **accept** this credential offer.  
3. Wallet4Agent:
   - Fetches issuer metadata:
     - `openid-credential-issuer`
     - `oauth-authorization-server`
   - Acts as an **OAuth client** to that issuer.  
4. Wallet4Agent obtains a **credential issuance access token**.  
5. Wallet4Agent generates a **proof of key ownership**:
   - A dedicated JWT signed by the agent’s **KMS‑backed key**  
   - Proves that the DID (and wallet) controls the key referenced in the credential.  
6. Wallet4Agent sends a **credential request** with this proof.  
7. The issuer returns a Verifiable Credential (SD‑JWT VC or VC JSON‑LD).  
8. Wallet4Agent stores the credential in the agent’s wallet as an **attestation**.  
9. The Agent can retrieve or present this credential via MCP tools.

All critical proofs and signatures in this flow are bound to the **KMS key associated with the agent**, not to any local file‑based key.

---

## 🧾 7. Verifying Users (OIDC4VP)

Wallet4Agent also integrates with **OIDC4VP** verifier services to validate **user identities**.

From the Agent’s perspective:

1. The Agent calls a **verification tool** (via MCP) to start a user verification session.  
2. Wallet4Agent (or its verifier backend) returns:
   - A **QR code** (image) or **deeplink URL** that the end‑user can open in their wallet app.  
   - A `session_id` or correlation identifier.  
3. The Agent displays the QR code or link to the user.  
4. The user scans with their **EUDI wallet** or compatible OIDC4VP wallet, and consents to share attributes.  
5. The Agent then periodically calls another MCP tool to **poll** the verification status.  
6. When verification completes, Wallet4Agent returns structured claims such as:
   - Verified **email**  
   - `over_18` or other age/eligibility attributes  
   - Profile attributes (name, country, assurance level, etc.)  
   - A wallet‑specific identifier, if relevant  

Design principle:

- The Agent **never sees raw tokens** (`id_token`, `vp_token`, etc.).  
- Only **safe, derived claims** are exposed, protecting the user while still giving the Agent the information it needs.

---

## 📦 8. Credential Storage & Retrieval

Each Agent wallet can hold **multiple credentials**. Conceptually, each credential record contains:

- The **format type**:
  - SD‑JWT VC (compact or JSON wrapped)
  - W3C VC JSON‑LD
- The **issuer** (DID or URL)
- The **credential type** (VCT or VC `type`)
- Timestamps (issuance time, possibly expiry)
- The **full verifiable credential payload**

MCP tools allow an Agent to:

- List all its credentials  
- Inspect a specific credential  
- Accept new credentials via credential offers  
- Query credentials issued to **another agent** (within authorization rules) to establish trust between agents

Wallet4Agent does not require the Agent to care about internal storage format; all details are surfaced in a structured, MCP‑friendly way.

---

## 🌐 9. Protected Resource Metadata (OAuth PRM)

To make Agent integration easier, Wallet4Agent publishes **OAuth Protected Resource metadata** in line with **RFC 9728**, for example:

```text
/.well-known/oauth-protected-resource/mcp
```

This metadata indicates:

- Supported **authentication methods** (e.g. bearer tokens in the `Authorization` header)  
- Whether access tokens are **bound to TLS client certificates** or other constraints  
- Which **authorization servers** are trusted for accessing the MCP resource  
- One or more **resource identifiers** that confirm to clients they are using the correct access token for this MCP resource

Result: a compliant OAuth2 client (your Agent infrastructure, gateway, or platform) can automatically discover **how to authenticate** against the Wallet4Agent MCP server.

---

## 🤝 10. Responsible AI & Human‑in‑the‑loop

Each agent wallet includes configuration that can be used to enforce **responsible behaviour**, such as:

- `always_human_in_the_loop` — a flag indicating that certain high‑impact actions should **require human approval**.

This can be used (by the developer or platform) to:

- Require a human confirmation before accepting high‑value credentials  
- Display prompts or logs in a human UI when sensitive operations occur  
- Provide transparency and auditability to users or administrators

These features are optional but recommended for sensitive or regulated use cases.

---

## 🛡️ 11. Why Wallet4Agent is Secure by Design

Wallet4Agent is built around a few strong security principles:

- ✔ **Immutable cryptographic identity** via DIDs  
- ✔ **Cloud KMS non‑exportable keys** for critical signatures  
- ✔ **Strict role separation** (Guest / Developer / Agent)  
- ✔ **Publicly verifiable DID Documents** containing the relevant keys  
- ✔ **RFC‑compliant OAuth2 flows** for access tokens  
- ✔ **Interoperability** with EUDI, OIDC4VP, OIDC4VCI ecosystems  
- ✔ **Zero‑knowledge handling of user tokens** during verification  
- ✔ **Accountability anchored to real owners** through owner bindings and config

The result: a foundation appropriate for **industrial‑grade agentic systems** where identity, trust, and accountability cannot be optional.

---

## 🧩 12. Summary for Developers

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
