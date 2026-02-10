# Agent Guide – Identity, Authentication, and Credentials

Wallet4Agent allows you to provision **trusted identities** and **credential wallets** for AI Agents — fully aligned with the **EUDI Wallet** architecture and **eIDAS v2**.

This guide complements **Getting Started with Wallet4Agent** and focuses on **agent-to-agent flows**: authentication, credential issuance, attestation discovery, and trust establishment.

All capabilities are exposed through a remote **MCP Server** compatible with any MCP-enabled agent framework.

---

# 1. 🔌 Connect to the MCP Server

Wallet4Agent exposes its APIs through an **MCP (Model Context Protocol) server**.

You can connect using the **MCP Inspector**:

👉 https://modelcontextprotocol.io/docs/tools/inspector

**MCP endpoint**
```
https://wallet4agent.com/mcp
```

- No bearer token is required for **guest access**
- Guest access allows account creation and tool discovery

---

# 2. 🧑‍💼 Create an Account and Root Identity

Create an account using:

```
create_account
```

You can choose the DID method for your root identity:

- **did:cheqd**  
  Fully decentralized identifier anchored on the **cheqd blockchain**.  
  Recommended for production and strong decentralization.

- **did:web**  
  DNS-based identifier under `wallet4agent.com`.  
  Useful for demos, pilots, or controlled environments.

This step creates:
- A **root DID** (Human or Company)
- A **base wallet** that will control all future agents

---

# 3. 🔑 Authenticate as Admin (Personal Access Token)

After account creation, Wallet4Agent returns an **Admin Personal Access Token (PAT)**.

Use it as a Bearer token:

```
Authorization: Bearer <ADMIN_PAT>
```

With the Admin PAT you can:
- Create agent identities
- Create and configure agent wallets
- Define ecosystem and security policies

---

# 4. 🤖 Create Agent Identities and Wallets

Authenticated as your **Human or Company account**, create one or more agents using:

```
create_agent_identifier_and_wallet
```

Each agent has:
- Its own **DID** (`did:cheqd` or `did:web`)
- Its own **wallet**
- Its own **DID Document**

For every agent you receive:
- An **Admin PAT** (for configuration)
- An **Agent PAT** (to act as the agent)

> You should create **at least two agents** to test agent-to-agent authentication.

---

# 5. 🧠 Act as an Agent (Agent Wallet Access)

Authenticate using the **Agent PAT**:

```
Authorization: Bearer <AGENT_PAT>
```

You now act **as the agent itself** and can:
- Receive verifiable credentials
- Authenticate to other agents
- Sign messages and payloads
- Publish or retrieve attestations

Each agent can only access **its own wallet**.

---

# 6. 🎫 Issue an Attestation to an Agent

To issue an attestation (for example ownership, role, or capability), use an **external OIDC4VCI issuer**.

Example sandbox issuer:

👉 https://talao.co/sandbox/issuer/test_14

Steps:
1. Enter the **agent wallet URL** (OIDC4VC Wallet endpoint)
2. Complete issuance
3. The credential is stored in the agent wallet

Credentials are typically stored as **SD-JWT Verifiable Credentials**.

---

# 7. 🔍 Inspect an Agent DID Document

Any agent DID can be resolved using the **Universal Resolver**:

👉 https://dev.uniresolver.io/

The DID Document exposes:
- Verification and authentication keys
- Wallet service endpoints
- Published **Linked Verifiable Presentations (Linked VPs)**

---

# 8. 🔄 Agent-to-Agent Authentication

Agents authenticate each other using **OIDC4VP / SIOPv2**.

Wallet4Agent provides a **single high-level tool** that:
- Starts agent authentication
- Automatically polls the result
- Returns the final status

This flow is:
- Fully cryptographic
- Synchronous and fast
- Human-free

Agents may retrieve **published attestations** of other agents during or after authentication.

---

# 9. 📜 Published Attestations Discovery

Agents can publish selected credentials as **Linked Verifiable Presentations**.

Other agents can:
- Resolve the DID
- Retrieve published attestations
- Verify issuer, validity, and claims

This enables:
- Capability discovery
- Trust establishment
- Delegation verification

---

# 10. 📚 Standards and Compliance

Wallet4Agent relies exclusively on **open European and IETF standards**:

- **Credential Issuance**: OIDC4VCI
- **Authentication & Verification**: OIDC4VP / SIOPv2
- **Credential Format**: IETF SD-JWT VC

These standards originate from:
- **eIDAS v2**
- **EUDI Wallet Architecture Reference Framework (ARF)**

---

# 11. 🎯 Typical Use Cases

- Trusted AI agents acting on behalf of humans or companies
- Secure agent-to-agent communication
- Capability-based authorization
- Verifiable delegation and mandates
- Cross-platform agent interoperability

---

# 12. ✅ Summary

Wallet4Agent provides:
- Decentralized agent identities
- Secure agent wallets
- Interoperable verifiable credentials
- Agent-to-agent authentication
- Full alignment with EUDI and eIDAS v2

All through:
- A single **MCP server**
- Simple Bearer-token security
- Standards-based protocols
