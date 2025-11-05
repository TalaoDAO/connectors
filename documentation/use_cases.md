# Use Cases

This page expands on the home overview. It explains **how each party** uses Wallet4Agent to build a **verifiable-by-default** environment for the Agentic Web.  
All capabilities are delivered by our **MCP server**, which exposes identity and trust tools to AI Agents at runtime and provides admin interfaces for organizations.

---

## For Developers (Agent Builders)

- **Provision a decentralized identity** for each AI Agent (DID such as `did:web` or `did:jwk`).  
- **Receive and store Verifiable Credentials (VCs)** in the agent’s wallet using **OIDC4VCI** (issuance).  
- **Publish a Linked Verifiable Presentation (Linked VP)** in the DID Document so peers can auto-discover proofs.  
- **Define trust policies** (who is trusted to issue what, revocation handling) and attach them to agent workflows.  
- **Operate with selective disclosure** using **SD‑JWT VCs**, and interoperate with **W3C JSON‑LD VCs** where required.  
- **Instrument audit logs** (signed receipts) to trace presentations and key lifecycle events.

**Typical developer journey**  
1) Register the agent → 2) Create DID → 3) Obtain credentials via OIDC4VCI → 4) Publish Linked VP → 5) Configure policies → 6) Deploy.

---

## For Enterprises & Organizations

- **Issue digital certificates/attestations to AI Agents**, signed with your organizational identifiers (DIDs or **X.509**).  
- **Gate access** to APIs and data by requesting **OpenID4VP** presentations from agents or users.  
- **Model roles & mandates** as verifiable credentials (e.g., “Procurement Bot”, “KYC‑cleared Agent”).  
- **Demonstrate compliance** (e.g., ISO, sectoral rules) by issuing and verifying compliance VCs.  
- **Revoke or rotate**: maintain status lists, key rotation, and policy updates across your agent fleet.  
- **Interoperate across ecosystems** (partner networks, wallets, and public trust frameworks) through open standards.

**Typical enterprise scenarios**  
- Certify internal agents for production systems.  
- Verify partner agents before granting API access.  
- Replace static API keys with verifiable, time‑bounded credentials.  
- Keep an auditable trail of agent actions and proofs.

---

## For Users & Citizens

- **Authenticate with trusted digital wallets**: U.S. mobile/driver’s license or **EUDI wallet** in the EU.  
- **Consent and privacy by design**: present only what is needed using **selective disclosure** (SD‑JWT).  
- **Human‑to‑agent interactions** become verifiable (the agent proves who it is, who controls it, and what it is allowed to do).  
- **Revoke consent** and inspect where and when credentials were presented.

---

## For AI Agents (Runtime Behavior)

- **Mutual authentication** with peers via DIDs; **auto‑fetch and verify Linked VPs** discovered in DID Documents.  
- **Present credentials** on demand using **OpenID4VP** (verifier receives a VP token + presentation submission).  
- **Verify other agents’ proofs** and apply local **trust policies** before exchanging data or actions.  
- **Sign messages and actions** with the agent’s DID keys; log signed receipts for accountability.  
- **Operate across regulated and decentralized ecosystems** without custom integrations, thanks to shared standards.

**Typical agent exchanges**  
- Agent ↔ Agent: DID discovery → fetch Linked VP → mutual verification → trusted session.  
- Agent ↔ Service: verifier issues an OpenID4VP request → agent returns a VP with selective disclosure → access granted.

---

## For Verifiers, Partners & Platforms

- **Discover proofs** via **Linked VP endpoints** from the counterparty’s DID Document (fast bootstrap).  
- **Request interactive proofs** using **OpenID4VP** (presentation definitions / constraints).  
- **Run continuous checks** for long‑lived relationships (expiry, revocation, issuer policy).  
- **Federate trust** across multiple issuers and frameworks (public sector, industry consortia, private PKI).

---

## End‑to‑End Flows (at a glance)

**Issuance (OIDC4VCI)**  
- Issuer publishes metadata → Holder (agent or user) obtains token (pre‑authorized or auth code) →  
  Holder proves key possession → Credential is issued (SD‑JWT VC or JSON‑LD VC) and stored in the wallet.

**Presentation (OpenID4VP)**  
- Verifier sends an authorization request with a presentation definition →  
  Holder selects matching VCs (with selective disclosure if SD‑JWT) → returns a VP token → Verifier validates and authorizes.

**Ambient trust (Linked VP + DIDs)**  
- Parties resolve the DID → discover a Linked VP service endpoint → fetch and verify a signed VP → apply policy → proceed or deny.

---

## Technology Stack

- **MCP Server**: provides all runtime tools to agents (sign, present, verify, policy, audit) and admin endpoints for organizations.  
- **Verifiable Credentials**: **SD‑JWT VC** (IETF, selective disclosure) and **W3C Verifiable Credentials (JSON‑LD)**.  
- **Protocols**: **OIDC4VCI** (issuance) and **OpenID4VP** (presentation) for cross‑ecosystem interoperability.  
- **Decentralized Identifiers (DIDs)**: e.g., `did:web`, `did:jwk`, with **Linked Verifiable Presentations** for zero‑touch discovery and verification.  
- **Audit & Governance**: signed receipts, revocation/status lists, key rotation, and policy‑driven access.

---

*Wallet4Agent is in early stage and evolves with W3C, DIF, and IETF communities. This document complements the home page for readers who want concrete use cases per party.*
