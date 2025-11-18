# Wallet4Agent — **MCP Server Flow-Centric Use Case Overview**


Wallet4Agent enables AI Agents to act as **verifiable digital entities**, executing tasks securely through identity, credentials, delegation, and policy enforcement.

---

# 🔄 **1. Core Interaction Flows Supported by the MCP Server**
These flows represent the **native operational model** of Wallet4Agent. All use cases derive from them.

## **1.1 User Authentication Flow (Natural Person → Agent)**
**Purpose:** Establish a verifiable identity context between the user and the agent.

1. Agent requests user authentication through the MCP.
2. User scans QR code or opens request in a digital wallet.
3. User presents selected claims (age, identity, residency, etc.).
4. MCP verifies issuer, signature, and trust chain.
5. Verified user attributes are delivered to the agent.
6. Agent proceeds according to policy (eligibility, permissions, restrictions).

---

## **1.2 Company Authentication Flow (Legal Person → Agent)**
**Purpose:** Verify a company before any corporate workflow is initiated.

1. Company submits verifiable corporate credentials.
2. MCP validates issuer (business registry, government system, trusted CA).
3. Verified company attributes—VAT, LEI, legal name—are returned.
4. Agent gains authorization to operate in a corporate context.

---

## **1.3 Delegation / Mandate Flow (Company or User → Agent)**
**Purpose:** Allow a person or company to authorize the agent to perform specific actions.

### Mandate Issuance
1. The principal (user or company) issues a **delegation credential**.
2. Credential contains:  Principal identity, Authorized agent identity (DID), Scope (signing, negotiation, data access, purchase, etc.), Validity period, Revocation endpoint
3. MCP verifies and records the delegation.
4. Delegation is securely stored in the agent’s credential wallet.

### Mandate Activation
5. Agent activates mandate and loads associated permissions.
6. Policies determine accessible services and allowed actions.

---

## **1.4 Service/API Access Flow (Agent → Enterprise or Public API)**
**Purpose:** Allow the agent to securely access a service, replacing API keys with verifiable authentication.

1. Agent calls a service endpoint.
2. Service returns a **VP Request** specifying required credentials.
3. MCP constructs a Verifiable Presentation from:
   - Agent DID
   - Delegation credential
   - User/company credentials (if required)
4. Service validates the VP:
   - Credential integrity
   - Issuer trust
   - Mandate scope
5. Service executes the requested action.

---

## **1.5 Corporate Signature Gateway Flow (Agent → Company Signature System)**
**Purpose:** Enable an agent to obtain a **legally valid corporate signature** using delegation.

### Signature Request Phase
1. Agent completes its assigned corporate task.
2. Agent prepares the document (hash, metadata, workflow ID).
3. Agent contacts the company’s signature gateway.
4. Gateway returns a VP Request detailing signature requirements.

### Proof Construction Phase
5. MCP assembles a VP containing:
   - Agent DID
   - Delegation credential (signing mandate)
   - Relevant company or employee credentials
   - Proof of possession

### Validation & Execution
6. Signature gateway validates:
   - Delegation authenticity
   - Authorization scope
   - Document hash integrity
7. Company signature authority applies a legally recognized corporate signature.
8. Gateway emits a signed receipt for compliance.

### Completion
9. Agent receives the signed document and receipt.
10. MCP logs a complete audit trail (DID, delegation, timestamp, hash).

---

# 🧱 **2. Supported Use Cases Derived From These Flows**
All real-world use cases must map directly to one or more MCP flows.

---

# 👤 **2.1 AI Agent ↔ User Use Cases**
Derived from: **User Authentication + Delegation + Service Access**

- Identity verification (KYC-lite or full)
- Access to personalized services
- Consent and authorization workflows
- Approval of payments and transactions
- Contract or agreement signing
- User attribute verification (age, residency, student status, etc.)
- Secure sharing of sensitive data

---

# 🏢 **2.2 AI Agent ↔ Company Use Cases**
Derived from: **Company Authentication + Delegation + Corporate Signature**

- Verification of legal entities
- Employee/role validation
- Corporate mandate issuance to agents
- Supplier / partner onboarding
- Agent access to corporate systems and APIs
- Approval workflows and corporate signatures
- Agent acting as a corporate representative (negotiation, filings)

---

# 🌐 **2.3 AI Agent ↔ Services / APIs Use Cases**
Derived from: **Service Access Flow**

- Secure authentication to services (OpenID4VP)
- Access to regulated financial, insurance, or government APIs
- Retrieval of user-approved data
- Signing and legal document workflows
- High-assurance operational actions

---

# 🧩 Summary

Wallet4Agent is now structured around **five core flows**: user authentication, company authentication, delegation, service access, and corporate signature. These flows provide the foundation for secure, auditable, and legally compliant interactions between AI Agents, natural persons, companies, and services.

All use cases must ultimately be expressed as combinations of these flows, ensuring clarity, security, and regulatory alignment.