# Platform Menu Page

**Audience:** Application developers using the platform to manage issuers, verifiers, credentials, and related tools.

The **Menu** page is your **main navigation hub**. From here, you can quickly access Sandbox and Production environments, manage keys and credentials, try validators, and explore documentation.

---

## Objective of the Page

The goal of this page is to give you a **clear overview of everything available in the platform**, allowing you to:

- Navigate to your **Sandbox** and **Production** issuers and verifiers.  
- Access **keys and credentials** management.  
- Try out **validators** for credentials and QR codes.  
- Manage **status lists** for revocation.  
- Jump directly to **documentation and guides**.  

---

## Page Layout & Sections

When you open the Menu page, you will see:

- **Header** — Includes the platform logo, an “Explain ?” help link, and your account menu (if logged in).  
- **Flashed messages** — Notifications from recent actions.  
- **Main sections** presented as cards. Each card links to a feature of the platform.  

The main sections are:

### Sandbox
Work in a **test environment** with no impact on production.  
- **Issuers** — Issue credentials in a live test environment.  
- **Verifiers** — Test credential verification workflows.  

### Production
Use the **live environment** with real issuers and verifiers.  
- **Issuer** — Issue credentials with qualified signatures.  
- **Verifier** — Verify credentials with registered verifiers.  
  - *Note:* If your subscription is **free**, these cards appear disabled until you upgrade.  

### Keys and Credentials
Manage your keys and stored credentials.  
- **Sandbox Keys** — Keys available in the test environment.  
- **Qualified Credentials** — Credentials hosted remotely (available only with a subscription).  

### Validators
AI-powered validation tools to inspect and test credentials.  
- **VC, EEA, etc.** — Scan Verifiable Credentials.  
- **Issuers and Verifiers (RP)** — Scan issuers and verifiers via QR codes.  

### Status List Manager
Test revocation and status list mechanisms.  
- **Token Status List (SD-JWT)** — Issue credentials with a status list endpoint for revocation.  
- **Bitstring Status List (JSON-LD)** — Local test with bitstring-based revocation.  

### Documentation
Access detailed developer documentation and specifications.  
- **Wallet Integration Guides** — How to integrate Talao’s wallet technology.  
- **Light Trusted List Mechanism** — Manage issuers and verifiers in a trusted ecosystem.  
- **Stablecoin Payments with Wallet** — Specification for secure, compliant stablecoin transfers using OIDC4VP and Verifiable Credentials.  

---

## Using the Menu Page Effectively

1. **Start in Sandbox** — Always begin by testing your issuers, verifiers, and keys in Sandbox.  
2. **Check subscription status** — Upgrade if you need access to Production issuers, verifiers, or qualified credentials.  
3. **Use validators** — Quickly scan credentials or QR codes when debugging integrations.  
4. **Manage status lists** — Experiment with revocation mechanisms to align with your use cases.  
5. **Explore documentation** — Use the linked guides to learn best practices and advanced integration options.  

---

## Related Pages

- **Verifier Selection** — Manage and test verifiers.  
- **Issuer Selection** — Manage and test issuers.  
- **Credential Management** — Store and manage your keys and credentials.  
- **Documentation Hub** — Full guides and API references for integration.  
