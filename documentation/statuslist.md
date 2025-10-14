# SD‑JWT Status List (Token Status) — User Guide

> Audience: **API Platform users issuing SD‑JWT Verifiable Credentials (VCs)**  
> Page: `statuslist.html` → **Activate** / **Revoke** an issued credential by flipping its bit in your Status List.

---

## What this page does

When you issue SD‑JWT VCs with **Status List** enabled, each credential is assigned an **index** within your issuer’s status list.  
This page lets you **activate** or **revoke** a credential later by toggling the bit at that index.

- **Activate** ⇒ the bit is set to the “active” value (credential is valid).  
- **Revoke** ⇒ the bit is set to the “revoked” value (credential should be treated as invalid).

Wallets and verifiers can check the status by reading your status list URL and the credential’s index.

> **Tip**: Use this page to handle support cases (lost device, suspected fraud) without re‑issuing all credentials.

---

## Prerequisites

- You have created an **Issuer** on the platform (see the *Create Issuer* documentation).  
- Your Issuer is configured to include **Status List** in SD‑JWT credentials.  
- You know the **Status List Index** for the credential you want to change. (You can log it at issuance time in your app.)

---

## Where to find it

- Navigate to **Menu → Issuer → Status List** (or the direct route your deployment provides).  
- The page title is **“Activate or Revoke an SD‑JWT Credential”**.

The page matches the platform styling: same header, layout, and footer as the issuer management screens.

---

## Quick how‑to (UI)

1. Open **Status List**.  
2. Enter the **Status List Index** (e.g., `1234`).  
3. Click **Revoke credential** *or* **Activate credential**.  
4. You’ll receive a success or error message depending on the outcome.

> Make sure you input the **exact index** that was associated to the credential at issuance time.

---

## API shape behind the page

The page posts a simple `application/x-www-form-urlencoded` form to the backend:

- **Endpoint**: `POST /issuer/statuslist` (your instance may expose a sandbox route as `/sandbox/issuer/statuslist`)  
- **Fields**:
  - `index` — *(string/int)* the status list bit index to update
  - `button` — *(string)* either `active` or `revoke` (the page uses the button value to choose the action)

### Example — cURL

```bash
curl -X POST https://<your-host>/issuer/statuslist   -H "Content-Type: application/x-www-form-urlencoded"   --data "index=1234&button=revoke"
```

To activate again:

```bash
curl -X POST https://<your-host>/issuer/statuslist   -H "Content-Type: application/x-www-form-urlencoded"   --data "index=1234&button=active"
```

> Authentication: This endpoint typically requires an authenticated session (same as when using the page). If your deployment protects it with API keys or cookies, include them accordingly.

### Example — Python `requests`

```python
import requests

session = requests.Session()  # include auth/cookies as needed
url = "https://<your-host>/issuer/statuslist"

# Revoke
resp = session.post(url, data={"index": 1234, "button": "revoke"})
resp.raise_for_status()
print(resp.text)

# Activate
resp = session.post(url, data={"index": 1234, "button": "active"})
resp.raise_for_status()
print(resp.text)
```

---

## Status List concepts (SD‑JWT)

- **Status List URL**: Your issuer publishes a compressed, bitstring list (or equivalent) at a well‑known URL.  
- **Index**: Each issued credential carries an index pointing to a bit in that list.  
- **Semantics**: Depending on the draft/implementation, `0/1` indicate “active” vs “revoked” (the platform handles this for you).  
- **Propagation**: Verifiers may cache the list; revocation propagates when they refresh the list (usually quickly).

> If you rotate or shard your lists, ensure your verifiers can still fetch the correct list for past credentials.

---

## Best practices

- **Log the index** you receive at issuance and store it with your credential record.  
- **Build tooling** in your back office to search by user/credential and surface the index.  
- **Automate**: For bulk incidents, script calls to the endpoint so you can revoke many indices at once.  
- **Monitor**: Keep an eye on error logs; network/CDN issues can temporarily affect list fetches by verifiers.

---

## Troubleshooting

**“I don’t know the index.”**  
Track it at issuance time. If unavailable, re‑issue the credential and revoke the old one (if you can locate its index later, revoke it too).

**“Revoke succeeded but verifiers still see it active.”**  
Verifiers may cache the status list. It should update on their next refresh. Check your CDN cache headers.

**“The page says required field missing.”**  
The form needs both: an `index` value and a button action (`active` or `revoke`).

**“How do I test safely?”**  
Use your sandbox route (if available) and issue test credentials with status list enabled. Flip their bits and verify with a test verifier.

---

## Change log

- **v1.0** — Initial guide (UI & API usage, best practices).
