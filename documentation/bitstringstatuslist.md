# JWT-VC Bitstring Status List — User Guide

> Audience: **API Platform users issuing JWT-based Verifiable Credentials (VCs)**  
> Page: `bitstringstatuslist.html` → **Activate** / **Revoke** an issued credential by flipping its bit in your **Bitstring Status List**.

---

## What this page does

When you issue JWT-VCs using the **Bitstring Status List** mechanism, each credential is assigned an **index** in a compact bitstring list your issuer publishes.  
This page lets you **activate** or **revoke** a credential later by toggling the bit at that index.

- **Activate** ⇒ the bit reflects “active/valid”.  
- **Revoke** ⇒ the bit reflects “revoked/invalid”.

Verifiers check the credential’s `credentialStatus` field (which includes the **status list URL** and the **index**) and then read the list to determine current status.

> Use this to handle lifecycle events (user offboarding, suspected compromise) *without re-issuing all credentials*.

---

## Prerequisites

- An **Issuer** exists on the platform and issues **JWT-VCs** with **Bitstring Status List** enabled.  
- You have recorded the **Status List Index** for the credential at issuance time.  
- You’re authenticated on the platform (same session/permissions used for issuer actions).

---

## Where to find it

- Navigate to **Menu → Issuer → Bitstring Status List** (exact path may vary per deployment).  
- Page title: **“Activate or Revoke a JWT-VC (Bitstring Status List)”**.

The page uses the same header/footer and overall layout as the issuer management screens for a consistent experience.

---

## Quick how-to (UI)

1. Open **Bitstring Status List**.  
2. Enter the **Status List Index** (e.g., `1234`).  
3. Click **Revoke credential** *or* **Activate credential**.  
4. The page displays a success or error message.

> Make sure to use the **exact index** associated with the credential’s `credentialStatus.statusListIndex`.

---

## API shape behind the page

The page submits a simple form to the backend:

- **Endpoint**: `POST /issuer/bitstringstatuslist`  
  (Your instance may also expose a sandbox route, e.g., `/sandbox/issuer/bitstringstatuslist`.)

- **Fields**:
  - `index` — *(string/int)* the bit index to update
  - `button` — *(string)* either `active` or `revoke` (chosen by the button you click)

### Example — cURL

```bash
# Revoke
curl -X POST https://<your-host>/issuer/bitstringstatuslist   -H "Content-Type: application/x-www-form-urlencoded"   --data "index=1234&button=revoke"

# Activate
curl -X POST https://<your-host>/issuer/bitstringstatuslist   -H "Content-Type: application/x-www-form-urlencoded"   --data "index=1234&button=active"
```

### Example — Python `requests`

```python
import requests

session = requests.Session()  # include auth/cookies/headers as required by your deployment
url = "https://<your-host>/issuer/bitstringstatuslist"

resp = session.post(url, data={"index": 1234, "button": "revoke"})
resp.raise_for_status()
print(resp.text)

resp = session.post(url, data={"index": 1234, "button": "active"})
resp.raise_for_status()
print(resp.text)
```

> **Auth note**: Production deployments typically require an authenticated session or API key for this endpoint.

---

## Bitstring Status List concepts

A typical JWT-VC using Bitstring Status List contains a `credentialStatus` object like:

```json
{
  "credentialStatus": {
    "id": "https://issuer.example.com/status/1#1234",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "1234",
    "statusListCredential": "https://issuer.example.com/status/1"
  }
}
```

- **statusListCredential** — URL where the bitstring list (or a credential encoding it) is published.  
- **statusListIndex** — Position of the credential’s bit in the list.  
- **statusPurpose** — Usually `revocation` (some deployments also use `suspension`).  
- **Semantics** — Your platform implementation decides which bit value means “revoked” vs “active” (the UI/API handles it for you).

> Verifiers typically cache the list for performance; revocations are recognized when caches refresh.

---

## Best practices

- **Log and store** the index on issuance so support teams can act quickly.  
- **Group by purpose**: If you use multiple lists (e.g., revocation vs suspension), ensure your system writes to the correct one.  
- **Automate bulk ops**: For incident response, script calls to process many indices at once.  
- **Set CDN/cache headers** for timely propagation to verifiers.  
- **Monitor**: Track errors from the update endpoint and the list publisher.

---

## Troubleshooting

**“I don’t know the index.”**  
Record it during issuance. If you’ve lost it, locate the credential’s `credentialStatus.statusListIndex` in your logs/store, or re-issue and revoke the old one once found.

**“Revocation doesn’t show up immediately.”**  
Check caching. Verifiers may cache the list; it updates on their next refresh. Ensure your publishing endpoint is healthy and cache TTLs are reasonable.

**“Form says a required field is missing.”**  
Provide both: an `index` and pick an action (`active` or `revoke`).

**“How do I test?”**  
Use your sandbox route (if available). Issue a test JWT-VC with Bitstring Status enabled, note its index, flip the bit, then verify with a test verifier.

---

## Change log

- **v1.0** — Initial guide (UI, API, concepts, and best practices).
