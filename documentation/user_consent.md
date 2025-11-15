# User Consent for SD-JWT Attestations (Platform Guide)

**Audience:** users of the platform.  
This guide explains how to use the **User Consent** page (`user_consent.html`) to review an SD-JWT VC, accept or reject it, and optionally publish it. The page receives the credential **via template (Jinja) injection**, not through URL parameters.

---

## What you’ll do on this page

- **Preview** the credential’s **payload only** (signatures are hidden).  
- **Inspect** technical details (raw header/payload, byte size).  
- **Choose** to **Accept** or **Reject** the credential.  
- If accepted, **decide** whether to **publish** it (public) or keep it **private**.  
- **Submit** your decision so the server stores the SD-JWT string and the human-readable payload.

---

## Quick Start (2 minutes)

1. The page automatically parses and displays the **payload** and quick facts (**Issuer**, **Subject**, **Issued/Expires**).  
2. Click **Accept** or **Reject**. If you accept, choose **Private** or **Public**.  

---

## Page layout & fields

### Header & context
- Title and help link in the header; same styling as other wallet pages.

### Quick facts card
- **Issuer** — from `payload.iss` (read-only).  
- **Subject (holder)** — from `payload.cnf.kid` or `payload.cnf` (read-only).  
- **Issued / Expires** — a single read-only line computed from `iat` and `exp` (ISO time).

> Want separate lines? Replace the “Issued / Expires” row with two rows (“Issued at”, “Expires at”) and set `#issued` / `#expires` in the script; see the inline comment in the JS section of this page.

### Human-readable payload
- A pretty-printed JSON view of the **payload with applied disclosures** (only claims; no signatures).  
- If there are **no disclosures** and no `_sd` anchors, the **entire payload** is shown (minus housekeeping keys).

### Technical details (toggle)
- **Raw SD-JWT size** (bytes) + **Copy** button.  
- **JWT header** (decoded).  
- **JWT payload (raw)** (decoded, before disclosure application).

### Decision & publishing
- **Reject** or **Accept** buttons.  
- If **Accept**, a block appears with:
  - **Private** (keep in agent wallet), or
  - **Public** (publish to DID Document / directory, depending on your backend).

---

## What gets submitted (POST /user/consent)

The form posts these fields to your server when you click **Submit**:

- `sd_jwt_vc` — the original combined SD-JWT string (from the hidden `<textarea>`).  
- `session_id` — your session correlation token (hidden `<input>`).  
- `decision` — `"accept"` or `"reject"` (set by the buttons).  
- `publish` — `"true"` or `"false"` (radio selection shown only after “Accept”).  
- `payload_applied_json` — JSON string of the **human-readable payload** after applying disclosures.

---

## How parsing & display work (client-side)

- The page expects the **combined SD-JWT** format:  
  `JWS ~ disclosure ~ disclosure … ~ (optional KB-JWT)`  
  It splits on `~`, finds the JWS part, and treats the rest as disclosures and optional holder-binding JWT.
- **Base64url decode with padding**: it normalizes and pads before `atob` to support any token length.
- **Header & payload** are decoded from the JWS and shown as JSON.
- **Disclosure application**:
  - Each disclosure is `b64u(JSON [salt, name, value])`.  
  - A SHA-256 digest of the disclosure (base64url) is matched against `_sd` anchors for a **lightweight inclusion check**.  
  - Verified keys are tagged (legend chips appear under the viewer).  
  - The resulting merged object is posted in `payload_applied_json`.

---

## Security & privacy notes

- **No network fetches** from the browser: all decode/render happens **locally** in the page.  
- **Only payload** is displayed; signatures are intentionally hidden from the main viewer.  
- Publishing is **opt-in** after acceptance; your backend controls what “public” means (e.g., DID Document update or directory entry).

---

## Troubleshooting

- **The page shows “No SD-JWT detected.”**  
  Ensure your backend renders the template with a non-empty `sd_jwt_vc` value (hidden `<textarea>`).
- **Garbled header/payload**  
  Usually base64 padding; the page already pads, but confirm the injected `sd_jwt_vc` isn’t truncated or HTML-escaped.
- **Nothing happens on Accept**  
  The **Submit** button is disabled until you click **Accept** or **Reject**. After clicking **Accept**, choose **Private**/**Public**; then **Submit** enables.
- **Need separate Issued/Expires lines**  
  Update the two fields in HTML and set them in JS as described above.

---

## Integration checklist (server-side)

- Render `user_consent.html` with:
  - `sd_jwt_vc` (string),  
  - `session_id` (string),  
  - optional `title`.  
  The form `POST`s to `/user/consent` (you can change to `{{ url_for('user_consent') }}`).
- In the POST handler, persist:
  - the original `sd_jwt_vc`,  
  - `decision`, `publish`,  
  - and parsed `payload_applied_json`.  
  Then proceed with storage/publishing according to your policy.

---

## Where to get help

- Click **“Explain ?”** in the page header to open the related help section.  
- If an SD-JWT doesn’t render, capture the first 64 chars of `sd_jwt_vc` and whether it ends with `~` (disclosures) when contacting support — it helps pinpoint parsing issues.

---

**You’re done!** You can now reliably gather user consent for SD-JWT attestations, post the result to your backend, and optionally publish the credential according to your business rules.
