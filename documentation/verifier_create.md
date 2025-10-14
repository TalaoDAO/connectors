# Create a Verifier (Bridge OIDC ↔ OIDC4VP)

**Audience:** application developers who are comfortable with OpenID Connect (OIDC) but new to OIDC4VP.

This page explains how to configure a **Verifier** using the *Create Verifier* form. A **Verifier** acts as a **bridge**:

- On the **application side**, it behaves like a classic **OIDC Relying Party (RP)**. Your app authenticates to the bridge with standard **client_id** / **client_secret** and calls the **Application API**.
- On the **wallet side**, the bridge manages the **OIDC4VP** flow to request and receive verifiable credentials (VCs) from the user’s wallet.

> In short: **you install/operate an OIDC client**, connect it to the bridge using your **application API credentials**, and the **bridge speaks OIDC4VP** to wallets for you.

---

## 1) Prerequisites

1. **OIDC client** in your application (any OIDC library/provider you normally use).
2. **Application API credentials** issued by the bridge:
   - `client_id`
   - `client_secret`
   - (optionally) API base URL / endpoints
3. (Optional) A **landing page** template to brand the user experience during verification.

Once your app can obtain an access token / session with the bridge using OIDC, you can control verification sessions through the Application API and the Verifier configuration described below.

---

## 2) Quick Start (minimal working setup)

1. **Open** *Create Verifier*.
2. **Verifier name** — a label for your verifier (internal/admin use).
3. **Landing page** — select a template from the dropdown.
4. **Credential ID** — choose from the dropdown of registered credentials.
5. **Draft** — leave on the default (currently Draft 30).
6. **Client ID Scheme** — keep the default suggested for the draft.
7. **Click Create Verifier**.

You can return later and adjust advanced options (response mode, encryption, formats, etc.).

---

## 3) Field-by-Field Guide (maps to the form)

### Basic

- **Verifier name** (`name`)
  Human-readable name for this verifier configuration.
- **Description** (`description`)
  Free text description.
- **Landing page** (`landing_page`)
  The HTML template shown to users during the verification flow.
- **Enable Log** (`log`)
  Yes/No toggle. When set to **Yes**, the bridge records request/response logs for debugging.
- **Credential ID for Request JWT** (`credential_id`)
  Select the credential/key material used to sign the request to the wallet.
- **Draft** (`draft`)
  Select the OIDC4VP draft version. Options include Draft 8, 18, 20, 22, 28, and Final 1.0. The available Client ID Schemes change based on this selection.
- **Client ID Scheme** (`client_id_scheme`)How the verifier identifies itself to wallets. Options vary by draft, common ones include:

  - `redirect_uri`
  - `decentralized_identifier` (or `did` in older drafts)
  - `x509_san_dns`
  - `verifier_attestation`

### Response

- **Response Type** (`response_type`)Choose what tokens to expect from the wallet:

  - `vp_token` (default)
  - `id_token`
  - `vp_token id_token` (both)
- **Response Mode** (`response_mode`)How the wallet delivers the result:

  - `direct_post`
  - `direct_post.jwt` (preferred for integrity)
- **Response Encryption** (`response_encryption`)
  Yes/No toggle. If enabled, the wallet encrypts the response.
- **Credential ID for Encryption Response** (`credential_id_for_encryption`)
  Select the credential/key the bridge should advertise for response encryption. Required when encryption is enabled.

### Presentation

- **Presentation Format** (`presentation_format`)

  - `presentation_exchange` (default; Presentation Definition)
  - `dcql_query` (Digital Credential Query Language)
- **Presentation (JSON)** (`presentation`)
  Optional JSON describing the Presentation Definition or DCQL query. Leave empty to accept defaults.

### Wallet & Redirect

- **Wallet Invocation Prefix** (`prefix`)The URI scheme to launch wallets, e.g.:

  - `openid-vc://` (default)
  - `openid4vp://`
  - `siopv2://`
  - `eudiw://`
  - vendor-specific schemes
- **Response Redirect URI** (`response_redirect_uri`)
  Where the bridge should redirect the browser after verification completes. Typically a return URL in your app.

### Verifier Metadata

- **Verifier Metadata (JSON)** (`metadata`)
  Optional JSON object with additional verifier metadata.
- **Verifier Info (JSON)** (`info`)
  Optional JSON array of additional information/attestations about this verifier.

---

## 4) Choosing the Right Draft & Scheme

Wallet ecosystems evolve quickly:

- Use the **default draft** shown in the form unless you have a specific target.
- For maximum compatibility:
  - Draft 28 or Final 1.0
  - Client ID Scheme = `redirect_uri`
  - Presentation Format = `presentation_exchange`
  - Response Mode = `direct_post.jwt`
  - Response Type = `vp_token`

If you need DID-based identification, choose `decentralized_identifier` (or `did` on older drafts).

---

## 5) End-to-End Flow

1. Your application authenticates to the bridge using its **Application API credentials**.
2. You create a **Verifier** with the form above.
3. Your app uses the **Application API** to start a verification session with that Verifier.
4. The user is directed to the bridge’s **landing page**, which launches their wallet (`prefix`).
5. The wallet returns the presentation to the bridge using your configured **Response Mode**, optionally encrypted.
6. The bridge validates and stores the presentation.
7. The bridge redirects the user back to your **Response Redirect URI**.
8. Your app calls the **Application API** to fetch the result.

---

## 6) Troubleshooting

- **Wallet doesn’t launch** → check the prefix you selected matches what the wallet supports.
- **No response received** → verify response mode and your network configuration.
- **Parsing errors** → try disabling encryption temporarily, then re-enable once debugged.
- **Invalid draft/scheme combo** → some schemes only exist on certain drafts. Switch draft or scheme as needed.

---

## 7) Security Notes

- Keep your `client_secret` private.
- Use `direct_post.jwt` and enable **Response Encryption** in production.
- Only use plaintext responses for local debugging.

---

## 8) Example of code

This section shows three **small, copy-paste** integration patterns that use a standard OAuth 2.0 / OIDC client library instead of custom plumbing.

* **Base URL:** `https://wallet-connectors.com` (provided by your platform)
* **Credentials:** `client_id`, `client_secret`, and a `redirect_uri` (provided by your platform)

### Endpoints you will call (Application API)

* **Authorize:** `GET/POST /verifier/authorize` – accepts standard OIDC params:

  `response_type` (`code` or `id_token`), `client_id`, `redirect_uri`, `scope` (e.g., `PID`), optional `state`, `nonce`, and PKCE (`code_challenge`, `code_challenge_method`). Optional `response_mode` (`query` or `fragment`).

  On success, the server redirects back to your `redirect_uri` with `code` and your `state`.
* **Token:** `POST /verifier/token` – `application/x-www-form-urlencoded`.

  Required: `grant_type=authorization_code`, `code`, `redirect_uri`; optional `code_verifier` if you used PKCE. Authenticate with **HTTP Basic** (`client_id:client_secret`) or **client_secret_post** (send both in the form). Returns `access_token` (and possibly `id_token`).
* **UserInfo:** `GET /verifier/userinfo` – with `Authorization: Bearer <access_token>`.

  Returns `{ "sub": "...", "vp_token": ... }` (the presentation / claims).
* **Discovery & Keys:**

  `GET /verifier/.well-known/openid-configuration`, `GET /verifier/jwks.json`.

> **Scopes tip:** `scope` conveys the credential type(s) you want. Example shown in the API: `"PID"`. Add others as your verifier requires.

### One-click HTTP link (CMS / low-code)

Use a plain link or button that starts the Authorization Code flow. Your backend will handle the callback + token exchange.

```markdown
[Verify my credentials](
  https://wallet-connectors.com/verifier/app/authorize
  ?response_type=id-token
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=https%3A%2F%2Fyour-app.example.com%2Fcallback
  &scope=pid
  &state=opaque_state
  &nonce=opaque_nonce
)
```

Example: [http://192.168.0.65:4000/verifier/app/authorize?response_type=id_token&client_id=0000&redirect_uri=https://talao.co&scope=pid&response_mode=query](http://192.168.0.65:4000/verifier/app/authorize?response_type=id_token&client_id=0000&redirect_uri=https://talao.co&scope=pid&response_mode=query)

If your app uses **PKCE** , also add `&code_challenge=YOUR_S256_CHALLENGE&code_challenge_method=S256`. (You’ll send `code_verifier` to `/verifier/token` later.)

### Python (Flask + `requests-oauthlib`) — short version

**Install**

```bash
pip install flask requests requests-oauthlib
```

**app.py**

```python
import os
from flask import Flask, redirect, request, session
from requests_oauthlib import OAuth2Session
import requests

BASE = "https://wallet-connectors.com"
AUTHORIZE_URL = f"{BASE}/verifier/authorize"
TOKEN_URL     = f"{BASE}/verifier/token"
USERINFO_URL  = f"{BASE}/verifier/userinfo"

CLIENT_ID     = os.getenv("YOUR_CLIENT_ID")
CLIENT_SECRET = os.getenv("YOUR_CLIENT_SECRET")
REDIRECT_URI  = "https://your-app.example.com/callback"  # must match the registered one
SCOPE         = ["PID"]  # add/adjust as needed

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "change-me")

@app.get("/")
def index():
    return '<a href="/login">Start verification</a>'

@app.get("/login")
def login():
    oauth = OAuth2Session(CLIENT_ID, scope=SCOPE, redirect_uri=REDIRECT_URI)
    auth_url, state = oauth.authorization_url(AUTHORIZE_URL)  # add PKCE params if you use PKCE
    session["oauth_state"] = state
    return redirect(auth_url)

@app.get("/callback")
def callback():
    oauth = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, state=session.get("oauth_state"))
    token = oauth.fetch_token(
        TOKEN_URL,
        client_secret=CLIENT_SECRET,                  # or client_secret_post
        authorization_response=request.url,
    )
    ui = requests.get(USERINFO_URL, headers={"Authorization": f"Bearer {token['access_token']}"})
    ui.raise_for_status()
    data = ui.json()
    return {"sub": data.get("sub"), "has_vp_token": bool(data.get("vp_token"))}

if __name__ == "__main__":
    app.run(port=3000, debug=True)
```

* `authorization_url(...)` builds the `/verifier/authorize` request. Required params: `response_type=code`, `client_id`, `redirect_uri`, `scope`; optional: `state`, `nonce`, PKCE.
* `fetch_token(...)` POSTs to `/verifier/token` with the authorization `code`. You can use **Basic** auth or **client_secret_post** . Add `code_verifier` if you used PKCE.
* `GET /verifier/userinfo` returns `sub` and `vp_token`.

### JavaScript (Node + Express + `simple-oauth2`) — short version

**Install**

```bash
npm i express express-session simple-oauth2 axios
```

**server.js**

```js
const express = require("express");
const session = require("express-session");
const axios = require("axios");
const { AuthorizationCode } = require("simple-oauth2");

const app = express();
app.use(session({ secret: process.env.SESSION_SECRET || "change-me", resave: false, saveUninitialized: true }));

const client = new AuthorizationCode({
  client: {
    id: process.env.YOUR_CLIENT_ID,
    secret: process.env.YOUR_CLIENT_SECRET
  },
  auth: {
    tokenHost: "https://wallet-connectors.com",
    tokenPath: "/verifier/token",
    authorizePath: "/verifier/authorize"
  }
});

const REDIRECT_URI = "https://your-app.example.com/callback";

app.get("/", (_req, res) => res.send('<a href="/login">Start verification</a>'));

app.get("/login", (req, res) => {
  const authorizationUri = client.authorizeURL({
    redirect_uri: REDIRECT_URI,
    scope: "PID",                          // add scopes as needed
    state: Math.random().toString(36).slice(2),
    // For PKCE, also pass code_challenge + method in authorizeURL options if your library supports it.
  });
  res.redirect(authorizationUri);
});

app.get("/callback", async (req, res, next) => {
  try {
    const tokenParams = { code: req.query.code, redirect_uri: REDIRECT_URI /* add code_verifier if PKCE */ };
    const accessToken = await client.getToken(tokenParams);
    const at = accessToken.token.access_token;

    const { data } = await axios.get("https://wallet-connectors.com/verifier/userinfo", {
      headers: { Authorization: `Bearer ${at}` },
    });

    res.json({ sub: data.sub, has_vp_token: Boolean(data.vp_token) });
  } catch (err) {
    next(err);
  }
});

app.listen(3000, () => console.log("http://localhost:3000"));
```

* The authorize step hits `/verifier/authorize` with the required parameters.
* Token exchange is a form-encoded POST to `/verifier/token` using Basic auth (or `client_secret_post`).
* User info + presentation are retrieved from `/verifier/userinfo`.

### Optional endpoints

* **Logout:** `GET/POST /verifier/logout?post_logout_redirect_uri=...&state=...&id_token_hint=...` – redirects back to your app after ending the session.
* **Discovery:** Use `/.well-known/openid-configuration` to discover `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, and `jwks_uri` at runtime (avoids hardcoding).

### Security & production checklist

* Use **PKCE** for public clients (browsers/mobile). Send `code_challenge` on authorize and `code_verifier` on token exchange.
* Validate `state` (and `nonce` if you request an `id_token`).
* Prefer HTTPS everywhere; keep `client_secret` server-side; rotate secrets regularly.
* Only request the scopes (credential types) you actually need, e.g., `PID`.
