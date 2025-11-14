from flask import Flask, request, jsonify, current_app, redirect
import base64
import jwt
import datetime
import uuid



CLIENTS = {
    "client_basic": {"secret": "basic_secret"},
    "client_post": {"secret": "post_secret"},
    "client_jwt": {"public_key": "your-public-key-here"},
    "did:web:wallet4agent.com:44cb989fc1d02ab8a25fa21d714750fa": {
        "secret": "gzWgnOtQwSktZduo49fe_2adwHon7u2u1_hknIeUlLsaEce6ZcH_xWg2Blr0fjuytO-JiKGIwlnD51y6dLCS9g"
    },
}



def init_app(app):
    # Authorization server endpoint for MCP server
    app.add_url_rule('/.well-known/oauth-authorization-server', view_func=oauth_metadata, methods=['GET'])
    app.add_url_rule('/oauth2/token', view_func=token, methods=['GET', 'POST'])

    return


def authenticate_client():
    """
    Try to authenticate the client using:
        1. Client Secret Basic
        2. Client Secret Post
        3. Client Assertion JWT
    Returns: (client_id or None, error_message or None)
    """

    # --- 1. CLIENT SECRET BASIC ---
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header.split(" ")[1]).decode()
            client_id, client_secret = decoded.split(":", 1)

            client = CLIENTS.get(client_id)
            if client and client.get("secret") == client_secret:
                return client_id, None
            return None, "invalid_client_credentials"
        except Exception:
            return None, "invalid_basic_auth"

    # --- 2. CLIENT SECRET POST ---
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    if client_id and client_secret:
        client = CLIENTS.get(client_id)
        if client and client.get("secret") == client_secret:
            return client_id, None
        return None, "invalid_client_credentials"

    # --- 3. CLIENT ASSERTION JWT ---
    client_assertion = request.form.get("client_assertion")
    client_assertion_type = request.form.get("client_assertion_type")

    if client_assertion and client_assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
        try:
            # Decode JWT using stored public key (simplified demo)
            decoded = jwt.decode(
                client_assertion,
                CLIENTS["client_jwt"]["public_key"],
                algorithms=["RS256"],
            )

            client_id = decoded.get("sub")
            if client_id in CLIENTS:
                return client_id, None
            return None, "unknown_client"
        except Exception:
            return None, "invalid_client_assertion"

    # No recognized authentication found
    return None, "authentication_required"


# MCP server AS token endpoint
def token():
    print(request.headers)
    print(request.form)
    client_id, error = authenticate_client()
    print(authenticate_client())
    if error:
        return (
            jsonify({
                "error": "invalid_client",
                "error_description": error
            }),
            401,
        )

    # Example: issue token
    access_token = jwt.encode(
        {
            "sub": client_id,
            "iat": datetime.datetime.now(),
            "exp": datetime.datetime.now() + datetime.timedelta(minutes=30)
        },
        "example-signing-secret",
        algorithm="HS256"
    )

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 1800
    })


def oauth_metadata():
    mode = current_app.config["MODE"]
    metadata = {
        "issuer": mode.server,
        "token_endpoint": mode.server + "token",
        "authorize_endpoint": mode.server + "authorize",

        "grant_types_supported": [
            "client_credentials",
            #"authorization_code",
            "refresh_token"
        ],

        "response_types_supported": [
            "token"
        ],

        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt"
        ],

        "token_endpoint_auth_signing_alg_values_supported": [
            "RS256",
            "ES256"
        ]
    }
    return jsonify(metadata)


# In-memory authorization code store (DEMO ONLY)
AUTHORIZATION_CODES = {}

# Registered redirect URIs (demo)
A_CLIENTS = {
    "client_basic": {
        "redirect_uris": ["http://localhost:6274/oauth/callback"]
    },
    "client_post": {
        "redirect_uris": ["http://localhost:6274/oauth/callback"]
    },
    "client_jwt": {
        "redirect_uris": ["http://localhost:6274/oauth/callback"]
    }
}


def authorize():
    """
    Minimal OAuth2 Authorization Endpoint
    Supports: response_type=code
    """

    response_type = request.args.get("response_type")
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope")
    state = request.args.get("state")

    # ---- 1. Validate mandatory parameters ----
    if response_type != "code":
        return jsonify({"error": "unsupported_response_type"}), 400

    if client_id not in A_CLIENTS:
        return jsonify({"error": "invalid_client"}), 400

    if redirect_uri not in A_CLIENTS[client_id]["redirect_uris"]:
        return jsonify({"error": "invalid_redirect_uri"}), 400

    # ---- 2. Simulate login and consent ----
    # In real servers, you would:
    #   - authenticate user
    #   - show consent screen
    #
    # Here we skip both steps (minimal example).
    user_id = "demo-user"

    # ---- 3. Generate authorization code ----
    auth_code = str(uuid.uuid4())

    AUTHORIZATION_CODES[auth_code] = {
        "client_id": client_id,
        "user_id": user_id,
        "scope": scope,
        "expires_at": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    }

    # ---- 4. Redirect with ?code=xxx&state=yyy ----
    redirect_url = f"{redirect_uri}?code={auth_code}"
    if state:
        redirect_url += f"&state={state}"

    return redirect(redirect_url, code=302)
